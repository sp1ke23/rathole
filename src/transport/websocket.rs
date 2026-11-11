use core::result::Result;
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use super::{AddrMaybeCached, SocketOpts, TcpTransport, TlsTransport, Transport};
use crate::config::TransportConfig;
use crate::constants::NETWORK_IO_TIMEOUT;
use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use bytes::Bytes;
use futures_core::stream::Stream;
use futures_sink::Sink;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::time::{self, Sleep};
use tokio_native_tls::TlsStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{accept_async_with_config, client_async_with_config};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};
use tokio_util::io::StreamReader;
use url::Url;

#[derive(Debug)]
enum TransportStream {
    Insecure(TcpStream),
    Secure(TlsStream<TcpStream>),
}

impl TransportStream {
    fn get_tcpstream(&self) -> &TcpStream {
        match self {
            TransportStream::Insecure(s) => s,
            TransportStream::Secure(s) => s.get_ref().get_ref().get_ref(),
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Secure(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Secure(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Secure(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TransportStream::Insecure(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Secure(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
enum ReadState {
    Reading,
    Flushing {
        close: bool,
        deadline: Pin<Box<Sleep>>,
    },
    Closed,
}

#[derive(Debug)]
struct StreamWrapper<S> {
    inner: WebSocketStream<S>,
    state: ReadState,
}

impl<S> StreamWrapper<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            state: ReadState::Reading,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for StreamWrapper<S> {
    type Item = Result<Bytes, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        for _ in 0..16 {
            match &mut stream.state {
                ReadState::Reading => {}
                ReadState::Flushing { close, deadline } => {
                    let result = match Pin::new(&mut stream.inner).poll_flush(cx) {
                        Poll::Ready(result) => {
                            result.map_err(|error| Error::new(ErrorKind::Other, error))
                        }
                        Poll::Pending => {
                            ready!(deadline.as_mut().poll(cx));
                            let error = Error::new(
                                ErrorKind::TimedOut,
                                "WebSocket control frame flush timed out",
                            );
                            tracing::debug!("{error}");
                            Err(error)
                        }
                    };
                    if *close || result.is_err() {
                        stream.state = ReadState::Closed;
                        return Poll::Ready(result.err().map(Err));
                    }
                    stream.state = ReadState::Reading;
                }
                ReadState::Closed => return Poll::Ready(None),
            }

            match ready!(Pin::new(&mut stream.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) if !data.is_empty() => {
                    return Poll::Ready(Some(Ok(Bytes::from(data))));
                }
                Some(Ok(Message::Pong(_) | Message::Binary(_))) => {}
                Some(Ok(message @ (Message::Ping(_) | Message::Close(_)))) => {
                    // tungstenite has already queued the reply. Flush it even
                    // when the peer waits for the reply before sending more data.
                    stream.state = ReadState::Flushing {
                        close: message.is_close(),
                        deadline: Box::pin(time::sleep(NETWORK_IO_TIMEOUT)),
                    };
                }
                Some(Ok(_)) => {
                    return Poll::Ready(Some(Err(Error::new(
                        ErrorKind::InvalidData,
                        "unexpected frame",
                    ))));
                }
                Some(Err(error)) => {
                    return Poll::Ready(Some(Err(Error::new(ErrorKind::Other, error))))
                }
                None => return Poll::Ready(None),
            }
        }

        // Buffered control frames can be ready without another socket poll.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[derive(Debug)]
pub struct WebsocketTunnel {
    inner: StreamReader<StreamWrapper<TransportStream>, Bytes>,
}

impl AsyncRead for WebsocketTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncBufRead for WebsocketTunnel {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        Pin::new(&mut self.get_mut().inner).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        Pin::new(&mut self.get_mut().inner).consume(amt)
    }
}

impl AsyncWrite for WebsocketTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let sw = self.get_mut().inner.get_mut();
        ready!(Pin::new(&mut sw.inner)
            .poll_ready(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err)))?;

        match Pin::new(&mut sw.inner).start_send(Message::Binary(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(Error::new(ErrorKind::Other, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut().inner)
            .poll_flush(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().inner.get_mut().inner)
            .poll_close(cx)
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }
}

#[derive(Debug)]
enum SubTransport {
    Secure(TlsTransport),
    Insecure(TcpTransport),
}

#[derive(Debug)]
pub struct WebsocketTransport {
    sub: SubTransport,
    conf: WebSocketConfig,
}

#[async_trait]
impl Transport for WebsocketTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = WebsocketTunnel;

    fn new(config: &TransportConfig) -> anyhow::Result<Self> {
        let wsconfig = config
            .websocket
            .as_ref()
            .ok_or_else(|| anyhow!("Missing websocket config"))?;

        let conf = WebSocketConfig {
            write_buffer_size: 0,
            ..WebSocketConfig::default()
        };
        let sub = match wsconfig.tls {
            true => SubTransport::Secure(TlsTransport::new(config)?),
            false => SubTransport::Insecure(TcpTransport::new(config)?),
        };
        Ok(WebsocketTransport { sub, conf })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        opt.apply(conn.inner.get_ref().inner.get_ref().get_tcpstream())
    }

    async fn bind<A: ToSocketAddrs + Send + Sync>(
        &self,
        addr: A,
    ) -> anyhow::Result<Self::Acceptor> {
        TcpListener::bind(addr).await.map_err(Into::into)
    }

    async fn accept(&self, a: &Self::Acceptor) -> anyhow::Result<(Self::RawStream, SocketAddr)> {
        let (s, addr) = match &self.sub {
            SubTransport::Insecure(t) => t.accept(a).await?,
            SubTransport::Secure(t) => t.accept(a).await?,
        };
        Ok((s, addr))
    }

    async fn handshake(&self, conn: Self::RawStream) -> anyhow::Result<Self::Stream> {
        let tsream = match &self.sub {
            SubTransport::Insecure(t) => TransportStream::Insecure(t.handshake(conn).await?),
            SubTransport::Secure(t) => TransportStream::Secure(t.handshake(conn).await?),
        };
        let wsstream = accept_async_with_config(tsream, Some(self.conf)).await?;
        let tun = WebsocketTunnel {
            inner: StreamReader::new(StreamWrapper::new(wsstream)),
        };
        Ok(tun)
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> anyhow::Result<Self::Stream> {
        let u = format!("ws://{}", &addr.addr.as_str());
        let url = Url::parse(&u).context("Invalid WebSocket URL")?;
        let tstream = match &self.sub {
            SubTransport::Insecure(t) => TransportStream::Insecure(t.connect(addr).await?),
            SubTransport::Secure(t) => TransportStream::Secure(t.connect(addr).await?),
        };
        let (wsstream, _) = client_async_with_config(url, tstream, Some(self.conf))
            .await
            .context("Failed to do WebSocket handshake")?;
        let tun = WebsocketTunnel {
            inner: StreamReader::new(StreamWrapper::new(wsstream)),
        };
        Ok(tun)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
    use tokio::time::{self, Duration};
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn send<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut WebSocketStream<S>,
        message: Message,
    ) -> anyhow::Result<()> {
        poll_fn(|cx| Pin::new(&mut *stream).poll_ready(cx)).await?;
        Pin::new(&mut *stream).start_send(message)?;
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush(cx)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn ping_receives_pong_before_the_next_binary_frame() -> anyhow::Result<()> {
        time::timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = AddrMaybeCached::new(&listener.local_addr()?.to_string());
            let transport = WebsocketTransport::new(&TransportConfig {
                websocket: Some(crate::config::WebsocketConfig { tls: false }),
                ..TransportConfig::default()
            })?;
            let peer = async {
                let (socket, _) = listener.accept().await?;
                let mut ws = tokio_tungstenite::accept_async(socket).await?;
                let payload = b"keepalive".to_vec();
                send(&mut ws, Message::Ping(payload.clone())).await?;
                let pong = poll_fn(|cx| Pin::new(&mut ws).poll_next(cx))
                    .await
                    .transpose()?;
                assert_eq!(pong, Some(Message::Pong(payload)));
                send(&mut ws, Message::Binary(b"payload".to_vec())).await?;
                send(&mut ws, Message::Pong(b"unsolicited".to_vec())).await?;
                send(&mut ws, Message::Binary(b" again".to_vec())).await?;
                send(&mut ws, Message::Close(None)).await?;
                let close = poll_fn(|cx| Pin::new(&mut ws).poll_next(cx))
                    .await
                    .transpose()?;
                assert_eq!(close, Some(Message::Close(None)));
                Ok::<_, anyhow::Error>(())
            };
            let tunnel = async {
                let mut stream = transport.connect(&addr).await?;
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await?;
                assert_eq!(data, b"payload again");
                Ok(())
            };
            tokio::try_join!(peer, tunnel)?;
            Ok(())
        })
        .await
        .context("WebSocket control exchange stalled")?
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_pong_flush_has_a_deadline() -> anyhow::Result<()> {
        let (socket, peer) = io::duplex(32);
        let ws = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
        let mut tunnel = StreamWrapper::new(ws);
        let mut peer = WebSocketStream::from_raw_socket(peer, Role::Client, None).await;
        tunnel.inner.get_mut().write_all(&[0; 32]).await?;
        send(&mut peer, Message::Ping(b"ping".to_vec())).await?;
        let start = time::Instant::now();
        let result = time::timeout(
            NETWORK_IO_TIMEOUT * 2,
            poll_fn(|cx| Pin::new(&mut tunnel).poll_next(cx)),
        )
        .await?;
        assert_eq!(result.unwrap().unwrap_err().kind(), ErrorKind::TimedOut);
        assert!(start.elapsed() >= NETWORK_IO_TIMEOUT);
        assert!(poll_fn(|cx| Pin::new(&mut tunnel).poll_next(cx))
            .await
            .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn control_frame_burst_yields_before_reading_binary() -> anyhow::Result<()> {
        time::timeout(Duration::from_secs(1), async {
            let (socket, peer) = io::duplex(4096);
            let ws = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
            let mut tunnel = StreamWrapper::new(ws);
            let mut peer = WebSocketStream::from_raw_socket(peer, Role::Client, None).await;
            for _ in 0..64 {
                send(&mut peer, Message::Pong(Vec::new())).await?;
            }
            send(&mut peer, Message::Binary(b"data".to_vec())).await?;
            let first_poll = poll_fn(|cx| Poll::Ready(Pin::new(&mut tunnel).poll_next(cx))).await;
            assert!(first_poll.is_pending());

            let other_task = tokio::spawn(async { "scheduled" });
            let data = poll_fn(|cx| Pin::new(&mut tunnel).poll_next(cx))
                .await
                .unwrap()?;
            assert_eq!(data, b"data"[..]);
            assert_eq!(other_task.await?, "scheduled");
            Ok(())
        })
        .await?
    }
}
