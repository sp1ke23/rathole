use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context as TaskContext, Poll};

use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use crate::config::{NoiseConfig, TransportConfig};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use snowstorm::{Builder, NoiseParams, NoiseStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

#[derive(Debug)]
pub struct NoiseSocket<S>(S);

impl<S: AsyncRead + Unpin> AsyncRead for NoiseSocket<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let remaining = buf.remaining();
        ready!(Pin::new(&mut self.get_mut().0).poll_read(cx, buf))?;
        // snowstorm 0.4.0 supplies a partially filled buffer when resuming a
        // length field, but checks the total filled length to detect EOF.
        if filled != 0 && remaining != 0 && buf.filled().len() == filled {
            let error = io::Error::new(
                ErrorKind::UnexpectedEof,
                "EOF in a partially read Noise length field",
            );
            tracing::debug!("{error}");
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for NoiseSocket<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

pub struct NoiseTransport {
    tcp: TcpTransport,
    config: NoiseConfig,
    params: NoiseParams,
    local_private_key: Vec<u8>,
    remote_public_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self.config)
    }
}

impl NoiseTransport {
    fn builder(&self) -> Builder {
        let builder = Builder::new(self.params.clone()).local_private_key(&self.local_private_key);
        match &self.remote_public_key {
            Some(x) => builder.remote_public_key(x),
            None => builder,
        }
    }
}

#[async_trait]
impl Transport for NoiseTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = NoiseStream<NoiseSocket<TcpStream>>;

    fn new(config: &TransportConfig) -> Result<Self> {
        let tcp = TcpTransport::new(config)?;

        let config = match &config.noise {
            Some(v) => v.clone(),
            None => return Err(anyhow!("Missing noise config")),
        };
        let builder = Builder::new(config.pattern.parse()?);

        let remote_public_key = match &config.remote_public_key {
            Some(x) => {
                Some(base64::decode(x).with_context(|| "Failed to decode remote_public_key")?)
            }
            None => None,
        };

        let local_private_key = match &config.local_private_key {
            Some(x) => base64::decode(x.as_bytes())
                .with_context(|| "Failed to decode local_private_key")?,
            None => builder.generate_keypair()?.private,
        };

        let params: NoiseParams = config.pattern.parse()?;

        Ok(NoiseTransport {
            tcp,
            config,
            params,
            local_private_key,
            remote_public_key,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        opt.apply(&conn.get_inner().0);
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor> {
        Ok(TcpListener::bind(addr).await?)
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        self.tcp
            .accept(a)
            .await
            .with_context(|| "Failed to accept TCP connection")
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        let conn = NoiseStream::handshake(NoiseSocket(conn), self.builder().build_responder()?)
            .await
            .with_context(|| "Failed to do noise handshake")?;
        Ok(conn)
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let conn = self
            .tcp
            .connect(addr)
            .await
            .with_context(|| "Failed to connect TCP socket")?;

        let conn = NoiseStream::handshake(NoiseSocket(conn), self.builder().build_initiator()?)
            .await
            .with_context(|| "Failed to do noise handshake")?;
        return Ok(conn);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{self, Duration};

    const PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

    #[tokio::test(start_paused = true)]
    async fn split_length_and_truncated_length_in_memory() -> Result<()> {
        time::timeout(Duration::from_secs(1), async {
            let (left, right) = tokio::io::duplex(1024);
            let initiator = Builder::new(PATTERN.parse()?).build_initiator()?;
            let responder = Builder::new(PATTERN.parse()?).build_responder()?;
            let (mut client, mut server) = tokio::try_join!(
                NoiseStream::handshake(left, initiator),
                NoiseStream::handshake(NoiseSocket(right), responder)
            )?;
            let mut encrypted = [0; 64];
            let len = client
                .get_state_mut()
                .write_message(b"hello", &mut encrypted)?;
            let mut socket = client.into_inner();
            let length = (len as u16).to_le_bytes();
            let send = async {
                socket.write_all(&length[..1]).await?;
                time::sleep(Duration::from_millis(10)).await;
                socket.write_all(&length[1..]).await?;
                socket.write_all(&encrypted[..len]).await?;
                socket.write_all(&length[..1]).await?;
                socket.shutdown().await
            };
            let mut payload = [0; 5];
            tokio::try_join!(send, server.read_exact(&mut payload))?;
            assert_eq!(&payload, b"hello");
            assert_eq!(
                server.read_u8().await.unwrap_err().kind(),
                ErrorKind::UnexpectedEof,
            );
            Ok(())
        })
        .await?
    }

    #[tokio::test]
    async fn tcp_partial_length_at_eof_releases_the_reader() -> Result<()> {
        time::timeout(Duration::from_secs(3), async {
            let transport = NoiseTransport::new(&TransportConfig {
                noise: Some(NoiseConfig {
                    pattern: PATTERN.into(),
                    local_private_key: None,
                    remote_public_key: None,
                }),
                ..TransportConfig::default()
            })?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (client, mut server) = tokio::try_join!(initiate(addr), async {
                let (socket, _) = listener.accept().await?;
                transport.handshake(socket).await
            })?;
            let mut socket = client.into_inner();
            socket.write_all(&[32]).await?;
            socket.shutdown().await?;
            assert_eq!(
                server.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );

            let (mut client, mut server) = tokio::try_join!(initiate(addr), async {
                let (socket, _) = listener.accept().await?;
                transport.handshake(socket).await
            })?;
            client.write_all(b"request").await?;
            client.shutdown().await?;
            let mut request = Vec::new();
            server.read_to_end(&mut request).await?;
            assert_eq!(request, b"request");
            server.write_all(b"reply").await?;
            server.shutdown().await?;
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await?;
            assert_eq!(reply, b"reply");
            Ok(())
        })
        .await
        .context("Noise read did not finish after TCP EOF")?
    }

    async fn initiate(addr: SocketAddr) -> Result<NoiseStream<TcpStream>> {
        let state = Builder::new(PATTERN.parse()?).build_initiator()?;
        Ok(NoiseStream::handshake(TcpStream::connect(addr).await?, state).await?)
    }
}
