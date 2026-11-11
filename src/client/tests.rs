use super::*;
use crate::config::{MaskedString, TransportConfig};
use tokio::net::TcpListener;

const SERVICE: &str = "backend";
const TOKEN: &str = "test-token";
const LOOPBACK: &str = "127.0.0.1:0";

#[derive(Debug)]
struct BlockedDataHello {
    attempts: mpsc::UnboundedSender<io::DuplexStream>,
}

#[async_trait::async_trait]
impl Transport for BlockedDataHello {
    type Acceptor = ();
    type RawStream = ();
    type Stream = io::DuplexStream;

    fn new(_: &TransportConfig) -> Result<Self> {
        unreachable!()
    }

    fn hint(_: &Self::Stream, _: SocketOpts) {}

    async fn bind<A: tokio::net::ToSocketAddrs + Send + Sync>(&self, _: A) -> Result<()> {
        unreachable!()
    }

    async fn accept(&self, _: &()) -> Result<((), SocketAddr)> {
        unreachable!()
    }

    async fn handshake(&self, _: ()) -> Result<Self::Stream> {
        unreachable!()
    }

    async fn connect(&self, _: &AddrMaybeCached) -> Result<Self::Stream> {
        let (stream, blocked_peer) = io::duplex(1);
        self.attempts.send(blocked_peer)?;
        Ok(stream)
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_data_hello_retries_within_one_budget() -> Result<()> {
    let (attempts, mut peers) = mpsc::unbounded_channel();
    let service = ClientServiceConfig::with_name(SERVICE);
    let args = RunDataChannelArgs {
        session_key: [0; protocol::HASH_WIDTH_IN_BYTES],
        remote_addr: AddrMaybeCached::new(LOOPBACK),
        connector: Arc::new(BlockedDataHello { attempts }),
        socket_opts: SocketOpts::from_client_cfg(&service),
        service,
    };
    let start = Instant::now();
    let error = time::timeout(DATA_CONNECT_TIMEOUT * 2, do_data_channel_handshake(&args))
        .await?
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Data channel handshake retry budget expired"
    );
    assert!(start.elapsed() >= DATA_CONNECT_TIMEOUT);
    assert!(start.elapsed() < DATA_CONNECT_TIMEOUT + Duration::from_millis(10));
    // Keep the non-reading peers alive until the budget expires. A second stream means
    // the first Hello timed out and the client retried before the overall deadline.
    assert!(peers.try_recv().is_ok());
    assert!(peers.try_recv().is_ok());
    assert!(peers.try_recv().is_err());
    Ok(())
}

fn client_config(listener: &TcpListener) -> Result<ClientConfig> {
    Ok(ClientConfig {
        remote_addr: listener.local_addr()?.to_string(),
        heartbeat_timeout: 1,
        services: HashMap::from([(
            SERVICE.into(),
            ClientServiceConfig {
                token: Some(MaskedString::from(TOKEN)),
                retry_interval: Some(1),
                ..ClientServiceConfig::with_name(SERVICE)
            },
        )]),
        ..ClientConfig::default()
    })
}

#[tokio::test]
async fn retries_stalled_hello_and_partial_ack() -> Result<()> {
    time::timeout(CONTROL_CONNECT_TIMEOUT + Duration::from_secs(5), async {
        tokio::try_join!(
            recover_stalled_control(false),
            recover_stalled_control(true)
        )?;
        Ok(())
    })
    .await
    .context("Client failed to recover a stalled control handshake")?
}

async fn recover_stalled_control(partial_ack: bool) -> Result<()> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let mut client = Client::<TcpTransport>::from(client_config(&listener)?).await?;
    let (shutdown, shutdown_rx) = broadcast::channel(1);
    let (updates, update_rx) = mpsc::channel(1);
    let client = tokio::spawn(async move { client.run(shutdown_rx, update_rx).await });

    let (mut stalled, _) = listener.accept().await?;
    if partial_ack {
        answer_control_hello(&mut stalled).await?;
        stalled.write_u8(0).await?;
    } else {
        assert!(matches!(
            read_hello(&mut stalled).await?,
            ControlChannelHello(..)
        ));
    }
    assert_eq!(stalled.read(&mut [0]).await?, 0);

    let (mut control, _) = listener.accept().await?;
    let key = answer_control_hello(&mut control).await?;
    control.write_all(&bincode::serialize(&Ack::Ok)?).await?;
    control
        .write_all(&bincode::serialize(&ControlChannelCmd::CreateDataChannel)?)
        .await?;
    let (mut data, _) = listener.accept().await?;
    assert!(matches!(read_hello(&mut data).await?, DataChannelHello(_, token) if token == key));

    updates
        .send(ConfigChange::ClientChange(ClientServiceChange::Delete(
            SERVICE.into(),
        )))
        .await?;
    time::timeout(Duration::from_secs(1), async {
        assert_eq!(control.read(&mut [0]).await?, 0);
        assert_eq!(data.read(&mut [0]).await?, 0);
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    shutdown.send(true)?;
    client.await??;
    Ok(())
}

async fn answer_control_hello<S: io::AsyncRead + io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<Nonce> {
    let hello = read_hello(stream).await?;
    assert!(
        matches!(hello, ControlChannelHello(_, digest) if digest == protocol::digest(SERVICE.as_bytes()))
    );
    let nonce = [42; protocol::HASH_WIDTH_IN_BYTES];
    let response = ControlChannelHello(CURRENT_PROTO_VERSION, nonce);
    stream.write_all(&bincode::serialize(&response)?).await?;
    stream.flush().await?;
    let Auth(key) = protocol::read_auth(stream).await?;
    Ok(key)
}

#[tokio::test]
async fn silent_http_proxy_times_out_and_shutdown_cancels_retry() -> Result<()> {
    time::timeout(CONTROL_CONNECT_TIMEOUT + Duration::from_secs(5), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let config = client_config(&listener)?;
        let mut transport = TransportConfig::default();
        transport.tcp.proxy = Some(format!("http://{}", listener.local_addr()?).parse()?);
        let handle = ControlChannelHandle::new(
            config.services[SERVICE].clone(),
            config.remote_addr,
            Arc::new(TcpTransport::new(&transport)?),
            config.heartbeat_timeout,
        );
        let (mut stalled, _) = listener.accept().await?;
        read_http_request(&mut stalled).await?;
        assert_eq!(stalled.read(&mut [0]).await?, 0);

        let (mut retry, _) = listener.accept().await?;
        read_http_request(&mut retry).await?;
        handle.shutdown();
        assert_eq!(
            time::timeout(Duration::from_secs(1), retry.read(&mut [0])).await??,
            0
        );
        Ok(())
    })
    .await
    .context("Silent proxy stalled the client")?
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn rejected_websocket_upgrade_is_retried() -> Result<()> {
    time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let config = client_config(&listener)?;
        let transport = TransportConfig {
            transport_type: TransportType::Websocket,
            websocket: Some(crate::config::WebsocketConfig { tls: false }),
            ..TransportConfig::default()
        };
        let transport = Arc::new(WebsocketTransport::new(&transport)?);
        let _handle = ControlChannelHandle::new(
            config.services[SERVICE].clone(),
            config.remote_addr,
            transport.clone(),
            config.heartbeat_timeout,
        );

        let (mut rejected, _) = listener.accept().await?;
        read_http_request(&mut rejected).await?;
        rejected
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let (retry, _) = listener.accept().await?;
        let mut control = transport.handshake(retry).await?;
        answer_control_hello(&mut control).await?;
        Ok(())
    })
    .await
    .context("Client did not retry the rejected WebSocket upgrade")?
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<()> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await?);
    }
    Ok(())
}

#[tokio::test]
async fn full_udp_reply_queue_does_not_block_the_visitor() -> Result<()> {
    time::timeout(Duration::from_secs(2), async {
        let backend = UdpSocket::bind(LOOPBACK).await?;
        let visitor = UdpSocket::bind(LOOPBACK).await?;
        visitor.connect(backend.local_addr()?).await?;
        let from = visitor.local_addr()?;
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        outbound_tx.try_send(UdpTraffic {
            from,
            data: Bytes::from_static(b"queued"),
        })?;
        let forwarder = tokio::spawn(run_udp_forwarder(visitor, inbound_rx, outbound_tx, from));
        for _ in 0..8 {
            backend.send_to(b"drop under backpressure", from).await?;
            tokio::task::yield_now().await;
        }

        inbound_tx.send(Bytes::from_static(b"visitor data")).await?;
        let mut buf = [0; 64];
        let (len, _) = backend.recv_from(&mut buf).await?;
        assert_eq!(&buf[..len], b"visitor data");
        drop(inbound_tx);
        forwarder.await??;
        assert_eq!(outbound_rx.recv().await.unwrap().data, b"queued"[..]);
        assert!(outbound_rx.recv().await.is_none());
        Ok(())
    })
    .await
    .context("UDP visitor was blocked by a full reply queue")?
}
