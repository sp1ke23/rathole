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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn stalled_backend_dial_times_out_and_hot_reload_cancels_it() -> Result<()> {
    time::timeout(NETWORK_IO_TIMEOUT + Duration::from_secs(3), async {
        tokio::try_join!(
            exercise_stalled_backend(false),
            exercise_stalled_backend(true)
        )?;
        Ok(())
    })
    .await
    .context("Stalled TCP backend did not release its tunnel")?
}

#[cfg(target_os = "linux")]
async fn exercise_stalled_backend(reload: bool) -> Result<()> {
    use tokio::net::{TcpSocket, TcpStream};

    let socket = TcpSocket::new_v4()?;
    socket.bind(LOOPBACK.parse()?)?;
    let backend = socket.listen(1)?;
    let backend_addr = backend.local_addr()?;
    let first = TcpStream::connect(backend_addr).await?;
    let second = TcpStream::connect(backend_addr).await?;
    let probe = time::timeout(Duration::from_millis(100), TcpStream::connect(backend_addr));
    assert!(probe.await.is_err(), "backend listen queue is not full");

    let listener = TcpListener::bind(LOOPBACK).await?;
    let mut config = client_config(&listener)?;
    config.heartbeat_timeout = 0;
    config.services.get_mut(SERVICE).unwrap().local_addr = backend_addr.to_string();
    let (shutdown, shutdown_rx) = broadcast::channel(1);
    let (updates, update_rx) = mpsc::channel(1);
    let client = tokio::spawn(run_client(
        Config {
            client: Some(config),
            server: None,
        },
        shutdown_rx,
        update_rx,
    ));
    let (mut control, _) = listener.accept().await?;
    answer_control_hello(&mut control).await?;
    control.write_all(&bincode::serialize(&Ack::Ok)?).await?;
    let mut data = request_tcp_tunnel(&listener, &mut control).await?;

    let stalled = time::timeout(Duration::from_millis(100), data.read(&mut [0])).await;
    assert!(
        stalled.is_err(),
        "data channel closed before the backend dial could stall"
    );
    let delete = ConfigChange::ClientChange(ClientServiceChange::Delete(SERVICE.into()));
    if reload {
        updates.send(delete).await?;
        assert_eq!(
            time::timeout(Duration::from_secs(1), data.read(&mut [0])).await??,
            0
        );
    } else {
        assert_eq!(data.read(&mut [0]).await?, 0);
        // Drain the original connections, then use the existing control session to forward again.
        drop((first, second));
        for _ in 0..2 {
            drop(backend.accept().await?);
        }
        let mut data = request_tcp_tunnel(&listener, &mut control).await?;
        let (mut local, _) = backend.accept().await?;
        data.write_all(b"ping").await?;
        let mut payload = [0; 4];
        local.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        updates.send(delete).await?;
        assert_eq!(control.read(&mut [0]).await?, 0);
        local.write_all(b"pong").await?;
        data.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"pong");
    }
    shutdown.send(true)?;
    client.await??;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn request_tcp_tunnel(
    listener: &TcpListener,
    control: &mut tokio::net::TcpStream,
) -> Result<tokio::net::TcpStream> {
    control
        .write_all(&bincode::serialize(&ControlChannelCmd::CreateDataChannel)?)
        .await?;
    let (mut data, _) = listener.accept().await?;
    assert!(matches!(read_hello(&mut data).await?, DataChannelHello(..)));
    data.write_all(&bincode::serialize(&DataChannelCmd::StartForwardTcp)?)
        .await?;
    Ok(data)
}

#[tokio::test(start_paused = true)]
async fn backend_dial_deadline_and_session_cancellation() -> Result<()> {
    use std::future::pending;

    let (session, mut closed) = broadcast::channel(1);
    let start = Instant::now();
    let err = connect_tcp_backend(pending::<Result<()>>(), &mut closed)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "TCP backend connection timed out");
    assert!(start.elapsed() >= NETWORK_IO_TIMEOUT);

    let start = Instant::now();
    let (result, ()) = tokio::join!(
        connect_tcp_backend(pending::<Result<()>>(), &mut closed),
        async {
            time::sleep(Duration::from_secs(1)).await;
            drop(session);
        }
    );
    assert!(result?.is_none());
    assert!(start.elapsed() < NETWORK_IO_TIMEOUT);
    // Shutdown wins even if the backend becomes ready in the same poll.
    assert!(connect_tcp_backend(async { Ok(()) }, &mut closed)
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn udp_queue_releases_its_byte_budget_on_dequeue_and_close() {
    let (sender, mut receiver) = DatagramSender::channel(UDP_SENDQ_SIZE);
    let payload = Bytes::from(vec![5; UDP_DATAGRAM_BUFFER_SIZE]);
    let packet = || UdpTraffic {
        from: SocketAddr::from(([127, 0, 0, 1], 1234)),
        data: payload.clone(),
    };
    for _ in 0..UDP_SENDQ_BYTES / payload.len() {
        assert_eq!(sender.try_send(packet()), DatagramSend::Queued);
    }
    assert_eq!(sender.try_send(packet()), DatagramSend::Full);
    let dequeued = receiver.try_recv().unwrap().into_packet();
    assert_eq!(dequeued.data, payload);
    assert_eq!(sender.try_send(packet()), DatagramSend::Queued);
    drop(receiver);
    assert_eq!(sender.bytes.available_permits(), UDP_SENDQ_BYTES);
    assert_eq!(sender.try_send(packet()), DatagramSend::Closed);
}

#[tokio::test]
async fn full_udp_reply_queue_does_not_block_the_visitor() -> Result<()> {
    time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            exercise_full_udp_reply_queue(1, 6),
            exercise_full_udp_reply_queue(UDP_SENDQ_SIZE, UDP_DATAGRAM_BUFFER_SIZE),
        )?;
        Ok(())
    })
    .await
    .context("UDP visitor was blocked by a full reply queue")?
}

async fn exercise_full_udp_reply_queue(capacity: usize, queued_len: usize) -> Result<()> {
    let backend = UdpSocket::bind(LOOPBACK).await?;
    let visitor = UdpSocket::bind(LOOPBACK).await?;
    visitor.connect(backend.local_addr()?).await?;
    let from = visitor.local_addr()?;
    let (inbound_tx, inbound_rx) = DatagramSender::channel(1);
    let (outbound_tx, mut outbound_rx) = DatagramSender::channel(capacity);
    let queued = Bytes::from(vec![3; queued_len]);
    let queued_count = capacity.min(UDP_SENDQ_BYTES / queued_len);
    for _ in 0..queued_count {
        assert_eq!(
            outbound_tx.try_send(UdpTraffic {
                from,
                data: queued.clone(),
            }),
            DatagramSend::Queued,
        );
    }
    let forwarder = tokio::spawn(async move {
        let buffer = Mutex::new(vec![0; UDP_DATAGRAM_BUFFER_SIZE]);
        run_udp_forwarder(visitor, inbound_rx, &outbound_tx, &buffer, from).await
    });
    for _ in 0..8 {
        backend.send_to(&[7; 64], from).await?;
        tokio::task::yield_now().await;
    }

    assert_eq!(
        inbound_tx.try_send(UdpTraffic {
            from,
            data: Bytes::from_static(b"visitor data"),
        }),
        DatagramSend::Queued
    );
    let mut buf = [0; 64];
    let (len, _) = backend.recv_from(&mut buf).await?;
    assert_eq!(&buf[..len], b"visitor data");
    drop(inbound_tx);
    forwarder.await??;
    for _ in 0..queued_count {
        assert_eq!(outbound_rx.recv().await.unwrap().into_packet().data, queued,);
    }
    assert!(outbound_rx.recv().await.is_none());
    Ok(())
}
