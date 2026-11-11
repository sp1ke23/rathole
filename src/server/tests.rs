use super::*;
use crate::config::MaskedString;
use crate::constants::UDP_BUFFER_SIZE;
use std::net::SocketAddr;

const LOOPBACK: &str = "127.0.0.1:0";
const SERVICE: &str = "backend";
const TOKEN: &str = "test-token";

#[tokio::test]
async fn tcp_visitor_skips_a_prewarmed_channel_at_eof() -> Result<()> {
    time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let (mut stale_peer, stale) = open_tcp_pair(&listener).await?;
        stale_peer.shutdown().await?;
        assert_eq!(stale.peek(&mut [0]).await?, 0);
        let (mut healthy_peer, healthy) = open_tcp_pair(&listener).await?;

        let exposed = TcpListener::bind(LOOPBACK).await?;
        let mut visitor = TcpStream::connect(exposed.local_addr()?).await?;
        let (data_tx, data_rx) = mpsc::channel(2);
        let (requests, _commands) = mpsc::channel(2);
        data_tx.send(stale).await?;
        data_tx.send(healthy).await?;
        let pool = tokio::spawn(async move {
            run_tcp_connection_pool::<TcpTransport>(exposed, &Mutex::new(data_rx), &requests).await
        });

        assert!(matches!(
            protocol::read_data_cmd(&mut healthy_peer).await?,
            DataChannelCmd::StartForwardTcp
        ));
        visitor.write_all(b"ping").await?;
        let mut payload = [0; 4];
        healthy_peer.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        healthy_peer.write_all(&payload).await?;
        visitor.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        pool.abort();
        Ok(())
    })
    .await
    .context("TCP visitor did not reach the healthy prewarmed tunnel")?
}

#[tokio::test]
async fn udp_pool_requests_replacements_after_discarding_invalid_tunnels() -> Result<()> {
    time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let (mut closed_peer, closed) = open_tcp_pair(&listener).await?;
        closed_peer.shutdown().await?;
        assert_eq!(closed.peek(&mut [0]).await?, 0);
        let (mut noisy_peer, noisy) = open_tcp_pair(&listener).await?;
        noisy_peer.write_u8(1).await?;
        assert_eq!(noisy.peek(&mut [0]).await?, 1);

        let socket = UdpSocket::bind(LOOPBACK).await?;
        let visitor = UdpSocket::bind(LOOPBACK).await?;
        visitor.connect(socket.local_addr()?).await?;
        let (data_tx, data_rx) = mpsc::channel(2);
        let (requests, mut commands) = mpsc::channel(2);
        data_tx.send(closed).await?;
        data_tx.send(noisy).await?;
        let pool = tokio::spawn(async move {
            run_udp_connection_pool::<TcpTransport>(socket, &Mutex::new(data_rx), &requests).await
        });
        commands
            .recv()
            .await
            .context("Missing replacement for closed tunnel")?;
        commands
            .recv()
            .await
            .context("Missing replacement for tunnel with unsolicited data")?;

        let (mut peer, healthy) = open_tcp_pair(&listener).await?;
        data_tx.send(healthy).await?;
        assert!(matches!(
            protocol::read_data_cmd(&mut peer).await?,
            DataChannelCmd::StartForwardUdp
        ));
        visitor.send(b"ping").await?;
        let len = peer.read_u8().await?;
        let packet = UdpTraffic::read(&mut peer, len).await?;
        assert_eq!(packet.data.as_ref(), b"ping");
        packet.write(&mut peer).await?;
        let mut payload = [0; 4];
        assert_eq!(visitor.recv(&mut payload).await?, payload.len());
        assert_eq!(&payload, b"ping");
        pool.abort();
        Ok(())
    })
    .await
    .context("UDP pool did not recover after discarding unusable tunnels")?
}

#[tokio::test]
async fn retries_missing_data_channels_for_tcp_and_udp() -> Result<()> {
    time::timeout(DATA_REQUEST_RETRY * 2 + Duration::from_secs(5), async {
        tokio::try_join!(
            recover_missing_channels(ServiceType::Tcp),
            recover_missing_channels(ServiceType::Udp),
            recover_missing_channels(ServiceType::TcpAndUdp),
        )?;
        Ok(())
    })
    .await
    .context("Data forwarding did not recover after requests were dropped")?
}

async fn recover_missing_channels(service_type: ServiceType) -> Result<()> {
    let has_tcp = matches!(service_type, ServiceType::Tcp | ServiceType::TcpAndUdp);
    let has_udp = matches!(service_type, ServiceType::Udp | ServiceType::TcpAndUdp);
    let (reserved_tcp, reserved_udp) = bind_ephemeral_tcp_and_udp().await?;
    let exposed = reserved_tcp.local_addr()?;
    drop((reserved_tcp, reserved_udp));

    let listener = TcpListener::bind(LOOPBACK).await?;
    let (mut control, stream) = open_tcp_pair(&listener).await?;
    let handle = ControlChannelHandle::<TcpTransport>::new(
        stream,
        ServerServiceConfig {
            service_type,
            bind_addr: exposed.to_string(),
            ..ServerServiceConfig::with_name("backend")
        },
        0,
    );
    for _ in 0..(usize::from(has_tcp) * TCP_POOL_SIZE + usize::from(has_udp) * UDP_POOL_SIZE) {
        expect_data_request(&mut control).await?;
    }

    let mut tcp = if has_tcp {
        let mut visitor = connect_when_listening(exposed).await?;
        visitor.write_all(b"tcp").await?;
        expect_data_request(&mut control).await?;
        Some(visitor)
    } else {
        None
    };
    let mut udp = if has_udp {
        let visitor = UdpSocket::bind(LOOPBACK).await?;
        visitor.connect(exposed).await?;
        Some(visitor)
    } else {
        None
    };

    // Ignore the first timed replacement too. The second must arrive on the same session.
    expect_data_request(&mut control).await?;
    expect_data_request(&mut control).await?;

    for _ in 0..(usize::from(has_tcp) + usize::from(has_udp)) {
        let (mut peer, stream) = open_tcp_pair(&listener).await?;
        handle.data_ch_tx.send(stream).await?;
        match protocol::read_data_cmd(&mut peer).await? {
            DataChannelCmd::StartForwardTcp => {
                let mut visitor = tcp.take().context("Unexpected TCP data channel")?;
                let mut payload = [0; 3];
                peer.read_exact(&mut payload).await?;
                assert_eq!(&payload, b"tcp");
                peer.write_all(&payload).await?;
                visitor.read_exact(&mut payload).await?;
                assert_eq!(&payload, b"tcp");
            }
            DataChannelCmd::StartForwardUdp => {
                let visitor = udp.take().context("Unexpected UDP data channel")?;
                visitor.send(b"udp").await?;
                let len = peer.read_u8().await?;
                let packet = UdpTraffic::read(&mut peer, len).await?;
                assert_eq!(packet.data.as_ref(), b"udp");
                packet.write(&mut peer).await?;
                let mut reply = [0; 4];
                let len = visitor.recv(&mut reply).await?;
                assert_eq!(&reply[..len], b"udp");
            }
        }
    }
    assert!(tcp.is_none() && udp.is_none());
    Ok(())
}

async fn expect_data_request(stream: &mut TcpStream) -> Result<()> {
    let command = protocol::read_control_cmd(stream).await?;
    assert!(matches!(command, ControlChannelCmd::CreateDataChannel));
    Ok(())
}

async fn connect_when_listening(addr: SocketAddr) -> io::Result<TcpStream> {
    loop {
        match TcpStream::connect(addr).await {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                time::sleep(Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
}

#[tokio::test]
async fn expires_a_waiting_tcp_visitor_and_serves_the_next_one() -> Result<()> {
    time::timeout(TCP_VISITOR_TIMEOUT + Duration::from_secs(5), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let exposed = listener.local_addr()?;
        let (data_tx, data_rx) = mpsc::channel(TCP_POOL_SIZE);
        let (requests, mut commands) = mpsc::channel(TCP_POOL_SIZE);
        let pool = tokio::spawn(async move {
            run_tcp_connection_pool::<TcpTransport>(listener, &Mutex::new(data_rx), &requests).await
        });

        let mut stalled = TcpStream::connect(exposed).await?;
        commands
            .recv()
            .await
            .context("Expected initial TCP request")?;
        assert_eq!(stalled.read(&mut [0]).await?, 0);

        let mut next = TcpStream::connect(exposed).await?;
        let tunnel = TcpListener::bind(LOOPBACK).await?;
        let (mut peer, stream) = open_tcp_pair(&tunnel).await?;
        data_tx.send(stream).await?;
        assert!(matches!(
            protocol::read_data_cmd(&mut peer).await?,
            DataChannelCmd::StartForwardTcp
        ));
        peer.write_all(b"ok").await?;
        let mut reply = [0; 2];
        next.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"ok");
        pool.abort();
        Ok(())
    })
    .await
    .context("TCP visitor deadline or subsequent connection failed")?
}

#[tokio::test]
async fn full_channel_pool_discards_late_arrivals() -> Result<()> {
    time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind(LOOPBACK).await?;
        let (_control, stream) = open_tcp_pair(&listener).await?;
        let handle = ControlChannelHandle::<TcpTransport>::new(
            stream,
            ServerServiceConfig {
                bind_addr: LOOPBACK.to_string(),
                ..ServerServiceConfig::with_name("backend")
            },
            0,
        );
        let nonce = [1; HASH_WIDTH_IN_BYTES];
        let mut channels = ControlChannelMap::new();
        let _ = channels.insert([2; HASH_WIDTH_IN_BYTES], nonce, handle);
        let channels = Arc::new(RwLock::new(channels));
        let mut parked = Vec::new();
        for _ in 0..TCP_POOL_SIZE {
            let (peer, stream) = open_tcp_pair(&listener).await?;
            do_data_channel_handshake(stream, channels.clone(), nonce).await?;
            parked.push(peer);
        }
        let (mut extra, stream) = open_tcp_pair(&listener).await?;
        do_data_channel_handshake(stream, channels.clone(), nonce).await?;
        assert_eq!(extra.read(&mut [0]).await?, 0);
        Ok(())
    })
    .await
    .context("Server did not discard a late tunnel for a full pool")?
}

#[tokio::test(start_paused = true)]
async fn times_out_writing_a_control_or_start_command() {
    let (mut writer, _blocked_peer) = io::duplex(1);
    let error = write_command(&mut writer, &[0; 4]).await.unwrap_err();
    assert_eq!(error.to_string(), "Command write timed out");
}

#[tokio::test(start_paused = true)]
async fn blocked_tcp_start_requests_a_replacement() -> Result<()> {
    let (data_tx, data_rx) = mpsc::channel(1);
    let (requests, mut commands) = mpsc::channel(1);
    let (blocked, _blocked_peer) = io::duplex(1);
    data_tx.send(blocked).await?;
    let pool = Mutex::new(data_rx);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp)?;
    let (_, observed) = time::timeout(NETWORK_IO_TIMEOUT * 2, async {
        tokio::try_join!(start_tcp_forward(&pool, &requests, &cmd), async {
            commands
                .recv()
                .await
                .context("Expected a request after the blocked StartForward")?;
            let (stream, mut peer) = io::duplex(8);
            data_tx.send(stream).await?;
            protocol::read_data_cmd(&mut peer).await
        })
    })
    .await??;
    assert!(matches!(observed, DataChannelCmd::StartForwardTcp));
    Ok(())
}

async fn server_config() -> Result<(ServerConfig, SocketAddr)> {
    let reservation = TcpListener::bind(LOOPBACK).await?;
    let addr = reservation.local_addr()?;
    Ok((
        ServerConfig {
            bind_addr: addr.to_string(),
            services: HashMap::from([(
                SERVICE.into(),
                ServerServiceConfig {
                    bind_addr: LOOPBACK.to_string(),
                    token: Some(MaskedString::from(TOKEN)),
                    ..ServerServiceConfig::with_name(SERVICE)
                },
            )]),
            ..ServerConfig::default()
        },
        addr,
    ))
}

async fn request_nonce<S: io::AsyncRead + io::AsyncWrite + Unpin>(conn: &mut S) -> Result<Nonce> {
    let hello = ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        protocol::digest(SERVICE.as_bytes()),
    );
    conn.write_all(&bincode::serialize(&hello)?).await?;
    conn.flush().await?;
    match read_hello(conn).await? {
        ControlChannelHello(_, nonce) => Ok(nonce),
        _ => bail!("Expected control Hello"),
    }
}

async fn authenticate<S: io::AsyncRead + io::AsyncWrite + Unpin>(conn: &mut S) -> Result<()> {
    let nonce = request_nonce(conn).await?;
    let auth = protocol::Auth(protocol::digest(&[TOKEN.as_bytes(), &nonce].concat()));
    conn.write_all(&bincode::serialize(&auth)?).await?;
    conn.flush().await?;
    assert!(matches!(protocol::read_ack(conn).await?, Ack::Ok));
    assert!(matches!(
        protocol::read_control_cmd(conn).await?,
        ControlChannelCmd::CreateDataChannel
    ));
    Ok(())
}

#[tokio::test]
async fn closes_partial_hello_and_auth_while_accepting_valid_clients() -> Result<()> {
    time::timeout(NETWORK_IO_TIMEOUT + Duration::from_secs(4), async {
        let (config, addr) = server_config().await?;
        let mut server = Server::<TcpTransport>::from(config).await?;
        let (shutdown, shutdown_rx) = broadcast::channel(1);
        let (_updates, update_rx) = mpsc::channel(1);
        let server = tokio::spawn(async move { server.run(shutdown_rx, update_rx).await });

        let mut stalled_hello = connect_when_listening(addr).await?;
        stalled_hello.write_u8(0).await?;
        let mut stalled_auth = TcpStream::connect(addr).await?;
        request_nonce(&mut stalled_auth).await?;
        stalled_auth.write_u8(0).await?;

        let mut valid = TcpStream::connect(addr).await?;
        time::timeout(Duration::from_secs(2), authenticate(&mut valid)).await??;
        assert_eq!(stalled_hello.read(&mut [0]).await?, 0);
        assert_eq!(stalled_auth.read(&mut [0]).await?, 0);

        let mut pending = TcpStream::connect(addr).await?;
        request_nonce(&mut pending).await?;
        shutdown.send(true)?;
        time::timeout(Duration::from_secs(2), async {
            assert_eq!(pending.read(&mut [0]).await?, 0);
            server.await??;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    })
    .await
    .context("Server failed to bound incomplete application handshakes")?
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn silent_websocket_handshake_does_not_block_another_connection() -> Result<()> {
    time::timeout(NETWORK_IO_TIMEOUT + Duration::from_secs(4), async {
        let (mut config, addr) = server_config().await?;
        config.transport.transport_type = TransportType::Websocket;
        config.transport.websocket = Some(crate::config::WebsocketConfig { tls: false });
        let transport = WebsocketTransport::new(&config.transport)?;
        let mut server = Server::<WebsocketTransport>::from(config).await?;
        let (shutdown, shutdown_rx) = broadcast::channel(1);
        let (_updates, update_rx) = mpsc::channel(1);
        let server = tokio::spawn(async move { server.run(shutdown_rx, update_rx).await });

        let mut stalled = connect_when_listening(addr).await?;
        time::timeout(Duration::from_secs(2), async {
            let address = crate::transport::AddrMaybeCached::new(&addr.to_string());
            let mut conn = transport.connect(&address).await?;
            authenticate(&mut conn).await
        })
        .await??;
        assert_eq!(stalled.read(&mut [0]).await?, 0);
        shutdown.send(true)?;
        server.await??;
        Ok(())
    })
    .await
    .context("A silent WebSocket handshake blocked the listener")?
}

async fn bind_ephemeral_tcp_and_udp() -> io::Result<(TcpListener, UdpSocket)> {
    bind_ephemeral_tcp_and_udp_at(LOOPBACK).await
}

async fn bind_ephemeral_tcp_and_udp_at(addr: &str) -> io::Result<(TcpListener, UdpSocket)> {
    // A port assigned to TCP may already be in use by UDP.
    let mut attempts_left = 16;
    loop {
        attempts_left -= 1;
        match bind_tcp_and_udp(addr).await {
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts_left > 0 => {}
            result => return result,
        }
    }
}

#[tokio::test]
async fn dual_listener_uses_one_ephemeral_port() -> Result<()> {
    let (tcp, udp) = bind_ephemeral_tcp_and_udp().await?;
    assert_ne!(tcp.local_addr()?.port(), 0);
    assert_eq!(tcp.local_addr()?, udp.local_addr()?);
    Ok(())
}

#[tokio::test]
async fn dual_listener_releases_tcp_when_udp_bind_fails() -> Result<()> {
    let udp = UdpSocket::bind(LOOPBACK).await?;
    let addr = udp.local_addr()?;
    let error = bind_tcp_and_udp(&addr.to_string()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    let _tcp = TcpListener::bind(addr).await?;
    Ok(())
}

#[tokio::test]
async fn dual_service_requests_fresh_udp_channel_after_prewarm_is_drained() -> Result<()> {
    time::timeout(Duration::from_secs(30), async {
        let tunnel_listener = TcpListener::bind(LOOPBACK).await?;
        let (mut control_peer, control_stream) = open_tcp_pair(&tunnel_listener).await?;
        let (reserved_tcp, reserved_udp) = bind_ephemeral_tcp_and_udp().await?;
        let exposed_addr = reserved_udp.local_addr()?;
        let visitor = UdpSocket::bind(LOOPBACK).await?;
        visitor.connect(exposed_addr).await?;
        drop((reserved_tcp, reserved_udp));

        let handle = ControlChannelHandle::<TcpTransport>::new(
            control_stream,
            ServerServiceConfig {
                service_type: ServiceType::TcpAndUdp,
                bind_addr: exposed_addr.to_string(),
                ..ServerServiceConfig::with_name("backend")
            },
            0,
        );

        let prewarm_count = TCP_POOL_SIZE + UDP_POOL_SIZE;
        let mut prewarmed_peers = Vec::with_capacity(prewarm_count);
        for _ in 0..prewarm_count {
            let command = protocol::read_control_cmd(&mut control_peer).await?;
            assert!(matches!(command, ControlChannelCmd::CreateDataChannel));
            let (peer, stream) = open_tcp_pair(&tunnel_listener).await?;
            handle.data_ch_tx.send(stream).await?;
            prewarmed_peers.push(peer);
        }

        // Withhold every replacement until all of the original connections have failed.
        for (index, mut peer) in prewarmed_peers.into_iter().enumerate() {
            let command = protocol::read_data_cmd(&mut peer).await?;
            assert!(matches!(command, DataChannelCmd::StartForwardUdp));
            let replacement_timeout = if index == 0 {
                // Start a frame without completing it, and keep the connection open.
                peer.write_u8(16).await?;
                NETWORK_IO_TIMEOUT + Duration::from_secs(3)
            } else {
                drop(peer);
                Duration::from_secs(3)
            };

            let command = time::timeout(
                replacement_timeout,
                protocol::read_control_cmd(&mut control_peer),
            )
            .await
            .with_context(|| {
                format!(
                    "No replacement request after UDP channel {} closed",
                    index + 1
                )
            })??;
            assert!(matches!(command, ControlChannelCmd::CreateDataChannel));
        }

        let (mut fresh_peer, fresh_stream) = open_tcp_pair(&tunnel_listener).await?;
        handle.data_ch_tx.send(fresh_stream).await?;
        let command = protocol::read_data_cmd(&mut fresh_peer).await?;
        assert!(matches!(command, DataChannelCmd::StartForwardUdp));

        let payload = b"UDP over a fresh channel";
        visitor.send(payload).await?;
        let header_len = fresh_peer.read_u8().await?;
        let packet = UdpTraffic::read(&mut fresh_peer, header_len).await?;
        assert_eq!(packet.from, visitor.local_addr()?);
        assert_eq!(packet.data.as_ref(), payload);
        packet.write(&mut fresh_peer).await?;
        let mut reply = [0; UDP_BUFFER_SIZE];
        let len = visitor.recv(&mut reply).await?;
        assert_eq!(&reply[..len], payload);
        Ok(())
    })
    .await
    .context("Timed out testing UDP recovery with an empty prewarm pool")?
}

async fn open_tcp_pair(listener: &TcpListener) -> io::Result<(TcpStream, TcpStream)> {
    let (peer, (stream, _)) = tokio::try_join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept()
    )?;
    Ok((peer, stream))
}

#[cfg(feature = "client")]
mod forwarding {
    use super::*;
    use crate::config::{ClientConfig, ClientServiceConfig};
    use crate::protocol::read_data_cmd;
    use tokio::sync::oneshot;

    const RETRY_DELAY: Duration = Duration::from_millis(20);

    #[tokio::test]
    async fn dual_service_recovers_udp_and_reconnects() -> Result<()> {
        time::timeout(
            Duration::from_secs(15),
            exercise_dual_service(LOOPBACK, &[0, 2048, 2049, 4096]),
        )
        .await
        .context("Timed out testing dual service forwarding")?
    }

    #[tokio::test]
    async fn dual_service_forwards_ipv6_udp_datagrams() -> Result<()> {
        const IPV6_LOOPBACK: &str = "[::1]:0";
        if let Err(error) = TcpListener::bind(IPV6_LOOPBACK).await {
            eprintln!("IPv6 loopback unavailable: {error}");
            return Ok(());
        }
        if let Err(error) = UdpSocket::bind(IPV6_LOOPBACK).await {
            eprintln!("IPv6 UDP loopback unavailable: {error}");
            return Ok(());
        }
        time::timeout(
            Duration::from_secs(15),
            exercise_dual_service(IPV6_LOOPBACK, &[4096]),
        )
        .await
        .context("Timed out testing IPv6 forwarding")?
    }

    async fn exercise_dual_service(loopback: &str, sizes: &[usize]) -> Result<()> {
        let (backend_tcp, backend_udp) = bind_ephemeral_tcp_and_udp_at(loopback)
            .await
            .context("Failed to bind the TCP and UDP echo backend")?;
        let backend_addr = backend_tcp.local_addr()?;
        let (exposed_tcp, exposed_udp) = bind_ephemeral_tcp_and_udp_at(loopback)
            .await
            .context("Failed to reserve the exposed TCP and UDP port")?;
        let exposed_addr = exposed_tcp.local_addr()?;
        let proxy = TcpListener::bind(LOOPBACK)
            .await
            .context("Failed to bind the tunnel proxy")?;
        let proxy_addr = proxy.local_addr()?;
        let control = TcpListener::bind(LOOPBACK)
            .await
            .context("Failed to reserve the server control port")?;
        let control_addr = control.local_addr()?;
        let visitor_udp = UdpSocket::bind(loopback)
            .await
            .context("Failed to bind the UDP visitor socket")?;
        visitor_udp
            .connect(exposed_addr)
            .await
            .with_context(|| format!("Failed to connect the UDP visitor to {exposed_addr}"))?;
        drop((exposed_tcp, exposed_udp, control));

        tokio::spawn(echo_tcp(backend_tcp));
        tokio::spawn(echo_udp(backend_udp));
        let (udp_tunnels_tx, mut udp_tunnels) = mpsc::unbounded_channel();
        tokio::spawn(proxy_tunnels(proxy, control_addr, udp_tunnels_tx));

        let token = MaskedString::from(TOKEN);
        let server_config = Config {
            server: Some(ServerConfig {
                bind_addr: control_addr.to_string(),
                heartbeat_interval: 0,
                services: HashMap::from([(
                    SERVICE.into(),
                    ServerServiceConfig {
                        service_type: ServiceType::TcpAndUdp,
                        bind_addr: exposed_addr.to_string(),
                        token: Some(token.clone()),
                        ..ServerServiceConfig::with_name(SERVICE)
                    },
                )]),
                ..ServerConfig::default()
            }),
            client: None,
        };
        let client_config = Config {
            server: None,
            client: Some(ClientConfig {
                remote_addr: proxy_addr.to_string(),
                heartbeat_timeout: 0,
                services: HashMap::from([(
                    SERVICE.into(),
                    ClientServiceConfig {
                        service_type: ServiceType::TcpAndUdp,
                        local_addr: backend_addr.to_string(),
                        token: Some(token),
                        retry_interval: Some(1),
                        ..ClientServiceConfig::with_name(SERVICE)
                    },
                )]),
                ..ClientConfig::default()
            }),
        };

        let (server_shutdown, server_rx) = broadcast::channel(1);
        let (server_updates, server_update_rx) = mpsc::channel(1);
        let server = tokio::spawn(run_server(server_config, server_rx, server_update_rx));

        let (client_shutdown, client_rx) = broadcast::channel(1);
        let (_client_updates, client_update_rx) = mpsc::channel(1);
        let client = tokio::spawn(crate::client::run_client(
            client_config.clone(),
            client_rx,
            client_update_rx,
        ));
        let first_udp = udp_tunnels.recv().await.context("First UDP tunnel")?;
        first_udp
            .start
            .send(())
            .map_err(|_| anyhow!("UDP tunnel closed"))?;
        let mut tcp = TcpStream::connect(exposed_addr)
            .await
            .with_context(|| format!("Failed to connect the TCP visitor to {exposed_addr}"))?;
        tokio::try_join!(
            check_tcp_echo(&mut tcp, b"initial TCP"),
            check_udp_echo(&visitor_udp, b"initial UDP"),
        )?;
        let second_visitor = UdpSocket::bind(loopback).await?;
        second_visitor.connect(exposed_addr).await?;
        for &size in sizes {
            let first = vec![23; size];
            let second = vec![191; size];
            tokio::try_join!(
                check_udp_echo(&visitor_udp, &first),
                check_udp_echo(&second_visitor, &second),
            )?;
        }
        // Some platforms impose a lower UDP socket limit than the IPv4 maximum.
        #[cfg(target_os = "linux")]
        if exposed_addr.is_ipv4() {
            check_udp_echo(&visitor_udp, &vec![83; 65507]).await?;
        }

        first_udp
            .disconnect
            .send(())
            .map_err(|_| anyhow!("UDP tunnel closed"))?;
        let replacement_udp = udp_tunnels.recv().await.context("Replacement UDP tunnel")?;
        // The proxy holds the replacement until the existing TCP stream has echoed again.
        check_tcp_echo(&mut tcp, b"TCP during UDP outage").await?;
        replacement_udp
            .start
            .send(())
            .map_err(|_| anyhow!("UDP tunnel closed"))?;
        tokio::try_join!(
            check_tcp_echo(&mut tcp, b"TCP after recovery"),
            check_udp_echo(&visitor_udp, b"recovered UDP"),
        )?;
        close_tcp(tcp).await?;

        client_shutdown.send(true)?;
        client.await??;
        wait_for_listeners_to_close(exposed_addr)
            .await
            .with_context(|| {
                format!("Failed to verify release of {exposed_addr} after client shutdown")
            })?;

        let (_client_updates, client_update_rx) = mpsc::channel(1);
        let client = tokio::spawn(crate::client::run_client(
            client_config,
            client_shutdown.subscribe(),
            client_update_rx,
        ));
        let reconnected_udp = udp_tunnels.recv().await.context("Reconnected UDP tunnel")?;
        reconnected_udp
            .start
            .send(())
            .map_err(|_| anyhow!("UDP tunnel closed"))?;
        let mut tcp = TcpStream::connect(exposed_addr)
            .await
            .with_context(|| format!("Failed to reconnect the TCP visitor to {exposed_addr}"))?;
        tokio::try_join!(
            check_tcp_echo(&mut tcp, b"reconnected TCP"),
            check_udp_echo(&visitor_udp, b"reconnected UDP"),
        )?;
        close_tcp(tcp).await?;

        server_updates
            .send(ConfigChange::ServerChange(ServerServiceChange::Delete(
                SERVICE.into(),
            )))
            .await?;
        wait_for_listeners_to_close(exposed_addr)
            .await
            .with_context(|| {
                format!("Failed to verify release of {exposed_addr} after service removal")
            })?;
        client_shutdown.send(true)?;
        server_shutdown.send(true)?;
        client.await??;
        server.await??;
        Ok(())
    }

    async fn wait_for_listeners_to_close(addr: SocketAddr) -> Result<()> {
        loop {
            match bind_tcp_and_udp(&addr.to_string()).await {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    time::sleep(RETRY_DELAY).await
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn close_tcp(mut stream: TcpStream) -> Result<()> {
        stream.shutdown().await?;
        assert_eq!(stream.read(&mut [0]).await?, 0);
        Ok(())
    }

    async fn echo_tcp(listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let (mut read, mut write) = stream.into_split();
            tokio::spawn(async move { io::copy(&mut read, &mut write).await });
        }
    }

    async fn echo_udp(socket: UdpSocket) -> io::Result<()> {
        let mut buf = vec![0; u16::MAX as usize];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..len], from).await?;
        }
    }

    async fn check_tcp_echo(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
        stream.write_all(payload).await?;
        let mut reply = vec![0; payload.len()];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, payload);
        Ok(())
    }

    async fn check_udp_echo(socket: &UdpSocket, payload: &[u8]) -> Result<()> {
        socket.send(payload).await?;
        let mut reply = vec![0; u16::MAX as usize];
        let len = socket.recv(&mut reply).await?;
        assert_eq!(len, payload.len(), "UDP echo length");
        assert_eq!(&reply[..len], payload);
        Ok(())
    }

    struct UdpTunnel {
        start: oneshot::Sender<()>,
        disconnect: oneshot::Sender<()>,
    }

    async fn proxy_tunnels(
        listener: TcpListener,
        control_addr: SocketAddr,
        udp_tunnels: mpsc::UnboundedSender<UdpTunnel>,
    ) -> io::Result<()> {
        loop {
            let (client, _) = listener.accept().await?;
            tokio::spawn(proxy_tunnel(client, control_addr, udp_tunnels.clone()));
        }
    }

    async fn proxy_tunnel(
        mut client: TcpStream,
        control_addr: SocketAddr,
        udp_tunnels: mpsc::UnboundedSender<UdpTunnel>,
    ) -> Result<()> {
        let mut server = loop {
            match TcpStream::connect(control_addr).await {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    time::sleep(RETRY_DELAY).await
                }
                result => break result?,
            }
        };
        let hello = read_hello(&mut client).await?;
        server.write_all(&bincode::serialize(&hello)?).await?;
        if matches!(hello, DataChannelHello(..)) {
            let cmd = read_data_cmd(&mut server).await?;
            if matches!(cmd, DataChannelCmd::StartForwardUdp) {
                let (start, ready) = oneshot::channel();
                let (disconnect, stop) = oneshot::channel();
                udp_tunnels.send(UdpTunnel { start, disconnect })?;
                ready.await?;
                client.write_all(&bincode::serialize(&cmd)?).await?;
                tokio::select! {
                    result = copy_bidirectional(&mut client, &mut server) => { result?; }
                    _ = stop => {}
                }
                return Ok(());
            }
            client.write_all(&bincode::serialize(&cmd)?).await?;
        }
        copy_bidirectional(&mut client, &mut server).await?;
        Ok(())
    }
}
