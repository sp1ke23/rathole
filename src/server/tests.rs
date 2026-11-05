use super::*;

#[tokio::test]
async fn dual_listener_uses_one_ephemeral_port() -> Result<()> {
    let (tcp, udp) = bind_tcp_and_udp("127.0.0.1:0").await?;
    assert_ne!(tcp.local_addr()?.port(), 0);
    assert_eq!(tcp.local_addr()?, udp.local_addr()?);
    Ok(())
}

#[tokio::test]
async fn dual_listener_releases_tcp_when_udp_bind_fails() -> Result<()> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = udp.local_addr()?;
    let error = bind_tcp_and_udp(&addr.to_string()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    let _tcp = TcpListener::bind(addr).await?;
    Ok(())
}

#[cfg(feature = "client")]
mod forwarding {
    use super::*;
    use crate::config::{ClientConfig, ClientServiceConfig, MaskedString};
    use crate::protocol::read_data_cmd;
    use std::net::SocketAddr;
    use tokio::sync::oneshot;

    const SERVICE: &str = "backend";
    const LOOPBACK: &str = "127.0.0.1:0";
    const RETRY_DELAY: Duration = Duration::from_millis(20);

    #[tokio::test]
    async fn dual_service_recovers_udp_and_reconnects() -> Result<()> {
        time::timeout(Duration::from_secs(15), exercise_dual_service())
            .await
            .context("Timed out testing dual service forwarding")?
    }

    async fn exercise_dual_service() -> Result<()> {
        let (backend_tcp, backend_udp) = bind_tcp_and_udp(LOOPBACK).await?;
        let backend_addr = backend_tcp.local_addr()?;
        let (exposed_tcp, exposed_udp) = bind_tcp_and_udp(LOOPBACK).await?;
        let exposed_addr = exposed_tcp.local_addr()?;
        let proxy = TcpListener::bind(LOOPBACK).await?;
        let proxy_addr = proxy.local_addr()?;
        let control = TcpListener::bind(LOOPBACK).await?;
        let control_addr = control.local_addr()?;
        let visitor_udp = UdpSocket::bind(LOOPBACK).await?;
        visitor_udp.connect(exposed_addr).await?;
        drop((exposed_tcp, exposed_udp, control));

        tokio::spawn(echo_tcp(backend_tcp));
        tokio::spawn(echo_udp(backend_udp));
        let (udp_tunnels_tx, mut udp_tunnels) = mpsc::unbounded_channel();
        tokio::spawn(proxy_tunnels(proxy, control_addr, udp_tunnels_tx));

        let token = MaskedString::from("test-token");
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
        let mut tcp = TcpStream::connect(exposed_addr).await?;
        tokio::try_join!(
            check_tcp_echo(&mut tcp, b"initial TCP"),
            check_udp_echo(&visitor_udp, b"initial UDP"),
        )?;

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
        wait_for_listeners_to_close(exposed_addr).await?;

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
        let mut tcp = TcpStream::connect(exposed_addr).await?;
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
        wait_for_listeners_to_close(exposed_addr).await?;
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
        let mut buf = [0; UDP_BUFFER_SIZE];
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
        let mut reply = [0; UDP_BUFFER_SIZE];
        let len = socket.recv(&mut reply).await?;
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
