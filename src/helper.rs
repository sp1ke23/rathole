#[cfg(feature = "client")]
use anyhow::Context;
use anyhow::{anyhow, Result};
use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};
use backoff::{backoff::Backoff, Notify};
#[cfg(feature = "client")]
use socket2::{Domain, Socket, Type};
use socket2::{SockRef, TcpKeepalive};
use std::{future::Future, net::SocketAddr, time::Duration};
#[cfg(feature = "client")]
use tokio::net::{TcpSocket, UdpSocket};
use tokio::{
    net::{lookup_host, TcpStream, ToSocketAddrs},
    sync::broadcast,
};
use tracing::trace;
use url::Url;

use crate::transport::AddrMaybeCached;

// Tokio hesitates to expose this option...So we have to do it on our own :(
// The good news is that using socket2 it can be easily done, without losing portability.
// See https://github.com/tokio-rs/tokio/issues/3082
pub fn try_set_tcp_keepalive(
    conn: &TcpStream,
    keepalive_duration: Duration,
    keepalive_interval: Duration,
) -> Result<()> {
    let s = SockRef::from(conn);
    let keepalive = TcpKeepalive::new()
        .with_time(keepalive_duration)
        .with_interval(keepalive_interval);

    trace!(
        "Set TCP keepalive {:?} {:?}",
        keepalive_duration,
        keepalive_interval
    );

    Ok(s.set_tcp_keepalive(&keepalive)?)
}

#[allow(dead_code)]
pub fn feature_not_compile(feature: &str) -> ! {
    panic!(
        "The feature '{}' is not compiled in this binary. Please re-compile rathole",
        feature
    )
}

pub async fn to_socket_addr<A: ToSocketAddrs>(addr: A) -> Result<SocketAddr> {
    lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| anyhow!("Failed to lookup the host"))
}

pub fn host_port_pair(s: &str) -> Result<(&str, u16)> {
    let semi = s.rfind(':').expect("missing semicolon");
    Ok((&s[..semi], s[semi + 1..].parse()?))
}

#[cfg(feature = "client")]
fn new_bound_socket(addr: SocketAddr, kind: Type, interface: &str) -> Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), kind, None)?;

    #[cfg(target_os = "linux")]
    let bind_result = socket.bind_device(Some(interface.as_bytes()));
    #[cfg(not(target_os = "linux"))]
    let bind_result: std::io::Result<()> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local_addr_if is only supported on Linux",
    ));
    bind_result.with_context(|| format!("Failed to bind socket to interface {:?}", interface))?;

    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(feature = "client")]
pub async fn tcp_connect_local<A: ToSocketAddrs>(
    addr: A,
    interface: Option<&str>,
) -> Result<TcpStream> {
    let Some(interface) = interface else {
        return Ok(TcpStream::connect(addr).await?);
    };

    let mut last_error = None;
    for addr in lookup_host(addr).await? {
        let result = match new_bound_socket(addr, Type::STREAM, interface) {
            Ok(socket) => TcpSocket::from_std_stream(socket.into())
                .connect(addr)
                .await
                .map_err(Into::into),
            Err(error) => Err(error),
        };
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("Failed to lookup the host")))
}

/// Create a UDP socket and connect to `addr`.
#[cfg(feature = "client")]
pub async fn udp_connect<A: ToSocketAddrs>(addr: A, interface: Option<&str>) -> Result<UdpSocket> {
    let addr = to_socket_addr(addr).await?;

    let bind_addr = match addr {
        SocketAddr::V4(_) => SocketAddr::from(([0; 4], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 8], 0)),
    };

    let s = if let Some(interface) = interface {
        let socket = new_bound_socket(addr, Type::DGRAM, interface)?;
        socket.bind(&bind_addr.into())?;
        UdpSocket::from_std(socket.into())?
    } else {
        UdpSocket::bind(bind_addr).await?
    };
    s.connect(addr).await?;
    Ok(s)
}

/// Create a TcpStream using a proxy
/// e.g. socks5://user:pass@127.0.0.1:1080 http://127.0.0.1:8080
pub async fn tcp_connect_with_proxy(
    addr: &AddrMaybeCached,
    proxy: Option<&Url>,
) -> Result<TcpStream> {
    if let Some(url) = proxy {
        let addr = &addr.addr;
        let mut s = TcpStream::connect((
            url.host_str().expect("proxy url should have host field"),
            url.port().expect("proxy url should have port field"),
        ))
        .await?;

        let auth = if !url.username().is_empty() || url.password().is_some() {
            Some(async_socks5::Auth {
                username: url.username().into(),
                password: url.password().unwrap_or("").into(),
            })
        } else {
            None
        };
        match url.scheme() {
            "socks5" => {
                async_socks5::connect(&mut s, host_port_pair(addr)?, auth).await?;
            }
            "http" => {
                let (host, port) = host_port_pair(addr)?;
                match auth {
                    Some(auth) => {
                        http_connect_tokio_with_basic_auth(
                            &mut s,
                            host,
                            port,
                            &auth.username,
                            &auth.password,
                        )
                        .await?
                    }
                    None => http_connect_tokio(&mut s, host, port).await?,
                }
            }
            _ => panic!("unknown proxy scheme"),
        }
        Ok(s)
    } else {
        Ok(match addr.socket_addr {
            Some(s) => TcpStream::connect(s).await?,
            None => TcpStream::connect(&addr.addr).await?,
        })
    }
}

// Wrapper of retry_notify
pub async fn retry_notify_with_deadline<I, E, Fn, Fut, B, N>(
    backoff: B,
    operation: Fn,
    notify: N,
    deadline: &mut broadcast::Receiver<bool>,
) -> Result<I>
where
    E: std::error::Error + Send + Sync + 'static,
    B: Backoff,
    Fn: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<I, backoff::Error<E>>>,
    N: Notify<E>,
{
    tokio::select! {
        v = backoff::future::retry_notify(backoff, operation, notify) => {
            v.map_err(anyhow::Error::new)
        }
        _ = deadline.recv() => {
            Err(anyhow!("shutdown"))
        }
    }
}

#[cfg(all(test, feature = "client", target_os = "linux"))]
mod tests {
    use super::*;
    use std::{env, io};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    const MISSING_INTERFACE: &str = "noif-rathole0";

    fn loopback_addrs() -> Vec<&'static str> {
        let mut addresses = vec!["127.0.0.1:0"];
        match std::net::UdpSocket::bind("[::1]:0") {
            Ok(_) => addresses.push("[::1]:0"),
            Err(error) => eprintln!("Skipping IPv6 loopback tests: {error}"),
        }
        addresses
    }

    fn assert_loopback_device(socket: SockRef<'_>) -> io::Result<()> {
        match socket.device() {
            Ok(device) => assert_eq!(device.as_deref(), Some(&b"lo"[..])),
            Err(error)
                if error.kind() == io::ErrorKind::InvalidInput
                    && matches!(
                        env::var("RATHOLE_TEST_ALLOW_QEMU_DEVICE_EINVAL").as_deref(),
                        Ok("1")
                    ) =>
            {
                // QEMU 6.1 forwards this option with a 4-byte buffer, which Linux rejects.
                eprintln!("Skipping SO_BINDTODEVICE readback under QEMU: {error}");
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    #[tokio::test]
    async fn tcp_local_addr_if() -> Result<()> {
        for loopback in loopback_addrs() {
            let listener = TcpListener::bind(loopback).await?;
            let addr = listener.local_addr()?;
            let unused = TcpSocket::new_v4()?;
            unused.bind("127.0.0.1:0".parse()?)?;
            let addresses = [unused.local_addr()?, addr];
            let mut client = tcp_connect_local(&addresses[..], Some("lo")).await?;
            assert_loopback_device(SockRef::from(&client))?;

            let (mut backend, _) = listener.accept().await?;
            client.write_all(b"ping").await?;
            let mut buf = [0; 4];
            timeout(Duration::from_secs(5), backend.read_exact(&mut buf)).await??;
            assert_eq!(&buf, b"ping");

            let error = tcp_connect_local(addr, Some(MISSING_INTERFACE))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(MISSING_INTERFACE));
            assert!(error.downcast_ref::<std::io::Error>().is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn udp_local_addr_if() -> Result<()> {
        for loopback in loopback_addrs() {
            let backend = UdpSocket::bind(loopback).await?;
            let addr = backend.local_addr()?;
            let client = udp_connect(addr, Some("lo")).await?;
            assert_loopback_device(SockRef::from(&client))?;

            client.send(b"ping").await?;
            let mut buf = [0; 4];
            let (len, from) =
                timeout(Duration::from_secs(5), backend.recv_from(&mut buf)).await??;
            assert_eq!(&buf[..len], b"ping");
            backend.send_to(b"pong", from).await?;
            let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
            assert_eq!(&buf[..len], b"pong");

            let error = udp_connect(addr, Some(MISSING_INTERFACE))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(MISSING_INTERFACE));
            assert!(error.downcast_ref::<std::io::Error>().is_some());
        }
        Ok(())
    }
}
