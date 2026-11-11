use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{
    listen_backoff, DATA_REQUEST_RETRY, NETWORK_IO_TIMEOUT, UDP_DATAGRAM_BUFFER_SIZE,
};
use crate::helper::retry_notify_with_deadline;
use crate::multi_map::MultiMap;
use crate::protocol::Hello::{ControlChannelHello, DataChannelHello};
use crate::protocol::{
    self, read_auth, read_hello, Ack, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic,
    HASH_WIDTH_IN_BYTES,
};
use crate::transport::{SocketOpts, TcpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;

use rand::RngCore;
use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time::{self, Instant};
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(feature = "tls")]
use crate::transport::TlsTransport;
#[cfg(feature = "websocket")]
use crate::transport::WebsocketTransport;

type ServiceDigest = protocol::Digest; // SHA256 of a service name
type Nonce = protocol::Digest; // Also called `session_key`

const TCP_POOL_SIZE: usize = 8; // The number of cached connections for TCP services
const UDP_POOL_SIZE: usize = 2; // The number of cached connections for UDP services
const VISITOR_QUEUE_SIZE: usize = 2048;
const MAX_PENDING_HANDSHAKES: usize = 128;
const TCP_VISITOR_TIMEOUT: Duration = Duration::from_secs(30);

// The entrypoint of running a server
pub async fn run_server(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = match config.server {
            Some(config) => config,
            None => {
                return Err(anyhow!("Try to run as a server, but the configuration is missing. Please add the `[server]` block"))
            }
        };

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut server = Server::<TcpTransport>::from(config).await?;
            server.run(shutdown_rx, update_rx).await?;
        }
        TransportType::Tls => {
            #[cfg(feature = "tls")]
            {
                let mut server = Server::<TlsTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "tls"))]
            crate::helper::feature_not_compile("tls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut server = Server::<NoiseTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(feature = "websocket")]
            {
                let mut server = Server::<WebsocketTransport>::from(config).await?;
                server.run(shutdown_rx, update_rx).await?;
            }
            #[cfg(not(feature = "websocket"))]
            crate::helper::feature_not_compile("websocket")
        }
    }

    Ok(())
}

// A hash map of ControlChannelHandles, indexed by ServiceDigest or Nonce
// See also MultiMap
type ControlChannelMap<T> = MultiMap<ServiceDigest, Nonce, ControlChannelHandle<T>>;

// Server holds all states of running a server
struct Server<T: Transport> {
    // `[server]` config
    config: Arc<ServerConfig>,

    // `[server.services]` config, indexed by ServiceDigest
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    // Collection of contorl channels
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    // Wrapper around the transport layer
    transport: Arc<T>,
}

// Generate a hash map of services which is indexed by ServiceDigest
fn generate_service_hashmap(
    server_config: &ServerConfig,
) -> HashMap<ServiceDigest, ServerServiceConfig> {
    let mut ret = HashMap::new();
    for u in &server_config.services {
        ret.insert(protocol::digest(u.0.as_bytes()), (*u.1).clone());
    }
    ret
}

impl<T: 'static + Transport> Server<T> {
    // Create a server from `[server]`
    pub async fn from(config: ServerConfig) -> Result<Server<T>> {
        let config = Arc::new(config);
        let services = Arc::new(RwLock::new(generate_service_hashmap(&config)));
        let control_channels = Arc::new(RwLock::new(ControlChannelMap::new()));
        let transport = Arc::new(T::new(&config.transport)?);
        Ok(Server {
            config,
            services,
            control_channels,
            transport,
        })
    }

    // The entry point of Server
    pub async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        // Listen at `server.bind_addr`
        let l = self
            .transport
            .bind(&self.config.bind_addr)
            .await
            .with_context(|| "Failed to listen at `server.bind_addr`")?;
        info!("Listening at {}", self.config.bind_addr);

        // Retry at least every 100ms
        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_millis(100),
            max_elapsed_time: None,
            ..Default::default()
        };

        let mut handshakes = JoinSet::new();

        // Wait for connections and shutdown signals
        loop {
            tokio::select! {
                // Wait for incoming control and data channels
                ret = self.transport.accept(&l), if handshakes.len() < MAX_PENDING_HANDSHAKES => {
                    match ret {
                        Err(err) => {
                            // Detects whether it's an IO error
                            if let Some(err) = err.downcast_ref::<io::Error>() {
                                // If it is an IO error, then it's possibly an
                                // EMFILE. So sleep for a while and retry
                                // TODO: Only sleep for EMFILE, ENFILE, ENOMEM, ENOBUFS
                                if let Some(d) = backoff.next_backoff() {
                                    error!("Failed to accept: {:#}. Retry in {:?}...", err, d);
                                    time::sleep(d).await;
                                } else {
                                    // This branch will never be executed according to the current retry policy
                                    error!("Too many retries. Aborting...");
                                    break;
                                }
                            }
                            // If it's not an IO error, then it comes from
                            // the transport layer, so just ignore it
                        }
                        Ok((conn, addr)) => {
                            backoff.reset();

                            let transport = self.transport.clone();
                            let services = self.services.clone();
                            let control_channels = self.control_channels.clone();
                            let server_config = self.config.clone();
                            handshakes.spawn(async move {
                                let result = async {
                                    let conn = time::timeout(NETWORK_IO_TIMEOUT, transport.handshake(conn))
                                        .await
                                        .context("Transport handshake timed out")?
                                        .context("Failed to do transport handshake")?;
                                    time::timeout(
                                        NETWORK_IO_TIMEOUT,
                                        handle_connection(conn, services, control_channels, server_config),
                                    )
                                    .await
                                    .context("Rathole handshake timed out")?
                                }.await;
                                if let Err(err) = result {
                                    error!("{:#}", err);
                                }
                            }.instrument(info_span!("connection", %addr)));
                        }
                    }
                },
                // Wait for the shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shuting down gracefully...");
                    break;
                },
                Some(e) = update_rx.recv() => {
                    self.handle_hot_reload(e).await;
                },
                Some(result) = handshakes.join_next() => {
                    if let Err(error) = result {
                        error!("Connection handshake task failed: {}", error);
                    }
                }
            }
        }

        handshakes.shutdown().await;
        info!("Shutdown");

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ServerChange(server_change) => match server_change {
                ServerServiceChange::Add(cfg) => {
                    let hash = protocol::digest(cfg.name.as_bytes());
                    let mut wg = self.services.write().await;
                    let _ = wg.insert(hash, cfg);

                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
                ServerServiceChange::Delete(s) => {
                    let hash = protocol::digest(s.as_bytes());
                    let mut wg = self.services.write().await;
                    let _ = wg.remove(&hash);

                    let mut wg = self.control_channels.write().await;
                    let _ = wg.remove1(&hash);
                }
            },
            ignored => warn!("Ignored {:?} since running as a server", ignored),
        }
    }
}

// Handle connections to `server.bind_addr`
async fn handle_connection<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    // Read hello
    let hello = read_hello(&mut conn).await?;
    match hello {
        ControlChannelHello(_, service_digest) => {
            do_control_channel_handshake(
                conn,
                services,
                control_channels,
                service_digest,
                server_config,
            )
            .await?;
        }
        DataChannelHello(_, nonce) => {
            do_data_channel_handshake(conn, control_channels, nonce).await?;
        }
    }
    Ok(())
}

async fn do_control_channel_handshake<T: 'static + Transport>(
    mut conn: T::Stream,
    services: Arc<RwLock<HashMap<ServiceDigest, ServerServiceConfig>>>,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    service_digest: ServiceDigest,
    server_config: Arc<ServerConfig>,
) -> Result<()> {
    info!("Try to handshake a control channel");

    T::hint(&conn, SocketOpts::for_control_channel());

    // Generate a nonce
    let mut nonce = vec![0u8; HASH_WIDTH_IN_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Send hello
    let hello_send = Hello::ControlChannelHello(
        protocol::CURRENT_PROTO_VERSION,
        nonce.clone().try_into().unwrap(),
    );
    conn.write_all(&bincode::serialize(&hello_send).unwrap())
        .await?;
    conn.flush().await?;

    // Lookup the service
    let service_config = services.read().await.get(&service_digest).cloned();
    let service_config = match service_config {
        Some(config) => config,
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            conn.flush().await?;
            bail!("No such a service {}", hex::encode(service_digest));
        }
    };

    let service_name = &service_config.name;

    // Calculate the checksum
    let mut concat = Vec::from(service_config.token.as_ref().unwrap().as_bytes());
    concat.append(&mut nonce);

    // Read auth
    let protocol::Auth(d) = read_auth(&mut conn).await?;

    // Validate
    let session_key = protocol::digest(&concat);
    if session_key != d {
        conn.write_all(&bincode::serialize(&Ack::AuthFailed).unwrap())
            .await?;
        conn.flush().await?;
        debug!(
            "Expect {}, but got {}",
            hex::encode(session_key),
            hex::encode(d)
        );
        bail!("Service {} failed the authentication", service_name);
    }

    conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
        .await?;
    conn.flush().await?;

    // A reload may have changed the configuration while authentication was in flight.
    let services = services.read().await;
    if services.get(&service_digest) != Some(&service_config) {
        bail!(
            "Configuration changed during authentication for service {}",
            service_name
        );
    }
    let mut channels = control_channels.write().await;
    if channels.remove1(&service_digest).is_some() {
        warn!(
            "Dropping previous control channel for service {}",
            service_name
        );
    }
    info!(service = %service_config.name, "Control channel established");
    let handle = ControlChannelHandle::new(conn, service_config, server_config.heartbeat_interval);
    let _ = channels.insert(service_digest, session_key, handle);

    Ok(())
}

async fn do_data_channel_handshake<T: 'static + Transport>(
    conn: T::Stream,
    control_channels: Arc<RwLock<ControlChannelMap<T>>>,
    nonce: Nonce,
) -> Result<()> {
    debug!("Try to handshake a data channel");

    // Validate
    let data_ch_tx = {
        let control_channels = control_channels.read().await;
        let Some(handle) = control_channels.get2(&nonce) else {
            warn!("Data channel has incorrect nonce");
            return Ok(());
        };
        T::hint(&conn, SocketOpts::from_server_cfg(&handle.service));
        handle.data_ch_tx.clone()
    };
    match data_ch_tx.try_send(conn) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => debug!("Data channel pool is full"),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            bail!("Data channel for a stale control channel")
        }
    }
    Ok(())
}

pub struct ControlChannelHandle<T: Transport> {
    // Shutdown the control channel by dropping it
    _shutdown_tx: broadcast::Sender<bool>,
    data_ch_tx: mpsc::Sender<T::Stream>,
    service: ServerServiceConfig,
}

impl<T> ControlChannelHandle<T>
where
    T: 'static + Transport,
{
    // Create a control channel handle, where the control channel handling task
    // and the connection pool task are created.
    #[instrument(name = "handle", skip_all, fields(service = %service.name))]
    fn new(
        conn: T::Stream,
        service: ServerServiceConfig,
        heartbeat_interval: u64,
    ) -> ControlChannelHandle<T> {
        // Create a shutdown channel
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<bool>(1);

        // Cache some data channels for later use
        let pool_size = match service.service_type {
            ServiceType::Tcp => TCP_POOL_SIZE,
            ServiceType::Udp => UDP_POOL_SIZE,
            ServiceType::TcpAndUdp => TCP_POOL_SIZE + UDP_POOL_SIZE,
        };
        let (data_ch_tx, data_ch_rx) = mpsc::channel(pool_size);
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::channel(pool_size);

        for _ in 0..pool_size {
            let _ = data_ch_req_tx.try_send(());
        }

        let bind_addr = service.bind_addr.clone();
        let service_type = service.service_type;
        let bind_shutdown_rx = shutdown_tx.subscribe();

        let ch = ControlChannel::<T> {
            conn,
            data_ch_req_rx,
            heartbeat_interval,
        };

        // The control session owns the listeners and pending data channels.
        tokio::spawn(
            async move {
                let result = tokio::select! {
                    result = ch.run() => result,
                    result = run_connection_pools::<T>(
                        service_type, bind_addr, data_ch_rx, data_ch_req_tx, bind_shutdown_rx,
                    ) => result,
                    _ = shutdown_rx.recv() => Ok(()),
                };
                if let Err(err) = result {
                    error!("{:#}", err);
                }
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle {
            _shutdown_tx: shutdown_tx,
            data_ch_tx,
            service,
        }
    }
}

struct ControlChannel<T: Transport> {
    conn: T::Stream, // The connection of control channel
    data_ch_req_rx: mpsc::Receiver<()>,
    heartbeat_interval: u64, // Application-layer heartbeat interval in secs
}

impl<T: Transport> ControlChannel<T> {
    // Run a control channel
    #[instrument(skip_all)]
    async fn run(mut self) -> Result<()> {
        let create_ch_cmd = bincode::serialize(&ControlChannelCmd::CreateDataChannel).unwrap();
        let heartbeat = bincode::serialize(&ControlChannelCmd::HeartBeat).unwrap();

        // The client sends no control messages after authentication. A read detects
        // disconnects even if heartbeats are disabled and the service is idle.
        loop {
            tokio::select! {
                val = self.data_ch_req_rx.recv() => {
                    if val.is_none() {
                        break;
                    }
                    write_command(&mut self.conn, &create_ch_cmd).await
                        .context("Failed to send data channel request")?;
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                    write_command(&mut self.conn, &heartbeat).await
                        .context("Failed to send heartbeat")?;
                }
                received = self.conn.read_u8() => {
                    if received.is_ok() {
                        warn!("Unexpected byte on the control channel");
                    }
                    break;
                }
            }
        }

        info!("Control channel shutdown");

        Ok(())
    }
}

async fn write_command<S: io::AsyncWrite + Unpin>(conn: &mut S, data: &[u8]) -> Result<()> {
    time::timeout(NETWORK_IO_TIMEOUT, async {
        conn.write_all(data).await?;
        conn.flush().await
    })
    .await
    .context("Command write timed out")??;
    Ok(())
}

async fn run_connection_pools<T: Transport>(
    service_type: ServiceType,
    bind_addr: String,
    data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::Sender<()>,
    mut shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let data_ch_rx = Mutex::new(data_ch_rx);
    let log_retry = |error, delay| {
        warn!(
            "Failed to listen at {}: {:#}. Retry in {:?}",
            bind_addr, error, delay
        )
    };

    match service_type {
        ServiceType::Tcp => {
            let listener = retry_notify_with_deadline(
                listen_backoff(),
                || async { Ok(TcpListener::bind(&bind_addr).await?) },
                log_retry,
                &mut shutdown_rx,
            )
            .await?;
            run_tcp_connection_pool::<T>(listener, &data_ch_rx, &data_ch_req_tx).await
        }
        ServiceType::Udp => {
            let socket = retry_notify_with_deadline(
                listen_backoff(),
                || async { Ok(UdpSocket::bind(&bind_addr).await?) },
                log_retry,
                &mut shutdown_rx,
            )
            .await?;
            run_udp_connection_pool::<T>(socket, &data_ch_rx, &data_ch_req_tx).await
        }
        ServiceType::TcpAndUdp => {
            let (listener, socket) = retry_notify_with_deadline(
                listen_backoff(),
                || async { Ok(bind_tcp_and_udp(&bind_addr).await?) },
                log_retry,
                &mut shutdown_rx,
            )
            .await?;
            tokio::try_join!(
                run_tcp_connection_pool::<T>(listener, &data_ch_rx, &data_ch_req_tx),
                run_udp_connection_pool::<T>(socket, &data_ch_rx, &data_ch_req_tx),
            )?;
            Ok(())
        }
    }
}

async fn bind_tcp_and_udp(addr: &str) -> io::Result<(TcpListener, UdpSocket)> {
    let listener = TcpListener::bind(addr).await?;
    let socket = UdpSocket::bind(listener.local_addr()?).await?;
    Ok((listener, socket))
}

async fn accept_tcp_visitors(
    listener: TcpListener,
    visitor_tx: mpsc::Sender<(TcpStream, Instant)>,
) -> Result<()> {
    let mut backoff = listen_backoff();
    loop {
        match listener.accept().await {
            Ok((incoming, addr)) => {
                let deadline = Instant::now() + TCP_VISITOR_TIMEOUT;
                backoff.reset();
                debug!("New visitor from {}", addr);
                visitor_tx.send((incoming, deadline)).await?;
            }
            Err(error) => {
                let Some(delay) = backoff.next_backoff() else {
                    return Err(error.into());
                };
                error!(
                    "Failed to accept TCP visitor: {}. Retry in {:?}",
                    error, delay
                );
                time::sleep(delay).await;
            }
        }
    }
}

fn request_data_channel(requests: &mpsc::Sender<()>) -> Result<()> {
    match requests.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(())) => bail!("Data channel request queue closed"),
    }
}

async fn take_data_channel<S: io::AsyncRead + Unpin>(
    data_ch_rx: &Mutex<mpsc::Receiver<S>>,
    requests: &mpsc::Sender<()>,
) -> Result<S> {
    loop {
        let received = {
            let mut channels = data_ch_rx.lock().await;
            time::timeout(DATA_REQUEST_RETRY, channels.recv()).await
        };
        match received {
            Ok(channel) => {
                let mut channel = channel.context("Data channel pool closed")?;
                // Poll once after releasing the shared receiver. The peer sends no
                // application bytes until it has received StartForward.
                let mut byte = [0];
                let mut buf = ReadBuf::new(&mut byte);
                let readiness =
                    poll_fn(|cx| Poll::Ready(Pin::new(&mut channel).poll_read(cx, &mut buf))).await;
                match readiness {
                    Poll::Pending => return Ok(channel),
                    Poll::Ready(Err(error)) => debug!("Discarding prewarmed channel: {}", error),
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                        debug!("Discarding prewarmed channel at EOF");
                    }
                    Poll::Ready(Ok(())) => {
                        debug!("Discarding prewarmed channel with unexpected data")
                    }
                }
                request_data_channel(requests)?;
            }
            Err(_) => {
                warn!("No data channel arrived. Requesting another");
                request_data_channel(requests)?;
            }
        }
    }
}

async fn start_tcp_forward<S: io::AsyncRead + io::AsyncWrite + Unpin>(
    data_ch_rx: &Mutex<mpsc::Receiver<S>>,
    requests: &mpsc::Sender<()>,
    cmd: &[u8],
) -> Result<S> {
    loop {
        let mut channel = take_data_channel(data_ch_rx, requests).await?;
        match write_command(&mut channel, cmd).await {
            Ok(()) => return Ok(channel),
            Err(error) => warn!("Failed to start TCP forwarding: {:#}", error),
        }
        request_data_channel(requests)?;
    }
}

#[instrument(skip_all)]
async fn run_tcp_connection_pool<T: Transport>(
    listener: TcpListener,
    data_ch_rx: &Mutex<mpsc::Receiver<T::Stream>>,
    data_ch_req_tx: &mpsc::Sender<()>,
) -> Result<()> {
    info!("Listening for TCP at {}", listener.local_addr()?);
    let (visitor_tx, mut visitor_rx) = mpsc::channel(VISITOR_QUEUE_SIZE);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();

    tokio::select! {
        result = accept_tcp_visitors(listener, visitor_tx) => result,
        result = async {
            while let Some((mut visitor, deadline)) = visitor_rx.recv().await {
                if Instant::now() >= deadline {
                    continue;
                }
                // Request a channel for this visitor or replenish the cached one it takes.
                request_data_channel(data_ch_req_tx)?;
                let start = start_tcp_forward(data_ch_rx, data_ch_req_tx, &cmd);
                let mut channel = match time::timeout_at(deadline, start).await {
                    Ok(result) => result?,
                    Err(_) => {
                        debug!("TCP visitor timed out waiting for a data channel");
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let _ = copy_bidirectional(&mut channel, &mut visitor).await;
                });
            }
            Ok(())
        } => result,
    }
}

#[instrument(skip_all)]
async fn run_udp_connection_pool<T: Transport>(
    socket: UdpSocket,
    data_ch_rx: &Mutex<mpsc::Receiver<T::Stream>>,
    requests: &mpsc::Sender<()>,
) -> Result<()> {
    info!("Listening for UDP at {}", socket.local_addr()?);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp).unwrap();
    let mut backoff = listen_backoff();
    loop {
        let conn = take_data_channel(data_ch_rx, requests).await?;
        let Err(error) = forward_udp(&socket, conn, &cmd).await else {
            return Ok(());
        };
        let Some(delay) = backoff.next_backoff() else {
            return Err(error);
        };
        warn!("UDP data channel ended: {:#}. Retry in {:?}", error, delay);
        time::sleep(delay).await;
        request_data_channel(requests)?;
    }
}

async fn forward_udp<S>(socket: &UdpSocket, mut conn: S, cmd: &[u8]) -> Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    write_command(&mut conn, cmd)
        .await
        .context("Failed to start UDP forwarding")?;

    let (mut rd, mut wr) = io::split(conn);
    let inbound = async {
        let mut buf = vec![0; UDP_DATAGRAM_BUFFER_SIZE];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            UdpTraffic::write_slice(&mut wr, from, &buf[..n]).await?;
        }
    };
    let outbound = async {
        loop {
            let hdr_len = rd.read_u8().await?;
            let packet = UdpTraffic::read(&mut rd, hdr_len).await?;
            time::timeout(
                NETWORK_IO_TIMEOUT,
                socket.send_to(&packet.data, packet.from),
            )
            .await
            .context("UDP send to visitor timed out")??;
        }
    };
    tokio::select! {
        result = inbound => result,
        result = outbound => result,
    }
}

#[cfg(test)]
mod tests;
