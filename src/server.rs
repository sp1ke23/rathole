use crate::config::{Config, ServerConfig, ServerServiceConfig, ServiceType, TransportType};
use crate::config_watcher::{ConfigChange, ServerServiceChange};
use crate::constants::{listen_backoff, UDP_BUFFER_SIZE};
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
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, info_span, instrument, warn, Instrument, Span};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(feature = "tls")]
use crate::transport::TlsTransport;
#[cfg(feature = "websocket")]
use crate::transport::WebsocketTransport;

type ServiceDigest = protocol::Digest; // SHA256 of a service name
type Nonce = protocol::Digest; // Also called `session_key`

const TCP_POOL_SIZE: usize = 8; // The number of cached connections for TCP servies
const UDP_POOL_SIZE: usize = 2; // The number of cached connections for UDP services
const CHAN_SIZE: usize = 2048; // The capacity of various chans
const HANDSHAKE_TIMEOUT: u64 = 5; // Timeout for transport handshake

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

        // Wait for connections and shutdown signals
        loop {
            tokio::select! {
                // Wait for incoming control and data channels
                ret = self.transport.accept(&l) => {
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

                            // Do transport handshake with a timeout
                            match time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT), self.transport.handshake(conn)).await {
                                Ok(conn) => {
                                    match conn.with_context(|| "Failed to do transport handshake") {
                                        Ok(conn) => {
                                            let services = self.services.clone();
                                            let control_channels = self.control_channels.clone();
                                            let server_config = self.config.clone();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_connection(conn, services, control_channels, server_config).await {
                                                    error!("{:#}", err);
                                                }
                                            }.instrument(info_span!("connection", %addr)));
                                        }, Err(e) => {
                                            error!("{:#}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Transport handshake timeout: {}", e);
                                }
                            }
                        }
                    }
                },
                // Wait for the shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shuting down gracefully...");
                    break;
                },
                e = update_rx.recv() => {
                    if let Some(e) = e {
                        self.handle_hot_reload(e).await;
                    }
                }
            }
        }

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
    let service_config = match services.read().await.get(&service_digest) {
        Some(v) => v,
        None => {
            conn.write_all(&bincode::serialize(&Ack::ServiceNotExist).unwrap())
                .await?;
            bail!("No such a service {}", hex::encode(service_digest));
        }
    }
    .to_owned();

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
        debug!(
            "Expect {}, but got {}",
            hex::encode(session_key),
            hex::encode(d)
        );
        bail!("Service {} failed the authentication", service_name);
    } else {
        // A reload may have replaced the configuration while authentication was in flight.
        let services = services.read().await;
        if services.get(&service_digest) != Some(&service_config) {
            bail!(
                "Configuration changed during authentication for service {}",
                service_name
            );
        }
        let mut h = control_channels.write().await;

        // If there's already a control channel for the service, then drop the old one.
        // Because a control channel doesn't report back when it's dead,
        // the handle in the map could be stall, dropping the old handle enables
        // the client to reconnect.
        if h.remove1(&service_digest).is_some() {
            warn!(
                "Dropping previous control channel for service {}",
                service_name
            );
        }

        // Send ack
        conn.write_all(&bincode::serialize(&Ack::Ok).unwrap())
            .await?;
        conn.flush().await?;

        info!(service = %service_config.name, "Control channel established");
        let handle =
            ControlChannelHandle::new(conn, service_config, server_config.heartbeat_interval);

        // Insert the new handle
        let _ = h.insert(service_digest, session_key, handle);
    }

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
    data_ch_tx
        .send(conn)
        .await
        .with_context(|| "Data channel for a stale control channel")?;
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

        // Store data channels
        let (data_ch_tx, data_ch_rx) = mpsc::channel(CHAN_SIZE * 2);

        // Store data channel creation requests
        let (data_ch_req_tx, data_ch_req_rx) = mpsc::unbounded_channel();

        // Cache some data channels for later use
        let pool_size = match service.service_type {
            ServiceType::Tcp => TCP_POOL_SIZE,
            ServiceType::Udp => UDP_POOL_SIZE,
            ServiceType::TcpAndUdp => TCP_POOL_SIZE + UDP_POOL_SIZE,
        };

        for _i in 0..pool_size {
            if let Err(e) = data_ch_req_tx.send(true) {
                error!("Failed to request data channel {}", e);
            };
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

// Control channel, using T as the transport layer. P is TcpStream or UdpTraffic
struct ControlChannel<T: Transport> {
    conn: T::Stream,                               // The connection of control channel
    data_ch_req_rx: mpsc::UnboundedReceiver<bool>, // Receives visitor connections
    heartbeat_interval: u64,                       // Application-layer heartbeat interval in secs
}

impl<T: Transport> ControlChannel<T> {
    async fn write_and_flush(&mut self, data: &[u8]) -> Result<()> {
        self.conn
            .write_all(data)
            .await
            .with_context(|| "Failed to write control cmds")?;
        self.conn
            .flush()
            .await
            .with_context(|| "Failed to flush control cmds")?;
        Ok(())
    }
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
                    match val {
                        Some(_) => {
                            if let Err(e) = self.write_and_flush(&create_ch_cmd).await {
                                error!("{:#}", e);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_interval)), if self.heartbeat_interval != 0 => {
                            if let Err(e) = self.write_and_flush(&heartbeat).await {
                                error!("{:#}", e);
                                break;
                            }
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

async fn run_connection_pools<T: Transport>(
    service_type: ServiceType,
    bind_addr: String,
    data_ch_rx: mpsc::Receiver<T::Stream>,
    data_ch_req_tx: mpsc::UnboundedSender<bool>,
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
            run_udp_connection_pool::<T>(socket, &data_ch_rx, None).await
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
                run_udp_connection_pool::<T>(socket, &data_ch_rx, Some(&data_ch_req_tx)),
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
    visitor_tx: mpsc::Sender<TcpStream>,
    data_ch_req_tx: &mpsc::UnboundedSender<bool>,
) -> Result<()> {
    let mut backoff = listen_backoff();
    loop {
        match listener.accept().await {
            Ok((incoming, addr)) => {
                data_ch_req_tx
                    .send(true)
                    .context("Failed to request a TCP data channel")?;
                backoff.reset();
                debug!("New visitor from {}", addr);
                visitor_tx.send(incoming).await?;
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

async fn take_data_channel<S>(data_ch_rx: &Mutex<mpsc::Receiver<S>>) -> Result<S> {
    data_ch_rx
        .lock()
        .await
        .recv()
        .await
        .context("No available data channels")
}

#[instrument(skip_all)]
async fn run_tcp_connection_pool<T: Transport>(
    listener: TcpListener,
    data_ch_rx: &Mutex<mpsc::Receiver<T::Stream>>,
    data_ch_req_tx: &mpsc::UnboundedSender<bool>,
) -> Result<()> {
    info!("Listening for TCP at {}", listener.local_addr()?);
    let (visitor_tx, mut visitor_rx) = mpsc::channel::<TcpStream>(CHAN_SIZE);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardTcp).unwrap();

    tokio::select! {
        result = accept_tcp_visitors(listener, visitor_tx, data_ch_req_tx) => result,
        result = async {
            while let Some(mut visitor) = visitor_rx.recv().await {
                loop {
                    let mut ch = take_data_channel(data_ch_rx).await?;
                    if ch.write_all(&cmd).await.is_ok() && ch.flush().await.is_ok() {
                        tokio::spawn(async move {
                            let _ = copy_bidirectional(&mut ch, &mut visitor).await;
                        });
                        break;
                    }
                    data_ch_req_tx.send(true).context("Failed to replace a TCP data channel")?;
                }
            }
            Ok(())
        } => result,
    }
}

#[instrument(skip_all)]
async fn run_udp_connection_pool<T: Transport>(
    socket: UdpSocket,
    data_ch_rx: &Mutex<mpsc::Receiver<T::Stream>>,
    replacement_requests: Option<&mpsc::UnboundedSender<bool>>,
) -> Result<()> {
    info!("Listening for UDP at {}", socket.local_addr()?);
    let cmd = bincode::serialize(&DataChannelCmd::StartForwardUdp).unwrap();
    let mut backoff = listen_backoff();
    loop {
        let conn = take_data_channel(data_ch_rx).await?;
        let Err(error) = forward_udp(&socket, conn, &cmd).await else {
            return Ok(());
        };
        let (Some(requests), Some(delay)) = (replacement_requests, backoff.next_backoff()) else {
            return Err(error);
        };
        warn!("UDP data channel ended: {:#}. Retry in {:?}", error, delay);
        time::sleep(delay).await;
        requests
            .send(true)
            .context("Failed to replace a UDP data channel")?;
    }
}

async fn forward_udp<S>(socket: &UdpSocket, mut conn: S, cmd: &[u8]) -> Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    conn.write_all(cmd).await?;
    conn.flush().await?;

    let mut buf = [0u8; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            // Forward inbound traffic to the client
            val = socket.recv_from(&mut buf) => {
                let (n, from) = val?;
                UdpTraffic::write_slice(&mut conn, from, &buf[..n]).await?;
            },

            // Forward outbound traffic from the client to the visitor
            hdr_len = conn.read_u8() => {
                let t = UdpTraffic::read(&mut conn, hdr_len?).await?;
                socket.send_to(&t.data, t.from).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests;
