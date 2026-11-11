use crate::config::{ClientConfig, ClientServiceConfig, Config, ServiceType, TransportType};
use crate::config_watcher::{ClientServiceChange, ConfigChange};
use crate::helper::{tcp_connect_local, udp_connect};
use crate::protocol::Hello::{self, *};
use crate::protocol::{
    self, read_ack, read_control_cmd, read_data_cmd, read_hello, Ack, Auth, ControlChannelCmd,
    DataChannelCmd, UdpTraffic, CURRENT_PROTO_VERSION,
};
use crate::transport::{AddrMaybeCached, SocketOpts, TcpTransport, Transport};
use anyhow::{anyhow, bail, Context, Result};
use backoff::ExponentialBackoff;
use backoff::{backoff::Backoff, future::retry_notify};
use bytes::Bytes;
use std::collections::{hash_map::Entry, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{self, Duration, Instant};
use tracing::{debug, error, info, instrument, warn, Instrument, Span};

#[cfg(feature = "noise")]
use crate::transport::NoiseTransport;
#[cfg(feature = "tls")]
use crate::transport::TlsTransport;
#[cfg(feature = "websocket")]
use crate::transport::WebsocketTransport;

use crate::constants::{
    run_control_chan_backoff, CONTROL_CONNECT_TIMEOUT, DATA_CONNECT_TIMEOUT, NETWORK_IO_TIMEOUT,
    UDP_BUFFER_SIZE, UDP_SENDQ_SIZE, UDP_TIMEOUT,
};

// The entrypoint of running a client
pub async fn run_client(
    config: Config,
    shutdown_rx: broadcast::Receiver<bool>,
    update_rx: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    let config = config.client.ok_or_else(|| {
        anyhow!(
        "Try to run as a client, but the configuration is missing. Please add the `[client]` block"
    )
    })?;

    match config.transport.transport_type {
        TransportType::Tcp => {
            let mut client = Client::<TcpTransport>::from(config).await?;
            client.run(shutdown_rx, update_rx).await
        }
        TransportType::Tls => {
            #[cfg(feature = "tls")]
            {
                let mut client = Client::<TlsTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "tls"))]
            crate::helper::feature_not_compile("tls")
        }
        TransportType::Noise => {
            #[cfg(feature = "noise")]
            {
                let mut client = Client::<NoiseTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "noise"))]
            crate::helper::feature_not_compile("noise")
        }
        TransportType::Websocket => {
            #[cfg(feature = "websocket")]
            {
                let mut client = Client::<WebsocketTransport>::from(config).await?;
                client.run(shutdown_rx, update_rx).await
            }
            #[cfg(not(feature = "websocket"))]
            crate::helper::feature_not_compile("websocket")
        }
    }
}

type ServiceDigest = protocol::Digest;
type Nonce = protocol::Digest;

// Holds the state of a client
struct Client<T: Transport> {
    config: ClientConfig,
    service_handles: HashMap<String, ControlChannelHandle>,
    transport: Arc<T>,
}

impl<T: 'static + Transport> Client<T> {
    // Create a Client from `[client]` config block
    async fn from(config: ClientConfig) -> Result<Client<T>> {
        let transport =
            Arc::new(T::new(&config.transport).with_context(|| "Failed to create the transport")?);
        Ok(Client {
            config,
            service_handles: HashMap::new(),
            transport,
        })
    }

    // The entrypoint of Client
    async fn run(
        &mut self,
        mut shutdown_rx: broadcast::Receiver<bool>,
        mut update_rx: mpsc::Receiver<ConfigChange>,
    ) -> Result<()> {
        for (name, config) in &self.config.services {
            // Create a control channel for each service defined
            let handle = ControlChannelHandle::new(
                (*config).clone(),
                self.config.remote_addr.clone(),
                self.transport.clone(),
                self.config.heartbeat_timeout,
            );
            self.service_handles.insert(name.clone(), handle);
        }

        // Wait for the shutdown signal
        loop {
            tokio::select! {
                val = shutdown_rx.recv() => {
                    match val {
                        Ok(_) => {}
                        Err(err) => {
                            error!("Unable to listen for shutdown signal: {}", err);
                        }
                    }
                    break;
                },
                Some(e) = update_rx.recv() => {
                    self.handle_hot_reload(e).await;
                }
            }
        }

        // Shutdown all services
        for (_, handle) in self.service_handles.drain() {
            handle.shutdown();
        }

        Ok(())
    }

    async fn handle_hot_reload(&mut self, e: ConfigChange) {
        match e {
            ConfigChange::ClientChange(client_change) => match client_change {
                ClientServiceChange::Add(cfg) => {
                    let name = cfg.name.clone();
                    let handle = ControlChannelHandle::new(
                        cfg,
                        self.config.remote_addr.clone(),
                        self.transport.clone(),
                        self.config.heartbeat_timeout,
                    );
                    let _ = self.service_handles.insert(name, handle);
                }
                ClientServiceChange::Delete(s) => {
                    let _ = self.service_handles.remove(&s);
                }
            },
            ignored => warn!("Ignored {:?} since running as a client", ignored),
        }
    }
}

struct RunDataChannelArgs<T: Transport> {
    session_key: Nonce,
    remote_addr: AddrMaybeCached,
    connector: Arc<T>,
    socket_opts: SocketOpts,
    service: ClientServiceConfig,
}

async fn do_data_channel_handshake<T: Transport>(
    args: &RunDataChannelArgs<T>,
) -> Result<T::Stream> {
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(100),
        max_interval: Duration::from_millis(100),
        max_elapsed_time: None,
        ..Default::default()
    };
    let hello = bincode::serialize(&Hello::DataChannelHello(
        CURRENT_PROTO_VERSION,
        args.session_key,
    ))?;
    let handshake = retry_notify(
        backoff,
        || async {
            time::timeout(NETWORK_IO_TIMEOUT, async {
                let mut conn = args
                    .connector
                    .connect(&args.remote_addr)
                    .await
                    .with_context(|| format!("Failed to connect to {}", &args.remote_addr))?;
                T::hint(&conn, args.socket_opts);
                conn.write_all(&hello)
                    .await
                    .context("Failed to write data Hello")?;
                conn.flush().await.context("Failed to flush data Hello")?;
                Ok(conn)
            })
            .await
            .context("Data channel handshake attempt timed out")
            .and_then(|result| result)
            .map_err(backoff::Error::transient)
        },
        |e, duration| {
            warn!("{:#}. Retry in {:?}", e, duration);
        },
    );
    time::timeout(DATA_CONNECT_TIMEOUT, handshake)
        .await
        .context("Data channel handshake retry budget expired")?
}

async fn run_data_channel<T: Transport>(
    args: Arc<RunDataChannelArgs<T>>,
    mut session_closed: broadcast::Receiver<()>,
) -> Result<()> {
    let (conn, command) = tokio::select! {
        biased;
        _ = session_closed.recv() => return Ok(()),
        result = async {
            let mut conn = do_data_channel_handshake(&args).await?;
            let command = read_data_cmd(&mut conn).await?;
            Ok::<_, anyhow::Error>((conn, command))
        } => result?,
    };

    match command {
        DataChannelCmd::StartForwardTcp => {
            if !matches!(
                args.service.service_type,
                ServiceType::Tcp | ServiceType::TcpAndUdp
            ) {
                bail!("Expect TCP traffic. Please check the configuration.")
            }
            run_data_channel_for_tcp::<T>(conn, &args.service).await?;
        }
        DataChannelCmd::StartForwardUdp => {
            if !matches!(
                args.service.service_type,
                ServiceType::Udp | ServiceType::TcpAndUdp
            ) {
                bail!("Expect UDP traffic. Please check the configuration.")
            }
            tokio::select! {
                _ = session_closed.recv() => {}
                result = run_data_channel_for_udp::<T>(conn, &args.service) => result?,
            }
        }
    }
    Ok(())
}

// Simply copying back and forth for TCP
#[instrument(skip_all, fields(local_addr = %service.local_addr))]
async fn run_data_channel_for_tcp<T: Transport>(
    mut conn: T::Stream,
    service: &ClientServiceConfig,
) -> Result<()> {
    debug!("New data channel starts forwarding");

    let mut local = tcp_connect_local(
        service.local_addr.as_str(),
        service.local_addr_if.as_deref(),
    )
    .await
    .with_context(|| {
        format!(
            "Failed to connect to {} for service {}",
            service.local_addr, service.name
        )
    })?;
    let _ = copy_bidirectional(&mut conn, &mut local).await;
    Ok(())
}

// Each UDP visitor gets its own socket to the local service.
#[instrument(skip_all, fields(local_addr = %service.local_addr))]
async fn run_data_channel_for_udp<T: Transport>(
    conn: T::Stream,
    service: &ClientServiceConfig,
) -> Result<()> {
    debug!("New data channel starts forwarding");
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpTraffic>(UDP_SENDQ_SIZE);
    let (mut rd, mut wr) = io::split(conn);

    let read = async {
        let mut port_map = HashMap::new();
        let mut forwarders = JoinSet::new();
        loop {
            let hdr_len = tokio::select! {
                biased;
                Some(result) = forwarders.join_next() => {
                    let (from, result) = result?;
                    port_map.remove(&from);
                    if let Err(error) = result {
                        debug!(%from, "UDP visitor forwarder ended: {:#}", error);
                    }
                    continue;
                }
                len = rd.read_u8() => len?,
            };
            let packet = UdpTraffic::read(&mut rd, hdr_len).await?;

            let tx = match port_map.entry(packet.from) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let connect = udp_connect(
                        service.local_addr.as_str(),
                        service.local_addr_if.as_deref(),
                    );
                    let socket = match time::timeout(NETWORK_IO_TIMEOUT, connect)
                        .await
                        .context("UDP backend connection timed out")
                        .and_then(|result| result)
                    {
                        Ok(socket) => socket,
                        Err(error) => {
                            warn!("Failed to connect to UDP backend: {:#}", error);
                            continue;
                        }
                    };
                    let (tx, rx) = mpsc::channel(UDP_SENDQ_SIZE);
                    let outbound_tx = outbound_tx.clone();
                    forwarders.spawn(async move {
                        let result = run_udp_forwarder(socket, rx, outbound_tx, packet.from).await;
                        (packet.from, result)
                    });
                    entry.insert(tx)
                }
            };
            // Drop a datagram when this visitor's queue is full or has closed.
            let _ = tx.try_send(packet.data);
        }
    };

    let write = async {
        while let Some(packet) = outbound_rx.recv().await {
            packet.write(&mut wr).await?;
        }
        Ok(())
    };

    tokio::select! {
        result = read => result,
        result = write => result,
    }
}

#[instrument(skip_all, fields(from))]
async fn run_udp_forwarder(
    socket: UdpSocket,
    mut inbound_rx: mpsc::Receiver<Bytes>,
    outbound_tx: mpsc::Sender<UdpTraffic>,
    from: SocketAddr,
) -> Result<()> {
    let mut buf = [0; UDP_BUFFER_SIZE];
    loop {
        tokio::select! {
            data = inbound_rx.recv() => {
                let Some(data) = data else { break };
                time::timeout(NETWORK_IO_TIMEOUT, socket.send(&data))
                    .await
                    .context("UDP backend send timed out")??;
            },
            result = socket.recv(&mut buf) => {
                let len = result?;
                let packet = UdpTraffic {
                    from,
                    data: Bytes::copy_from_slice(&buf[..len]),
                };
                // UDP replies can be dropped under backpressure.
                if let Err(mpsc::error::TrySendError::Closed(_)) = outbound_tx.try_send(packet) {
                    break;
                }
            },
            _ = time::sleep(Duration::from_secs(UDP_TIMEOUT)) => break,
        }
    }
    Ok(())
}

// Control channel, using T as the transport layer
struct ControlChannel<T: Transport> {
    digest: ServiceDigest,        // SHA256 of the service name
    service: ClientServiceConfig, // `[client.services.foo]` config block
    remote_addr: String,          // `client.remote_addr`
    transport: Arc<T>,            // Wrapper around the transport layer
    heartbeat_timeout: u64,       // Application layer heartbeat timeout in secs
}

// Handle of a control channel
// Dropping it will also drop the actual control channel
struct ControlChannelHandle {
    shutdown_tx: oneshot::Sender<u8>,
}

impl<T: 'static + Transport> ControlChannel<T> {
    async fn handshake(&self) -> Result<(T::Stream, RunDataChannelArgs<T>)> {
        let mut remote_addr = AddrMaybeCached::new(&self.remote_addr);
        remote_addr.resolve().await?;

        let mut conn = self
            .transport
            .connect(&remote_addr)
            .await
            .with_context(|| format!("Failed to connect to {}", &self.remote_addr))?;
        T::hint(&conn, SocketOpts::for_control_channel());

        // Send hello
        debug!("Sending hello");
        let hello_send = Hello::ControlChannelHello(CURRENT_PROTO_VERSION, self.digest);
        conn.write_all(&bincode::serialize(&hello_send).unwrap())
            .await?;
        conn.flush().await?;

        // Read hello
        debug!("Reading hello");
        let nonce = match read_hello(&mut conn).await? {
            ControlChannelHello(_, d) => d,
            _ => {
                bail!("Unexpected type of hello");
            }
        };

        // Send auth
        debug!("Sending auth");
        let mut concat = Vec::from(self.service.token.as_ref().unwrap().as_bytes());
        concat.extend_from_slice(&nonce);

        let session_key = protocol::digest(&concat);
        let auth = Auth(session_key);
        conn.write_all(&bincode::serialize(&auth).unwrap()).await?;
        conn.flush().await?;

        // Read ack
        debug!("Reading ack");
        match read_ack(&mut conn).await? {
            Ack::Ok => {}
            v => {
                return Err(anyhow!("{}", v))
                    .with_context(|| format!("Authentication failed: {}", self.service.name));
            }
        }

        // Socket options for the data channel
        let socket_opts = SocketOpts::from_client_cfg(&self.service);
        let args = RunDataChannelArgs {
            session_key,
            remote_addr,
            connector: self.transport.clone(),
            socket_opts,
            service: self.service.clone(),
        };
        Ok((conn, args))
    }

    #[instrument(skip_all)]
    async fn run(&self) -> Result<()> {
        let (mut conn, data_ch_args) = time::timeout(CONTROL_CONNECT_TIMEOUT, self.handshake())
            .await
            .context("Control channel handshake timed out")??;
        info!("Control channel established");
        let data_ch_args = Arc::new(data_ch_args);
        // Dropping the sender cancels data channels that are still being set up.
        let (session_open, _) = broadcast::channel(1);

        loop {
            tokio::select! {
                val = read_control_cmd(&mut conn) => {
                    let val = val?;
                    debug!( "Received {:?}", val);
                    match val {
                        ControlChannelCmd::CreateDataChannel => {
                            let args = data_ch_args.clone();
                            let session_closed = session_open.subscribe();
                            tokio::spawn(async move {
                                if let Err(e) = run_data_channel(args, session_closed).await.context("Failed to run the data channel") {
                                    warn!("{:#}", e);
                                }
                            }.instrument(Span::current()));
                        },
                        ControlChannelCmd::HeartBeat => ()
                    }
                },
                _ = time::sleep(Duration::from_secs(self.heartbeat_timeout)), if self.heartbeat_timeout != 0 => {
                    return Err(anyhow!("Heartbeat timed out"))
                }
            }
        }
    }
}

impl ControlChannelHandle {
    #[instrument(name="handle", skip_all, fields(service = %service.name))]
    fn new<T: 'static + Transport>(
        service: ClientServiceConfig,
        remote_addr: String,
        transport: Arc<T>,
        heartbeat_timeout: u64,
    ) -> ControlChannelHandle {
        let digest = protocol::digest(service.name.as_bytes());

        info!("Starting {}", hex::encode(digest));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let mut retry_backoff = run_control_chan_backoff(service.retry_interval.unwrap());

        let channel = ControlChannel {
            digest,
            service,
            remote_addr,
            transport,
            heartbeat_timeout,
        };

        tokio::spawn(
            async move {
                loop {
                    let start = Instant::now();
                    let result = tokio::select! {
                        biased;
                        _ = &mut shutdown_rx => break,
                        result = channel.run() => result,
                    };
                    let Err(err) = result.context("Failed to run the control channel") else {
                        break;
                    };
                    if start.elapsed() > Duration::from_secs(3) {
                        // The client runs for at least 3 secs and then disconnects
                        retry_backoff.reset();
                    }

                    let Some(duration) = retry_backoff.next_backoff() else {
                        error!("{:#}. Control channel retries exhausted", err);
                        break;
                    };
                    error!("{:#}. Retry in {:?}...", err, duration);
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        _ = time::sleep(duration) => {}
                    }
                }
                info!("Control channel shutdown");
            }
            .instrument(Span::current()),
        );

        ControlChannelHandle { shutdown_tx }
    }

    fn shutdown(self) {
        // A send failure shows that the actor has already shutdown.
        let _ = self.shutdown_tx.send(0u8);
    }
}

#[cfg(test)]
mod tests;
