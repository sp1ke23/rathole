use backoff::ExponentialBackoff;
use std::time::Duration;

// FIXME: Determine reasonable size
/// UDP MTU. Currently far larger than necessary
pub const UDP_BUFFER_SIZE: usize = 2048;
pub const UDP_SENDQ_SIZE: usize = 1024;
pub const UDP_TIMEOUT: u64 = 60;
pub const NETWORK_IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "client")]
pub const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "client")]
pub const DATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "server")]
pub const DATA_REQUEST_RETRY: Duration = Duration::from_secs(10);

pub fn listen_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: None,
        max_interval: Duration::from_secs(1),
        ..Default::default()
    }
}

pub fn run_control_chan_backoff(interval: u64) -> ExponentialBackoff {
    ExponentialBackoff {
        randomization_factor: 0.2,
        max_elapsed_time: None,
        multiplier: 3.0,
        max_interval: Duration::from_secs(interval),
        ..Default::default()
    }
}
