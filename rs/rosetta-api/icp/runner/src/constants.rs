use tokio::time::Duration;

pub const DEFAULT_DECIMAL_PLACES: u8 = 8;
pub const DEFAULT_TOKEN_SYMBOL: &str = "ICP";
pub const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);
/// Maximum number of retries when waiting for Rosetta to start.
/// With WAIT_BETWEEN_ATTEMPTS of 100ms, this gives a 100 second timeout.
pub const NUM_TRIES: u64 = 1000;
