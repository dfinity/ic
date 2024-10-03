use tokio::time::Duration;

pub const DEFAULT_DECIMAL_PLACES: u8 = 8;
pub const DEFAULT_TOKEN_SYMBOL: &str = "ICP";
pub const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);
pub const NUM_TRIES: u64 = 1000;
