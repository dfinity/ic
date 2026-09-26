use tokio::time::Duration;

pub const DEFAULT_DECIMAL_PLACES: u8 = 8;
pub const DEFAULT_TOKEN_SYMBOL: &str = "ICP";
pub const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);
pub const NUM_TRIES: u64 = 1000;
/// Total wall-clock budget for starting Rosetta, across all attempts. It
/// bounds the time a test can spend in `start_rosetta` well below the 900 s
/// bazel timeout of a `large` test, so that a Rosetta that never becomes
/// ready fails the test with a message instead of letting bazel kill the test
/// binary (which also discards the captured output of all other tests).
/// A healthy start takes well under a second.
pub const START_TIMEOUT: Duration = Duration::from_secs(120);
/// How often starting Rosetta is attempted (within `START_TIMEOUT`) when it
/// exits before becoming ready. Rosetta exits when the ledger is unreachable
/// during its initialization, which happens when the (PocketIC) replica is
/// temporarily unresponsive.
pub const MAX_START_ATTEMPTS: u32 = 10;
/// How long to wait between two attempts to start Rosetta.
pub const WAIT_BETWEEN_START_ATTEMPTS: Duration = Duration::from_secs(1);
