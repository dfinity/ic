use std::time::Duration;

/// New directory structure:
///
/// - dependencies/
///   |- A
///   |- B
///
/// - group_dir/
///   |- root_env/               <-- the root test environment
///      |- dependencies:symlink
///   |- setup/                  <-- test_env
///      |- ic_prep
///      |- test.log             <-- prefix
///   |- tests/
///      |- basic_health_test/   <-- test_env
///         |- ic_prep
///         |- test.log          <-- prefix :: log1
///      |- other_test/          <-- test_env
///         |- ic_prep
///         |- test.log          <-- prefix :: log2
///   |- tear_down/
///         |- ic_prep
///         |- test.log          <-- prefix :: finalization_log
/// Username for the ssh session.
pub const SSH_USERNAME: &str = "admin";
// Name of the network interfaces on the Node.
pub const DEVICE_NAME: &str = "enp1s0";
// Name of the tests directory within the group directory.
pub const TESTS_DIR: &str = "tests";

// Name of the group setup directory within the working directory.
pub const GROUP_SETUP_DIR: &str = "setup";

// Name of the root test environment.
pub const ROOT_ENV_DIR: &str = "root_env";

pub const DEFAULT_FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub const ASYNC_LOG_CHANNEL_SIZE: usize = 8192;

pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const GROUP_TTL: Duration = Duration::from_secs(90);

pub const LOG_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

fn node_logs(farm_group_name: &str) -> String {
    format!("/app/kibana#/discover?_g=(time:(from:now-1y,to:now))&_a=(columns:!(_source),index:c8cf8e20-593f-11ec-9f11-0fb8445c6897,interval:auto,query:(language:kuery,query:'tags:%22{}%22'),sort:!(!('@timestamp',desc)))", farm_group_name)
}
const KIBANA_BASE_URL: &str = "https://kibana.testnet.dfinity.network";

pub fn kibana_link(farm_group_name: &str) -> String {
    format!("{}{}", KIBANA_BASE_URL, node_logs(farm_group_name))
}

pub const PANIC_LOG_PREFIX: &str = "[Function panicked]: ";
pub const SUBREPORT_LOG_PREFIX: &str = "[SubReport]: ";
