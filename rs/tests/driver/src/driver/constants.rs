use std::time::Duration;

#[allow(clippy::doc_overindented_list_items)]
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
///   |- journald_logs/          <-- journald records persisted by logs_stream_task
///      |- nodes/<node_id>.jsonl   (scanned by assert_no_unallowed_log_patterns on the local backend)
///      |- uvms/<vm_name>.jsonl
///   |- local_backend/          <-- local backend state (VM disks, consoles, sockets)
///
/// Only the `*_env`/`setup`/`tests/<test>` directories are test environments
/// (and get copied on fork); `journald_logs/` and `local_backend/` are siblings
/// that are never copied.
///
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

fn node_logs(infra_group_name: &str) -> String {
    format!(
        "/app/discover#/?_g=(time:(from:now-1y,to:now))&_a=(columns:!(host.name,message,level),filters:!(('$state':(store:appState),query:(match_phrase:(tags:{infra_group_name})))),grid:(columns:(host.name:(width:513))),index:'535335e8-7195-4af7-95ab-e59ab3bb8056',interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))"
    )
}
const KIBANA_BASE_URL: &str = "https://kibana.testnet.dfinity.network";

pub fn kibana_link(infra_group_name: &str) -> String {
    format!("{}{}", KIBANA_BASE_URL, node_logs(infra_group_name))
}

pub const PANIC_LOG_PREFIX: &str = "[Function panicked]: ";
pub const SUBREPORT_LOG_PREFIX: &str = "[SubReport]: ";

pub const COLOCATE_CONTAINER_NAME: &str = "system_test";
