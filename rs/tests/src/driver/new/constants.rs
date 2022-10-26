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

// Name of the tests directory within the group directory.
pub const TESTS_DIR: &str = "tests";

// Name of the group setup directory within the working directory.
pub const GROUP_SETUP_DIR: &str = "setup";

// Name of the root test environment.
pub const ROOT_ENV_DIR: &str = "root_env";

pub const DEFAULT_FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub const ASYNC_LOG_CHANNEL_SIZE: usize = 8192;
