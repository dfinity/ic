/// New directory structure:
///
/// - group_dir
///   |- setup                 <-- test_env
///      |- ic_prep
///      |- test.log           <-- prefix
///   |- tests
///      |- basic_health_test  <-- test_env
///         |- ic_prep
///         |- test.log        <-- prefix :: log1
///      |- other_test         <-- test_env
///         |- ic_prep
///         |- test.log        <-- prefix :: log2

// Name of the tests directory within the group directory.
pub const TESTS_DIR: &str = "tests";

// Name of the group setup directory within the working directory.
pub const GROUP_SETUP_DIR: &str = "setup";

pub const DEFAULT_FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub const ASYNC_LOG_CHANNEL_SIZE: usize = 8192;
