// Constants used in the test-driver.

pub const N_THREADS_PER_SUITE: usize = 8;
pub const N_THREADS_PER_POT: usize = 8;
// File that describes the expectations of the test suite execution.
// Namely, it defines, which suite/pots/tests are expected to be executed/skipped.
pub const TEST_SUITE_CONTRACT_FILE: &str = "suite_execution_contract.json";
// Each test after execution dumps this result file, which contains the test info Passed/Failed(Message)/Skipped.
pub const TEST_RESULT_FILE: &str = "test_execution_result.json";
pub const TEST_SUITE_RESULT_FILE: &str = "test-results.json";
// Name of the system environment directory.
pub const SYSTEM_ENV_DIR: &str = "system_env";
