// Constants used in the test-driver.

pub const N_THREADS_PER_SUITE: usize = 8;
pub const N_THREADS_PER_POT: usize = 8;
// File containing info about the nodes.
// In particular, one can find whether some node has malicious behavior.
pub const NODES_INFO: &str = "nodes_info.json";
// File that describes the expectations of the test suite execution.
// Namely, it defines, which suite/pots/tests are expected to be executed/skipped.
pub const TEST_SUITE_CONTRACT_FILE: &str = "suite_execution_contract.json";
// Each test after execution dumps this result file, which contains the test info Passed/Failed(Message)/Skipped.
pub const TEST_RESULT_FILE: &str = "test_execution_result.json";
// Each pot setup evaluation dumps this file, which contains setup info Passed/Failed(Message).
pub const POT_SETUP_RESULT_FILE: &str = "pot_setup_result.json";
// File containing the final summary of the suite execution.
pub const TEST_SUITE_RESULT_FILE: &str = "test-results.json";
// File containing slack alert messages for the failed pots.
pub const SLACK_FAILURE_ALERTS_FILE: &str = "slack_alerts.json";
// Name of the system environment directory with a working directory.
pub const SYSTEM_ENV_DIR: &str = "system_env";
// Name of the tests directory within the pot directory.
pub const TESTS_DIR: &str = "tests";
// Name of the pot setup directory within the working directory.
pub const POT_SETUP_DIR: &str = "setup";
// Test owner channels
pub const TEST_FAILURE_CHANNEL: &str = "test-failure-alerts";
pub const ENG_TESTING_CHANNEL: &str = "eng-testing";
pub const ENG_CONSENSUS_CHANNEL: &str = "eng-consensus-test-failures";
pub const ENG_ORCHESTRATOR_CHANNEL: &str = "eng-orchestrator-test-failures";
pub const ENG_NODE_CHANNEL: &str = "eng-node";
pub const ENG_FINANCIAL_INTEGRATION: &str = "eng-financial-integration";
