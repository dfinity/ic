# E2E Test Plan

Maps SCENARIO-* identifiers to end-to-end test procedures.

## Format

Each entry specifies:
- **SCENARIO ID**: The SCENARIO-* being tested
- **Environment**: Required test infrastructure (local replica, PocketIC, testnet)
- **Prerequisites**: State setup needed before the test
- **Procedure**: Steps to execute
- **Expected Result**: What success looks like
- **Automation**: Link to automated test if available

---

## Execution Domain

### SCENARIO-SCHED-001: Round execution phases
- **Environment**: PocketIC or state_machine_tests
- **Prerequisites**: Canister installed with pending messages
- **Procedure**: Execute one round, verify phase ordering via metrics
- **Expected Result**: Phases execute in defined order (prep → consensus drain → heap check → raw_rand → install_code → inner round → finalization)
- **Automation**: `rs/execution_environment/src/scheduler/tests/scheduling.rs`

### SCENARIO-EXEC-008: Upgrade mode stages
- **Environment**: state_machine_tests
- **Prerequisites**: Canister installed with pre_upgrade/post_upgrade hooks
- **Procedure**: Call install_code with mode=upgrade, verify stage execution order
- **Expected Result**: validate → pre_upgrade → new state → start → post_upgrade
- **Automation**: `rs/execution_environment/tests/execution_test.rs`

### SCENARIO-DTS-015: Upgrade with DTS across stages
- **Environment**: state_machine_tests with DTS enabled
- **Prerequisites**: Large canister requiring multi-round upgrade
- **Procedure**: Trigger upgrade, verify execution spans multiple rounds
- **Expected Result**: State machine transitions: PausedPreUpgrade → PausedStart → PausedPostUpgrade
- **Automation**: `rs/execution_environment/tests/dts.rs`

---

## Consensus Domain

### SCENARIO-CONS-019: Finalization conditions
- **Environment**: consensus integration test framework
- **Prerequisites**: Multi-node test with notarization
- **Procedure**: Verify finalization only occurs with single notarized block and no conflicting shares
- **Expected Result**: Finalization share produced only under strict safety conditions
- **Automation**: `rs/consensus/tests/integration.rs`

---

## Governance Domain

### SCENARIO-NNS-008: Wait For Quiet deadline extension
- **Environment**: state_machine_tests or PocketIC
- **Prerequisites**: NNS governance canister with neurons
- **Procedure**: Submit proposal, cast vote that flips majority, verify deadline extension
- **Expected Result**: Deadline extended by up to WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS (2 days)
- **Automation**: `rs/nns/governance/tests/governance.rs`

---

## Additional scenarios to be mapped as Phase 4 (missing test coverage) progresses.
