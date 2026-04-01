# Project Status

Last updated: 2026-04-01

## Current Phase: 1 — BMAD Bootstrap

## What's Done
- _bmad/ bootstrapped (prd.md, architecture.md, traceability.md)
- .harness/ scaffolded (config.yaml, generator/evaluator prompts)
- ops/ tracking created
- **11 domains migrated to capability specs:**
  - execution-scheduler: 9 REQs, 21 SCENARIOs
  - execution-canister-lifecycle: 7 REQs, 31 SCENARIOs
  - execution-cycles: 18 REQs, 42 SCENARIOs
  - execution-dts: 8 REQs, 21 SCENARIOs
  - execution-wasm: 6 REQs, 28 SCENARIOs
  - execution-system-api: 13 REQs, 31 SCENARIOs
  - execution-memory: 6 REQs, 25 SCENARIOs
  - messaging: 6 REQs, 22 SCENARIOs
  - networking-https-outcalls: 5 REQs, 16 SCENARIOs
  - state-manager: 9 REQs, 28 SCENARIOs
  - ingress-manager: 4 REQs, 22 SCENARIOs

## What's Next
1. consensus (large — 37KB spec)
2. state-management/replicated-state.md
3. state-management/checkpoint.md, certification.md
4. crypto/signatures.md, dkg.md, canister_threshold_signatures.md
5. networking/p2p.md, xnet.md
6. governance/nns-governance.md, sns/
7. ledger/icp-ledger.md, icrc-standards.md
8. registry/spec.md, boundary-node/spec.md

## Metrics
- Domains with capability specs: 28 / 28 (100%)
- Total REQs: ~185
- Total SCENARIOs: ~530
- REQs with tests linked: 0 (phase 3 work)

## Phase 2 Complete
All 28 domains migrated to REQ-*/SCENARIO-* capability specs.

## Phase 3: Link Tests to REQ-* IDs (In Progress)

### Linked so far
- `rs/execution_environment/src/scheduler/tests/scheduling.rs` → REQ-SCHED-001,002,003,009
- `rs/execution_environment/src/scheduler/tests/dts.rs` → REQ-DTS-001,004,005,007,008
- `rs/execution_environment/src/scheduler/tests/charging.rs` → REQ-SCHED-009, REQ-CYC-003,007,018
- `rs/execution_environment/src/scheduler/tests/rate_limiting.rs` → REQ-SCHED-003,007
- `rs/execution_environment/src/scheduler/tests/subnet_messages.rs` → REQ-SCHED-005
- `rs/execution_environment/src/scheduler/tests/routing.rs` → REQ-SCHED-006
- `rs/execution_environment/src/scheduler/tests/timers.rs` → REQ-SCHED-003, REQ-SYSAPI-006
- `rs/cycles_account_manager/tests/cycles_account_manager.rs` → REQ-CYC-001 through 016
- `rs/messaging/tests/messaging.rs` → REQ-MSG-001 through 005
- `rs/ingress_manager/src/ingress_selector.rs` → REQ-ING-002,003

- `rs/execution_environment/tests/execution_test.rs` → REQ-EXEC-*, REQ-WASM-*
- `rs/execution_environment/tests/dts.rs` → REQ-DTS-002,003,004,006
- `rs/execution_environment/tests/canister_settings.rs` → REQ-EXEC-006
- `rs/execution_environment/tests/canister_snapshots.rs` → REQ-STATE-007, REQ-EXEC-007
- `rs/execution_environment/tests/storage_reservation.rs` → REQ-CYC-008, REQ-MEM-003
- `rs/execution_environment/tests/hypervisor.rs` → REQ-WASM-001,003,004, REQ-SYSAPI-*, REQ-MEM-001,002
- `rs/state_manager/tests/state_manager.rs` → REQ-STMGR-001..007, REQ-CKPT-001,003
- `rs/https_outcalls/consensus/src/payload_builder/tests.rs` → REQ-HTTPS-003
- `rs/https_outcalls/consensus/src/pool_manager.rs` → REQ-HTTPS-004
- `rs/consensus/tests/integration.rs` → REQ-CONS-001..005,010
- `rs/nns/governance/tests/governance.rs` → REQ-NNS-003..008
- `rs/ledger_suite/icp/ledger/src/tests.rs` → REQ-ICP-001..006
- `rs/ledger_suite/icrc1/ledger/src/tests.rs` → REQ-ICRC-001..004
- `rs/crypto/tests/integration_test.rs` → REQ-SIG-*, REQ-DKG-001,004, REQ-THRESH-002,005
- `rs/registry/canister/tests/integration_tests_3.rs` → REQ-REG-001..003

- `rs/embedders/tests/misc_tests.rs` → REQ-WASM-001,002
- `rs/replicated_state/tests/replicated_state.rs` → REQ-STATE-003,004,005,008
- `rs/sns/governance/tests/governance.rs` → REQ-SNS-002..006
- `rs/xnet/payload_builder/src/tests.rs` → REQ-XNET-002
- `rs/query_stats/src/payload_builder.rs` → REQ-QS-003,004
- `rs/certification/src/tests.rs` → REQ-CERT-001,002,004

- `rs/execution_environment/src/query_handler/query_cache.rs` → REQ-WASM-004, REQ-SYSAPI-005
- `rs/canister_sandbox/src/dts/tests.rs` → REQ-DTS-003,004, REQ-WASM-003
- `rs/state_manager/src/checkpoint.rs` → REQ-CKPT-001..005
- `rs/boundary_node/ic_boundary/src/core.rs` → REQ-BN-001..004
- `rs/pocket_ic_server/tests/test.rs` → REQ-PIC-001..007

### Phase 3 COMPLETE: All 28/28 domains have test linkage
