# Traceability Matrix

Last updated: 2026-04-01
Methodology: https://github.com/ianblenke/agentic-refactor-rules

## Status Legend
- `not-started` — no capability spec exists yet (narrative only)
- `narrative` — spec migrated to REQ-*/SCENARIO-* format, not yet linked in tests
- `linked` — test files reference REQ-* IDs
- `verified` — Evaluator agent independently confirmed coverage

---

## execution-scheduler

| REQ ID | Description | Status | Scenarios | Test Files |
|--------|-------------|--------|-----------|-----------|
| REQ-SCHED-001 | Round structure phases | narrative | SCENARIO-SCHED-001,002,003 | scheduler/tests/ |
| REQ-SCHED-002 | Inner round iterations | narrative | SCENARIO-SCHED-004,005 | scheduler/tests/scheduling.rs |
| REQ-SCHED-003 | Canister ordering | narrative | SCENARIO-SCHED-006,007,008,009 | scheduler/tests/scheduling.rs |
| REQ-SCHED-004 | Long-running / DTS | narrative | SCENARIO-SCHED-010,011,012 | execution_test.rs |
| REQ-SCHED-005 | Subnet messages | narrative | SCENARIO-SCHED-013,014 | scheduler/tests/ |
| REQ-SCHED-006 | Message induction | narrative | SCENARIO-SCHED-015 | messaging/tests/ |
| REQ-SCHED-007 | Heap delta | narrative | SCENARIO-SCHED-016,017,018 | scheduler/tests/ |
| REQ-SCHED-008 | Ingress lifecycle | narrative | SCENARIO-SCHED-019,020 | scheduler/tests/ |
| REQ-SCHED-009 | Idle charging | narrative | SCENARIO-SCHED-021 | scheduler/tests/ |

---

## Domains Pending Migration (27 remaining)

| Domain | Narrative Spec | REQ Prefix | Priority |
|--------|----------------|------------|----------|
| execution-canister-lifecycle | execution/canister-lifecycle.md | REQ-EXEC-* | high |
| execution-cycles | execution/cycles.md | REQ-CYC-* | high |
| execution-dts | execution/deterministic-time-slicing.md | REQ-DTS-* | high |
| execution-wasm | execution/wasm-execution.md | REQ-WASM-* | high |
| execution-system-api | execution/system-api.md | REQ-SYSAPI-* | high |
| execution-memory | execution/memory-management.md | REQ-MEM-* | high |
| execution-query | execution/query-execution.md | REQ-QUERY-* | high |
| execution-sandboxing | execution/canister-sandboxing.md | REQ-SAND-* | medium |
| consensus | consensus/spec.md | REQ-CONS-* | high |
| messaging | messaging/spec.md | REQ-MSG-* | high |
| networking-p2p | networking/p2p.md | REQ-P2P-* | medium |
| networking-https-outcalls | networking/https-outcalls.md | REQ-HTTPS-* | high |
| networking-xnet | networking/xnet.md | REQ-XNET-* | medium |
| state-replicated | state-management/replicated-state.md | REQ-STATE-* | high |
| state-manager | state-management/state-manager.md | REQ-STMGR-* | high |
| state-checkpoint | state-management/checkpoint.md | REQ-CKPT-* | high |
| state-certification | state-management/certification.md | REQ-CERT-* | high |
| crypto-signatures | crypto/signatures.md | REQ-SIG-* | high |
| crypto-dkg | crypto/dkg.md | REQ-DKG-* | high |
| crypto-threshold | crypto/canister_threshold_signatures.md | REQ-THRESH-* | high |
| governance-nns | governance/nns-governance.md | REQ-NNS-* | medium |
| governance-sns | governance/sns/ | REQ-SNS-* | medium |
| ledger-icp | ledger/icp-ledger.md | REQ-ICP-* | medium |
| ledger-icrc | ledger/icrc-standards.md | REQ-ICRC-* | medium |
| registry | registry/spec.md | REQ-REG-* | medium |
| ingress-manager | ingress-manager/spec.md | REQ-ING-* | medium |
| boundary-node | boundary-node/spec.md | REQ-BN-* | medium |
