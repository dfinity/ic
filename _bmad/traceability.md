# Traceability Matrix

Last updated: 2026-04-01 (Phase 3: test linkage in progress)
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
| REQ-SCHED-001 | Round structure phases | linked | SCENARIO-SCHED-001,002,003 | scheduler/tests/scheduling.rs |
| REQ-SCHED-002 | Inner round iterations | linked | SCENARIO-SCHED-004,005 | scheduler/tests/scheduling.rs |
| REQ-SCHED-003 | Canister ordering | linked | SCENARIO-SCHED-006,007,008,009 | scheduling.rs, timers.rs, rate_limiting.rs |
| REQ-SCHED-004 | Long-running / DTS | linked | SCENARIO-SCHED-010,011,012 | scheduler/tests/dts.rs |
| REQ-SCHED-005 | Subnet messages | linked | SCENARIO-SCHED-013,014 | scheduler/tests/subnet_messages.rs |
| REQ-SCHED-006 | Message induction | linked | SCENARIO-SCHED-015 | scheduler/tests/routing.rs |
| REQ-SCHED-007 | Heap delta | linked | SCENARIO-SCHED-016,017,018 | scheduler/tests/rate_limiting.rs |
| REQ-SCHED-008 | Ingress lifecycle | narrative | SCENARIO-SCHED-019,020 | scheduler/tests/ |
| REQ-SCHED-009 | Idle charging | narrative | SCENARIO-SCHED-021 | scheduler/tests/ |

---

## execution-canister-lifecycle
| REQ-EXEC-001 through REQ-EXEC-007 | Canister lifecycle | narrative | canister_manager/tests.rs |
| SCENARIO-EXEC-001 through SCENARIO-EXEC-031 | 31 scenarios | narrative | canister_manager/tests.rs |

## execution-cycles
| REQ-CYC-001 through REQ-CYC-018 | Cycles accounting | linked | rs/cycles_account_manager/ |
| SCENARIO-CYC-001 through SCENARIO-CYC-042 | 42 scenarios | linked | tests/cycles_account_manager.rs |

## execution-dts
| REQ-DTS-001 through REQ-DTS-008 | Deterministic Time Slicing | linked | execution_test.rs |
| SCENARIO-DTS-001 through SCENARIO-DTS-021 | 21 scenarios | linked | scheduler/tests/dts.rs |

## execution-wasm
| REQ-WASM-001 through REQ-WASM-006 | Wasm execution | narrative | rs/embedders/tests/ |
| SCENARIO-WASM-001 through SCENARIO-WASM-028 | 28 scenarios | narrative | rs/embedders/tests/ |

## execution-canister-lifecycle
| REQ-EXEC-001 through REQ-EXEC-007 | Canister lifecycle | linked | execution_test.rs, canister_settings.rs, canister_snapshots.rs |

## execution-system-api
| REQ-SYSAPI-001 through REQ-SYSAPI-013 | System API | linked | rs/execution_environment/tests/hypervisor.rs |
| SCENARIO-SYSAPI-001 through SCENARIO-SYSAPI-031 | 31 scenarios | linked | hypervisor.rs |

## execution-memory
| REQ-MEM-001 through REQ-MEM-006 | Memory management | linked | rs/execution_environment/tests/ |
| SCENARIO-MEM-001 through SCENARIO-MEM-025 | 25 scenarios | linked | hypervisor.rs, storage_reservation.rs |

## messaging
| REQ-MSG-001 through REQ-MSG-006 | Message routing | linked | rs/messaging/tests/ |
| SCENARIO-MSG-001 through SCENARIO-MSG-022 | 22 scenarios | linked | rs/messaging/tests/messaging.rs |

## networking-https-outcalls
| REQ-HTTPS-001 through REQ-HTTPS-005 | HTTPS outcalls | linked | rs/https_outcalls/consensus/ |
| SCENARIO-HTTPS-001 through SCENARIO-HTTPS-016 | 16 scenarios | linked | payload_builder/tests.rs, pool_manager.rs |

## state-manager
| REQ-STMGR-001 through REQ-STMGR-009 | State manager | linked | rs/state_manager/tests/ |
| SCENARIO-STMGR-001 through SCENARIO-STMGR-028 | 28 scenarios | linked | state_manager/tests/state_manager.rs |

## consensus
| REQ-CONS-001 through REQ-CONS-010 | Consensus | linked | rs/consensus/tests/ |
| SCENARIO-CONS-001 through SCENARIO-CONS-022 | 22 scenarios | linked | consensus/tests/integration.rs |

## governance-nns
| REQ-NNS-001 through REQ-NNS-008 | NNS governance | linked | rs/nns/governance/tests/ |
| SCENARIO-NNS-001 through SCENARIO-NNS-016 | 16 scenarios | linked | governance/tests/governance.rs |

## ledger-icp
| REQ-ICP-001 through REQ-ICP-006 | ICP ledger | linked | rs/ledger_suite/icp/ |
| SCENARIO-ICP-001 through SCENARIO-ICP-012 | 12 scenarios | linked | ledger_suite/icp/ledger/src/tests.rs |

## ledger-icrc
| REQ-ICRC-001 through REQ-ICRC-005 | ICRC standards | linked | rs/ledger_suite/icrc1/ |
| SCENARIO-ICRC-001 through SCENARIO-ICRC-011 | 11 scenarios | linked | ledger_suite/icrc1/ledger/src/tests.rs |

## crypto-signatures
| REQ-SIG-001 through REQ-SIG-006 | Crypto signatures | linked | rs/crypto/tests/ |
| SCENARIO-SIG-001 through SCENARIO-SIG-012 | 12 scenarios | linked | crypto/tests/integration_test.rs |

## crypto-dkg
| REQ-DKG-001 through REQ-DKG-008 | DKG | linked | rs/crypto/tests/ |
| SCENARIO-DKG-001 through SCENARIO-DKG-014 | 14 scenarios | linked | crypto/tests/integration_test.rs |

## crypto-threshold
| REQ-THRESH-001 through REQ-THRESH-006 | Threshold signatures | linked | rs/crypto/tests/ |
| SCENARIO-THRESH-001 through SCENARIO-THRESH-013 | 13 scenarios | linked | crypto/tests/integration_test.rs |

## registry
| REQ-REG-001 through REQ-REG-003 | Registry | linked | rs/registry/canister/tests/ |
| SCENARIO-REG-001 through SCENARIO-REG-012 | 12 scenarios | linked | registry/canister/tests/integration_tests_3.rs |

## ingress-manager
| REQ-ING-001 through REQ-ING-004 | Ingress manager | linked | rs/ingress_manager/ |
| SCENARIO-ING-001 through SCENARIO-ING-022 | 22 scenarios | linked | rs/ingress_manager/src/ingress_selector.rs |

---

## Domains Still Needing Test Linkage (Phase 3 remaining)

| Domain | REQ Prefix | Status | Notes |
|--------|------------|--------|-------|
| execution-wasm | REQ-WASM-* | narrative | rs/embedders/tests/ not yet linked |
| execution-query | REQ-QUERY-* | narrative | rs/execution_environment/ query tests |
| execution-sandboxing | REQ-SAND-* | narrative | rs/canister_sandbox/ |
| networking-p2p | REQ-P2P-* | narrative | rs/transport/tests/ |
| networking-xnet | REQ-XNET-* | narrative | rs/xnet/tests/ |
| state-replicated | REQ-STATE-* | narrative | rs/replicated_state/tests/ |
| state-checkpoint | REQ-CKPT-* | narrative | rs/state_manager/src/checkpoint.rs |
| state-certification | REQ-CERT-* | narrative | rs/certification/tests/ |
| governance-sns | REQ-SNS-* | narrative | rs/sns/governance/tests/ |
| boundary-node | REQ-BN-* | narrative | rs/boundary_node/ic_boundary/tests/ |
| query-stats | REQ-QS-* | narrative | rs/query_stats/tests/ |
| pocket-ic-server | REQ-PIC-* | narrative | rs/pocket_ic_server/tests/ |
