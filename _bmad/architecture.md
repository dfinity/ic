# IC Architecture Overview

Last Reconciled: 2026-04-01

## System Layers

```
┌─────────────────────────────────────────┐
│  Governance Layer                       │
│  NNS, SNS, CMC, Ledger, Rosetta        │
├─────────────────────────────────────────┤
│  Execution Layer                        │
│  Scheduler, ExecutionEnvironment,       │
│  Hypervisor, CanisterManager, DTS       │
├─────────────────────────────────────────┤
│  Messaging Layer                        │
│  MessageRouting, IngressManager,        │
│  HttpOutcalls, XNet, P2P                │
├─────────────────────────────────────────┤
│  Consensus Layer                        │
│  IC Consensus, tECDSA, DKG              │
├─────────────────────────────────────────┤
│  State Management Layer                 │
│  ReplicatedState, StateManager,         │
│  Checkpoint, PageMap, Certification     │
├─────────────────────────────────────────┤
│  Infrastructure Layer                   │
│  IC-OS, Replica, Orchestrator,          │
│  Registry, Crypto, Networking           │
└─────────────────────────────────────────┘
```

## Domain → Spec Mapping

| Domain | Spec Directory | REQ-* Prefix | Status |
|--------|----------------|--------------|--------|
| execution-scheduler | openspec/capabilities/execution-scheduler/ | REQ-SCHED-* | migrated |
| execution-canister-lifecycle | openspec/specs/execution/canister-lifecycle.md | — | narrative |
| execution-cycles | openspec/specs/execution/cycles.md | — | narrative |
| execution-dts | openspec/specs/execution/deterministic-time-slicing.md | — | narrative |
| execution-wasm | openspec/specs/execution/wasm-execution.md | — | narrative |
| execution-system-api | openspec/specs/execution/system-api.md | — | narrative |
| consensus | openspec/specs/consensus/spec.md | — | narrative |
| messaging | openspec/specs/messaging/spec.md | — | narrative |
| networking-p2p | openspec/specs/networking/p2p.md | — | narrative |
| networking-https-outcalls | openspec/specs/networking/https-outcalls.md | — | narrative |
| state-management | openspec/specs/state-management/ | — | narrative |
| crypto | openspec/specs/crypto/ | — | narrative |
| governance-nns | openspec/specs/governance/nns-governance.md | — | narrative |
| governance-sns | openspec/specs/governance/sns/ | — | narrative |
| ledger | openspec/specs/ledger/ | — | narrative |
| registry | openspec/specs/registry/ | — | narrative |
| boundary-node | openspec/specs/boundary-node/ | — | narrative |
| ingress-manager | openspec/specs/ingress-manager/spec.md | — | narrative |
| query-stats | openspec/specs/query-stats/spec.md | — | narrative |
| infrastructure | openspec/specs/infrastructure/ | — | narrative |
| pocket-ic | openspec/specs/pocket-ic-server/spec.md | — | narrative |
| testing | openspec/specs/testing/ | — | narrative |
| types-and-interfaces | openspec/specs/types-and-interfaces/ | — | narrative |

## Key Design Decisions

### Dual-Directory Approach
- `openspec/specs/` — existing narrative specs (crate coverage, human reference)
- `openspec/capabilities/` — REQ-*/SCENARIO-* specs (machine-verifiable, traceable)
- Both coexist; capabilities/ is the authoritative source for traceability

### REQ-* Naming Convention
`REQ-<DOMAIN>-<NNN>` where DOMAIN is a short uppercase prefix (SCHED, EXEC, CONS, MSG, NET, STATE, CRYPTO, GOV, LED, REG, BN)

### SCENARIO-* Naming Convention
`SCENARIO-<DOMAIN>-<NNN>` — tied to a specific REQ, given-when-then format

### Migration Priority
1. High-churn domains (execution, consensus) — most test failures traceable here
2. Protocol-critical domains (state-management, crypto, messaging)
3. Infrastructure domains (registry, networking, governance)
