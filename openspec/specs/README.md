# Internet Computer (IC) - OpenSpec Specifications

Complete specifications for the Internet Computer protocol implementation.

## Architecture Overview

The IC is a decentralized cloud computing platform that runs WebAssembly canisters
on a network of replicated subnets. Each subnet runs a BFT consensus protocol and
executes canisters deterministically.

## Subsystem Map

| Subsystem | Spec Directory | Source Code | Description |
|-----------|---------------|-------------|-------------|
| [Consensus](./consensus/) | `consensus/` | `rs/consensus/` | BFT block production, notarization, finalization |
| [Crypto](./crypto/) | `crypto/` | `rs/crypto/` | Threshold signatures, BLS, ECDSA, TLS, DKG |
| [Execution](./execution/) | `execution/` | `rs/execution_environment/`, `rs/embedders/`, `rs/canister_sandbox/` | Wasm execution, cycles, scheduling |
| [Networking](./networking/) | `networking/` | `rs/p2p/`, `rs/xnet/`, `rs/http_endpoints/` | P2P, cross-net, HTTP API |
| [State Management](./state-management/) | `state-management/` | `rs/state_manager/`, `rs/replicated_state/` | Checkpointing, sync, certification |
| [Governance](./governance/) | `governance/` | `rs/nns/`, `rs/sns/`, `rs/nervous_system/` | NNS, SNS, proposals, neurons |
| [Ledger](./ledger/) | `ledger/` | `rs/ledger_suite/`, `rs/rosetta-api/` | ICP ledger, ICRC tokens, Rosetta |
| [Registry](./registry/) | `registry/` | `rs/registry/` | System configuration, node/subnet mgmt |
| [Bitcoin Integration](./bitcoin-integration/) | `bitcoin-integration/` | `rs/bitcoin/` | ckBTC, UTXO management |
| [Ethereum Integration](./ethereum-integration/) | `ethereum-integration/` | `rs/ethereum/`, `rs/cross-chain/` | ckETH, EVM interaction |
| [Boundary Node](./boundary-node/) | `boundary-node/` | `rs/boundary_node/` | HTTP gateway, routing |
| [Infrastructure](./infrastructure/) | `infrastructure/` | `rs/orchestrator/`, `rs/replica/`, `rs/ic_os/` | Node operations, deployment |
| [Types & Interfaces](./types-and-interfaces/) | `types-and-interfaces/` | `rs/types/`, `rs/interfaces/` | Core types, trait contracts |
| [Canister Management](./canister-management/) | `canister-management/` | `rs/ingress_manager/`, `rs/messaging/` | Ingress, routing, validation |
| [Testing](./testing/) | `testing/` | `rs/tests/`, `rs/test_utilities/` | Test frameworks, system tests |

## Data Flow

```
User Request
    |
    v
[Boundary Node] --> [HTTP Endpoints] --> [Ingress Manager]
                                              |
                                              v
                                    [Consensus Layer]
                                    (Block Making -> Notarization -> Finalization)
                                              |
                                              v
                                    [Message Routing]
                                              |
                                              v
                                    [Execution Environment]
                                    (Wasm Runtime -> System API -> Cycles)
                                              |
                                              v
                                    [State Manager]
                                    (Checkpoint -> Certify -> Sync)
                                              |
                                              v
                                    [P2P / XNet]
                                    (Cross-subnet messaging)
```

## Cross-Cutting Concerns

- **Determinism**: All execution must be deterministic across replicas
- **Certification**: State trees are certified via threshold signatures
- **Cycles**: All computation is metered via cycles
- **Registry**: System configuration is stored in the NNS registry
- **Protobuf**: All wire formats use Protocol Buffers
