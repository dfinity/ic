# API Boundary Nodes Discovery Library

[API Boundary Nodes (BNs)](https://forum.dfinity.org/t/boundary-node-roadmap/15562) of the [Internet Computer](https://internetcomputer.org/) (IC) are currently undergoing decentralization. This transition allows IC clients to route [API system calls](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-interface) directly through API BNs, which are now part of the IC landscape. Previously, all IC clients relied on centralized Boundary Nodes served via `ic0.app` through DNS-based resolution.

The decentralization of API BNs places the responsibility of discovering and routing requests to these nodes on IC clients. This library comes at rescue and provides essential support for IC clients using [agent-rs](https://github.com/dfinity/agent-rs) to communicate with the IC. Library offers convenient abstractions for building a custom transport layer for the `agent-rs`. This transport layer runs background services that automatically detect available API BNs, monitor topology changes, assess API BNs' health, and route requests to the nearest API BN. Usage of the `Agent` remains unchanged for the clients.

**NOTE**: This library is currently in the prototype phase and will eventually be integrated into [agent-rs](https://github.com/dfinity/agent-rs).

### Examples
[Basic library usage](https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/boundary_node/discower_bowndary/examples/basic_library_usage.rs) with `agent-rs`.
```
$ cargo run --bin basic_library_usage
```
[Dynamic routing](https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/boundary_node/discower_bowndary/examples/api_bn_dynamic_routing.rs) via API BNs:
```
$ cargo run --bin api_bn_dynamic_routing
```