# Canister sandbox

This implements the canister wasm sandboxing logic: All wasm execution are
pulled out from the replica itself and pushed into separate processes, one
per canister.

## Code organization

- The top-level `canister_sandbox` crate is the binary that will be run as
  the sandbox process. It is just a simple wrapper that launches all logic
  implemented in other crates from its `main` function

- `common` implements the IPC mechanisms and protocols used between replica
  and sandbox process. The actual protocol definitions are found in
  the `common/src/protocol` module

- `backend_lib` implements the logic to be run in the sandbox process. It is
  organized as a library crate, with the main crate just calling its
  entry point.

- `replica_controller2` implements the replica side control of the sandbox
  mechanism. It provides on the one hand the API "glue" towards the execution
  layer, and on the other hand all logic to manage and talk to the backend
  processes. This also includes starting the backend processes.
