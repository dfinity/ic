# Canister sandbox

This implements the canister wasm sandboxing logic: All wasm execution are
pulled out from the replica itself and pushed into separate processes, one
per canister.

## Code organization

- The top-level `canister_sandbox` crate contains the `backend_lib` library for
running the sandbox process as well as the sandbox process binary. 

- `common` implements the IPC mechanisms and protocols used between replica
  and sandbox process. The actual protocol definitions are found in
  the `common/src/protocol` module

- `replica_controller` implements the replica side control of the sandbox
  mechanism. It provides on the one hand the API "glue" towards the execution
  layer, and on the other hand all logic to manage and talk to the backend
  processes. This also includes starting the backend processes.
