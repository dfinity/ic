# vsock_lib

Shared protocol and transport implementation for HostOS/GuestOS vsock
communication.

## How it works
- `protocol/` defines the JSON-serialized request/response types and the narrow
  command set allowed across the GuestOS/HostOS boundary.
- `guest/` provides the client implementation used by `vsock_guest` and tests.
- `host/` provides the server loop and command dispatch used by `vsock_host`.

The host-side dispatcher is where privileged actions happen, so this crate is
the main place to review when changing the GuestOS ↔ HostOS control surface.
