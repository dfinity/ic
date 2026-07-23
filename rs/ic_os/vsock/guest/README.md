# vsock_guest

GuestOS-side CLI for sending allowlisted commands to HostOS over vsock.

## How it works
- Parses a small flag-based CLI into a `vsock_lib::protocol::Command`.
- Sends the command through `LinuxVSockClient`.
- Prints the returned payload to stdout.
- Mirrors `notify` messages to the local GuestOS console so they are visible
  even when the host console is not.

This binary is intentionally narrow: it exposes only the externally supported
subset of the shared vsock protocol.
