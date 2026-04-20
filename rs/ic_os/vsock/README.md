# Vsock

The vsock channel is the main GuestOS → HostOS command path for the small set of
actions that GuestOS cannot perform on its own.

This directory contains three Rust crates:

- `vsock_guest`: GuestOS-side CLI/client.
- `vsock_host`: HostOS-side server binary.
- `vsock_lib`: Shared transport, protocol, and host/guest helpers.

To maintain the isolation boundary between the two operating systems, the
protocol intentionally exposes only a narrow, allowlisted command set.

All commands are initiated from GuestOS. This is a constrained escape hatch for
the small number of host-level actions that GuestOS cannot perform by itself,
not a general-purpose HostOS/GuestOS RPC interface.

## Commands

The following commands are supported:

| Command                | Parameters     | Description                                                                               |
|------------------------|----------------|-------------------------------------------------------------------------------------------|
| attach-hsm             |                | Request that HostOS attach the HSM to the GuestOS VM.                                     |
| detach-hsm             |                | Request that HostOS detach the HSM from the GuestOS VM.                                   |
| get-hostos-version     |                | Return the HostOS software version.                                                       |
| upgrade                | URL, hash      | Ask HostOS to stage and apply a HostOS upgrade.                                           |
| notify                 | message, count | Ask HostOS to print a message to the host console.                                        |
| start-upgrade-guest-vm |                | Internal command used by the GuestOS upgrade flow to ask HostOS to launch the Upgrade VM. |

## Compatibility
The version handshake is implemented in the shared protocol types. The HostOS
server can return its protocol version so GuestOS-side callers can detect major
compatibility problems.

## Trust boundary notes
The vsock transport is local to the HostOS/GuestOS pair, but it is still treated
as a narrow control boundary rather than a trust boundary. Sensitive decisions
such as release identity or disk-key release are enforced elsewhere via
attestation/measurement checks, not merely by the existence of a vsock request.

## Response

`vsock_guest` prints successful payloads to stdout and reports protocol or
execution errors on stderr.
