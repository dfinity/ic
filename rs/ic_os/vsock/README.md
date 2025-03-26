# Vsock

The vsock is the GuestOS’s only means of communicating with the HostOS. The vsock exists to perform certain functions unavailable to the GuestOS.

The `vsock_guest` binary runs in the GuestOS and sends messages over the vsock channel to the `vsock_host` binary running in the HostOS.

`vsock_guest` is used solely by the orchestator.

The `protocol` module defines the communication protocol and offers utility functions for communication.

To maintain the highest level of isolation and security between the two operating systems, the GuestOS is restricted to strictly defined commands.

## Commands

The following commands are supported:

| Command               | Parameters | Description |
| --------------------  | --------- | --------------- |
| attach-hsm            |           | Request that the HostOS attach the HSM to the GuestOS virtual machine.  |
| detach-hsm            |           | Request that the HostOS detach the HSM from the GuestOS virtual machine. Note that the attach and detach-hsm commands are being phased out in favor of the virtual-hsm onboarding, which does not use the vsock. |
| get-hostos-version    |           | Request that the HostOS return its version.  |
| upgrade               | URL, hash | Request that the HostOS download and apply a given HostOS upgrade, then trigger a reboot of HostOS. Upgrades are triggered by NNS proposals. Unlike guestOS upgrades, which are triggered at a subnet level, the HostOS upgrades occur by datacenter or by individual nodes to avoid subnet downtime, as rebooting the HostOS typically takes several minutes. |
| notify                | message   | Request that the HostOS output a given message a certain number of times to the host terminal. The command is used to log info on the HostOS (e.g., "orchestrator started," "replica starting up").  |

## Compatibility
The current versions of the guest and host vsock are:
* guest: 1.0.0
* host: 1.0.0

Note that both the guest and host vsock are backward compatible with each other's older versions.

## Response

The guest vsock will output a Payload enum (see Payload definition in /protocol) to stdout for successful commands and output a string error to stderr for errors.
