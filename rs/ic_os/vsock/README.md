# Vsock

## Description

The vsock_guest binary runs in the guest VM and sends messages over the vsock channel to the vsock_host running in the hostOS.
The vsock_guest is used by the orchestator to call commands in the hostOS.

protocol defines the communication protocol and offers utility functions for communication.

## Comands

The following commands are supported:

| Command               | Parameters | Description |
| --------------------  | --------- | --------------- |
| attach-hsm            |           | Request that the HostOS attach the HSM to the GuestOS virtual machine.  |
| detach-hsm            |           | Request that the HostOS detach the HSM from the GuestOS virtual machine. Note that the attach and detach-hsm commands are being phased out in favor of the virtual-hsm onboarding, which does not use the vsock. |
| get-hostos-version    |           | Request that the HostOS return its version.  |
| upgrade               | URL, hash | Request that the HostOS download and applies a given HostOS upgrade, then trigger a reboot of HostOS. Upgrades are triggered by NNS proposals. Unlike guestOS upgrades, which are triggered at a subnet level, the HostOS upgrades occur by datacenter or by individual nodes to avoid subnet downtime, as rebooting the HostOS typically takes several minutes. |
| set-node-id           | Node ID   | Request that the HostOS adds the provided node-ID to its hostname as a way to identify which node-ids corresponds to which machines. Note that set-node-id is not currently called by the orchestrator, but we would like this functionality, eventually.  |
| notify                | message   | Request that the HostOS output a given message a certain number of times to the host terminal. The command is used to log info on the HostOS (ex: "orchestrator started," "replica starting up").  |

## Compatibility
The current versions of the guest and host vsock are:
* guest: 1.0.0
* host: 1.0.0

Note that both the guest and host vsock are backwards compatible with each other's older version.

## Response

The guest vsock will output a Payload enum (see Payload definition in /protocol) to stdout for successful commands and output a string error to stderr for errors.