
# Description

The vsock_agent runs in the guest VM and sends messages to the host (hypervisor) over the vsock channel.

At the moment the following commands are supported:

- `attach-hsm` - Request to connect the HSM via virtual USB to this VM.
- `detach-hsm` - Request to disconnect the HSM from this VM.
- `upgrade` - Request that the HostOS applies the given update.
- `set-node-id` - Request that the host add node information to hostname.
- `join-success` - Request that the HostOS notifies operator of a successful network join.
