# deterministic_ips

Generates deterministic node MAC addresses and derives SLAAC IPv6 addresses from
them.

## How it works
- Uses the management/BMC MAC address, deployment environment, and node type
  (`SetupOS`, `HostOS`, `GuestOS`, and related variants) as the stable inputs.
- Encodes the node type into reserved bytes in the generated MAC address so the
  different IC-OS layers stay distinguishable.
- Hashes the stable inputs to derive the remaining MAC bytes.
- The resulting MAC can then be converted into the node's deterministic IPv6
  address with the `MacAddr6Ext` SLAAC helper.

The crate exposes both a library API and the `deterministic-ips` CLI for
inspection and debugging.

An easy way to recognize these addresses is:

- `HostOS` addresses contain `:6800:`
- `GuestOS` addresses contain `:6801:`
