# network

Generates systemd-networkd configuration for SetupOS and HostOS.

## How it works
- Accepts typed `NetworkSettings` from `config_types`.
- Resolves the management MAC either from config or by calling `ipmitool lan
  print`.
- Uses `deterministic_ips` to derive the node MAC and IPv6 address.
- Writes the final systemd-networkd files via `systemd.rs`.

Currently the implementation is centered around deterministic IPv6
configuration; router-advertisement and fixed-address modes are explicitly
rejected.
