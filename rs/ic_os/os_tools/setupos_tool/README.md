# setupos_tool

SetupOS-side operational CLI.

## How it works
- `generate-network-config` renders systemd-networkd configuration from the
  typed SetupOS config.
- `generate-ipv6-address` prints the deterministic IPv6 address for a given node
  type.
- `check-elected-version` reads the local version file and checks whether that
  version is present in the NNS registry.

