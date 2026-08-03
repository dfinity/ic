# guestos_tool

GuestOS-side operational CLI.

## How it works
- `generate-network-config` renders systemd-networkd files from the GuestOS
  config object.
- `regenerate-network-config` optionally overlays IPv4 settings and restarts
  `systemd-networkd`.
- `cloud-provision` temporarily configures networking, queries the cloud
  metadata service, and writes the fetched `config.json` to disk.

The cloud-specific provisioning logic lives in `cloud_provision.rs`; the network
rendering logic lives in `generate_network_config.rs`.
