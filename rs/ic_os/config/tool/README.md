# config_tool

`config_tool` is the main crate for translating operator-facing IC-OS inputs
into the typed JSON configs consumed by SetupOS, HostOS, and GuestOS.

## How it works
- `setupos/*` reads user-provided files such as `config.ini` and
  `deployment.json` and assembles `SetupOSConfig`.
- `hostos/*` derives HostOS and GuestOS-side configuration and bootstrap
  artifacts from higher-level config objects.
- `guestos/*` bootstraps GuestOS state, renders replica config, and can obtain
  config from cloud metadata in dev environments.
- `src/main.rs` exposes the main operational subcommands such as
  `create-setupos-config`, `generate-hostos-config`, `bootstrap-ic-node`, and
  `generate-ic-config`.

## Important invariant
All structs serialized by this crate come from `config_types`, so configuration
changes must remain backward compatible.
For detailed guidelines on updating the configuration, please refer to the documentation
in config_types [`lib.rs`](../types/src/lib.rs).
Any changes to the configuration should undergo a thorough review process to ensure they follow
the guidelines.

For details on the IC-OS configuration mechanism, refer to [ic-os/docs/Configuration.adoc](../../../../ic-os/docs/Configuration.adoc)