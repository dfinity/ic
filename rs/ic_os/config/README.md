# IC-OS Config

IC-OS Config is responsible for managing the configuration of IC-OS images.

SetupOS transforms user-facing configuration files (like `config.ini`, `deployment.json`, etc.) into a SetupOSConfig struct. Then, in production, configuration is propagated from SetupOS → HostOS → GuestOS (→ replica) via the HostOSConfig and GuestOSConfig structures.

All access to configuration and the config partition should go through the config structures.

For testing, IC-OS Config is also used to create GuestOS configuration directly.

When updating the IC-OS configuration, it's crucial to ensure backwards compatibility.
For detailed guidelines on updating the configuration, please refer to the documentation in config_types [`lib.rs`](../config_types/src/lib.rs).
Any changes to the configuration should undergo a thorough review process to ensure they follow the guidlines.

For details on the IC-OS configuration mechanism, refer to [ic-os/docs/Configuration.adoc](../../../ic-os/docs/Configuration.adoc)