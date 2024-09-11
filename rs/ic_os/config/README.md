# IC-OS Config

IC-OS Config is responsible for managing the configuration of IC-OS images. 

SetupOS transforms user-facing configuration files (like `config.ini`, `deployment.json`, etc.) into a SetupOSConfig struct. Then, in production, configuration is propagated from SetupOS → HostOS → GuestOS (→ replica) via the HostOSConfig and GuestOSConfig structures.

All access to configuration and the config partition should go through the config structures.

For testing, IC-OS Config is also used to create HostOS and GuestOS configuration directly.