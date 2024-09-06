# IC-OS Config

IC-OS Config is responsible for managing the configuration of IC-OS images. It transforms user-facing configuration files (like `config.ini`, `deployment.json`, etc.) into structured configurations used by SetupOS, HostOS, and GuestOS components.

In production, configuration is propagated from SetupOS → HostOS → GuestOS (→ replica)

IC-OS Config is also used to create HostOS and GuestOS configuration directly for testing and development purposes.