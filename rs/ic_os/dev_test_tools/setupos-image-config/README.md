# setupos-image-config

Utility for injecting configuration into an existing SetupOS disk image without
rebuilding the image from scratch.

## How it works
- Opens the config and data partitions inside the image with `partition_tools`.
- Rewrites `config.ini` and `deployment.json` in place.
- Optionally injects SSH authorized keys, node operator key material, and the
  NNS public key override.
- The `setupos-inject-config` binary is the operational entry point.

This is primarily used in dev/test workflows where rebuilding a full SetupOS
image would be too slow.
