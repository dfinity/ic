# guest_upgrade_shared

Shared API and protocol definitions for the GuestOS upgrade key-exchange flow.

## What lives here
- gRPC types generated from the upgrade service protobuf definitions.
- Shared constants such as `DEFAULT_SERVER_PORT` and the store partition device
  path.
- The custom-data encoding used to bind both sides' ephemeral TLS keys into the
  SEV attestation reports.

The structures in `attestation.rs` are intentionally stability-sensitive:
changing them changes the attestation custom-data bytes and will break
verification across client and server.
