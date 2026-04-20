# config_types

Canonical typed representation of IC-OS configuration.

## How it works
- Defines the versioned config structs shared across SetupOS, HostOS, and
  GuestOS, including `SetupOSConfig`, `HostOSConfig`, and `GuestOSConfig`.
- Encodes the rollout path of configuration data as it moves from SetupOS input
  files to HostOS and then to GuestOS.
- Documents the backward-compatibility rules directly in `src/lib.rs`; those
  rules are part of the crate's contract.

## Backward compatibility
- `compatibility_tests/` contains fixture-based tests that make sure new code
  can still deserialize historical config payloads.
