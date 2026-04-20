# sev_guest_firmware

Trait abstraction over the AMD SEV guest firmware device.

## Why it exists
- Production code talks to `/dev/sev-guest` through this interface.
- Test code can inject a mock implementation instead of touching real firmware.
- The trait exposes only the operations IC-OS needs today: attestation report
  generation and derived-key generation, plus a few test-oriented capability
  flags.

If a crate needs SEV guest functionality but also needs to stay testable, it
should depend on this trait rather than on the concrete firmware implementation.
