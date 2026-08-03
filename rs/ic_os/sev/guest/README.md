# sev_guest

Guest-side SEV-SNP primitives used by GuestOS runtime services.

## How it works
- `key_deriver.rs` asks the SEV guest firmware to derive keys that are bound to
  the VM measurement.
- `attestation_package.rs` generates full attestation packages using the guest
  firmware plus the configured certificate chain.
- `is_sev_active()` is the quick runtime probe used to gate SEV-only code
  paths.

In the IC-OS model, SEV guest firmware provides two especially important
primitives:
- attestation reports that prove which GuestOS configuration was launched, and
- sealing/derived keys that tie persistent data access to that specific node and
  launched software configuration.

This crate is the bridge between higher-level IC-OS logic and the low-level
firmware interface defined in `sev_guest_firmware`.
