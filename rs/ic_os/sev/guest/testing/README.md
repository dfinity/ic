# sev_guest_testing

Mocks and fake signers for testing guest-side SEV flows.

## What it provides
- `MockSevGuestFirmwareBuilder` for constructing firmware doubles with explicit
  measurements, chip IDs, derived keys, and failure modes.
- Fake attestation-report signers for tests that need verifiable but synthetic
  attestation packages.
