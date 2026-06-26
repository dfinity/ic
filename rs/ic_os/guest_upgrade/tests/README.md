# guest_upgrade_tests

Integration-style test crate for the GuestOS disk-encryption key exchange.

## How it works
- Builds a fake registry with elected (approved) launch measurements.
- Uses mock SEV guest firmware and fake attestation signers to model both VMs.
- Starts the server and client agents together and exercises success and failure
  paths such as non-elected measurements, mismatched chip IDs, or invalid custom
  data.

This crate is the best place to look when changing the upgrade attestation
protocol because it shows the expected end-to-end behavior.
