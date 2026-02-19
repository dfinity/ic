# Change Log

## [0.4.0] - 2025-09-29

### Breaking changes

- Fixed an inconsistency with the Rust backend in the signature format returned by `ManagementCanister.signWithBls`. Before, we returned the full response from `vetkd_derive_key` while we only need the last 48 bytes, which is the signature. Also, added a check to `signWithBls` which traps if the provided vetKD key id is not `#bls12_381_g2`.

- Fixed an inconsistency with the Rust backend in the returned text error messages. Two error messages were starting with a capital instead of small letter. This is now fixed.

- Extract state to state structures to separate the data from the state. This enables enhanced orthogonal persistence by declaring actors to be `persistent`.

## [0.3.0] - 2025-06-30

### Breaking changes

- Fixed a few inconsistencies with the Rust backend of encrypted maps. 

### Changed

- Updates dependencies.

### Added
- Sign with BLS and VetKD helper functions.

## [0.2.0] - 2025-06-18

### Fixed
- Links in code docs.
- Repository in mops.toml.

## [0.1.0] - 2025-06-11

Initial release