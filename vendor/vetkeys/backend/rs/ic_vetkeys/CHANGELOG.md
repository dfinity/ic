# Change Log

## [0.6.0] - 2025-11-24

### Added

- Added support for offline generation of keys relative to the PocketIC master keys, similar to the existing functionality for offline derivation relative to the production master public keys.

### Changed

- Increased CDK dependency to version 0.19
- Changes to format of the AES-GCM encryption helpers added in 0.5.0. This version can decrypt messages encrypted by 0.5.0, but 0.5.0 cannot decrypt messages encrypted by 0.6.0

## [0.5.0] - 2025-09-08

### Added

- Add AES-GCM encryption helpers ([#220](https://github.com/dfinity/vetkeys/pull/220)). The helpers are available in a `DerivedKeyMaterial` struct, which can be created using `VetKey::as_derived_key_material`. Encryption/decryption is done with `DerivedKeyMaterial::encrypt_message` and `DerivedKeyMaterial::decrypt_message`.

### Changed

- Use optimized G2 generator point multiplication ([#219](https://github.com/dfinity/vetkeys/pull/219)). This improves the performance of public key derivation (`MasterPublicKey::derive_canister_key` and `DerivedPublicKey::derive_sub_key`) and IBE encryption/decryption (`IbeCiphertext::encrypt` and `IbeCiphertext::decrypt`).

### Fixed

- Removes the modified appendix from the LICENSE file to ensure full compliance with the Apache 2.0 license, which should remain in its original, unmodified form ([#225](https://github.com/dfinity/vetkeys/pull/225)).

## [0.4.0] - 2025-08-05

### Breaking changes

- Bumped `ic-stable-structures` to `v0.7.0`.

### Added

- Added MasterPublicKey::for_mainnet_key which allows accessing the production public keys

- Added IbeCiphertext plaintext_size and ciphertext_size helpers

- Add VrfOutput type for using VetKeys as a Verifiable Random Function

- `derive(Deserialize)` for `EncryptedMapData`

### Changed

- Set MSRV to 1.85

## [0.3.0] - 2025-06-30

### Added

- An additional sanity check that the public key is not the identity.

### Changed

- Improved docs.

- Added zeroization of the used memory.

- Updated dependencies.

## [0.2.0] - 2025-06-08

### Breaking Changes

- Changed error types of `crate::management_canister::{bls_public_key, sign_with_bls}`.

### Fixed

- Links in code docs.

### Changed

- Bumped `ic_cdk` to `v0.18.3`. Due to this update, the internally dispatched `vetkd_derive_key` calls now attach exactly the needed the amount of cycles (and not sometimes more cycles as it was the case before) because the new version of `ic_cdk` determines the cost by using the `ic0_cost_vetkd_derive_key` endpoint.

## [0.1.0] - 2025-05-27

Initial release
