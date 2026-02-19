# Change Log

## [0.5.0] - Unreleased

### Added

- Make `deriveSymmetricKey` non-`@internal`.
- `DerivedKeyMaterial` encryption now supports authenticated data
- `DerivedKeyMaterial` encryption uses a different format for encryption now.
  Decryption of old messages is supported, however older versions of this library
  will not be able to read messages encrypted by this or newer versions.

### Changed


- Make `DerivedKeyMaterial.deriveAesGcmCryptoKey` `@internal`.

## [0.4.0] - 2025-08-04

### Added

- Added MasterPublicKey.productionKey which allows accessing the production public keys

- Added IbeCiphertext plaintextSize and ciphertextSize helpers

- Add VrfOutput type for using VetKeys as a Verifiable Random Function

### Changed

 - Bump `@dfinity` agent-related packages to major version `3`.

## [0.3.0] - 2025-06-30

### Changed

- Added isValidTransportPublicKey function

- Improved code docs.

- Added `deserialize` methods.

- Updated dependencies.

## [0.2.0] - 2025-06-08

### Fixed
- Links in code docs.

### Changed
- The code docs now live on github.io.
- Replaces some instances of `window` with `globalThis` in a few places for better node compatibility.

## [0.1.0] - 2025-05-27

Initial release
