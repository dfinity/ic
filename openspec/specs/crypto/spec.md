# Crypto Subsystem

**Crates**: `ic-crypto-for-verification-only`, `ic-crypto-iccsa`, `ic-crypto-secrets-containers`, `ic-crypto-temp-crypto`, `ic-crypto-temp-crypto-vault`, `ic-signer`

The IC crypto subsystem (`rs/crypto/`) provides cryptographic operations for Internet Computer nodes including key generation, distributed key generation, signing, signature verification, TLS handshakes, hashing, pseudorandom number generation, and verifiable encrypted threshold key derivation (vetKD).

This specification is split into the following files for manageability:

- [signatures.md](signatures.md) - Basic signatures, multi-signatures, threshold signatures
- [canister_threshold_signatures.md](canister_threshold_signatures.md) - Threshold ECDSA, threshold Schnorr (BIP340/Ed25519), and canister signatures (ICCSA)
- [dkg.md](dkg.md) - Non-interactive DKG (NI-DKG) and Interactive DKG (IDkg) protocols
- [tls.md](tls.md) - TLS configuration and handshake
- [key_management.md](key_management.md) - Key generation, validation, rotation, and registry checks
- [hashing_and_prng.md](hashing_and_prng.md) - SHA-2 hashing, CSPRNG, tree hashing
- [vetkd.md](vetkd.md) - Verifiable Encrypted Threshold Key Derivation
- [utilities.md](utilities.md) - Secrets containers, standalone signature verifier, verification-only component

## Core Architecture

### Requirement: CryptoComponent Instantiation
The `CryptoComponentImpl` is the central struct providing all crypto operations for a node. It wraps a Crypto Service Provider (CSP), a vault for secret key operations, a registry client, and a threshold signature data store.

#### Scenario: Creating a CryptoComponent
- **WHEN** a node creates a `CryptoComponent` with a `CryptoConfig`, registry client, logger, and optional metrics registry
- **THEN** the component initializes a CSP vault from the config
- **AND** derives the node's `NodeId` from its node signing public key
- **AND** collects and stores key count metrics for the latest registry version

#### Scenario: Shared CryptoComponent via Arc
- **WHEN** multiple subsystems need access to the crypto component
- **THEN** the component must be shared via `Arc::clone` (not by creating multiple instances with the same config)
- **AND** concurrent state access issues are avoided

#### Scenario: CryptoComponent with UnixSocket vault
- **WHEN** the config's vault type is `UnixSocket`
- **THEN** a `tokio_runtime_handle` must be provided
- **AND** if `tokio_runtime_handle` is `None`, the constructor panics

### Requirement: Unsafe Code Prohibition
The crypto crate forbids unsafe code at the crate level.

#### Scenario: Unsafe code detected
- **WHEN** any code in `rs/crypto/src/` uses `unsafe`
- **THEN** compilation fails due to `#![forbid(unsafe_code)]`

### Requirement: Logging and Metrics
All crypto operations log their start/end with debug-level logging and observe duration metrics.

#### Scenario: Crypto operation logging
- **WHEN** any trait method on `CryptoComponentImpl` is called
- **THEN** a log entry is produced at the start (with parameters) and end (with result status)
- **AND** the duration is observed via the metrics subsystem
- **AND** a `log_id` is generated from the current time (or 0 if debug logging is disabled)
