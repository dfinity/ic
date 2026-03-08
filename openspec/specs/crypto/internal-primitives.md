# Crypto Internal Primitives Specification

**Crates**: `ic-crypto-internal-threshold-sig-canister-threshold-sig-test-utils`, `ic-crypto-node-key-generation`, `ic-crypto-node-key-validation`, `ic-crypto-sha2`, `ic-crypto-standalone-sig-verifier`

This specification covers the internal cryptographic primitive crates that form the foundation of the Internet Computer's cryptographic subsystem. These crates reside under `rs/crypto/internal/` and provide low-level implementations for signatures, encryption, key generation, threshold cryptography, and related building blocks.

Covered crates (by group):

1. **Seed and Key Derivation** -- `ic-crypto-internal-seed`, `ic-crypto-internal-hmac`
2. **Basic Signature Primitives** -- Ed25519, ECDSA secp256k1, ECDSA secp256r1, RSA PKCS#1, COSE, DER utils
3. **BLS12-381 Curve Library** -- `ic-crypto-internal-bls12-381-type`
4. **VetKD** -- `ic-crypto-internal-bls12-381-vetkd`
5. **BLS Multi-Signatures** -- `ic-crypto-internal-multi-sig-bls12381`
6. **BLS Threshold Signatures** -- `ic-crypto-internal-threshold-sig-bls12381`
7. **NI-DKG** -- Forward-secure encryption, Groth20 NIZK proofs, chunking
8. **Canister Threshold Signatures (IDKG)** -- Dealings, transcripts, complaints, MEGa encryption, polynomial commitments, ZK proofs
9. **Threshold Signing** -- ECDSA, BIP340 Schnorr, EdDSA, key derivation (BIP32/SLIP-0010)
10. **Elliptic Curve Abstraction** -- Multi-curve group/scalar types, random oracle
11. **Internal Types** -- `ic-crypto-internal-types`
12. **TLS Internals** -- `ic-crypto-internal-tls`
13. **Crypto Service Provider** -- `ic-crypto-internal-csp`
14. **Logging and Monitoring** -- `ic-crypto-internal-logmon`
15. **Test Vectors** -- `ic-crypto-internal-test-vectors`

---

## Requirements

### Requirement: Seed Generation and Derivation (ic-crypto-internal-seed)

The `ic-crypto-internal-seed` crate provides the `Seed` type, which encapsulates a 32-byte cryptovariable. Seeds can be created from byte arrays or RNGs, derived into child seeds using domain separators, and converted into deterministic ChaCha20 random number generators. Derivation uses XMD (expand_message_xmd with SHA-256) to ensure domain separation.

Path: `rs/crypto/internal/crypto_lib/seed/`

#### Scenario: Create seed from bytes
- **WHEN** `Seed::from_bytes` is called with an arbitrary byte slice
- **THEN** a `Seed` is produced by hashing the input with domain separator `"ic-crypto-seed-from-bytes"` via XMD
- **AND** the resulting seed has exactly 32 bytes of internal state

#### Scenario: Create seed from RNG
- **WHEN** `Seed::from_rng` is called with a cryptographically secure RNG
- **THEN** 32 bytes are read from the RNG
- **AND** a `Seed` is produced by hashing those bytes with domain separator `"ic-crypto-seed-from-rng"` via XMD

#### Scenario: Derive child seed
- **WHEN** `seed.derive(domain_separator)` is called on an existing seed
- **THEN** a new `Seed` is produced by hashing the parent seed's value with the given domain separator via XMD
- **AND** different domain separators produce different derived seeds
- **AND** the parent seed remains unchanged

#### Scenario: Convert seed to RNG
- **WHEN** `seed.into_rng()` is called
- **THEN** the seed is consumed and a `ChaCha20Rng` is returned, seeded with the seed's 32-byte value
- **AND** the RNG output is deterministic given the same seed

#### Scenario: Seed debug output is redacted
- **WHEN** a `Seed` is formatted with the `Debug` trait
- **THEN** the output reads `"Seed - REDACTED"` and does not reveal the internal value

#### Scenario: Seed is zeroized on drop
- **WHEN** a `Seed` goes out of scope
- **THEN** the internal 32-byte value is securely zeroed from memory

---

### Requirement: HMAC and HKDF (ic-crypto-internal-hmac)

The `ic-crypto-internal-hmac` crate provides HMAC (RFC 2104) and HKDF (RFC 5869) implementations supporting SHA-224, SHA-256, and SHA-512 hash functions.

Path: `rs/crypto/internal/crypto_lib/hmac/`

#### Scenario: HMAC one-shot computation
- **WHEN** `Hmac::<H>::hmac(key, input)` is called with a key and input
- **THEN** an HMAC tag is computed conforming to RFC 2104
- **AND** the output length matches the hash function's output length

#### Scenario: HMAC incremental computation
- **WHEN** an `Hmac` instance is created with `new(key)`, data is provided via multiple `write` calls, and `finish` is called
- **THEN** the result is identical to a one-shot HMAC over the concatenated input
- **AND** keys longer than the hash block size are first hashed before use

#### Scenario: HKDF key derivation
- **WHEN** `hkdf::<H>(output_len, key_material, salt, info)` is called
- **THEN** the extract step computes `PRK = HMAC(salt, key_material)`
- **AND** the expand step produces `output_len` bytes of derived key material
- **AND** the output conforms to RFC 5869

#### Scenario: HKDF output length limit
- **WHEN** `hkdf` is called with `output_len` exceeding `255 * hash_output_length`
- **THEN** `HkdfError::RequestedOutputTooLong` is returned

#### Scenario: HKDF with zero output length
- **WHEN** `hkdf` is called with `output_len = 0`
- **THEN** an empty `Vec<u8>` is returned without error

---

### Requirement: Ed25519 Basic Signatures (ic-crypto-internal-basic-sig-ed25519)

The `ic-crypto-internal-basic-sig-ed25519` crate implements Ed25519 key generation, signing, verification, and DER encoding/decoding of public keys per RFC 8032 and RFC 8410.

Path: `rs/crypto/internal/crypto_lib/basic_sig/ed25519/`

#### Scenario: Ed25519 key pair generation from seed
- **WHEN** `keypair_from_seed(seed)` is called with a `Seed`
- **THEN** a deterministic Ed25519 key pair `(SecretKeyBytes, PublicKeyBytes)` is generated
- **AND** the secret key is wrapped in a `SecretArray` for secure handling

#### Scenario: Ed25519 signing
- **WHEN** `sign(msg, sk)` is called with a message and a valid secret key
- **THEN** a 64-byte Ed25519 signature is produced
- **AND** the signature is deterministic for the same message and key

#### Scenario: Ed25519 signature verification
- **WHEN** `verify(sig, msg, pk)` is called with a valid signature, message, and public key
- **THEN** `Ok(())` is returned
- **AND** if the signature is invalid or the message differs, `CryptoError::SignatureVerification` is returned

#### Scenario: Ed25519 malformed public key rejection
- **WHEN** `verify` is called with a public key that is not a valid curve point
- **THEN** `CryptoError::MalformedPublicKey` is returned

#### Scenario: Ed25519 DER public key round-trip
- **WHEN** a public key is encoded with `public_key_to_der` and decoded with `public_key_from_der`
- **THEN** the resulting `PublicKeyBytes` matches the original
- **AND** the DER encoding uses OID 1.3.101.112 per RFC 8410

#### Scenario: Ed25519 public key validation
- **WHEN** `verify_public_key(pk)` is called
- **THEN** it returns `true` only if the key is a valid point on the Ed25519 curve in the prime-order subgroup (torsion-free)

---

### Requirement: ECDSA secp256k1 Basic Signatures (ic-crypto-internal-basic-sig-ecdsa-secp256k1)

The `ic-crypto-internal-basic-sig-ecdsa-secp256k1` crate implements ECDSA signing and verification over the secp256k1 curve, along with DER key encoding.

Path: `rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256k1/`

#### Scenario: ECDSA secp256k1 signing
- **WHEN** `sign(msg, sk)` is called with a message digest and a secret key in RFC 5915 DER format
- **THEN** an ECDSA signature is produced using the secp256k1 curve
- **AND** the message is treated as a pre-hashed digest

#### Scenario: ECDSA secp256k1 verification
- **WHEN** `verify(sig, msg, pk)` is called with valid inputs
- **THEN** `Ok(())` is returned if the signature is valid
- **AND** signature verification allows malleable (non-s-normalized) signatures for backward compatibility with OpenSSL behavior

#### Scenario: ECDSA secp256k1 DER public key parsing
- **WHEN** `public_key_from_der(pk_der)` is called with a DER-encoded public key
- **THEN** the key is deserialized and validated as a point on secp256k1
- **AND** non-canonical DER encodings are rejected with `CryptoError::MalformedPublicKey`

#### Scenario: ECDSA secp256k1 DER public key encoding
- **WHEN** `public_key_to_der(pk)` is called with a valid public key
- **THEN** the key is serialized to canonical DER format
- **AND** invalid public keys return `CryptoError::MalformedPublicKey`

#### Scenario: ECDSA secp256k1 malformed secret key
- **WHEN** `sign` is called with an invalid secret key
- **THEN** `CryptoError::MalformedSecretKey` is returned without leaking secret key information in the error message

---

### Requirement: ECDSA secp256r1 (P-256) Basic Signatures (ic-crypto-internal-basic-sig-ecdsa-secp256r1)

The `ic-crypto-internal-basic-sig-ecdsa-secp256r1` crate implements ECDSA signing and verification over the P-256 (secp256r1) curve.

Path: `rs/crypto/internal/crypto_lib/basic_sig/ecdsa_secp256r1/`

#### Scenario: ECDSA P-256 signing
- **WHEN** `sign(msg, sk)` is called with a message digest and a secret key
- **THEN** an ECDSA signature is produced using the P-256 curve
- **AND** if the digest length is invalid, `CryptoError::InvalidArgument` is returned

#### Scenario: ECDSA P-256 verification
- **WHEN** `verify(sig, msg, pk)` is called
- **THEN** `Ok(())` is returned for valid signatures
- **AND** `CryptoError::SignatureVerification` is returned for invalid signatures

#### Scenario: ECDSA P-256 canonical DER key parsing
- **WHEN** `public_key_from_der(pk_der)` is called
- **THEN** only canonical DER encodings are accepted
- **AND** the decoded key is returned as uncompressed SEC1 bytes

#### Scenario: ECDSA P-256 malformed secret key
- **WHEN** `sign` is called with an invalid secret key
- **THEN** `CryptoError::MalformedSecretKey` is returned without leaking sensitive information

---

### Requirement: RSA PKCS#1 v1.5 Signature Verification (ic-crypto-internal-basic-sig-rsa-pkcs1)

The `ic-crypto-internal-basic-sig-rsa-pkcs1` crate provides RSA public key parsing and PKCS#1 v1.5 signature verification (SHA-256), as specified in RFC 8017.

Path: `rs/crypto/internal/crypto_lib/basic_sig/rsa_pkcs1/`

#### Scenario: RSA public key size validation
- **WHEN** an RSA public key is parsed from DER SPKI encoding
- **THEN** the key size must be between 2048 and 8192 bits inclusive
- **AND** keys outside this range are rejected

#### Scenario: RSA PKCS#1 v1.5 signature verification
- **WHEN** a signature is verified against a message using an RSA public key
- **THEN** the verification uses SHA-256 as the hash function and PKCS#1 v1.5 padding
- **AND** invalid signatures are rejected with an appropriate error

#### Scenario: RSA public key serialization round-trip
- **WHEN** an `RsaPublicKey` is serialized with serde and deserialized
- **THEN** the DER encoding round-trips correctly
- **AND** the internal `rsa::RsaPublicKey` is reconstructed from the DER bytes on deserialization

---

### Requirement: COSE Public Key Parsing (ic-crypto-internal-basic-sig-cose)

The `ic-crypto-internal-basic-sig-cose` crate parses COSE-encoded public keys (RFC 8152) supporting ECDSA P-256 (ES256) and RSA PKCS#1 v1.5 (RS256) algorithms.

Path: `rs/crypto/internal/crypto_lib/basic_sig/cose/`

#### Scenario: COSE ECDSA P-256 key extraction
- **WHEN** a COSE-encoded key with `kty=EC2`, `alg=ES256`, and `crv=P-256` is provided
- **THEN** the public key coordinates (x, y) are extracted and returned as a DER-encoded key

#### Scenario: COSE RSA key extraction
- **WHEN** a COSE-encoded key with `kty=RSA` and `alg=RS256` is provided
- **THEN** the RSA modulus (n) and exponent (e) are extracted and returned as a DER-encoded SPKI key

#### Scenario: Unsupported COSE algorithm rejection
- **WHEN** a COSE key with an unsupported algorithm type or key type is provided
- **THEN** an appropriate error is returned

---

### Requirement: DER Encoding Utilities (ic-crypto-internal-basic-sig-der-utils)

The `ic-crypto-internal-basic-sig-der-utils` crate provides utilities for constructing and parsing DER-encoded `SubjectPublicKeyInfo` (SPKI) structures per RFC 5280 and `AlgorithmIdentifier` structures per RFC 5480.

Path: `rs/crypto/internal/crypto_lib/basic_sig/der_utils/`

#### Scenario: SPKI construction with OID parameters
- **WHEN** a `PkixAlgorithmIdentifier` is constructed with an OID and optional parameters
- **THEN** the resulting DER encoding is a valid ASN.1 SEQUENCE containing the algorithm OID and parameters

#### Scenario: Null parameter handling
- **WHEN** an `AlgorithmIdentifier` is constructed with `PkixAlgorithmParameters::Null`
- **THEN** an explicit ASN.1 NULL is included in the encoding
- **AND** omitting the parameter entirely is also supported via `new_with_empty_param`

---

### Requirement: BLS12-381 Type Library (ic-crypto-internal-bls12-381-type)

The `ic-crypto-internal-bls12-381-type` crate provides wrapper types and operations for BLS12-381 curve arithmetic, including scalar, G1, G2, and Gt elements. It also implements polynomial arithmetic, Lagrange interpolation, hash-to-curve, and optimized multi-scalar multiplication.

Path: `rs/crypto/internal/crypto_lib/bls12_381/type/`

#### Scenario: Scalar arithmetic
- **WHEN** `Scalar` values are added, subtracted, multiplied, or inverted
- **THEN** the operations are performed modulo the BLS12-381 group order
- **AND** scalar values are zeroized on drop

#### Scenario: G1 and G2 point operations
- **WHEN** elliptic curve points in G1 or G2 are added, negated, or scalar-multiplied
- **THEN** the results are valid points in the respective group
- **AND** serialization and deserialization round-trip correctly

#### Scenario: Hash-to-curve for G1
- **WHEN** `G1Projective::hash(domain_separator, msg)` is called
- **THEN** a deterministic point in G1 is produced using the hash_to_curve algorithm (XMD with SHA-256, SSWU map)
- **AND** the result conforms to the IETF hash-to-curve specification

#### Scenario: Hash-to-scalar
- **WHEN** `Scalar::hash(domain_separator, msg)` is called
- **THEN** a deterministic scalar is produced using hash-to-field with XMD

#### Scenario: Pairing computation
- **WHEN** `Gt::multipairing` is called with pairs of G1 and G2 points
- **THEN** the result is the product of individual pairings
- **AND** the identity element is returned if and only if the pairing equation holds

#### Scenario: Lagrange interpolation
- **WHEN** `LagrangeCoefficients` are computed for a set of node indices
- **THEN** the coefficients enable reconstruction of polynomial values at any point from evaluations at the given indices
- **AND** `InterpolationError` is returned if indices are duplicated or the set is empty

#### Scenario: Polynomial evaluation
- **WHEN** a `Polynomial` is evaluated at a given scalar
- **THEN** the result equals the sum of `coefficient_i * x^i` for all terms

#### Scenario: Point deserialization caching
- **WHEN** `G2Affine::deserialize_cached` is called repeatedly with the same bytes
- **THEN** the deserialized point is returned from cache on subsequent calls for improved performance

#### Scenario: Invalid point rejection
- **WHEN** an invalid byte encoding is provided to `G1Affine::deserialize` or `G2Affine::deserialize`
- **THEN** `PairingInvalidPoint::InvalidPoint` is returned
- **AND** similarly `PairingInvalidScalar::InvalidScalar` for invalid scalar encodings

---

### Requirement: VetKD - Verifiably Encrypted Threshold Key Derivation (ic-crypto-internal-bls12-381-vetkd)

The `ic-crypto-internal-bls12-381-vetkd` crate implements verifiably encrypted threshold key derivation as described in the ePrint paper (2023/616). It supports derivation of keys from a master public key using canister ID and optional context.

Path: `rs/crypto/internal/crypto_lib/bls12_381/vetkd/`

#### Scenario: Derivation context creation
- **WHEN** `DerivationContext::new(canister_id, context)` is called
- **THEN** a derivation context is created that binds the derived key to the given canister ID and context
- **AND** an empty context byte array results in no context-level derivation step

#### Scenario: Derived public key computation
- **WHEN** `DerivedPublicKey::derive_sub_key(master_pk, context)` is called
- **THEN** a derived G2 public key is computed as `g2 * offset + master_pk`
- **AND** the offset is derived by hashing the master public key and canister ID with domain separator `"ic-vetkd-bls12-381-g2-canister-id"`
- **AND** if a context is provided, an additional offset is added using domain separator `"ic-vetkd-bls12-381-g2-context"`

#### Scenario: Transport public key serialization round-trip
- **WHEN** a `TransportPublicKey` is serialized and deserialized
- **THEN** the result equals the original key
- **AND** invalid point encodings are rejected with `TransportPublicKeyDeserializationError::InvalidPublicKey`

#### Scenario: Encrypted key validity check
- **WHEN** an encrypted key or encrypted key share is checked for validity
- **THEN** pairing checks verify `e(c1, g2) == e(g1, c2)` and `e(c3, g2) == e(tpk, c2) * e(msg, dpki)`
- **AND** both conditions must hold for the encrypted key to be considered valid

#### Scenario: Encrypted key share combination
- **WHEN** threshold-many valid encrypted key shares are combined
- **THEN** the result is a valid encrypted key that can be decrypted by the transport key holder
- **AND** invalid or insufficient shares result in `EncryptedKeyCombinationError`

#### Scenario: Derived public key serialization round-trip
- **WHEN** a `DerivedPublicKey` is serialized and deserialized
- **THEN** the result equals the original derived key
- **AND** invalid G2 point encodings are rejected with `PublicKeyDeserializationError::InvalidPublicKey`

---

### Requirement: BLS12-381 Multi-Signatures (ic-crypto-internal-multi-sig-bls12381)

The `ic-crypto-internal-multi-sig-bls12381` crate implements BLS multi-signatures over the BLS12-381 curve. It supports key generation, individual signing, proof of possession, signature combination, and verification.

Path: `rs/crypto/internal/crypto_lib/multi_sig/bls12_381/`

#### Scenario: Multi-signature key pair generation
- **WHEN** `keypair_from_seed(seed)` is called
- **THEN** a BLS12-381 key pair `(SecretKeyBytes, PublicKeyBytes)` is generated deterministically from the seed
- **AND** the public key is a point in G2 and the secret key is a scalar

#### Scenario: Individual multi-signature signing
- **WHEN** `sign(message, secret_key)` is called
- **THEN** the message is hashed to a point in G1 and multiplied by the secret key to produce an individual signature

#### Scenario: Proof of Possession (PoP) creation
- **WHEN** `create_pop(public_key, secret_key)` is called
- **THEN** a PoP is created as a domain-separated signature on the public key itself
- **AND** `CryptoError::MalformedPublicKey` is returned if the public key cannot be parsed as a valid G2 point

#### Scenario: Proof of Possession (PoP) verification
- **WHEN** `verify_pop(pop, public_key)` is called
- **THEN** the PoP is verified by checking the BLS pairing equation with a domain-separated hash
- **AND** verification includes checking that the public key is on the curve and in the correct subgroup
- **AND** invalid PoPs return `CryptoError::PopVerification`

#### Scenario: Multi-signature combination
- **WHEN** `combine(signatures)` is called with a list of individual signatures
- **THEN** the signatures are aggregated (point addition in G1) into a single combined signature
- **AND** malformed individual signatures cause `CryptoError::MalformedSignature`

#### Scenario: Individual signature verification
- **WHEN** `verify_individual(message, signature, public_key)` is called
- **THEN** the signature is verified by checking the BLS pairing equation `e(sig, g2) == e(H(msg), pk)`
- **AND** verification failure returns `CryptoError::SignatureVerification`

#### Scenario: Combined multi-signature verification
- **WHEN** `verify_combined(message, signature, public_keys)` is called with all signer public keys
- **THEN** the aggregated public key is computed and the BLS pairing equation is checked
- **AND** verification succeeds only if the combined signature was formed from valid individual signatures of all listed signers

#### Scenario: Public key caching for verification
- **WHEN** public keys are deserialized during verification via `key_from_bytes_with_cache`
- **THEN** `G2Affine::deserialize_cached` is used to cache deserialized points for performance

---

### Requirement: BLS12-381 Threshold Signatures (ic-crypto-internal-threshold-sig-bls12381)

The `ic-crypto-internal-threshold-sig-bls12381` crate implements threshold BLS signatures. It provides key generation for (t,n)-threshold schemes, individual signing and verification, signature combination via Lagrange interpolation, and public key derivation from public coefficients.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/`

#### Scenario: Threshold key generation
- **WHEN** `generate_threshold_key(seed, threshold, receivers)` is called
- **THEN** a random polynomial of degree `threshold - 1` is generated from the seed
- **AND** `PublicCoefficientsBytes` (commitments to polynomial coefficients) and `receivers` secret key shares are returned
- **AND** an error is returned if `threshold > receivers`

#### Scenario: Individual threshold signing
- **WHEN** a signatory signs a message with their secret key share
- **THEN** the message is hashed to G1 using domain separator `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"` (Basic ciphersuite per draft-irtf-cfrg-bls-signature-04)
- **AND** the hash point is multiplied by the key share to produce the signature

#### Scenario: Individual public key derivation
- **WHEN** `individual_public_key(public_coefficients, index)` is called
- **THEN** the individual public key for the signatory at `index` is computed by evaluating the polynomial commitment at that index
- **AND** this derived key can verify signatures from that specific signatory

#### Scenario: Public key from secret key
- **WHEN** `public_key_from_secret_key(secret_key)` is called
- **THEN** the public key is computed as `g2 * secret_key` using the G2 generator

#### Scenario: Threshold signature combination
- **WHEN** `combine_signatures(signatures, threshold)` is called with at least `threshold` valid individual signatures
- **THEN** the signatures are combined using Lagrange interpolation to produce a single threshold signature
- **AND** the combined signature is unique regardless of which qualifying set of signatories contributed
- **AND** the combined signature has the same size as an individual signature

#### Scenario: Combined threshold signature verification
- **WHEN** a combined signature is verified against the public coefficients
- **THEN** the verification checks the BLS pairing equation using the threshold public key (constant term of the polynomial commitment)
- **AND** a combined signature from fewer than `threshold` valid shares will fail verification

#### Scenario: Invalid threshold configuration
- **WHEN** `generate_threshold_key` is called with `threshold > receivers`
- **THEN** an error is returned because it is impossible to form a valid combined signature

---

### Requirement: NI-DKG - Non-Interactive Distributed Key Generation (ic-crypto-internal-threshold-sig-bls12381 ni_dkg module)

The NI-DKG module implements non-interactive distributed key generation based on "Non-interactive distributed key generation and key resharing" by Jens Groth (ePrint 2021/339), using the BLS12-381 curve with forward-secure encryption and Groth20 NIZK proofs.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/bls12_381/src/ni_dkg/`

#### Scenario: Forward-secure encryption key generation
- **WHEN** a forward-secure encryption key pair is generated
- **THEN** the public key is a point in G1 with a proof of possession (`FsEncryptionPop`)
- **AND** the secret key is a binary tree encryption (BTE) node structure (`FsEncryptionSecretKey`) containing `BTENodeBytes`
- **AND** the maximum supported epoch is `2^LAMBDA_T - 1` where `LAMBDA_T = 32`

#### Scenario: Forward-secure encryption
- **WHEN** a dealing is encrypted for a set of receivers using their forward-secure public keys at a given epoch
- **THEN** each receiver's share is encrypted under their public key using the `DOMAIN_CIPHERTEXT_NODE` domain separator `"ic-fs-encryption/binary-tree-node"`
- **AND** the ciphertext can only be decrypted with the secret key for the correct epoch

#### Scenario: Forward-secure key update (epoch advancement)
- **WHEN** a node advances its forward-secure secret key to a new epoch
- **THEN** all key material for previous epochs is securely deleted
- **AND** decryption of ciphertexts for past epochs becomes impossible (forward secrecy)

#### Scenario: NI-DKG NIZK proof of correct sharing
- **WHEN** a dealer creates a dealing with a NIZK proof
- **THEN** the `nizk_sharing` module generates a proof that the dealing shares are consistent with the polynomial commitment
- **AND** any node can verify this proof without access to secret key material

#### Scenario: NI-DKG NIZK proof of correct chunking
- **WHEN** a dealing includes chunked ciphertexts
- **THEN** the `nizk_chunking` module generates a proof that the chunks are correctly formed
- **AND** the proof is verifiable by any party

#### Scenario: NI-DKG dealing verification
- **WHEN** a dealing is publicly verified
- **THEN** the NIZK proofs are checked for correctness
- **AND** the commitments are validated for structural correctness

#### Scenario: Encryption key proof of possession
- **WHEN** a forward-secure encryption key pair is generated
- **THEN** the `encryption_key_pop` module generates a proof of possession for the public key
- **AND** `verify_pop` can verify this proof to ensure the key holder knows the corresponding secret key

#### Scenario: Discrete log recovery for decryption
- **WHEN** a receiver decrypts their share from a dealing
- **THEN** `HonestDealerDlogLookupTable` is used for shares from honest dealers
- **AND** `CheatingDealerDlogSolver` is used as a fallback for potentially dishonest dealers
- **AND** the recovered share is verified against the polynomial commitment

#### Scenario: Groth20 BLS12-381 types
- **WHEN** NI-DKG key material is serialized
- **THEN** `FsEncryptionSecretKey` stores BTE nodes as CBOR-serialized data
- **AND** `BTENodeBytes` contains public elements (`tau`), G1 elements (`a`), and G2 elements (`b`, `d_t`, `d_h`)
- **AND** Debug output of secret key components is redacted

---

### Requirement: Canister Threshold Signatures - IDKG Dealings (ic-crypto-internal-threshold-sig-canister-threshold-sig idkg/dealings)

The IDKG dealings module implements the creation and verification of interactive DKG dealings that distribute secret shares to receivers using MEGa encryption. Five dealing types are supported.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/idkg/dealings.rs`

#### Scenario: Random dealing creation
- **WHEN** a `Random` dealing is created
- **THEN** a random polynomial is generated and shares are encrypted under receiver MEGa public keys
- **AND** the dealing includes a Pedersen commitment to the polynomial
- **AND** no zero-knowledge proof is required

#### Scenario: RandomUnmasked dealing creation
- **WHEN** a `RandomUnmasked` dealing is created
- **THEN** the dealing includes a simple (dlog) commitment instead of a Pedersen commitment
- **AND** no zero-knowledge proof is required

#### Scenario: ReshareOfUnmasked dealing creation
- **WHEN** a `ReshareOfUnmasked` dealing is created
- **THEN** the dealing outputs an unmasked dealing
- **AND** no proof is required since equivalence is provable from the commitments

#### Scenario: ReshareOfMasked dealing with proof
- **WHEN** a `ReshareOfMasked` dealing is created
- **THEN** the dealing includes a `ProofOfMaskedResharing` zero-knowledge proof
- **AND** the proof demonstrates the resharing is consistent with the input masked commitment

#### Scenario: UnmaskedTimesMasked dealing with proof
- **WHEN** an `UnmaskedTimesMasked` dealing is created
- **THEN** the dealing includes a `ProofOfProduct` zero-knowledge proof
- **AND** the proof demonstrates the output commitment opens to the product of the input openings

#### Scenario: Dealing public verification
- **WHEN** a dealing is publicly verified
- **THEN** any party can check the zero-knowledge proof (if present) and commitment structure
- **AND** no secret keys are required

#### Scenario: Dealing private verification
- **WHEN** a dealing is privately verified by a receiver
- **THEN** the receiver decrypts their share from the MEGa ciphertext
- **AND** the decrypted plaintext is checked for consistency with the commitment

#### Scenario: SecretShares debug is redacted
- **WHEN** `SecretShares` are formatted with `Debug`
- **THEN** the output includes the variant name and curve type but marks values as `"REDACTED"`

---

### Requirement: Canister Threshold Signatures - IDKG Transcripts (ic-crypto-internal-threshold-sig-canister-threshold-sig idkg/transcript)

The IDKG transcript module implements creation and verification of transcripts, which combine multiple verified dealings into a single combined commitment representing the distributed secret.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/idkg/transcript.rs`

#### Scenario: Transcript creation by summation
- **WHEN** a transcript is created from `Random` or `RandomUnmasked` dealings
- **THEN** the combined commitment is computed by summing the individual dealing commitments (`CombinedCommitment::BySummation`)
- **AND** the transcript's constant term represents the combined threshold public key

#### Scenario: Transcript creation by interpolation
- **WHEN** a transcript is created from resharing dealings
- **THEN** the combined commitment is computed via Lagrange interpolation (`CombinedCommitment::ByInterpolation`) of the dealing commitments
- **AND** the result preserves the relationship to the original secret

#### Scenario: Transcript verification
- **WHEN** a transcript is verified against a set of dealings
- **THEN** the transcript is recomputed from the dealings and compared to the given transcript
- **AND** equality confirms the transcript is consistent with the dealings

#### Scenario: Transcript operation commitment types
- **WHEN** a transcript operation is `Random`, the result is `Pedersen` (masked)
- **AND** when the operation is `RandomUnmasked`, the result is `Simple` (unmasked)
- **AND** when the operation is `ReshareOfMasked` or `ReshareOfUnmasked`, the result is `Simple` (unmasked)
- **AND** when the operation is `UnmaskedTimesMasked`, the result is `Pedersen` (masked)

#### Scenario: Transcript serialization round-trip
- **WHEN** an `IDkgTranscriptInternal` is serialized with CBOR and deserialized
- **THEN** the result equals the original transcript

#### Scenario: Transcript constant term extraction
- **WHEN** `constant_term()` is called on a transcript
- **THEN** the constant term of the combined commitment is returned
- **AND** this represents the threshold public key for signing operations

---

### Requirement: Canister Threshold Signatures - IDKG Complaints (ic-crypto-internal-threshold-sig-canister-threshold-sig idkg/complaints)

The complaints module enables receivers to generate complaints against dealings that cannot be correctly decrypted, along with verification of those complaints.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/idkg/complaints.rs`

#### Scenario: Complaint generation
- **WHEN** a receiver attempts to decrypt dealings and a dealing's ciphertext is inconsistent with its commitment
- **THEN** an `IDkgComplaintInternal` is generated containing a `ProofOfDLogEquivalence` and a shared secret
- **AND** the complaint proves that the dealing was incorrect without revealing the receiver's secret key

#### Scenario: Complaint generation iterates all dealings
- **WHEN** `generate_complaints` is called with a set of verified dealings
- **THEN** each dealing is decrypted and checked against its commitment
- **AND** a complaint is generated for each dealing that fails the check
- **AND** the complaint seed is derived using `DomainSep::SeedForComplaint(alg, dealer_index)`

#### Scenario: Complaint verification
- **WHEN** a complaint is verified
- **THEN** the `ProofOfDLogEquivalence` is checked against the dealing's ciphertext and commitment
- **AND** a valid complaint proves the dealing was faulty

#### Scenario: Complaint serialization round-trip
- **WHEN** an `IDkgComplaintInternal` is serialized with CBOR and deserialized
- **THEN** the result equals the original complaint

---

### Requirement: Canister Threshold Signatures - MEGa Encryption (ic-crypto-internal-threshold-sig-canister-threshold-sig idkg/mega)

The MEGa (Multi-Encryption Gadget) module implements the encryption scheme used to securely transmit secret shares to individual receivers within IDKG dealings.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/idkg/mega/`

#### Scenario: MEGa key pair generation
- **WHEN** a MEGa key pair is generated from a random number generator
- **THEN** a private key (scalar) and public key (curve point) are produced
- **AND** the public key can be serialized and deserialized

#### Scenario: MEGa encryption of single values
- **WHEN** a single scalar value is encrypted under a receiver's MEGa public key
- **THEN** a `MEGaCiphertextType::Single` ciphertext is produced
- **AND** the ciphertext includes an additive mask derived from a random oracle

#### Scenario: MEGa encryption of value pairs
- **WHEN** a pair of scalars (value + mask for Pedersen commitments) is encrypted
- **THEN** a `MEGaCiphertextType::Pairs` ciphertext is produced

#### Scenario: MEGa decryption and commitment check
- **WHEN** a receiver decrypts a MEGa ciphertext with their private key
- **THEN** the plaintext share is recovered
- **AND** the share is verified against the polynomial commitment
- **AND** if the share is inconsistent, an error is returned enabling complaint generation

#### Scenario: MEGa public key validation on deserialization
- **WHEN** `MEGaPublicKey::deserialize(curve, value)` is called
- **THEN** successful deserialization guarantees the public key is a valid point on the specified curve

#### Scenario: MEGa ciphertext type tag consistency
- **WHEN** a `MEGaCiphertextType` is created
- **THEN** `Single` has tag `"single"` and `Pairs` has tag `"pairs"`

---

### Requirement: Canister Threshold Signatures - Polynomial Commitments (ic-crypto-internal-threshold-sig-canister-threshold-sig)

The commitment system supports two types of polynomial commitments used throughout the threshold signature protocol: Simple (dlog) commitments and Pedersen commitments.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/utils/poly.rs` and `idkg/transcript.rs`

#### Scenario: Simple commitment creation
- **WHEN** a `SimpleCommitment` is created from polynomial coefficients
- **THEN** each commitment point is `g * coefficient_i` where `g` is the group generator
- **AND** the commitment uniquely determines the polynomial's evaluations at any point

#### Scenario: Pedersen commitment creation
- **WHEN** a `PedersenCommitment` is created from polynomial coefficients and masking values
- **THEN** each commitment point is `g * coefficient_i + h * mask_i` where `h` is a second generator
- **AND** the commitment hides the polynomial values (information-theoretically)

#### Scenario: Commitment evaluation at a node index
- **WHEN** `evaluate_at(node_index)` is called on a polynomial commitment
- **THEN** the committed value at that node index is computed from the commitment points
- **AND** this can verify individual secret shares without knowing the polynomial

#### Scenario: Commitment constant term extraction
- **WHEN** `constant_term()` is called on a polynomial commitment
- **THEN** the first coefficient commitment is returned
- **AND** for threshold signatures, this represents the threshold public key

#### Scenario: Polynomial coefficient storage
- **WHEN** a `Polynomial` is constructed
- **THEN** coefficients are stored in little-endian ordering (a_0 at index 0)
- **AND** leading zero coefficients are tolerated in equality comparisons
- **AND** Debug output redacts the coefficient values

---

### Requirement: Canister Threshold Signatures - Zero Knowledge Proofs (ic-crypto-internal-threshold-sig-canister-threshold-sig idkg/zk)

The ZK proofs module provides three zero-knowledge proofs used in the IDKG protocol to ensure dealing correctness.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/idkg/zk.rs`

#### Scenario: ProofOfEqualOpenings
- **WHEN** a `ProofOfEqualOpenings` is created
- **THEN** it proves that a Simple commitment `B = SimpleCom(b)` and a Pedersen commitment `A = PedersenCom(a, r)` satisfy `a = b`
- **AND** the proof consists of a challenge and a response (Fiat-Shamir)
- **AND** the proof does not reveal the committed value or prove knowledge of the opening

#### Scenario: ProofOfProduct
- **WHEN** a `ProofOfProduct` is created
- **THEN** it proves that a Pedersen commitment opens to the product of the openings of a Simple and another Pedersen commitment
- **AND** this is used in `UnmaskedTimesMasked` dealings

#### Scenario: ProofOfDLogEquivalence
- **WHEN** a `ProofOfDLogEquivalence` is created
- **THEN** it proves that two group elements share the same discrete logarithm relationship
- **AND** this is used in complaint generation to prove a dealing is faulty

---

### Requirement: Canister Threshold Signatures - ECDSA Signing (ic-crypto-internal-threshold-sig-canister-threshold-sig signing/ecdsa)

The ECDSA signing module implements threshold ECDSA signature share generation and combination, supporting both secp256k1 and secp256r1 curves.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/ecdsa.rs`

#### Scenario: ECDSA signature share generation
- **WHEN** a signature share is created with a key share, presignature transcript, key transcript, derivation path, hashed message, and randomness
- **THEN** the presignature is rerandomized to prevent bias from malicious nodes
- **AND** the ECDSA conversion function computes the x-coordinate of the presignature point reduced modulo the scalar field order
- **AND** a key tweak is derived from the derivation path for BIP32-compatible key derivation

#### Scenario: ECDSA hash-to-integer conversion
- **WHEN** a hashed message is converted to a scalar for ECDSA
- **THEN** the hash length must match the curve's scalar byte length
- **AND** values larger than the group order are reduced modulo the order via `from_bytes_wide`

#### Scenario: ECDSA presignature rerandomization
- **WHEN** a presignature is rerandomized for signing
- **THEN** the randomizer is derived from a `RandomOracle` with `DomainSep::RerandomizePresig(alg)`
- **AND** inputs include the randomness, hashed message, presignature point, and key tweak
- **AND** this prevents malicious signers from biasing the nonce

#### Scenario: ECDSA curve support
- **WHEN** ECDSA signing is invoked
- **THEN** K256 maps to `IdkgProtocolAlgorithm::EcdsaSecp256k1`
- **AND** P256 maps to `IdkgProtocolAlgorithm::EcdsaSecp256r1`
- **AND** unsupported curves return `CanisterThresholdError::CurveMismatch`

#### Scenario: ECDSA presignature must be RandomUnmasked
- **WHEN** a presignature transcript is used for ECDSA signing
- **THEN** the combined commitment must be `CombinedCommitment::BySummation` with a `PolynomialCommitment::Simple`
- **AND** other commitment types return `CanisterThresholdError::UnexpectedCommitmentType`

---

### Requirement: Canister Threshold Signatures - BIP340 Schnorr Signing (ic-crypto-internal-threshold-sig-canister-threshold-sig signing/bip340)

The BIP340 module implements threshold Schnorr signature share generation conforming to BIP-340 (Bitcoin Taproot) using the secp256k1 curve.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/bip340.rs`

#### Scenario: BIP340 challenge hash computation
- **WHEN** the Fiat-Shamir challenge is computed
- **THEN** the tagged hash `SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || R_x || P_x || msg)` is used
- **AND** the result is interpreted as a scalar modulo the secp256k1 group order via `from_bytes_wide`

#### Scenario: BIP340 even-Y normalization
- **WHEN** a point's Y coordinate is odd
- **THEN** the point is negated to ensure even-Y representation per BIP-340
- **AND** a boolean flag indicates whether negation occurred, so the secret key share can be adjusted accordingly

#### Scenario: Taproot key derivation (BIP-341)
- **WHEN** a Taproot tweak is computed for a public key with a script tree hash
- **THEN** the tagged hash `SHA256(SHA256("TapTweak") || SHA256("TapTweak") || P_x || h)` is used as the tweak scalar

#### Scenario: BIP340 serialization format
- **WHEN** points are serialized for BIP340
- **THEN** `serialize_bip340()` produces x-coordinate-only serialization per the BIP-340 specification

---

### Requirement: Canister Threshold Signatures - EdDSA (Ed25519) Signing (ic-crypto-internal-threshold-sig-canister-threshold-sig signing/eddsa)

The EdDSA module implements threshold Ed25519 signature share generation using the Ed25519 curve.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/eddsa.rs`

#### Scenario: EdDSA challenge hash computation
- **WHEN** the Fiat-Shamir challenge for EdDSA is computed
- **THEN** `SHA-512(R || P || msg)` is used following the Ed25519 specification
- **AND** the SHA-512 output is interpreted in little-endian byte order (reversed before big-endian scalar conversion)

#### Scenario: EdDSA presignature rerandomization
- **WHEN** the presignature is rerandomized for EdDSA signing
- **THEN** the randomization prevents bias from malicious nodes (unlike standard deterministic EdDSA)
- **AND** the rerandomization incorporates the derived key, randomness, and message
- **AND** this follows the approach described in "The many faces of Schnorr" by Victor Shoup (ePrint 2023/1019)

---

### Requirement: Canister Threshold Signatures - Key Derivation (ic-crypto-internal-threshold-sig-canister-threshold-sig signing/key_derivation)

The key derivation module implements extended BIP32/SLIP-0010 key derivation supporting arbitrary-length derivation indices, compatible with standard BIP32 when 4-byte indices are used.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/signing/key_derivation.rs`

#### Scenario: Standard BIP32 derivation path
- **WHEN** `DerivationPath::new_bip32(indices)` is called with 32-bit indices
- **THEN** a derivation path is created with each index as a 4-byte big-endian `DerivationIndex`
- **AND** the derivation is compatible with standard BIP32 / SLIP-0010

#### Scenario: Extended derivation with arbitrary byte strings
- **WHEN** `DerivationPath::new(path)` is called with `DerivationIndex` values of arbitrary byte length
- **THEN** the derivation extends BIP32 to support non-standard index sizes
- **AND** the maximum derivation path length is 255 levels (`MAXIMUM_DERIVATION_PATH_LENGTH`)

#### Scenario: Child key derivation (CKD)
- **WHEN** child key derivation is performed along a path
- **THEN** HMAC-SHA512 is used to compute the child key tweak and chain code at each level
- **AND** if the HMAC output exceeds the group order, the SLIP-0010 convention is followed (skip and increment counter)

#### Scenario: Derive tweak from key transcript
- **WHEN** `derive_tweak` is called with a master public key point
- **THEN** the cumulative tweak scalar and derived chain key are returned
- **AND** the derived public key equals `master_pk + g * tweak`

---

### Requirement: Canister Threshold Signatures - Elliptic Curve Abstraction (ic-crypto-internal-threshold-sig-canister-threshold-sig utils/group)

The group abstraction provides `EccScalar` and `EccPoint` wrapper types supporting K256 (secp256k1), P256 (secp256r1), and Ed25519 curves through a unified interface.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/utils/group.rs` and `group/`

#### Scenario: Multi-curve support
- **WHEN** `EccCurveType` is used
- **THEN** three curves are supported: `K256` (256-bit scalar), `P256` (256-bit scalar), and `Ed25519` (255-bit scalar)
- **AND** operations on mismatched curve types return `CanisterThresholdError::CurveMismatch`

#### Scenario: Hash-to-point
- **WHEN** `EccPoint::hash_to_point(curve, input, domain_separator)` is called
- **THEN** a deterministic point on the specified curve is produced conforming to the IETF hash-to-curve specification

#### Scenario: Scalar from wide bytes
- **WHEN** `EccScalar::from_bytes_wide(curve, bytes)` is called
- **THEN** the input is interpreted as a big-endian integer and reduced modulo the group order

#### Scenario: Node index multiplication optimization
- **WHEN** `EccPoint::mul_by_node_index` is called
- **THEN** a simple square-and-multiply implementation is used instead of constant-time multiplication
- **AND** this is safe because node indices are both small and public

#### Scenario: Curve-specific implementations
- **WHEN** curve operations are performed
- **THEN** K256 is implemented via the `k256` crate
- **AND** P256 is implemented via the `p256` crate
- **AND** Ed25519 is implemented via the `curve25519-dalek` crate

---

### Requirement: Canister Threshold Signatures - Random Oracle (ic-crypto-internal-threshold-sig-canister-threshold-sig utils/ro)

The `RandomOracle` provides a domain-separated, order-independent hash construction based on XMD for use throughout the threshold signature protocol.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/utils/ro.rs`

#### Scenario: Random oracle input ordering independence
- **WHEN** inputs are added to a `RandomOracle` with tagged names
- **THEN** the inputs are sorted by name before hashing
- **AND** the insertion order does not affect the output

#### Scenario: Random oracle typed outputs
- **WHEN** the random oracle output is requested as a scalar, point, or bytestring
- **THEN** the XMD construction produces domain-separated output of the appropriate type
- **AND** each input type has a distinct tag byte: Bytestring=1, Integer=2, Point=3, Scalar=4

#### Scenario: Domain separator uniqueness
- **WHEN** a `RandomOracle` is created with a domain separator
- **THEN** the domain separator must be unique for each usage context
- **AND** the `&'static str` requirement (on `new_with_string_dst`) helps ensure domain separators are compile-time constants

#### Scenario: Input name length limit
- **WHEN** input names are added to the random oracle
- **THEN** names can be at most 255 bytes long
- **AND** names are literal constants that describe the semantic meaning of the input

---

### Requirement: Canister Threshold Signatures - Attack Model (ic-crypto-internal-threshold-sig-canister-threshold-sig)

The canister threshold signature crate explicitly documents its attack model and security considerations.

Path: `rs/crypto/internal/crypto_lib/threshold_sig/canister_threshold_sig/src/lib.rs`

#### Scenario: Timing and cache side-channel protection
- **WHEN** secret-dependent operations are performed
- **THEN** constant-time implementations are used to resist timing and cache-based side channels
- **AND** the `subtle` crate is used for constant-time comparisons and conditional selections

#### Scenario: Public-value optimization exception
- **WHEN** operations involve public values such as node indices
- **THEN** non-constant-time optimizations (e.g., square-and-multiply for `mul_by_node_index`) may be used
- **AND** this exception is explicitly documented

#### Scenario: No power analysis or fault attack protection
- **WHEN** the threat model is considered
- **THEN** no provision is made for power analysis attacks or fault injection attacks
- **AND** this limitation is explicitly documented in the crate-level documentation

---

### Requirement: Crypto Internal Types (ic-crypto-internal-types)

The `ic-crypto-internal-types` crate defines the low-level type representations used across the crypto component, including curve point encodings, encryption types, threshold signature types, and NI-DKG epoch types.

Path: `rs/crypto/internal/crypto_lib/types/`

#### Scenario: Type layering
- **WHEN** internal types are used
- **THEN** external API types wrap internal types as private fields named `internal`
- **AND** internal CSP types wrap even more internal representations
- **AND** this layering prevents external callers from accessing implementation details

#### Scenario: BLS12-381 curve byte representations
- **WHEN** `G1Bytes`, `G2Bytes`, or `FrBytes` are used
- **THEN** they provide fixed-size byte arrays for serialized curve elements
- **AND** the representations match the canonical BLS12-381 encoding

#### Scenario: NI-DKG Epoch type
- **WHEN** an `Epoch` value is used
- **THEN** it represents a forward-secure encryption epoch as a 32-bit value
- **AND** epochs are monotonically increasing and support the range `[0, 2^32 - 1]`

#### Scenario: Zeroize on drop for secret types
- **WHEN** secret key types go out of scope
- **THEN** their memory is securely zeroed via `Zeroize` and `ZeroizeOnDrop` traits

#### Scenario: Forward-secure encryption types
- **WHEN** NI-DKG forward-secure encryption types are used
- **THEN** `CspFsEncryptionPublicKey` and `CspFsEncryptionPop` provide the external interface
- **AND** `FsEncryptionCiphertextBytes` holds the encrypted dealing data

---

### Requirement: TLS Key Material Generation (ic-crypto-internal-tls)

The `ic-crypto-internal-tls` crate provides low-level TLS key material generation, producing Ed25519 key pairs wrapped in X.509 v3 certificates.

Path: `rs/crypto/internal/crypto_lib/tls/`

#### Scenario: TLS certificate and key pair generation
- **WHEN** a TLS key pair and certificate are generated from a seed
- **THEN** an Ed25519 key pair is created deterministically from the seed
- **AND** the public key is embedded in a self-signed X.509 v3 certificate
- **AND** the certificate is DER-encoded as `TlsEd25519CertificateDerBytes`

#### Scenario: TLS secret key format
- **WHEN** a TLS secret key is serialized
- **THEN** the result is a DER-encoded Ed25519 secret key in PKCS#8 v1 format (RFC 5208) as `TlsEd25519SecretKeyDerBytes`
- **AND** the key bytes are protected by `SecretBytes` and zeroized on drop

#### Scenario: TLS certificate validity period
- **WHEN** a TLS certificate is generated
- **THEN** the certificate includes a valid time range (not-before and not-after)
- **AND** `TlsKeyPairAndCertGenerationError::InvalidArguments` is returned for invalid parameters

#### Scenario: TLS certificate subject
- **WHEN** a TLS certificate is generated for a node
- **THEN** the certificate's distinguished name includes the node identifier

---

### Requirement: Crypto Service Provider (ic-crypto-internal-csp)

The `ic-crypto-internal-csp` crate implements the Crypto Service Provider (CSP), which serves as the primary interface between the crypto component and secret key storage. It orchestrates calls to all internal primitive crates and manages keys through a vault abstraction.

Path: `rs/crypto/internal/crypto_service_provider/`

#### Scenario: CSP trait composition
- **WHEN** a type implements `CryptoServiceProvider`
- **THEN** it must implement `CspSigner`, `ThresholdSignatureCspClient`, and `NiDkgCspClient`
- **AND** the `Csp` struct provides the production implementation backed by a `CspVault`

#### Scenario: CSP vault abstraction
- **WHEN** the CSP interacts with secret keys
- **THEN** all operations go through the `CspVault` trait, which supports both local and remote vault implementations
- **AND** `LocalCspVault` manages keys in-process
- **AND** `RemoteCspVault` delegates to a separate vault server process via `run_csp_vault_server`

#### Scenario: Basic signature operations via CSP
- **WHEN** basic signing is requested through the CSP
- **THEN** the vault looks up the secret key by `KeyId`
- **AND** `CspBasicSignatureError::SecretKeyNotFound` is returned if the key does not exist
- **AND** `CspBasicSignatureError::WrongSecretKeyType` is returned if the key type does not match
- **AND** `CspBasicSignatureError::MalformedPublicKey` is returned for invalid public keys

#### Scenario: Basic signature key generation via CSP
- **WHEN** key generation is requested
- **THEN** a new key pair is generated and stored in the vault
- **AND** `CspBasicSignatureKeygenError::DuplicateKeyId` is returned if a key with the same ID already exists

#### Scenario: Multi-signature operations via CSP
- **WHEN** multi-signature operations are requested
- **THEN** the CSP delegates to `ic-crypto-internal-multi-sig-bls12381`
- **AND** `CspMultiSignatureError::UnsupportedAlgorithm` is returned for non-BLS12-381 algorithm IDs
- **AND** `CspMultiSignatureError::SecretKeyNotFound` is returned if the signing key is missing

#### Scenario: Threshold signature operations via CSP
- **WHEN** threshold signature operations are requested
- **THEN** the CSP delegates to the BLS12-381 threshold signature crate
- **AND** key shares are stored in and retrieved from the secret key store
- **AND** `CspThresholdSignError` is returned for signing failures

#### Scenario: NI-DKG operations via CSP
- **WHEN** NI-DKG dealing creation or key generation is requested
- **THEN** the CSP coordinates with the forward-secure encryption crate and Groth20 NIZK crate
- **AND** epoch management ensures forward secrecy of key material

#### Scenario: IDKG and canister threshold operations via CSP
- **WHEN** IDKG dealing, transcript loading, or threshold signing is requested
- **THEN** the CSP delegates to `ic-crypto-internal-threshold-sig-canister-threshold-sig`
- **AND** MEGa key pairs are managed through the vault for encryption/decryption of dealing shares
- **AND** `CspCreateMEGaKeyError` is returned for MEGa key generation failures

#### Scenario: VetKD operations via CSP
- **WHEN** VetKD encrypted key share creation is requested
- **THEN** the CSP delegates to `ic-crypto-internal-bls12-381-vetkd`
- **AND** the `VetKdDerivationContext`, transport public key, and master key are used to produce the `VetKdEncryptedKeyShareContent`

#### Scenario: CSP metrics and logging
- **WHEN** cryptographic operations are performed through the CSP
- **THEN** `CryptoMetrics` from `ic-crypto-internal-logmon` are recorded
- **AND** the `ReplicaLogger` is used for operation logging

#### Scenario: Public and secret key store management
- **WHEN** the CSP manages keys
- **THEN** the `public_key_store` module manages public key persistence
- **AND** the `secret_key_store` module (implementing `SecretKeyStore` trait) manages secret key storage
- **AND** key retrieval is performed by `KeyId`

---

### Requirement: Crypto Logging and Monitoring (ic-crypto-internal-logmon)

The `ic-crypto-internal-logmon` crate provides logging and Prometheus metrics instrumentation for the crypto component.

Path: `rs/crypto/internal/logmon/`

#### Scenario: Crypto metrics collection
- **WHEN** cryptographic operations are performed
- **THEN** `CryptoMetrics` tracks operation counts, durations, and key counts via Prometheus metrics
- **AND** metrics are organized by operation type (signing, key generation, DKG, etc.)

#### Scenario: Key count reporting
- **WHEN** `KeyCounts` are reported
- **THEN** the number of keys of each type in the key store is available as a metric

---

### Requirement: Crypto Test Vectors (ic-crypto-internal-test-vectors)

The `ic-crypto-internal-test-vectors` crate provides static test vectors for verifying crypto implementations, with no dependencies on other IC crates.

Path: `rs/crypto/internal/test_vectors/`

#### Scenario: Ed25519 test vectors
- **WHEN** Ed25519 implementation is tested
- **THEN** known-answer test vectors from the `ed25519` module are available for key generation, signing, and verification

#### Scenario: Multi-BLS12-381 test vectors
- **WHEN** multi-signature BLS12-381 implementation is tested
- **THEN** test vectors from the `multi_bls12_381` module for key pairs, signatures, and combined signatures are available

#### Scenario: General test data
- **WHEN** crypto implementations are tested
- **THEN** the `test_data` module provides general-purpose test data
- **AND** the `unhex` module provides hex decoding utilities for test vectors

#### Scenario: No IC crate dependencies
- **WHEN** the test vectors crate is compiled
- **THEN** it has zero dependencies on other `ic-*` crates
- **AND** this ensures test vectors are independently verifiable

---

### Requirement: Secret Key Memory Protection

Across all internal primitive crates, secret key material must be protected in memory with secure zeroization and redacted debug output.

#### Scenario: Secret key zeroization on drop
- **WHEN** any secret key type (`SecretKeyBytes`, `Seed`, `FsEncryptionSecretKey`, `MEGaPrivateKey`, `TlsEd25519SecretKeyDerBytes`) goes out of scope
- **THEN** the memory holding the secret material is securely zeroed via `ZeroizeOnDrop`

#### Scenario: Secret key debug redaction
- **WHEN** any secret key type is formatted with `Debug`
- **THEN** the output does not reveal secret key bytes
- **AND** types like `Seed` show `"Seed - REDACTED"`, `SecretShares` show the variant name with `"REDACTED"`, and `BTENodeBytes` redact secret components

#### Scenario: Secret array wrapper usage
- **WHEN** Ed25519 or ECDSA secret keys are stored
- **THEN** they are wrapped in `SecretArray` (from `ic-crypto-secrets-containers`) which provides controlled exposure via `expose_secret()`
- **AND** accidental logging or display of secret material is prevented
