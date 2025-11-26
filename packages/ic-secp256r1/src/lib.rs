#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]

//! A crate with handling of ECDSA keys over the secp256r1 curve

use p256::{AffinePoint, NistP256, Scalar, elliptic_curve::Curve};
use rand::{CryptoRng, RngCore};
use std::sync::LazyLock;
use zeroize::ZeroizeOnDrop;

/// An error indicating that decoding a key failed
#[derive(Clone, Debug)]
pub enum KeyDecodingError {
    /// The key encoding was invalid in some way
    InvalidKeyEncoding(String),
    /// The PEM encoding was invalid
    InvalidPemEncoding(String),
    /// The PEM encoding had an unexpected label
    UnexpectedPemLabel(String),
}

static ECDSA_OID: LazyLock<simple_asn1::OID> =
    LazyLock::new(|| simple_asn1::oid!(1, 2, 840, 10045, 2, 1));

/// See RFC 5759 section 3.2
static SECP256R1_OID: LazyLock<simple_asn1::OID> =
    LazyLock::new(|| simple_asn1::oid!(1, 2, 840, 10045, 3, 1, 7));

/// A component of a derivation path
#[derive(Clone, Debug)]
pub struct DerivationIndex(pub Vec<u8>);

/// Derivation Path
///
/// A derivation path is simply a sequence of DerivationIndex
#[derive(Clone, Debug)]
pub struct DerivationPath {
    path: Vec<DerivationIndex>,
}

impl DerivationPath {
    /// Create a BIP32-style derivation path
    ///
    /// See SLIP-10 <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
    /// for details of derivation paths
    pub fn new_bip32(bip32: &[u32]) -> Self {
        let mut path = Vec::with_capacity(bip32.len());
        for n in bip32 {
            path.push(DerivationIndex(n.to_be_bytes().to_vec()));
        }
        Self::new(path)
    }

    /// Create a free-form derivation path
    pub fn new(path: Vec<DerivationIndex>) -> Self {
        Self { path }
    }

    /// Create a path from a canister ID and a user provided path
    pub fn from_canister_id_and_path(canister_id: &[u8], path: &[Vec<u8>]) -> Self {
        let mut vpath = Vec::with_capacity(1 + path.len());
        vpath.push(DerivationIndex(canister_id.to_vec()));

        for n in path {
            vpath.push(DerivationIndex(n.to_vec()));
        }
        Self::new(vpath)
    }

    /// Return the length of this path
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Return if this path is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the components of the derivation path
    pub fn path(&self) -> &[DerivationIndex] {
        &self.path
    }

    fn ckd(idx: &[u8], input: &[u8], chain_code: &[u8; 32]) -> ([u8; 32], Scalar) {
        use hmac::{Hmac, Mac};
        use p256::elliptic_curve::ops::Reduce;
        use sha2::Sha512;

        let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code)
            .expect("HMAC-SHA-512 should accept 256 bit key");

        hmac.update(input);
        hmac.update(idx);

        let hmac_output: [u8; 64] = hmac.finalize().into_bytes().into();

        let fb: p256::FieldBytes = p256::FieldBytes::from_slice(&hmac_output[..32]);
        let next_offset: p256::Scalar = Reduce::reduce(fb);
        let next_chain_key: [u8; 32] = hmac_output[32..].to_vec().try_into().expect("Correct size");

        // If iL >= order, try again with the "next" index as described in SLIP-10
        if next_offset.to_bytes().to_vec() != hmac_output[..32] {
            let mut next_input = [0u8; 33];
            next_input[0] = 0x01;
            next_input[1..].copy_from_slice(&next_chain_key);
            Self::ckd(idx, &next_input, chain_code)
        } else {
            (next_chain_key, next_offset)
        }
    }

    fn ckd_pub(
        idx: &[u8],
        pt: AffinePoint,
        chain_code: &[u8; 32],
    ) -> ([u8; 32], Scalar, AffinePoint) {
        use p256::ProjectivePoint;
        use p256::elliptic_curve::group::GroupEncoding;

        let mut ckd_input = pt.to_bytes();

        let pt: ProjectivePoint = pt.into();

        loop {
            let (next_chain_code, next_offset) = Self::ckd(idx, &ckd_input, chain_code);
            let next_offset_pt: ProjectivePoint = Group::mul_by_generator(&next_offset);
            let next_pt = (pt + next_offset_pt).to_affine();

            // If the new key is not infinity, we're done: return the new key
            if !bool::from(next_pt.is_identity()) {
                return (next_chain_code, next_offset, next_pt);
            }

            // Otherwise set up the next input as defined by SLIP-0010
            ckd_input[0] = 0x01;
            ckd_input[1..].copy_from_slice(&next_chain_code);
        }
    }

    fn derive_offset(
        &self,
        pt: AffinePoint,
        chain_code: &[u8; 32],
    ) -> (AffinePoint, Scalar, [u8; 32]) {
        let mut offset = Scalar::ZERO;
        let mut pt = pt;
        let mut chain_code = *chain_code;

        for idx in self.path() {
            let (next_chain_code, next_offset, next_pt) = Self::ckd_pub(&idx.0, pt, &chain_code);
            chain_code = next_chain_code;
            pt = next_pt;
            offset = offset.add(&next_offset);
        }

        (pt, offset, chain_code)
    }
}

const PEM_HEADER_PKCS8: &str = "PRIVATE KEY";
const PEM_HEADER_RFC5915: &str = "EC PRIVATE KEY";

/// DER encode the public point into a SubjectPublicKeyInfo
///
/// The public_point can be either the compressed or uncompressed format
fn der_encode_ecdsa_spki_pubkey(public_point: &[u8]) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256r1_oid = ASN1Block::ObjectIdentifier(0, SECP256R1_OID.clone());
    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256r1_oid]);

    let key_bytes = ASN1Block::BitString(0, public_point.len() * 8, public_point.to_vec());

    let blocks = vec![alg_id, key_bytes];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

fn der_encode_rfc5915_privatekey(
    secret_key: &[u8],
    include_curve: bool,
    public_key: Option<Vec<u8>>,
) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let ecdsa_version = ASN1Block::Integer(0, BigInt::new(num_bigint::Sign::Plus, vec![1]));
    let key_bytes = ASN1Block::OctetString(0, secret_key.to_vec());
    let mut key_blocks = vec![ecdsa_version, key_bytes];

    if include_curve {
        let tag0 = BigUint::new(vec![0]);
        let secp256r1_oid = Box::new(ASN1Block::ObjectIdentifier(0, SECP256R1_OID.clone()));
        let oid_param = ASN1Block::Explicit(ASN1Class::ContextSpecific, 0, tag0, secp256r1_oid);
        key_blocks.push(oid_param);
    }

    if let Some(public_key) = public_key {
        let tag1 = BigUint::new(vec![1]);
        let pk_bs = Box::new(ASN1Block::BitString(
            0,
            public_key.len() * 8,
            public_key.to_vec(),
        ));
        let pk_param = ASN1Block::Explicit(ASN1Class::ContextSpecific, 0, tag1, pk_bs);
        key_blocks.push(pk_param);
    }

    to_der(&ASN1Block::Sequence(0, key_blocks))
        .expect("Failed to encode ECDSA private key as RFC 5915 DER")
}

fn der_encode_pkcs8_rfc5208_private_key(secret_key: &[u8]) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let pkcs8_version = ASN1Block::Integer(0, BigInt::new(num_bigint::Sign::Plus, vec![0]));
    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256r1_oid = ASN1Block::ObjectIdentifier(0, SECP256R1_OID.clone());

    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256r1_oid]);

    let octet_string =
        ASN1Block::OctetString(0, der_encode_rfc5915_privatekey(secret_key, false, None));

    let blocks = vec![pkcs8_version, alg_id, octet_string];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

fn der_decode_rfc5915_privatekey(der: &[u8]) -> Result<Vec<u8>, KeyDecodingError> {
    use simple_asn1::*;

    let der = simple_asn1::from_der(der)
        .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;

    let seq = match der.len() {
        1 => der.first(),
        x => {
            return Err(KeyDecodingError::InvalidKeyEncoding(format!(
                "Unexpected number of elements {x}"
            )));
        }
    };

    if let Some(ASN1Block::Sequence(_, seq)) = seq {
        // mandatory field: version, should be equal to 1
        match seq.first() {
            Some(ASN1Block::Integer(_, _version)) => {}
            _ => {
                return Err(KeyDecodingError::InvalidKeyEncoding(
                    "Version field was not an integer".to_string(),
                ));
            }
        };

        // mandatory field: the private key
        let private_key = match seq.get(1) {
            Some(ASN1Block::OctetString(_, sk)) => sk.clone(),
            _ => {
                return Err(KeyDecodingError::InvalidKeyEncoding(
                    "Not an octet string".to_string(),
                ));
            }
        };

        // following may be optional params and/or public key, which
        // we ignore

        Ok(private_key)
    } else {
        Err(KeyDecodingError::InvalidKeyEncoding(
            "Not a sequence".to_string(),
        ))
    }
}

fn pem_encode(raw: &[u8], label: &'static str) -> String {
    pem::encode(&pem::Pem::new(label, raw))
}

/// An ECDSA private key
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    key: p256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        Self::generate_using_rng(&mut rng)
    }

    /// Generate an INSECURE key usable for testing
    pub fn generate_insecure_key_for_testing(seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        Self::generate_using_rng(&mut rng)
    }

    /// Generate a new random private key using some provided RNG
    pub fn generate_using_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = p256::ecdsa::SigningKey::random(rng);
        Self { key }
    }

    /// Deserialize a private key encoded in SEC1 format
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let byte_array: [u8; <NistP256 as Curve>::FieldBytesSize::USIZE] =
            bytes.try_into().map_err(|_e| {
                KeyDecodingError::InvalidKeyEncoding(format!("invalid key size = {}.", bytes.len()))
            })?;

        let key = p256::ecdsa::SigningKey::from_bytes(&GenericArray::from(byte_array))
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in RFC 5915 format
    pub fn deserialize_rfc5915_der(der: &[u8]) -> Result<Self, KeyDecodingError> {
        let key = der_decode_rfc5915_privatekey(der)?;
        Self::deserialize_sec1(&key)
    }

    /// Deserialize a private key encoded in PKCS8 format
    pub fn deserialize_pkcs8_der(der: &[u8]) -> Result<Self, KeyDecodingError> {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in PKCS8 format with PEM encoding
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der =
            pem::parse(pem).map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{e:?}")))?;
        if der.tag() != PEM_HEADER_PKCS8 {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag().to_string()));
        }

        Self::deserialize_pkcs8_der(der.contents())
    }

    /// Deserialize a private key encoded in RFC 5915 format with PEM encoding
    pub fn deserialize_rfc5915_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der =
            pem::parse(pem).map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{e:?}")))?;
        if der.tag() != PEM_HEADER_RFC5915 {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag().to_string()));
        }

        Self::deserialize_rfc5915_der(der.contents())
    }

    /// Serialize the private key as RFC 5915
    pub fn serialize_rfc5915_der(&self) -> Vec<u8> {
        let sk = self.serialize_sec1();
        let pk = self.public_key().serialize_sec1(false);
        der_encode_rfc5915_privatekey(&sk, true, Some(pk))
    }

    /// Serialize the private key as RFC5915 format in PEM encoding
    pub fn serialize_rfc5915_pem(&self) -> String {
        pem_encode(&self.serialize_rfc5915_der(), PEM_HEADER_RFC5915)
    }

    /// Serialize the private key to a simple bytestring
    ///
    /// This uses the SEC1 encoding, which is just the representation
    /// of the secret integer in a 32-byte array, encoding it using
    /// big-endian notation.
    pub fn serialize_sec1(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// Serialize the private key as PKCS8 format in DER encoding
    pub fn serialize_pkcs8_der(&self) -> Vec<u8> {
        der_encode_pkcs8_rfc5208_private_key(&self.serialize_sec1())
    }

    /// Serialize the private key as PKCS8 format in PEM encoding
    pub fn serialize_pkcs8_pem(&self) -> String {
        pem_encode(&self.serialize_pkcs8_der(), PEM_HEADER_PKCS8)
    }

    /// Sign a message
    ///
    /// The message is hashed with SHA-256
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        use p256::ecdsa::{Signature, signature::Signer};
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().into()
    }

    /// Sign a message digest
    pub fn sign_digest(&self, digest: &[u8]) -> Option<[u8; 64]> {
        if digest.len() < 16 {
            // p256 arbitrarily rejects digests that are < 128 bits
            return None;
        }

        use p256::ecdsa::{Signature, signature::hazmat::PrehashSigner};
        let sig: Signature = self
            .key
            .sign_prehash(digest)
            .expect("Failed to sign digest");
        Some(sig.to_bytes().into())
    }

    /// Return the public key corresponding to this private key
    pub fn public_key(&self) -> PublicKey {
        let key = self.key.verifying_key();
        PublicKey { key: *key }
    }

    /// Derive a private key from this private key using a derivation path
    ///
    /// As long as each index of the derivation path is a 4-byte input with the highest
    /// bit cleared, this derivation scheme matches SLIP-10
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (Self, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a private key from this private key using a derivation path
    /// and chain code
    ///
    /// As long as each index of the derivation path is a 4-byte input with the highest
    /// bit cleared, this derivation scheme matches SLIP-10
    ///
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        use p256::NonZeroScalar;

        let public_key: AffinePoint = *self.key.verifying_key().as_affine();
        let (_pt, offset, derived_chain_code) =
            derivation_path.derive_offset(public_key, chain_code);

        let derived_scalar = self.key.as_nonzero_scalar().as_ref().add(&offset);

        let nz_ds =
            NonZeroScalar::new(derived_scalar).expect("Derivation always produces non-zero sum");

        let derived_key = Self {
            key: p256::ecdsa::SigningKey::from(nz_ds),
        };

        (derived_key, derived_chain_code)
    }
}

/// An ECDSA public key
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKey {
    key: p256::ecdsa::VerifyingKey,
}

impl PublicKey {
    /// Deserialize a public key stored in SEC1 format
    ///
    /// This is just the encoding of the point. Both compressed and uncompressed
    /// points are accepted
    ///
    /// See SEC1 <https://www.secg.org/sec1-v2.pdf> section 2.3.3 for details of the format
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in DER SubjectPublicKeyInfo format
    pub fn deserialize_der(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        use p256::pkcs8::DecodePublicKey;
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{e:?}")))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in PEM SubjectPublicKeyInfo format
    pub fn deserialize_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der =
            pem::parse(pem).map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{e:?}")))?;
        if der.tag() != "PUBLIC KEY" {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag().to_string()));
        }

        Self::deserialize_der(der.contents())
    }

    /// Serialize a public key in SEC1 format
    ///
    /// The point can optionally be compressed
    ///
    /// See SEC1 <https://www.secg.org/sec1-v2.pdf> section 2.3.3 for details of the format
    pub fn serialize_sec1(&self, compressed: bool) -> Vec<u8> {
        self.key.to_encoded_point(compressed).to_bytes().to_vec()
    }

    /// Serialize a public key in DER as a SubjectPublicKeyInfo
    pub fn serialize_der(&self) -> Vec<u8> {
        der_encode_ecdsa_spki_pubkey(&self.serialize_sec1(false))
    }

    /// Serialize a public key in PEM encoding of a SubjectPublicKeyInfo
    pub fn serialize_pem(&self) -> String {
        pem_encode(&self.serialize_der(), "PUBLIC KEY")
    }

    /// Verify a (message,signature) pair
    ///
    /// Be aware that this verification does not ensure non-malleability
    ///
    /// Some usages of ECDSA rely on non-malleability properties of ECDSA.  This
    /// particularly arises in the context of crypto currencies of various
    /// types. ECDSA signatures are usually malleable, in that if (r,s) is a
    /// valid signature, then (r,-s) is also valid. To avoid this malleability,
    /// some systems require that s be "normalized" to the smallest value.
    ///
    /// This normalization is quite common on secp256k1, but is virtually
    /// unknown and unimplemented for secp256r1. The vast majority of secp256r1
    /// signatures will not be normalized. Thus this verification *does not*
    /// ensure any non-malleability properties.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        let signature = match p256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        self.key.verify(message, &signature).is_ok()
    }

    /// Verify a (message digest,signature) pair
    pub fn verify_signature_prehashed(&self, digest: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let signature = match p256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        self.key.verify_prehash(digest, &signature).is_ok()
    }

    /// Derive a public key from this public key using a derivation path
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (Self, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a public key from this public key using a derivation path
    /// and chain code
    ///
    /// This derivation matches SLIP-10
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        let public_key: AffinePoint = *self.key.as_affine();
        let (pt, _offset, chain_code) = derivation_path.derive_offset(public_key, chain_code);

        let derived_key = Self {
            key: p256::ecdsa::VerifyingKey::from(
                p256::PublicKey::from_affine(pt).expect("Derived point is valid"),
            ),
        };

        (derived_key, chain_code)
    }
}
