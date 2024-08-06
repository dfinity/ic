#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![forbid(missing_docs)]

//! A crate with handling of ECDSA keys over the secp256k1 curve

use k256::{
    elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        Curve,
    },
    AffinePoint, Scalar, Secp256k1,
};
use rand::{CryptoRng, RngCore};
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

impl std::fmt::Display for KeyDecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for KeyDecodingError {}

lazy_static::lazy_static! {

    /// See RFC 3279 section 2.3.5
    static ref ECDSA_OID: simple_asn1::OID = simple_asn1::oid!(1, 2, 840, 10045, 2, 1);

    /// See "SEC 2: Recommended Elliptic Curve Domain Parameters"
    /// Section A.2.1
    /// https://www.secg.org/sec2-v2.pdf
    static ref SECP256K1_OID: simple_asn1::OID = simple_asn1::oid!(1, 3, 132, 0, 10);
}

/// A component of a derivation path
#[derive(Debug, Clone)]
pub struct DerivationIndex(pub Vec<u8>);

/// Derivation Path
///
/// A derivation path is simply a sequence of DerivationIndex
#[derive(Debug, Clone)]
pub struct DerivationPath {
    path: Vec<DerivationIndex>,
}

impl DerivationPath {
    /// Create a BIP32-style derivation path
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
        use k256::{elliptic_curve::ops::Reduce, sha2::Sha512};

        let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code)
            .expect("HMAC-SHA-512 should accept 256 bit key");

        hmac.update(input);
        hmac.update(idx);

        let hmac_output: [u8; 64] = hmac.finalize().into_bytes().into();

        let fb = k256::FieldBytes::from_slice(&hmac_output[..32]);
        let next_offset = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(fb);
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
        use k256::elliptic_curve::{
            group::prime::PrimeCurveAffine, group::GroupEncoding, ops::MulByGenerator,
        };
        use k256::ProjectivePoint;

        let mut ckd_input = pt.to_bytes();

        let pt: ProjectivePoint = pt.into();

        loop {
            let (next_chain_code, next_offset) = Self::ckd(idx, &ckd_input, chain_code);

            let next_pt = (pt + k256::ProjectivePoint::mul_by_generator(&next_offset)).to_affine();

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

/*
RFC 5915 <https://www.rfc-editor.org/rfc/rfc5915> specifies how to
encode ECC private keys in ASN.1

Ordinarily this encoding is used embedded within a PKCS #8 ASN.1
PrivateKeyInfo block <https://www.rfc-editor.org/rfc/rfc5208>.
However OpenSSL's command line utility by default uses the "bare" RFC
5915 ECPrivateKey structure to represent ECDSA keys, and as a
consequence many utilities originally written using OpenSSL use this
format instead of PKCS #8.

If the RFC 5915 block is destined to be included in a PKCS #8 encoding,
then we omit the curve parameter, as the curve is instead specified in
the PKCS #8 privateKeyAlgorithm field. This is controlled by the `include_curve`
parameter.

The public key can be optionally specified in the ECPrivateKey structure;
if the `public_key` argument is `Some` then it is included.
*/
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
        let secp256k1_oid = Box::new(ASN1Block::ObjectIdentifier(0, SECP256K1_OID.clone()));
        let oid_param = ASN1Block::Explicit(ASN1Class::ContextSpecific, 0, tag0, secp256k1_oid);
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

fn der_decode_rfc5915_privatekey(der: &[u8]) -> Result<Vec<u8>, KeyDecodingError> {
    use simple_asn1::*;

    let der = simple_asn1::from_der(der)
        .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;

    let seq = match der.len() {
        1 => der.first(),
        x => {
            return Err(KeyDecodingError::InvalidKeyEncoding(format!(
                "Unexpected number of elements {}",
                x
            )))
        }
    };

    if let Some(ASN1Block::Sequence(_, seq)) = seq {
        // mandatory field: version, should be equal to 1
        match seq.first() {
            Some(ASN1Block::Integer(_, _version)) => {}
            _ => {
                return Err(KeyDecodingError::InvalidKeyEncoding(
                    "Version field was not an integer".to_string(),
                ))
            }
        };

        // mandatory field: the private key
        let private_key = match seq.get(1) {
            Some(ASN1Block::OctetString(_, sk)) => sk.clone(),
            _ => {
                return Err(KeyDecodingError::InvalidKeyEncoding(
                    "Not an octet string".to_string(),
                ))
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

fn der_encode_pkcs8_rfc5208_private_key(secret_key: &[u8]) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let pkcs8_version = ASN1Block::Integer(0, BigInt::new(num_bigint::Sign::Plus, vec![0]));
    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256k1_oid = ASN1Block::ObjectIdentifier(0, SECP256K1_OID.clone());

    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256k1_oid]);

    let octet_string =
        ASN1Block::OctetString(0, der_encode_rfc5915_privatekey(secret_key, false, None));

    let blocks = vec![pkcs8_version, alg_id, octet_string];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

/// DER encode the public point into a SubjectPublicKeyInfo
///
/// The public_point can be either the compressed or uncompressed format
fn der_encode_ecdsa_spki_pubkey(public_point: &[u8]) -> Vec<u8> {
    use simple_asn1::*;

    // simple_asn1::to_der can only fail if you use an invalid object identifier
    // so to avoid returning a Result from this function we use expect

    let ecdsa_oid = ASN1Block::ObjectIdentifier(0, ECDSA_OID.clone());
    let secp256k1_oid = ASN1Block::ObjectIdentifier(0, SECP256K1_OID.clone());
    let alg_id = ASN1Block::Sequence(0, vec![ecdsa_oid, secp256k1_oid]);

    let key_bytes = ASN1Block::BitString(0, public_point.len() * 8, public_point.to_vec());

    let blocks = vec![alg_id, key_bytes];

    simple_asn1::to_der(&ASN1Block::Sequence(0, blocks))
        .expect("Failed to encode ECDSA private key as DER")
}

fn pem_encode(raw: &[u8], label: &'static str) -> String {
    pem::encode(&pem::Pem {
        tag: label.to_string(),
        contents: raw.to_vec(),
    })
}

/// An ECDSA private key
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    key: k256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_using_rng(&mut rng)
    }

    /// Generate a new random private key using some provided RNG
    pub fn generate_using_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = k256::ecdsa::SigningKey::random(rng);
        Self { key }
    }

    /// Deserialize a private key encoded in SEC1 format
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let byte_array: [u8; <Secp256k1 as Curve>::FieldBytesSize::USIZE] =
            bytes.try_into().map_err(|_e| {
                KeyDecodingError::InvalidKeyEncoding(format!("invalid key size = {}.", bytes.len()))
            })?;

        let key = k256::ecdsa::SigningKey::from_bytes(&GenericArray::from(byte_array))
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in PKCS8 format
    pub fn deserialize_pkcs8_der(der: &[u8]) -> Result<Self, KeyDecodingError> {
        use k256::pkcs8::DecodePrivateKey;
        let key = k256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a private key encoded in PKCS8 format with PEM encoding
    pub fn deserialize_pkcs8_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != PEM_HEADER_PKCS8 {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_pkcs8_der(&der.contents)
    }

    /// Deserialize a private key encoded in RFC 5915 format
    pub fn deserialize_rfc5915_der(der: &[u8]) -> Result<Self, KeyDecodingError> {
        let key = der_decode_rfc5915_privatekey(der)?;
        Self::deserialize_sec1(&key)
    }

    /// Deserialize a private key encoded in RFC 5915 format with PEM encoding
    pub fn deserialize_rfc5915_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != PEM_HEADER_RFC5915 {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag));
        }
        Self::deserialize_rfc5915_der(&der.contents)
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

    /// Serialize the private key as RFC 5915 in DER encoding
    pub fn serialize_rfc5915_der(&self) -> Vec<u8> {
        let sk = self.serialize_sec1();
        let pk = self.public_key().serialize_sec1(false);
        der_encode_rfc5915_privatekey(&sk, true, Some(pk))
    }

    /// Serialize the private key as RFC 5915 in PEM encoding
    pub fn serialize_rfc5915_pem(&self) -> String {
        pem_encode(&self.serialize_rfc5915_der(), PEM_HEADER_RFC5915)
    }

    /// Sign a message
    ///
    /// The message is hashed with SHA-256 and the signature is
    /// normalized (using the minimum-s approach of BitCoin)
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        use k256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().into()
    }

    /// Sign a message digest
    ///
    /// The signature is normalized (using the minimum-s approach of BitCoin)
    pub fn sign_digest(&self, digest: &[u8]) -> Option<[u8; 64]> {
        if digest.len() < 16 {
            // k256 arbitrarily rejects digests that are < 128 bits
            return None;
        }

        use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
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
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold ECDSA with secp256k1 and BIP340 Schnorr
    ///
    /// As long as each index of the derivation path is a 4-byte input with the highest
    /// bit cleared, this derivation scheme matches BIP32 and SLIP-10
    ///
    /// See <https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-ecdsa_public_key>
    /// for details on the derivation scheme.
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (Self, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a private key from this private key using a derivation path
    /// and chain code
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold ECDSA with secp256k1 and BIP340 Schnorr
    ///
    /// As long as each index of the derivation path is a 4-byte input with the highest
    /// bit cleared, this derivation scheme matches BIP32 and SLIP-10
    ///
    /// See <https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-ecdsa_public_key>
    /// for details on the derivation scheme.
    ///
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        use k256::NonZeroScalar;

        let public_key: AffinePoint = *self.key.verifying_key().as_affine();
        let (_pt, offset, derived_chain_code) =
            derivation_path.derive_offset(public_key, chain_code);

        let derived_scalar = self.key.as_nonzero_scalar().as_ref().add(&offset);

        let nz_ds =
            NonZeroScalar::new(derived_scalar).expect("Derivation always produces non-zero sum");

        let derived_key = Self {
            key: k256::ecdsa::SigningKey::from(nz_ds),
        };

        (derived_key, derived_chain_code)
    }
}

/// An ECDSA public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: k256::ecdsa::VerifyingKey,
}

impl PublicKey {
    /// Deserialize a public key stored in SEC1 format
    ///
    /// This is just the encoding of the point. Both compressed and uncompressed
    /// points are accepted
    ///
    /// See SEC1 <https://www.secg.org/sec1-v2.pdf> section 2.3.3 for details of the format
    pub fn deserialize_sec1(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in DER SubjectPublicKeyInfo format
    pub fn deserialize_der(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        use k256::pkcs8::DecodePublicKey;
        let key = k256::ecdsa::VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| KeyDecodingError::InvalidKeyEncoding(format!("{:?}", e)))?;
        Ok(Self { key })
    }

    /// Deserialize a public key stored in PEM SubjectPublicKeyInfo format
    pub fn deserialize_pem(pem: &str) -> Result<Self, KeyDecodingError> {
        let der = pem::parse(pem)
            .map_err(|e| KeyDecodingError::InvalidPemEncoding(format!("{:?}", e)))?;
        if der.tag != "PUBLIC KEY" {
            return Err(KeyDecodingError::UnexpectedPemLabel(der.tag));
        }

        Self::deserialize_der(&der.contents)
    }

    /// Serialize a public key in SEC1 format
    ///
    /// The point can optionally be compressed
    ///
    /// See SEC1 <https://www.secg.org/sec1-v2.pdf> section 2.3.3 for details
    pub fn serialize_sec1(&self, compressed: bool) -> Vec<u8> {
        self.key.to_encoded_point(compressed).as_bytes().to_vec()
    }

    /// Serialize a public key in DER as a SubjectPublicKeyInfo
    pub fn serialize_der(&self) -> Vec<u8> {
        der_encode_ecdsa_spki_pubkey(&self.serialize_sec1(false))
    }

    /// Serialize a public key in PEM encoding of a SubjectPublicKeyInfo
    pub fn serialize_pem(&self) -> String {
        pem_encode(&self.serialize_der(), "PUBLIC KEY")
    }

    /// Verify a (message,signature) pair, requiring s-normalization
    ///
    /// If used to verify signatures generated by a library that does not
    /// perform s-normalization, this function will reject roughly half of all
    /// signatures.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;
        let signature = match k256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        /*
         * In k256 0.11 and earlier, verify required that s be normalized. There is a regression in
         * k256 0.12 (https://github.com/RustCrypto/elliptic-curves/issues/908) which causes either s
         * to be accepted. Until this is fixed, include an explicit check on the sign of s.
         */
        if signature.normalize_s().is_some() {
            return false;
        }

        self.key.verify(message, &signature).is_ok()
    }

    /// Verify a (message,signature) pair
    ///
    /// The message is hashed with SHA-256
    ///
    /// This accepts signatures without s-normalization
    ///
    /// ECDSA signatures are a tuple of integers (r,s) which satisfy a certain
    /// equation which involves also the public key and the message.  A quirk of
    /// ECDSA is that if (r,s) is a valid signature then (r,-s) is also a valid
    /// signature (here negation is modulo the group order).
    ///
    /// This means that given a valid ECDSA signature, it is possible to create
    /// a "new" ECDSA signature that is also valid, without having access to the
    /// public key. Unlike `verify_signature`, this function accepts either `s`
    /// value.
    pub fn verify_signature_with_malleability(&self, message: &[u8], signature: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;
        let signature = match k256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        if let Some(normalized) = signature.normalize_s() {
            self.key.verify(message, &normalized).is_ok()
        } else {
            self.key.verify(message, &signature).is_ok()
        }
    }

    /// Verify a (message digest,signature) pair
    pub fn verify_signature_prehashed(&self, digest: &[u8], signature: &[u8]) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signature = match k256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        /*
         * In k256 0.11 and earlier, verify required that s be normalized. There is a regression in
         * k256 0.12 (https://github.com/RustCrypto/elliptic-curves/issues/908) which causes either s
         * to be accepted. Until this is fixed, include an explicit check on the sign of s.
         */
        if signature.normalize_s().is_some() {
            return false;
        }

        self.key.verify_prehash(digest, &signature).is_ok()
    }

    /// Verify a (message digest,signature) pair
    ///
    /// This accepts signatures without s-normalization
    ///
    /// ECDSA signatures are a tuple of integers (r,s) which satisfy a certain
    /// equation which involves also the public key and the message.  A quirk of
    /// ECDSA is that if (r,s) is a valid signature then (r,-s) is also a valid
    /// signature (here negation is modulo the group order).
    ///
    /// This means that given a valid ECDSA signature, it is possible to create
    /// a "new" ECDSA signature that is also valid, without having access to the
    /// public key. Unlike `verify_signature_prehashed`, this function accepts either `s`
    /// value.
    pub fn verify_signature_prehashed_with_malleability(
        &self,
        digest: &[u8],
        signature: &[u8],
    ) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signature = match k256::ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        if let Some(normalized) = signature.normalize_s() {
            self.key.verify_prehash(digest, &normalized).is_ok()
        } else {
            self.key.verify_prehash(digest, &signature).is_ok()
        }
    }

    /// Determines the [`RecoveryId`] for a given public key, digest and signature.
    ///
    /// The recovery cannot fail if the parameters are correct, meaning that
    /// `signature` corresponds to a signature on the given `digest`
    /// with the secret key associated with this `PublicKey`.
    ///
    /// # Errors
    /// See [`RecoveryError`] for details.
    pub fn try_recovery_from_digest(
        &self,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<RecoveryId, RecoveryError> {
        let signature = k256::ecdsa::Signature::from_slice(signature)
            .map_err(|e| RecoveryError::SignatureParseError(e.to_string()))?;
        k256::ecdsa::RecoveryId::trial_recovery_from_prehash(&self.key, digest, &signature)
            .map(|recid| RecoveryId { recid })
            .map_err(|e| RecoveryError::WrongParameters(e.to_string()))
    }

    /// Derive a public key from this public key using a derivation path
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold ECDSA with secp256k1 and BIP340 Schnorr
    ///
    pub fn derive_subkey(&self, derivation_path: &DerivationPath) -> (Self, [u8; 32]) {
        let chain_code = [0u8; 32];
        self.derive_subkey_with_chain_code(derivation_path, &chain_code)
    }

    /// Derive a public key from this public key using a derivation path
    /// and chain code
    ///
    /// This is the same derivation system used by the Internet Computer when
    /// deriving subkeys for threshold ECDSA with secp256k1 and BIP340 Schnorr
    ///
    /// This derivation matches BIP340 and SLIP-10
    pub fn derive_subkey_with_chain_code(
        &self,
        derivation_path: &DerivationPath,
        chain_code: &[u8; 32],
    ) -> (Self, [u8; 32]) {
        let public_key: AffinePoint = *self.key.as_affine();
        let (pt, _offset, chain_code) = derivation_path.derive_offset(public_key, chain_code);

        let derived_key = Self {
            key: k256::ecdsa::VerifyingKey::from(
                k256::PublicKey::from_affine(pt).expect("Derived point is valid"),
            ),
        };

        (derived_key, chain_code)
    }
}

/// An error indicating that recovering the recovery of the signature y parity bit failed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryError {
    /// The signature is syntactically invalid and cannot be parsed.
    SignatureParseError(String),
    /// Recovery failed which can only happen if parameters are wrong:
    /// signature was not done on given digest or was done by another key pair.
    WrongParameters(String),
}

/// Given an ECDSA signature `(r,s)` and a signed digest, there can be several public
/// keys that could verify this signature. This is problematic for certain applications (Bitcoin, Ethereum)
/// where the public key is not transmitted but computed from the signature.
/// The [`RecoveryId`] determines uniquely which one of those public keys (and corresponding secret key)
/// was used and is usually transmitted together with the signature.
///
/// Note that in secp256k1 there can be at most 4 public keys for a given signature `(r,s)` and message digest `d`.
/// The public key is determined by the following equation `r⁻¹(𝑠𝑅 − d𝐺)`,
/// where `R` is a point on the curve and can have 4 possible values
/// (see [Public Key Recovery Operation](https://www.secg.org/sec1-v2.pdf)):
/// 1. `(r, y)`
/// 2. `(r, -y)`
/// 3. `(r + n, y' )`
/// 4. `(r + n, -y')`
///
/// where `y`, `y'` are computed from the affine x-coordinate together with the curve equation and `n` is the order of the curve.
/// Note that because the affine coordinates are over `𝔽ₚ`, where `p > n` but `p` and `n` are somewhat close from each other,
/// the last 2 possibilities often do not exist, see [`RecoveryId::is_x_reduced`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryId {
    recid: k256::ecdsa::RecoveryId,
}

impl RecoveryId {
    /// True iff the affine y-coordinate of `𝑘×𝑮` odd.
    pub const fn is_y_odd(&self) -> bool {
        self.recid.is_y_odd()
    }

    /// True iff the affine x-coordinate of `𝑘×𝑮` overflows the curve order.
    ///
    /// This is `false` with overwhelming probability and some applications like Ethereum completely ignore this bit.
    /// To see why, recall that in ECDSA the signature starts with choosing a random number `𝑘` in `[1, n-1]` and computing `𝑘×𝑮`
    /// which is an element of the elliptic curve and whose affine x-coordinate is in `𝔽ₚ`.
    /// This value is then reduced modulo `n` to get `r` (the first part of the signature),
    /// which can only happen if the affine x-coordinate of `𝑘×𝑮` is in the interval `[n, p-1]`,
    /// which contains `p-n` elements.
    ///
    /// However, the number of affine x-coordinates in 𝔽ₚ is `(n-1)/2`
    /// (since every x-coordinate corresponds to 2 symmetric points on the curve which also contains the point at infinity),
    /// and so the probability that a random affine x-coordinate is in `[n, p-1]`
    /// is `(p-n)/((n-1)/2) = 2(p-n)/(n-1)`, which with secp256k1 parameters is less than `2⁻¹²⁵`:
    /// * `p = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F > 2²⁵⁵`
    /// * `n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 > 2²⁵⁵`
    /// * `p-n = 432420386565659656852420866390673177326 < 2¹²⁹`
    /// * `2(p-n)/(n-1) < 2 * 2¹²⁹ * 2⁻²⁵⁵ = 2⁻¹²⁵`
    pub const fn is_x_reduced(&self) -> bool {
        self.recid.is_x_reduced()
    }

    /// Convert this [`RecoveryId`] into a `u8`.
    pub const fn to_byte(&self) -> u8 {
        self.recid.to_byte()
    }
}
