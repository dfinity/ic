use super::*;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_multi_sig_bls12381::types as multi_sig_types;
use ic_crypto_internal_test_vectors::unhex::{
    hex_to_32_bytes, hex_to_48_bytes, hex_to_64_bytes, hex_to_96_bytes,
};
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::{
    EphemeralPublicKeyBytes, EphemeralSecretKeyBytes,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types as ni_dkg_types;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::FsEncryptionSecretKey;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_sig_types;
use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPop, FsEncryptionPublicKey,
};
use ic_crypto_secrets_containers::SecretArray;

impl CspSecretKey {
    /// This function is only used for tests
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
            SecretArray::new_and_dont_zeroize_argument(&hex_to_32_bytes(hex)),
        ))
    }

    /// This function is only used for tests
    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes(hex_to_32_bytes(hex)))
    }
}

impl CspPublicKey {
    /// This function is only used for tests
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(hex_to_32_bytes(hex)))
    }

    /// This function is only used for tests
    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspPublicKey::MultiBls12_381(multi_types::PublicKeyBytes(hex_to_96_bytes(hex)))
    }
}

impl CspSignature {
    /// This function is only used for tests
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspSignature::Ed25519(ed25519_types::SignatureBytes(hex_to_64_bytes(hex)))
    }

    /// This function is only used for tests
    pub fn multi_bls12381_individual_from_hex(hex: &str) -> Self {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
            multi_types::IndividualSignatureBytes(hex_to_48_bytes(hex)),
        ))
    }

    /// This function is only used for tests
    pub fn thres_bls12381_indiv_from_array_of(byte: u8) -> Self {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(
            threshold_types::IndividualSignatureBytes(
                [byte; threshold_types::IndividualSignatureBytes::SIZE],
            ),
        ))
    }

    /// This function is only used for tests
    pub fn thres_bls12381_combined_from_array_of(byte: u8) -> Self {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
            threshold_types::CombinedSignatureBytes(
                [byte; threshold_types::CombinedSignatureBytes::SIZE],
            ),
        ))
    }
}

impl CspPop {
    /// This function is only used for tests
    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspPop::MultiBls12_381(multi_types::PopBytes(hex_to_48_bytes(hex)))
    }
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ecdsa_secp256r1_signature() -> CspSignature {
    let mut random_bytes = [0; ecdsa_secp256r1_types::SignatureBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ecdsa_secp256k1_public_key() -> CspPublicKey {
    let mut random_bytes = [0; ecdsa_secp256k1_types::PublicKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspPublicKey::EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes(random_bytes.to_vec()))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ecdsa_secp256r1_public_key() -> CspPublicKey {
    let mut random_bytes = [0; ecdsa_secp256r1_types::PublicKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspPublicKey::EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes(random_bytes.to_vec()))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ed25519_public_key() -> CspPublicKey {
    let mut random_bytes = [0; ed25519_types::PublicKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ed25519_secret_key() -> CspSecretKey {
    let mut random_bytes = [0; ed25519_types::SecretKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&random_bytes),
    ))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_secp256k1_signature() -> CspSignature {
    let mut random_bytes = [0; 64];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSignature::EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ed25519_signature() -> CspSignature {
    let mut random_bytes = [0; 64];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSignature::Ed25519(ed25519_types::SignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_multi_bls12381_public_key() -> CspPublicKey {
    let mut random_bytes = [0; multi_sig_types::PublicKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspPublicKey::MultiBls12_381(multi_sig_types::PublicKeyBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_multi_bls12381_secret_key() -> CspSecretKey {
    let mut random_bytes = [0; multi_sig_types::SecretKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSecretKey::MultiBls12_381(multi_sig_types::SecretKeyBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_tls_ed25519_secret_key() -> CspSecretKey {
    let mut random_bytes = [0; 42];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
        bytes: random_bytes.to_vec(),
    })
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_rsa_public_key() -> CspPublicKey {
    let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA key generation failed");
    let der = rsa
        .public_key_to_der()
        .expect("Converting RSA key to DER failed");
    CspPublicKey::RsaSha256(rsa::RsaPublicKey::from_der_spki(&der).expect("Invalid RSA key"))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_multi_bls12381_combined_signature() -> MultiBls12_381_Signature {
    let mut random_bytes = [0; multi_sig_types::CombinedSignatureBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    MultiBls12_381_Signature::Combined(multi_sig_types::CombinedSignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_multi_bls12381_individual_signature() -> MultiBls12_381_Signature {
    let mut random_bytes = [0; multi_sig_types::IndividualSignatureBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    MultiBls12_381_Signature::Individual(multi_sig_types::IndividualSignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_threshold_bls12381_secret_key() -> CspSecretKey {
    let mut random_bytes = [0; threshold_sig_types::SecretKeyBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    CspSecretKey::ThresBls12_381(threshold_sig_types::SecretKeyBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_ephemeral_key_set() -> CspSecretKey {
    let mut random_sk_bytes = [0; EphemeralSecretKeyBytes::SIZE];
    for b in random_sk_bytes.iter_mut() {
        *b = rand::random();
    }
    let mut random_pk_bytes = [0; EphemeralPublicKeyBytes::SIZE];
    for b in random_pk_bytes.iter_mut() {
        *b = rand::random();
    }
    let mut random_pop_bytes = [0; EphemeralPopBytes::SIZE];
    for b in random_pop_bytes.iter_mut() {
        *b = rand::random();
    }
    let eph_key_set = EphemeralKeySetBytes {
        secret_key_bytes: EphemeralSecretKeyBytes(random_sk_bytes),
        public_key_bytes: EphemeralPublicKeyBytes(random_pk_bytes),
        pop_bytes: EphemeralPopBytes(random_pop_bytes),
    };
    CspSecretKey::Secp256k1WithPublicKey(eph_key_set)
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_fs_encryption_key_set() -> CspSecretKey {
    // TODO(CRP-862): produce random values rather than default.
    let fs_enc_key_set = ni_dkg_types::FsEncryptionKeySetWithPop {
        public_key: FsEncryptionPublicKey(Default::default()),
        pop: FsEncryptionPop {
            pop_key: Default::default(),
            challenge: Default::default(),
            response: Default::default(),
        },
        secret_key: FsEncryptionSecretKey { bte_nodes: vec![] },
    };
    CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(
        fs_enc_key_set,
    ))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_threshold_bls12381_combined_signature() -> ThresBls12_381_Signature {
    let mut random_bytes = [0; threshold_sig_types::CombinedSignatureBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    ThresBls12_381_Signature::Combined(threshold_sig_types::CombinedSignatureBytes(random_bytes))
}

/// This function is only used for tests
#[allow(unused)]
pub fn arbitrary_threshold_bls12381_individual_signature() -> ThresBls12_381_Signature {
    let mut random_bytes = [0; threshold_sig_types::IndividualSignatureBytes::SIZE];
    for b in random_bytes.iter_mut() {
        *b = rand::random();
    }
    ThresBls12_381_Signature::Individual(threshold_sig_types::IndividualSignatureBytes(
        random_bytes,
    ))
}
