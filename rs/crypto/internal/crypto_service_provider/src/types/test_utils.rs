use super::*;
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1::RsaPublicKey as IcRsaPublicKey;
use ic_crypto_internal_multi_sig_bls12381::types as multi_sig_types;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_test_vectors::unhex::{
    hex_to_32_bytes, hex_to_48_bytes, hex_to_64_bytes, hex_to_96_bytes,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types as ni_dkg_types;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::FsEncryptionSecretKey;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_sig_types;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    CommitmentOpeningBytes, EccCurveType, EccScalarBytes, MEGaKeySetK256Bytes,
    MEGaPrivateKeyK256Bytes, MEGaPublicKeyK256Bytes, gen_keypair,
};
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPop, FsEncryptionPublicKey,
};
use ic_crypto_secrets_containers::SecretArray;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::convert::TryFrom;

prop_compose! {
    pub fn arbitrary_ecdsa_secp256r1_signature()(
        random_bytes in [any::<u8>(); ecdsa_secp256r1_types::SignatureBytes::SIZE]
    ) -> CspSignature {
        CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_ecdsa_secp256k1_public_key()(
        random_bytes in [any::<u8>(); ecdsa_secp256k1_types::PublicKeyBytes::SIZE]
    ) -> CspPublicKey {
        CspPublicKey::EcdsaSecp256k1(ecdsa_secp256k1_types::PublicKeyBytes(random_bytes.to_vec()))
    }
}

prop_compose! {
    pub fn arbitrary_ecdsa_secp256r1_public_key()(
        random_bytes in [any::<u8>(); ecdsa_secp256r1_types::PublicKeyBytes::SIZE]
    ) -> CspPublicKey {
        CspPublicKey::EcdsaP256(ecdsa_secp256r1_types::PublicKeyBytes(random_bytes.to_vec()))
    }
}

prop_compose! {
    pub fn arbitrary_ed25519_public_key()(
        random_bytes in [any::<u8>(); ed25519_types::PublicKeyBytes::SIZE]
    ) -> CspPublicKey {
        CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_ed25519_secret_key()(
        random_bytes in [any::<u8>(); ed25519_types::SecretKeyBytes::SIZE]
    ) -> CspSecretKey {
        CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
            SecretArray::new_and_dont_zeroize_argument(&random_bytes),
        ))
    }
}

prop_compose! {
    pub fn arbitrary_secp256k1_signature()(
        random_bytes in [any::<u8>(); 64]
    ) -> CspSignature {
        CspSignature::EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes(random_bytes))
    }
}

prop_compose! {

    pub fn arbitrary_ed25519_signature()(
        random_bytes in [any::<u8>(); 64]
    ) -> CspSignature {
        CspSignature::Ed25519(ed25519_types::SignatureBytes(random_bytes))
    }
}

prop_compose! {

    pub fn arbitrary_multi_bls12381_public_key()(
        random_bytes in [any::<u8>(); multi_sig_types::PublicKeyBytes::SIZE]
    ) -> CspPublicKey {
        CspPublicKey::MultiBls12_381(multi_sig_types::PublicKeyBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_multi_bls12381_secret_key()(
        random_bytes in [any::<u8>(); multi_sig_types::SecretKeyBytes::SIZE]
    ) -> CspSecretKey {
        CspSecretKey::MultiBls12_381(multi_sig_types::SecretKeyBytes::new(
            SecretArray::new_and_dont_zeroize_argument(&random_bytes),
        ))
    }
}

prop_compose! {
    pub fn arbitrary_tls_ed25519_secret_key()(
        random_bytes in [any::<u8>(); 42]
    ) -> CspSecretKey {
        CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(random_bytes.to_vec()))
    }
}

prop_compose! {
    pub fn arbitrary_rsa_public_key()(
        random_bytes in proptest::array::uniform32(any::<u8>())
    ) -> CspPublicKey {
        use ::rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
        let rng = &mut ChaCha20Rng::from_seed(random_bytes);
        let priv_key = RsaPrivateKey::new(rng, 2048).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        CspPublicKey::RsaSha256(
            IcRsaPublicKey::from_der_spki(
                pub_key.to_public_key_der().expect("failed to convert to DER").as_ref()
            ).expect("Invalid RSA key")
        )
    }
}

prop_compose! {
    pub fn arbitrary_multi_bls12381_combined_signature()(
        random_bytes in [any::<u8>(); multi_sig_types::CombinedSignatureBytes::SIZE]
    ) -> MultiBls12_381_Signature {
        MultiBls12_381_Signature::Combined(multi_sig_types::CombinedSignatureBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_multi_bls12381_individual_signature()(
        random_bytes in [any::<u8>(); multi_sig_types::IndividualSignatureBytes::SIZE]
    ) -> MultiBls12_381_Signature {
        MultiBls12_381_Signature::Individual(multi_sig_types::IndividualSignatureBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_threshold_bls12381_secret_key()(
        random_bytes in [any::<u8>(); threshold_sig_types::SecretKeyBytes::SIZE]
    ) -> CspSecretKey {
        CspSecretKey::ThresBls12_381(threshold_sig_types::SecretKeyBytes::new(
            SecretArray::new_and_dont_zeroize_argument(&random_bytes),
        ))
    }
}

pub fn default_fs_encryption_key_set() -> CspSecretKey {
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

prop_compose! {
    pub fn arbitrary_threshold_bls12381_combined_signature()(
        random_bytes in proptest::array::uniform::<_,
            { threshold_sig_types::CombinedSignatureBytes::SIZE }
        >(any::<u8>())
    ) -> ThresBls12_381_Signature {
        ThresBls12_381_Signature::Combined(threshold_sig_types::CombinedSignatureBytes(random_bytes))
    }
}

prop_compose! {
    pub fn arbitrary_threshold_bls12381_individual_signature()(
        random_bytes in proptest::array::uniform::<_,
            { threshold_sig_types::IndividualSignatureBytes::SIZE }
        >(any::<u8>())
    ) -> ThresBls12_381_Signature {
        ThresBls12_381_Signature::Individual(threshold_sig_types::IndividualSignatureBytes(
            random_bytes,
        ))
    }
}

prop_compose! {
    pub fn arbitrary_mega_k256_encryption_key_set()(
        random_bytes in proptest::array::uniform32(any::<u8>())
    ) -> CspSecretKey {
        let rng = &mut ChaCha20Rng::from_seed(random_bytes);
        let seed = Seed::from_rng(rng);

        let (public_key, private_key) = gen_keypair(EccCurveType::K256, seed);
        let public_key =
            MEGaPublicKeyK256Bytes::try_from(&public_key).expect("just-generated key should serialize");
        let private_key = MEGaPrivateKeyK256Bytes::try_from(&private_key)
            .expect("just-generated key should serialize");
        CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
            public_key,
            private_key,
        })
    }
}

pub fn arbitrary_threshold_ecdsa_opening() -> impl Strategy<Value = CspSecretKey> {
    prop_oneof![
        arbitrary_simple_threshold_ecdsa_opening(),
        arbitrary_pedersen_threshold_ecdsa_opening(),
    ]
}

prop_compose! {
    pub fn arbitrary_simple_threshold_ecdsa_opening()
    (bytes in proptest::array::uniform32(any::<u8>())) -> CspSecretKey{
        CspSecretKey::IDkgCommitmentOpening(CommitmentOpeningBytes::Simple(
            EccScalarBytes::K256(Box::new(bytes)),
        ))
    }
}

prop_compose! {
    pub fn arbitrary_pedersen_threshold_ecdsa_opening()(
        bytes_0 in proptest::array::uniform32(any::<u8>()),
        bytes_1 in proptest::array::uniform32(any::<u8>())
    ) -> CspSecretKey{
        CspSecretKey::IDkgCommitmentOpening(CommitmentOpeningBytes::Pedersen(
            EccScalarBytes::K256(Box::new(bytes_0)),
            EccScalarBytes::K256(Box::new(bytes_1)),
        ))
    }
}

impl CspSecretKey {
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
            SecretArray::new_and_dont_zeroize_argument(&hex_to_32_bytes(hex)),
        ))
    }

    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes::new(
            SecretArray::new_and_dont_zeroize_argument(&hex_to_32_bytes(hex)),
        ))
    }
}

impl CspPublicKey {
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(hex_to_32_bytes(hex)))
    }

    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspPublicKey::MultiBls12_381(multi_types::PublicKeyBytes(hex_to_96_bytes(hex)))
    }
}

impl CspSignature {
    pub fn ed25519_from_hex(hex: &str) -> Self {
        CspSignature::Ed25519(ed25519_types::SignatureBytes(hex_to_64_bytes(hex)))
    }

    pub fn multi_bls12381_individual_from_hex(hex: &str) -> Self {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
            multi_types::IndividualSignatureBytes(hex_to_48_bytes(hex)),
        ))
    }

    pub fn thres_bls12381_indiv_from_array_of(byte: u8) -> Self {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(
            threshold_types::IndividualSignatureBytes(
                [byte; threshold_types::IndividualSignatureBytes::SIZE],
            ),
        ))
    }

    pub fn thres_bls12381_combined_from_array_of(byte: u8) -> Self {
        CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
            threshold_types::CombinedSignatureBytes(
                [byte; threshold_types::CombinedSignatureBytes::SIZE],
            ),
        ))
    }
}

impl CspPop {
    pub fn multi_bls12381_from_hex(hex: &str) -> Self {
        CspPop::MultiBls12_381(multi_types::PopBytes(hex_to_48_bytes(hex)))
    }
}
