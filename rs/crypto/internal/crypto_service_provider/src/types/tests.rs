use super::*;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_test_vectors::ed25519::{
    TESTVEC_ED25519_STABILITY_1_SIG, TESTVEC_RFC8032_ED25519_1_SIG, TESTVEC_RFC8032_ED25519_2_SIG,
    TESTVEC_RFC8032_ED25519_SHA_ABC_PK, TESTVEC_RFC8032_ED25519_SHA_ABC_SIG,
    TESTVEC_RFC8032_ED25519_SHA_ABC_SK,
};
use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_1_PK;
use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::types::{
    BTENodeBytes, FsEncryptionKeySetWithPop, FsEncryptionSecretKey,
};
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::types::CspFsEncryptionKeySet;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    EccCurveType, MEGaPrivateKey, MEGaPrivateKeyK256Bytes, MEGaPublicKeyK256Bytes,
};
use ic_crypto_internal_types::curves::bls12_381::{FrBytes, G1Bytes, G2Bytes};
use ic_crypto_internal_types::encrypt::forward_secure::groth20_bls12_381::{
    FsEncryptionPop, FsEncryptionPublicKey,
};
use ic_crypto_secrets_containers::SecretArray;
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, CryptoHashableTestDummy, UserPublicKey};
use std::convert::TryFrom;
use strum::EnumCount;

fn sk_ed25519_bytes(key: &CspSecretKey) -> Option<&[u8; 32]> {
    match key {
        CspSecretKey::Ed25519(bytes) => Some(bytes.0.expose_secret()),
        _ => None,
    }
}

#[test]
fn should_return_correct_ed25519_secret_key_bytes_for_ed25519_secret_key() {
    let ed25519_csp_sk = CspSecretKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SK);

    assert_eq!(
        sk_ed25519_bytes(&ed25519_csp_sk).unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_SK)
    );
}

#[test]
fn should_return_no_ed25519_secret_key_bytes_for_non_ed25519_secret_key() {
    let secret_key = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes::new(
        SecretArray::new_and_dont_zeroize_argument(&[0u8; multi_types::SecretKeyBytes::SIZE]),
    ));
    assert!(sk_ed25519_bytes(&secret_key).is_none())
}

#[test]
fn should_redact_csp_secret_key_ed25519_debug() {
    let cspsk_ed25519 = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&[1u8; ed25519_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(
        "CspSecretKey::Ed25519 - REDACTED",
        format!("{cspsk_ed25519:?}")
    );
}

#[test]
fn should_redact_csp_secret_key_multi_debug() {
    let cspsk_multi = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes::new(
        SecretArray::new_and_dont_zeroize_argument(&[1u8; multi_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(
        "CspSecretKey::MultiBls12_381 - REDACTED",
        format!("{cspsk_multi:?}")
    );
}

#[test]
fn should_redact_csp_secret_key_thres_debug() {
    let cspsk_thresh = CspSecretKey::ThresBls12_381(threshold_types::SecretKeyBytes::new(
        SecretArray::new_and_dont_zeroize_argument(&[1u8; threshold_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(
        "CspSecretKey::ThresBls12_381 - REDACTED",
        format!("{cspsk_thresh:?}")
    );
}

#[test]
fn should_redact_csp_secret_key_tls_ed25519_debug() {
    let cspsk_tls = CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(vec![1u8; 3]));
    assert_eq!(
        "CspSecretKey::TlsEd25519 - REDACTED",
        format!("{cspsk_tls:?}")
    );
}

#[test]
fn should_redact_csp_secret_key_fs_encryption_debug() {
    let cspsk_fs = CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(
        FsEncryptionKeySetWithPop {
            public_key: FsEncryptionPublicKey(G1Bytes([1u8; G1Bytes::SIZE])),
            pop: FsEncryptionPop {
                pop_key: G1Bytes([1; G1Bytes::SIZE]),
                challenge: FrBytes([1; FrBytes::SIZE]),
                response: FrBytes([1; FrBytes::SIZE]),
            },
            secret_key: FsEncryptionSecretKey {
                bte_nodes: vec![
                    BTENodeBytes {
                        tau: vec![1, 2, 3],
                        a: G1Bytes([1; G1Bytes::SIZE]),
                        b: G2Bytes([1; G2Bytes::SIZE]),
                        d_t: vec![G2Bytes([1; G2Bytes::SIZE])],
                        d_h: vec![G2Bytes([1; G2Bytes::SIZE])],
                        e: G2Bytes([1; G2Bytes::SIZE]),
                    };
                    1
                ],
            },
        },
    ));
    assert_eq!(
        "CspSecretKey::FsEncryption - REDACTED",
        format!("{cspsk_fs:?}")
    );
}

#[test]
fn should_return_correct_enum_variant() {
    // Ed25519
    let key = CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&[0; ed25519_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(key.enum_variant(), "Ed25519");

    // MultiBls12_381
    let key = CspSecretKey::MultiBls12_381(multi_types::SecretKeyBytes::new(
        SecretArray::new_and_dont_zeroize_argument(&[0; multi_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(key.enum_variant(), "MultiBls12_381");

    // ThresBls12_381
    let key = CspSecretKey::ThresBls12_381(threshold_types::SecretKeyBytes::new(
        SecretArray::new_and_dont_zeroize_argument(&[0; threshold_types::SecretKeyBytes::SIZE]),
    ));
    assert_eq!(key.enum_variant(), "ThresBls12_381");

    // TlsEd25519
    let key = CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(vec![]));
    assert_eq!(key.enum_variant(), "TlsEd25519");

    // FsEncryption
    let key = CspSecretKey::FsEncryption(CspFsEncryptionKeySet::Groth20WithPop_Bls12_381(
        FsEncryptionKeySetWithPop {
            public_key: FsEncryptionPublicKey(G1Bytes([0; G1Bytes::SIZE])),
            pop: FsEncryptionPop {
                pop_key: G1Bytes([1; G1Bytes::SIZE]),
                challenge: FrBytes([1; FrBytes::SIZE]),
                response: FrBytes([1; FrBytes::SIZE]),
            },
            secret_key: FsEncryptionSecretKey { bte_nodes: vec![] },
        },
    ));
    assert_eq!(key.enum_variant(), "FsEncryption");

    let rng = &mut Seed::from_bytes(&[0u8; 32]).into_rng();
    let mega_private_key = MEGaPrivateKey::generate(EccCurveType::K256, rng);
    let mega_private_key_bytes = MEGaPrivateKeyK256Bytes::try_from(&mega_private_key).unwrap();
    let mega_public_key = mega_private_key.public_key();
    let mega_public_key_bytes = MEGaPublicKeyK256Bytes::try_from(&mega_public_key).unwrap();
    let key = CspSecretKey::MEGaEncryptionK256(MEGaKeySetK256Bytes {
        public_key: mega_public_key_bytes,
        private_key: mega_private_key_bytes,
    });
    assert_eq!(key.enum_variant(), "MEGaEncryptionK256");

    let key = CspSecretKey::IDkgCommitmentOpening(CommitmentOpeningBytes::Simple(
        EccScalarBytes::K256(Box::new([0u8; 32])),
    ));
    assert_eq!(key.enum_variant(), "IDkgCommitmentOpening");

    // Please add here tests for newly added ’CspSecretKey’ enums and increment the counter to match their count.
    assert_eq!(CspSecretKey::COUNT, 7);
}

#[test]
fn should_return_correct_ed25519_pubkey_bytes_for_ed25519_pubkey() {
    let ed25519_csp_pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK);

    assert_eq!(
        ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_return_no_ed25519_pubkey_bytes_for_non_ed25519_pubkey() {
    assert!(
        CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK)
            .ed25519_bytes()
            .is_none()
    )
}

#[test]
fn should_return_correct_ed25519_signature_bytes_for_ed25519_signature() {
    let ed25519_csp_sig = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_SIG);

    assert_eq!(
        ed25519_csp_sig.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_SIG)
    );
}

#[test]
fn should_return_no_ed25519_signature_bytes_for_non_ed25519_signature() {
    let signature = CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
        multi_types::IndividualSignatureBytes([0u8; multi_types::IndividualSignatureBytes::SIZE]),
    ));
    assert!(signature.ed25519_bytes().is_none())
}

#[test]
fn should_correctly_convert_basic_signature_to_ed25519_csp_signature() {
    let sig = BasicSigOf::<CryptoHashableTestDummy>::new(BasicSig(hex_to_byte_vec(
        TESTVEC_ED25519_STABILITY_1_SIG,
    )));

    let ed25519_csp_sig = SigConverter::for_target(AlgorithmId::Ed25519)
        .try_from_basic(&sig)
        .unwrap();

    assert_eq!(
        ed25519_csp_sig.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_ED25519_STABILITY_1_SIG)
    );
}

#[test]
fn should_correctly_convert_ed25519_csp_pubkey_to_user_public_key() {
    let ed25519_csp_pk = CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK);

    let user_pk = UserPublicKey::try_from(ed25519_csp_pk).unwrap();

    assert_eq!(
        user_pk.key,
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_correctly_convert_ed25519_user_public_key_to_csp_public_key() {
    let user_pk = UserPublicKey {
        key: hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK),
        algorithm_id: AlgorithmId::Ed25519,
    };

    let ed25519_csp_pk = CspPublicKey::try_from(&user_pk).unwrap();

    assert_eq!(
        ed25519_csp_pk.ed25519_bytes().unwrap().to_vec(),
        hex_to_byte_vec(TESTVEC_RFC8032_ED25519_SHA_ABC_PK)
    );
}

#[test]
fn should_fail_to_convert_ed25519_user_pubkey_with_invalid_length_to_csp_pubkey() {
    let user_pk = UserPublicKey {
        key: vec![],
        algorithm_id: AlgorithmId::Ed25519,
    };

    let err = CspPublicKey::try_from(&user_pk).unwrap_err();

    assert!(err.is_malformed_public_key());
}

#[test]
fn should_correctly_compare_csp_signatures() {
    let ed25519_s1 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SIG);
    let ed25519_s1_2 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_1_SIG);
    let ed25519_s2 = CspSignature::ed25519_from_hex(TESTVEC_RFC8032_ED25519_2_SIG);

    assert_eq!(ed25519_s1, ed25519_s1_2);
    assert_ne!(ed25519_s1, ed25519_s2);
}

#[test]
fn csp_signatures_should_have_a_nice_debug_representation() {
    let test_vectors = vec![
        (
            CspSignature::EcdsaP256(ecdsa_secp256r1_types::SignatureBytes(
                [0u8; ecdsa_secp256r1_types::SignatureBytes::SIZE],
            )),
            "CspSignature::EcdsaP256(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\")",
        ),
        (
            CspSignature::EcdsaSecp256k1(ecdsa_secp256k1_types::SignatureBytes(
                [0u8; ecdsa_secp256k1_types::SignatureBytes::SIZE],
            )),
            "CspSignature::EcdsaSecp256k1(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\")",
        ),
        (
            CspSignature::Ed25519(ed25519_types::SignatureBytes(
                [0u8; ed25519_types::SignatureBytes::SIZE],
            )),
            "CspSignature::Ed25519(SignatureBytes(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"))",
        ),
        (
            CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(
                multi_types::IndividualSignatureBytes(
                    [0u8; multi_types::IndividualSignatureBytes::SIZE],
                ),
            )),
            "CspSignature::MultiBls12_381(Individual(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"))",
        ),
        (
            CspSignature::MultiBls12_381(MultiBls12_381_Signature::Combined(
                multi_types::CombinedSignatureBytes(
                    [0u8; multi_types::CombinedSignatureBytes::SIZE],
                ),
            )),
            "CspSignature::MultiBls12_381(Combined(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"))",
        ),
        (
            CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(
                threshold_types::IndividualSignatureBytes(
                    [0u8; multi_types::IndividualSignatureBytes::SIZE],
                ),
            )),
            "CspSignature::ThresBls12_381(Individual(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"))",
        ),
        (
            CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(
                threshold_types::CombinedSignatureBytes(
                    [0u8; multi_types::CombinedSignatureBytes::SIZE],
                ),
            )),
            "CspSignature::ThresBls12_381(Combined(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"))",
        ),
        (
            CspSignature::RsaSha256(vec![1, 2, 3, 4]),
            "CspSignature::RsaSha256(\"AQIDBA==\")",
        ),
    ];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{value:?}"), *formatted);
    }
}
