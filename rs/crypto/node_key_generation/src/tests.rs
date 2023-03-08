#![allow(clippy::unwrap_used)]

use super::*;
use assert_matches::assert_matches;
use ic_crypto_internal_csp::types::CspPop;
use ic_crypto_internal_csp::types::CspPublicKey;
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPop;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPublicKey;
use ic_crypto_node_key_validation::ValidNodeSigningPublicKey;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types_test_utils::ids::node_test_id;

const RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE: &str = "99991231235959Z";

mod generate_node_signing_keys {
    use super::*;

    #[test]
    fn should_delegate_to_csp() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_node_signing_public_key = with_csp_gen_node_signing_key_pair(&mut csp);

        let actual_node_signing_public_key = generate_node_signing_keys(&csp);

        assert_eq!(
            actual_node_signing_public_key,
            expected_node_signing_public_key
        );
    }
}

mod generate_committee_signing_keys {
    use super::*;

    #[test]
    fn should_delegate_to_csp() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_committee_signing_public_key =
            with_csp_gen_committee_signing_key_pair(&mut csp);

        let actual_committee_signing_public_key = generate_committee_signing_keys(&csp);

        assert_eq!(
            actual_committee_signing_public_key,
            expected_committee_signing_public_key
        )
    }
}

mod generate_tls_keys {
    use super::generate_tls_keys;
    use super::*;
    use ic_types_test_utils::ids::node_test_id;

    const NODE_ID: u64 = 123;

    #[test]
    fn should_delegate_to_csp_with_correct_not_after() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_tls_certificate = with_csp_gen_tls_key_pair(
            &mut csp,
            node_test_id(NODE_ID),
            RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE.to_string(),
        );

        let actual_tls_certificate = generate_tls_keys(&csp, node_test_id(NODE_ID));

        assert_eq!(actual_tls_certificate, expected_tls_certificate);
    }
}

mod generate_dkg_dealing_encryption_keys {
    use super::*;

    const NODE_ID: u64 = 123;

    #[test]
    fn should_delegate_to_csp() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_dkg_dealing_encryption_pk =
            with_csp_dkg_gen_dealing_encryption_key_pair(&mut csp, node_test_id(NODE_ID));

        let actual_dkg_dealing_encryption_pk =
            generate_dkg_dealing_encryption_keys(&csp, node_test_id(NODE_ID));

        assert_eq!(
            actual_dkg_dealing_encryption_pk,
            expected_dkg_dealing_encryption_pk
        );
    }
}

mod generate_idkg_dealing_encryption_keys {
    use super::*;
    use crate::IDkgDealingEncryptionKeysGenerationError;
    use ic_crypto_internal_threshold_sig_ecdsa::ThresholdEcdsaError::CurveMismatch;

    #[test]
    fn should_delegate_to_csp() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_idkg_dealing_encryption_pk =
            with_csp_idkg_gen_dealing_encryption_key_pair(&mut csp);

        let actual_idkg_dealing_encryption_pk = generate_idkg_dealing_encryption_keys(&csp)
            .expect("error generation I-DKG dealing encryption keys");

        assert_eq!(
            actual_idkg_dealing_encryption_pk,
            expected_idkg_dealing_encryption_pk
        );
    }

    #[test]
    fn should_return_transient_error() {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_idkg_gen_dealing_encryption_key_pair()
            .times(1)
            .return_const(Err(CspCreateMEGaKeyError::TransientInternalError {
                internal_error: "RPC error".to_string(),
            }));

        let public_key = generate_idkg_dealing_encryption_keys(&csp);

        assert_matches!(public_key, Err(IDkgDealingEncryptionKeysGenerationError::TransientInternalError(e)) if e == "RPC error")
    }

    #[test]
    fn should_return_internal_error() {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_idkg_gen_dealing_encryption_key_pair()
            .times(1)
            .return_const(Err(CspCreateMEGaKeyError::FailedKeyGeneration(
                CurveMismatch,
            )));

        let public_key = generate_idkg_dealing_encryption_keys(&csp);

        assert_matches!(
            public_key,
            Err(IDkgDealingEncryptionKeysGenerationError::InternalError(e)) if e.contains("CurveMismatch")
        )
    }
}

mod generate_required_node_keys_once_internal {
    use super::*;
    use ic_crypto_internal_csp::vault::api::ValidatePksAndSksKeyPairError::PublicKeyNotFound;

    #[test]
    fn should_return_already_existing_keys() {
        let expected_keys = valid_node_public_keys();
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_validate_pks_and_sks()
            .times(1)
            .return_const(Ok(expected_keys.clone()));

        let result = generate_node_keys_once_internal(&csp);

        assert_eq!(result, Ok(expected_keys));
    }

    #[test]
    fn should_return_transient_error() {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_validate_pks_and_sks().times(1).return_const(Err(
            ValidatePksAndSksError::TransientInternalError("RPC fails".to_string()),
        ));

        let result = generate_node_keys_once_internal(&csp);

        assert_matches!(result, Err( NodeKeyGenerationError::TransientInternalError(e)) if e == "RPC fails");
    }

    #[test]
    #[should_panic]
    fn should_panic_on_any_inconsistent_key_store_error() {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_validate_pks_and_sks().times(1).return_const(Err(
            ValidatePksAndSksError::NodeSigningKeyError(PublicKeyNotFound),
        ));

        let _result = generate_node_keys_once_internal(&csp);
    }

    #[test]
    fn should_generate_keys_when_keystore_empty() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let valid_node_public_keys = with_csp_generating_all_keys(&mut csp);
        with_validate_pks_and_sks_returning(
            &mut csp,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Ok(valid_node_public_keys.clone()),
        );

        let result = generate_node_keys_once_internal(&csp);

        assert_eq!(result, Ok(valid_node_public_keys));
    }

    #[test]
    #[should_panic(expected = "EmptyPublicKeyStore")]
    fn should_panic_when_keystore_empty_on_second_call() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let _valid_node_public_keys = with_csp_generating_all_keys(&mut csp);
        with_validate_pks_and_sks_returning(
            &mut csp,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
        );

        let _result = generate_node_keys_once_internal(&csp);
    }

    #[test]
    #[should_panic(expected = "NodeSigningKeyError(PublicKeyNotFound)")]
    fn should_panic_on_any_inconsistent_key_store_error_on_second_call() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let _valid_node_public_keys = with_csp_generating_all_keys(&mut csp);
        with_validate_pks_and_sks_returning(
            &mut csp,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::NodeSigningKeyError(
                PublicKeyNotFound,
            )),
        );

        let _result = generate_node_keys_once_internal(&csp);
    }

    #[test]
    fn should_return_transient_error_on_second_call() {
        let mut csp = MockAllCryptoServiceProvider::new();
        let _valid_node_public_keys = with_csp_generating_all_keys(&mut csp);
        with_validate_pks_and_sks_returning(
            &mut csp,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::TransientInternalError(
                "RPC fails".to_string(),
            )),
        );

        let result = generate_node_keys_once_internal(&csp);

        assert_matches!(result, Err( NodeKeyGenerationError::TransientInternalError(e)) if e == "RPC fails");
    }
}

fn with_validate_pks_and_sks_returning(
    csp: &mut MockAllCryptoServiceProvider,
    result_on_first_call: Result<ValidNodePublicKeys, ValidatePksAndSksError>,
    result_on_second_call: Result<ValidNodePublicKeys, ValidatePksAndSksError>,
) {
    let mut counter = 0_u8;
    csp.expect_validate_pks_and_sks()
        .times(2)
        .returning(move || match counter {
            0 => {
                counter += 1;
                result_on_first_call.clone()
            }
            1 => {
                counter += 1;
                result_on_second_call.clone()
            }
            _ => panic!("validate_pks_and_sks called too many times!"),
        });
}

fn with_csp_gen_node_signing_key_pair(csp: &mut MockAllCryptoServiceProvider) -> PublicKey {
    let node_signing_public_key = valid_node_signing_public_key();
    csp.expect_gen_node_signing_key_pair()
        .times(1)
        .return_const(Ok(CspPublicKey::ed25519_from_hex(&hex::encode(
            node_signing_public_key.key_value.clone(),
        ))));
    node_signing_public_key
}

fn with_csp_gen_committee_signing_key_pair(csp: &mut MockAllCryptoServiceProvider) -> PublicKey {
    let committee_signing_public_key = valid_committee_signing_public_key();
    csp.expect_gen_committee_signing_key_pair()
        .times(1)
        .return_const(Ok((
            CspPublicKey::multi_bls12381_from_hex(&hex::encode(
                committee_signing_public_key.key_value.clone(),
            )),
            CspPop::multi_bls12381_from_hex(&hex::encode(
                committee_signing_public_key
                    .proof_data
                    .clone()
                    .expect("missing pop"),
            )),
        )));
    committee_signing_public_key
}

fn with_csp_gen_tls_key_pair(
    csp: &mut MockAllCryptoServiceProvider,
    node_id: NodeId,
    not_after: String,
) -> TlsPublicKeyCert {
    let tls_certificate = valid_tls_certificate();
    csp.expect_gen_tls_key_pair()
        .times(1)
        .withf(move |_node_id, _not_after| *_node_id == node_id && _not_after == not_after)
        .return_const(Ok(tls_certificate.clone()));
    tls_certificate
}

fn with_csp_dkg_gen_dealing_encryption_key_pair(
    csp: &mut MockAllCryptoServiceProvider,
    node_id: NodeId,
) -> PublicKeyProto {
    let dkg_dealing_encryption_pk = valid_dkg_dealing_encryption_public_key();

    csp.expect_gen_dealing_encryption_key_pair()
        .times(1)
        .withf(move |_node_id| *_node_id == node_id)
        .return_const(Ok((
            CspFsEncryptionPublicKey::try_from(&dkg_dealing_encryption_pk)
                .expect("invalid DKG key"),
            CspFsEncryptionPop::try_from(&dkg_dealing_encryption_pk).expect("invalid DKG key"),
        )));
    dkg_dealing_encryption_pk
}

fn with_csp_idkg_gen_dealing_encryption_key_pair(
    csp: &mut MockAllCryptoServiceProvider,
) -> PublicKeyProto {
    let idkg_dealing_encryption_pk = valid_idkg_dealing_encryption_public_key();
    csp.expect_idkg_gen_dealing_encryption_key_pair()
        .times(1)
        .return_const(Ok(MEGaPublicKey::deserialize(
            EccCurveType::K256,
            &idkg_dealing_encryption_pk.key_value,
        )
        .expect("invalid MEGa public key")));
    idkg_dealing_encryption_pk
}

fn with_csp_generating_all_keys(csp: &mut MockAllCryptoServiceProvider) -> ValidNodePublicKeys {
    let node_signing_pk = with_csp_gen_node_signing_key_pair(csp);
    let node_id = *ValidNodeSigningPublicKey::try_from(node_signing_pk.clone())
        .expect("invalid node signing public key")
        .derived_node_id();
    let committee_signing_pk = with_csp_gen_committee_signing_key_pair(csp);
    let tls_certificate = with_csp_gen_tls_key_pair(
        csp,
        node_id,
        RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE.to_string(),
    );
    let dkg_dealing_encryption_pk = with_csp_dkg_gen_dealing_encryption_key_pair(csp, node_id);
    let idkg_dealing_encryption_pk = with_csp_idkg_gen_dealing_encryption_key_pair(csp);
    ValidNodePublicKeys::try_from(
        CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_pk),
            committee_signing_public_key: Some(committee_signing_pk),
            tls_certificate: Some(tls_certificate.to_proto()),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_pk),
        },
        node_id,
    )
    .expect("invalid node public keys")
}

fn valid_node_public_keys() -> ValidNodePublicKeys {
    let node_id = *ValidNodeSigningPublicKey::try_from(valid_node_signing_public_key())
        .expect("invalid node signing public key")
        .derived_node_id();
    ValidNodePublicKeys::try_from(
        CurrentNodePublicKeys {
            node_signing_public_key: Some(valid_node_signing_public_key()),
            committee_signing_public_key: Some(valid_committee_signing_public_key()),
            tls_certificate: Some(valid_tls_certificate().to_proto()),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        },
        node_id,
    )
    .expect("invalid node public keys")
}

fn valid_node_signing_public_key() -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmId::Ed25519 as i32,
        key_value: hex_decode("58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f"),
        proof_data: None,
        timestamp: None,
    }
}

fn valid_committee_signing_public_key() -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmId::MultiBls12_381 as i32,
        key_value: hex_decode(
            "8dab94740858cc96e8df512d8d81730a94d0f3534f30\
                cebd35ee2006ce4a449cad611dd7d97bbc44256932da4d4a76a70b9f347e4a989a3073fc7\
                c2d51bf30804ebbc5c3c6da08b8392d2482473290aff428868caabbc26eec4e7bc59209eb0a",
        ),
        proof_data: Some(hex_decode(
            "afc3038c06223258a14af7c942428fe42f89f8d733e4f\
                5ea8d34a90c0df142697802a6f22633df890a1ce5b774b23aed",
        )),
        timestamp: None,
    }
}

fn valid_tls_certificate() -> TlsPublicKeyCert {
    TlsPublicKeyCert::try_from(X509PublicKeyCert {
        certificate_der: hex_decode(
            "3082015630820108a00302010202140098d074\
                7d24ca04a2f036d8665402b4ea784830300506032b6570304a3148304606035504030\
                c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673365732d7a3234\
                6a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d6161653020170d3\
                232313130343138313231345a180f39393939313233313233353935395a304a314830\
                4606035504030c3f34696e71622d327a63766b2d663679716c2d736f776f6c2d76673\
                365732d7a32346a642d6a726b6f772d6d686e73642d756b7666702d66616b35702d61\
                6165302a300506032b6570032100246acd5f38372411103768e91169dadb7370e9990\
                9a65639186ac6d1c36f3735300506032b6570034100d37e5ccfc32146767e5fd73343\
                649f5b5564eb78e6d8d424d8f01240708bc537a2a9bcbcf6c884136d18d2b475706d7\
                bb905f52faf28707735f1d90ab654380b",
        ),
    })
    .expect("invalid TLS certificate")
}

fn valid_dkg_dealing_encryption_public_key() -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
        key_value: hex_decode(
            "ad36a01cbd40dcfa36ec21a96bedcab17372a9cd2b9eba6171ebeb28dd041a\
                    d5cbbdbb4bed55f59938e8ffb3dd69e386",
        ),
        proof_data: Some(hex_decode(
            "a1781847726f7468323057697468506f705f42\
                6c7331325f333831a367706f705f6b65795830b751c9585044139f80abdebf38d7f30\
                aeb282f178a5e8c284f279eaad1c90d9927e56cac0150646992bce54e08d317ea6963\
                68616c6c656e676558203bb20c5e9c75790f63aae921316912ffc80d6d03946dd21f8\
                5c35159ca030ec668726573706f6e7365582063d6cf189635c0f3111f97e69ae0af8f\
                1594b0f00938413d89dbafc326340384",
        )),
        timestamp: None,
    }
}

fn valid_idkg_dealing_encryption_public_key() -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmId::MegaSecp256k1 as i32,
        key_value: hex_decode("03e1e1f76e9d834221a26c4a080b65e60d3b6f9c1d6e5b880abf916a364893da2e"),
        proof_data: None,
        timestamp: None,
    }
}

fn hex_decode<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    hex::decode(data).expect("failed to decode hex")
}
