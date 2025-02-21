use super::*;
use assert_matches::assert_matches;
use ic_crypto_internal_csp_test_utils::types::{
    csp_pk_ed25519_from_hex, csp_pk_multi_bls12381_from_hex, csp_pop_multi_bls12381_from_hex,
};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{EccCurveType, MEGaPublicKey};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPop;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspFsEncryptionPublicKey;
use ic_crypto_node_key_validation::ValidNodeSigningPublicKey;
use ic_crypto_test_utils_keys::public_keys::{
    valid_committee_signing_public_key, valid_dkg_dealing_encryption_public_key,
    valid_idkg_dealing_encryption_public_key, valid_node_signing_public_key,
};
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::time::Time;
use ic_types_test_utils::ids::node_test_id;

mod generate_node_signing_keys {
    use super::*;

    #[test]
    fn should_delegate_to_vault() {
        let mut vault = MockLocalCspVault::new();
        let expected_node_signing_public_key = with_vault_gen_node_signing_key_pair(&mut vault);

        let actual_node_signing_public_key = generate_node_signing_keys(&vault);

        assert_eq!(
            actual_node_signing_public_key,
            expected_node_signing_public_key
        );
    }
}

mod generate_committee_signing_keys {
    use super::*;

    #[test]
    fn should_delegate_to_vault() {
        let mut vault = MockLocalCspVault::new();
        let expected_committee_signing_public_key =
            with_vault_gen_committee_signing_key_pair(&mut vault);

        let actual_committee_signing_public_key = generate_committee_signing_keys(&vault);

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
    fn should_delegate_to_vault() {
        let mut vault = MockLocalCspVault::new();
        let (expected_tls_certificate, _validation_time) =
            with_vault_gen_tls_key_pair(&mut vault, node_test_id(NODE_ID));

        let actual_tls_certificate = generate_tls_keys(&vault, node_test_id(NODE_ID));

        assert_eq!(actual_tls_certificate, expected_tls_certificate);
    }
}

mod generate_dkg_dealing_encryption_keys {
    use super::*;

    const NODE_ID: u64 = 123;

    #[test]
    fn should_delegate_to_vault() {
        let mut vault = MockLocalCspVault::new();
        let expected_dkg_dealing_encryption_pk =
            with_vault_dkg_gen_dealing_encryption_key_pair(&mut vault, node_test_id(NODE_ID));

        let actual_dkg_dealing_encryption_pk =
            generate_dkg_dealing_encryption_keys(&vault, node_test_id(NODE_ID));

        assert_eq!(
            actual_dkg_dealing_encryption_pk,
            expected_dkg_dealing_encryption_pk
        );
    }
}

mod generate_idkg_dealing_encryption_keys {
    use super::*;
    use crate::IDkgDealingEncryptionKeysGenerationError;
    use ic_crypto_internal_threshold_sig_canister_threshold_sig::CanisterThresholdSerializationError;

    #[test]
    fn should_delegate_to_vault() {
        let mut vault = MockLocalCspVault::new();
        let expected_idkg_dealing_encryption_pk =
            with_vault_idkg_gen_dealing_encryption_key_pair(&mut vault);

        let actual_idkg_dealing_encryption_pk = generate_idkg_dealing_encryption_keys(&vault)
            .expect("error generation I-DKG dealing encryption keys");

        assert_eq!(
            actual_idkg_dealing_encryption_pk,
            expected_idkg_dealing_encryption_pk
        );
    }

    #[test]
    fn should_return_transient_error() {
        let mut vault = MockLocalCspVault::new();
        vault
            .expect_idkg_gen_dealing_encryption_key_pair()
            .times(1)
            .return_const(Err(CspCreateMEGaKeyError::TransientInternalError {
                internal_error: "RPC error".to_string(),
            }));

        let public_key = generate_idkg_dealing_encryption_keys(&vault);

        assert_matches!(public_key, Err(IDkgDealingEncryptionKeysGenerationError::TransientInternalError(e)) if e == "RPC error")
    }

    #[test]
    fn should_return_internal_error() {
        let mut vault = MockLocalCspVault::new();
        vault
            .expect_idkg_gen_dealing_encryption_key_pair()
            .times(1)
            .return_const(Err(CspCreateMEGaKeyError::SerializationError(
                CanisterThresholdSerializationError("TEST".to_string()),
            )));

        let public_key = generate_idkg_dealing_encryption_keys(&vault);

        assert_matches!(
            public_key,
            Err(IDkgDealingEncryptionKeysGenerationError::InternalError(e)) if e.contains("TEST")
        )
    }
}

mod generate_required_node_keys_once_internal {
    use super::*;
    use ic_crypto_internal_csp::vault::api::ValidatePksAndSksKeyPairError::PublicKeyNotFound;

    #[test]
    fn should_return_already_existing_keys() {
        let expected_keys = valid_node_public_keys();
        let mut vault = MockLocalCspVault::new();
        vault
            .expect_validate_pks_and_sks()
            .times(1)
            .return_const(Ok(expected_keys.clone()));

        let result = generate_node_keys_once_internal(&vault);

        assert_eq!(result, Ok(expected_keys));
    }

    #[test]
    fn should_return_transient_error() {
        let mut vault = MockLocalCspVault::new();
        vault
            .expect_validate_pks_and_sks()
            .times(1)
            .return_const(Err(ValidatePksAndSksError::TransientInternalError(
                "RPC fails".to_string(),
            )));

        let result = generate_node_keys_once_internal(&vault);

        assert_matches!(result, Err( NodeKeyGenerationError::TransientInternalError(e)) if e == "RPC fails");
    }

    #[test]
    #[should_panic]
    fn should_panic_on_any_inconsistent_key_store_error() {
        let mut vault = MockLocalCspVault::new();
        vault
            .expect_validate_pks_and_sks()
            .times(1)
            .return_const(Err(ValidatePksAndSksError::NodeSigningKeyError(
                PublicKeyNotFound,
            )));

        let _result = generate_node_keys_once_internal(&vault);
    }

    #[test]
    fn should_generate_keys_when_keystore_empty() {
        let mut vault = MockLocalCspVault::new();
        let valid_node_public_keys = with_vault_generating_all_keys(&mut vault);
        with_validate_pks_and_sks_returning(
            &mut vault,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Ok(valid_node_public_keys.clone()),
        );

        let result = generate_node_keys_once_internal(&vault);

        assert_eq!(result, Ok(valid_node_public_keys));
    }

    #[test]
    #[should_panic(expected = "EmptyPublicKeyStore")]
    fn should_panic_when_keystore_empty_on_second_call() {
        let mut vault = MockLocalCspVault::new();
        let _valid_node_public_keys = with_vault_generating_all_keys(&mut vault);
        with_validate_pks_and_sks_returning(
            &mut vault,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
        );

        let _result = generate_node_keys_once_internal(&vault);
    }

    #[test]
    #[should_panic(expected = "NodeSigningKeyError(PublicKeyNotFound)")]
    fn should_panic_on_any_inconsistent_key_store_error_on_second_call() {
        let mut vault = MockLocalCspVault::new();
        let _valid_node_public_keys = with_vault_generating_all_keys(&mut vault);
        with_validate_pks_and_sks_returning(
            &mut vault,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::NodeSigningKeyError(
                PublicKeyNotFound,
            )),
        );

        let _result = generate_node_keys_once_internal(&vault);
    }

    #[test]
    fn should_return_transient_error_on_second_call() {
        let mut vault = MockLocalCspVault::new();
        let _valid_node_public_keys = with_vault_generating_all_keys(&mut vault);
        with_validate_pks_and_sks_returning(
            &mut vault,
            Err(ValidatePksAndSksError::EmptyPublicKeyStore),
            Err(ValidatePksAndSksError::TransientInternalError(
                "RPC fails".to_string(),
            )),
        );

        let result = generate_node_keys_once_internal(&vault);

        assert_matches!(result, Err( NodeKeyGenerationError::TransientInternalError(e)) if e == "RPC fails");
    }
}

fn with_validate_pks_and_sks_returning(
    vault: &mut MockLocalCspVault,
    result_on_first_call: Result<ValidNodePublicKeys, ValidatePksAndSksError>,
    result_on_second_call: Result<ValidNodePublicKeys, ValidatePksAndSksError>,
) {
    let mut counter = 0_u8;
    vault
        .expect_validate_pks_and_sks()
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

fn with_vault_gen_node_signing_key_pair(vault: &mut MockLocalCspVault) -> PublicKey {
    let node_signing_public_key = valid_node_signing_public_key();
    vault
        .expect_gen_node_signing_key_pair()
        .times(1)
        .return_const(Ok(csp_pk_ed25519_from_hex(&hex::encode(
            node_signing_public_key.key_value.clone(),
        ))));
    node_signing_public_key
}

fn with_vault_gen_committee_signing_key_pair(vault: &mut MockLocalCspVault) -> PublicKey {
    let committee_signing_public_key = valid_committee_signing_public_key();
    vault
        .expect_gen_committee_signing_key_pair()
        .times(1)
        .return_const(Ok((
            csp_pk_multi_bls12381_from_hex(&hex::encode(
                committee_signing_public_key.key_value.clone(),
            )),
            csp_pop_multi_bls12381_from_hex(&hex::encode(
                committee_signing_public_key
                    .proof_data
                    .clone()
                    .expect("missing pop"),
            )),
        )));
    committee_signing_public_key
}

fn with_vault_gen_tls_key_pair(
    vault: &mut MockLocalCspVault,
    node_id: NodeId,
) -> (TlsPublicKeyCert, Time) {
    let (tls_certificate, validation_time) = valid_tls_certificate();
    vault
        .expect_gen_tls_key_pair()
        .times(1)
        .withf(move |node_id_| *node_id_ == node_id)
        .return_const(Ok(tls_certificate.clone()));
    (tls_certificate, validation_time)
}

fn with_vault_dkg_gen_dealing_encryption_key_pair(
    vault: &mut MockLocalCspVault,
    node_id: NodeId,
) -> PublicKeyProto {
    let dkg_dealing_encryption_pk = valid_dkg_dealing_encryption_public_key();

    vault
        .expect_gen_dealing_encryption_key_pair()
        .times(1)
        .withf(move |_node_id| *_node_id == node_id)
        .return_const(Ok((
            CspFsEncryptionPublicKey::try_from(&dkg_dealing_encryption_pk)
                .expect("invalid DKG key"),
            CspFsEncryptionPop::try_from(&dkg_dealing_encryption_pk).expect("invalid DKG key"),
        )));
    dkg_dealing_encryption_pk
}

fn with_vault_idkg_gen_dealing_encryption_key_pair(
    vault: &mut MockLocalCspVault,
) -> PublicKeyProto {
    let idkg_dealing_encryption_pk = valid_idkg_dealing_encryption_public_key();
    vault
        .expect_idkg_gen_dealing_encryption_key_pair()
        .times(1)
        .return_const(Ok(MEGaPublicKey::deserialize(
            EccCurveType::K256,
            &idkg_dealing_encryption_pk.key_value,
        )
        .expect("invalid MEGa public key")));
    idkg_dealing_encryption_pk
}

fn with_vault_generating_all_keys(vault: &mut MockLocalCspVault) -> ValidNodePublicKeys {
    let node_signing_pk = with_vault_gen_node_signing_key_pair(vault);
    let node_id = *ValidNodeSigningPublicKey::try_from(node_signing_pk.clone())
        .expect("invalid node signing public key")
        .derived_node_id();
    let committee_signing_pk = with_vault_gen_committee_signing_key_pair(vault);
    let (tls_certificate, validation_time) = with_vault_gen_tls_key_pair(vault, node_id);
    let dkg_dealing_encryption_pk = with_vault_dkg_gen_dealing_encryption_key_pair(vault, node_id);
    let idkg_dealing_encryption_pk = with_vault_idkg_gen_dealing_encryption_key_pair(vault);

    ValidNodePublicKeys::try_from(
        CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_pk),
            committee_signing_public_key: Some(committee_signing_pk),
            tls_certificate: Some(tls_certificate.to_proto()),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_pk),
        },
        node_id,
        validation_time,
    )
    .expect("invalid node public keys")
}

fn valid_node_public_keys() -> ValidNodePublicKeys {
    let node_id = *ValidNodeSigningPublicKey::try_from(valid_node_signing_public_key())
        .expect("invalid node signing public key")
        .derived_node_id();
    let (valid_tls_certificate, validation_time) = valid_tls_certificate();

    ValidNodePublicKeys::try_from(
        CurrentNodePublicKeys {
            node_signing_public_key: Some(valid_node_signing_public_key()),
            committee_signing_public_key: Some(valid_committee_signing_public_key()),
            tls_certificate: Some(valid_tls_certificate.to_proto()),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        },
        node_id,
        validation_time,
    )
    .expect("invalid node public keys")
}

fn valid_tls_certificate() -> (TlsPublicKeyCert, Time) {
    let (tls_cert, validation_time) =
        ic_crypto_test_utils_keys::public_keys::valid_tls_certificate_and_validation_time();
    (
        TlsPublicKeyCert::try_from(tls_cert).expect("invalid TLS certificate"),
        validation_time,
    )
}
