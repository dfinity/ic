use crate::vault::api::{
    CspVault, ExternalPublicKeyError, LocalPublicKeyError, NodeKeysError, NodeKeysErrors,
    PksAndSksContainsErrors, SecretKeyError,
};
use crate::vault::test_utils::public_key_store::{
    generate_all_keys, generate_idkg_dealing_encryption_key_pair, NODE_1, NOT_AFTER,
};
use crate::ExternalPublicKeys;
use assert_matches::assert_matches;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

pub fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_one_idkg_key(
    csp_vault: Arc<dyn CspVault>,
) {
    let current_node_public_keys = generate_all_keys(&csp_vault);
    assert!(csp_vault
        .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
        .is_ok());
}

pub fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys(
    csp_vault: Arc<dyn CspVault>,
) {
    let current_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert!(csp_vault
        .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
        .is_ok());
}

pub fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_with_multiple_idkg_keys_and_external_key_not_first_in_vector(
    csp_vault: Arc<dyn CspVault>,
) {
    let _initial_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    let current_node_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Failed to get current node public keys");
    let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert!(csp_vault
        .pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys))
        .is_ok());
}

pub fn should_return_success_for_pks_and_sks_contains_if_all_keys_match_where_idkg_keys_have_different_timestamps(
    csp_vault: Arc<dyn CspVault>,
) {
    let _current_node_public_keys = generate_all_keys(&csp_vault);
    let mut external_public_keys = convert_to_external_public_keys(
        csp_vault
            .current_node_public_keys_with_timestamps()
            .expect("error getting current node public keys with timestamp"),
    );
    external_public_keys
        .idkg_dealing_encryption_public_key
        .timestamp = external_public_keys
        .idkg_dealing_encryption_public_key
        .timestamp
        .expect("timestamp of generated iDKG dealing encryption key is none")
        .checked_add(42);
    assert!(csp_vault.pks_and_sks_contains(external_public_keys).is_ok());
}

pub fn should_return_error_for_pks_and_sks_contains_if_no_keys_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let _current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(shadow_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            committee_signing_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            tls_certificate_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            dkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            idkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_node_signing_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    current_node_public_keys.node_signing_public_key = {
        let _ = shadow_csp_vault
            .gen_node_signing_key_pair()
            .expect("Failed to generate node signing key pair");
        shadow_csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys")
            .node_signing_public_key
    };

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_committee_signing_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    current_node_public_keys.committee_signing_public_key = {
        let _ = shadow_csp_vault
            .gen_committee_signing_key_pair()
            .expect("Failed to generate committee signing key pair");
        shadow_csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys")
            .committee_signing_public_key
    };

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_dkg_dealing_encryption_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    current_node_public_keys.dkg_dealing_encryption_public_key = {
        let _ = shadow_csp_vault
            .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
            .expect("Failed to generate dkg dealing encryption signing key pair");
        shadow_csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys")
            .dkg_dealing_encryption_public_key
    };

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            idkg_dealing_encryption_key_error: None,
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_tls_certificate_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    current_node_public_keys.tls_certificate = {
        let _ = shadow_csp_vault
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("Failed to generate tks certificate");
        shadow_csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys")
            .tls_certificate
    };

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_idkg_dealing_encryption_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    current_node_public_keys.idkg_dealing_encryption_public_key = {
        let _ = generate_idkg_dealing_encryption_key_pair(&shadow_csp_vault);
        shadow_csp_vault
            .current_node_public_keys()
            .expect("Failed to get current node public keys")
            .idkg_dealing_encryption_public_key
    };

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: None,
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::NotFound),
            }),
        }))
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_external_node_signing_key_is_malformed(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    if let Some(node_signing_public_key) = &mut current_node_public_keys.node_signing_public_key {
        node_signing_public_key.key_value = b"malformed key".to_vec();
    } else {
        panic!("Node signing key missing");
    }

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            }),
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        })) if malformed_error.contains("Malformed Ed25519 public key")
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_external_committee_signing_key_is_malformed(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    if let Some(committee_signing_public_key) =
        &mut current_node_public_keys.committee_signing_public_key
    {
        committee_signing_public_key.key_value = b"malformed key".to_vec();
    } else {
        panic!("Committee signing key missing");
    }

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            }),
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        })) if malformed_error.contains("Malformed MultiBls12_381 public key")
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_external_dkg_dealing_encryption_key_is_malformed(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    if let Some(dkg_dealing_encryption_public_key) =
        &mut current_node_public_keys.dkg_dealing_encryption_public_key
    {
        dkg_dealing_encryption_public_key.key_value = b"malformed key".to_vec();
    } else {
        panic!("DKG dealing encryption key missing");
    }

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            }),
            idkg_dealing_encryption_key_error: None,
        })) if malformed_error.contains("Malformed public key")
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_external_tls_certificate_is_malformed(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    if let Some(tls_certificate) = &mut current_node_public_keys.tls_certificate {
        tls_certificate.certificate_der = b"malformed certificate".to_vec();
    } else {
        panic!("TLS certificate missing");
    }

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            }),
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: None,
        })) if malformed_error.contains("Malformed certificate: TlsPublicKeyCertCreationError")
    );
}

pub fn should_return_error_for_pks_and_sks_contains_if_external_idkg_dealing_encryption_key_is_malformed(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    if let Some(idkg_dealing_encryption_public_key) =
        &mut current_node_public_keys.idkg_dealing_encryption_public_key
    {
        idkg_dealing_encryption_public_key.key_value = b"malformed key".to_vec();
    } else {
        panic!("iDKG dealing encryption key missing");
    }

    let result =
        csp_vault.pks_and_sks_contains(convert_to_external_public_keys(current_node_public_keys));
    assert_matches!(
        result,
        Err(PksAndSksContainsErrors::NodeKeysErrors(NodeKeysErrors {
            node_signing_key_error: None,
            committee_signing_key_error: None,
            tls_certificate_error: None,
            dkg_dealing_encryption_key_error: None,
            idkg_dealing_encryption_key_error: Some(NodeKeysError {
                external_public_key_error: Some(ExternalPublicKeyError(malformed_error)),
                local_public_key_error: Some(LocalPublicKeyError::Mismatch),
                secret_key_error: Some(SecretKeyError::CannotComputeKeyId),
            }),
        })) if malformed_error.contains("Malformed public key: I-DKG dealing encryption key malformed")
    );
}

pub(crate) fn convert_to_external_public_keys(
    current_node_public_keys: CurrentNodePublicKeys,
) -> ExternalPublicKeys {
    ExternalPublicKeys {
        node_signing_public_key: current_node_public_keys
            .node_signing_public_key
            .expect("node signing public key missing"),
        committee_signing_public_key: current_node_public_keys
            .committee_signing_public_key
            .expect("committee signing public key missing"),
        tls_certificate: current_node_public_keys
            .tls_certificate
            .expect("tls certificate missing"),
        dkg_dealing_encryption_public_key: current_node_public_keys
            .dkg_dealing_encryption_public_key
            .expect("dkg dealing encryption public key missing"),
        idkg_dealing_encryption_public_key: current_node_public_keys
            .idkg_dealing_encryption_public_key
            .expect("idkg dealing encryption public key missing"),
    }
}
