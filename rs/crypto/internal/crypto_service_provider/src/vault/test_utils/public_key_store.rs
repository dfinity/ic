use crate::keygen::utils::{
    committee_signing_pk_to_proto, dkg_dealing_encryption_pk_to_proto,
    idkg_dealing_encryption_pk_to_proto, node_signing_pk_to_proto,
};
use crate::vault::api::CspVault;
use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

pub const NODE_1: u64 = 4241;
pub const FIXED_SEED: u64 = 42;
pub const NOT_AFTER: &str = "25670102030405Z";

pub fn should_retrieve_current_public_keys(csp_vault: Arc<dyn CspVault>) {
    let node_signing_public_key = csp_vault
        .gen_node_signing_key_pair()
        .expect("Could not generate node signing keys");
    let committee_signing_public_key = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Could not generate committee signing keys");
    let cert = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Generation of TLS keys failed.");
    let (nidkg_public_key, nidkg_pop) = csp_vault
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate DKG dealing encryption keys");
    let idkg_public_key = generate_idkg_dealing_encryption_key_pair(&csp_vault);

    let current_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Error retrieving current node public keys");

    assert_eq!(
        current_public_keys,
        CurrentNodePublicKeys {
            node_signing_public_key: Some(node_signing_pk_to_proto(node_signing_public_key)),
            committee_signing_public_key: Some(committee_signing_pk_to_proto(
                committee_signing_public_key
            )),
            tls_certificate: Some(cert.to_proto()),
            dkg_dealing_encryption_public_key: Some(dkg_dealing_encryption_pk_to_proto(
                nidkg_public_key,
                nidkg_pop
            )),
            idkg_dealing_encryption_public_key: Some(idkg_dealing_encryption_pk_to_proto(
                idkg_public_key
            ))
        }
    )
}

pub fn should_retrieve_last_idkg_public_key(csp_vault: Arc<dyn CspVault>) {
    let idkg_public_key_1 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_1.clone()),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );

    let idkg_public_key_2 = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert_ne!(idkg_public_key_1, idkg_public_key_2);
    assert_eq!(
        idkg_dealing_encryption_pk_to_proto(idkg_public_key_2),
        csp_vault
            .current_node_public_keys()
            .expect("Error retrieving current node public keys")
            .idkg_dealing_encryption_public_key
            .expect("missing iDKG key")
    );
}

pub fn should_return_true_for_pks_contains_if_all_keys_match_with_one_idkg_key(
    csp_vault: Arc<dyn CspVault>,
) {
    let current_node_public_keys = generate_all_keys(&csp_vault);
    assert!(csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_true_for_pks_contains_for_empty_current_node_public_keys(
    csp_vault: Arc<dyn CspVault>,
) {
    let _current_node_public_keys = generate_all_keys(&csp_vault);
    let empty_current_node_public_keys = CurrentNodePublicKeys {
        node_signing_public_key: None,
        committee_signing_public_key: None,
        tls_certificate: None,
        dkg_dealing_encryption_public_key: None,
        idkg_dealing_encryption_public_key: None,
    };
    assert!(csp_vault
        .pks_contains(empty_current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_false_for_pks_contains_if_node_signing_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);
    current_node_public_keys.node_signing_public_key =
        shadow_node_public_keys.node_signing_public_key;
    assert!(!csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_false_for_pks_contains_if_committee_signing_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);
    current_node_public_keys.committee_signing_public_key =
        shadow_node_public_keys.committee_signing_public_key;
    assert!(!csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_false_for_pks_contains_if_dkg_dealing_encryption_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);
    current_node_public_keys.dkg_dealing_encryption_public_key =
        shadow_node_public_keys.dkg_dealing_encryption_public_key;
    assert!(!csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_false_for_pks_contains_if_tls_certificate_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);
    current_node_public_keys.tls_certificate = shadow_node_public_keys.tls_certificate;
    assert!(!csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_false_for_pks_contains_if_idkg_dealing_encryption_key_does_not_match(
    csp_vault: Arc<dyn CspVault>,
    shadow_csp_vault: Arc<dyn CspVault>,
) {
    let mut current_node_public_keys = generate_all_keys(&csp_vault);
    let shadow_node_public_keys = generate_all_keys(&shadow_csp_vault);
    current_node_public_keys.idkg_dealing_encryption_public_key =
        shadow_node_public_keys.idkg_dealing_encryption_public_key;
    assert!(!csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys(
    csp_vault: Arc<dyn CspVault>,
) {
    let current_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert!(csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

pub fn should_return_true_for_pks_contains_if_all_keys_match_with_multiple_idkg_keys_and_registry_key_not_first_in_vector(
    csp_vault: Arc<dyn CspVault>,
) {
    let _initial_node_public_keys = generate_all_keys(&csp_vault);
    let _second_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    let current_node_public_keys = csp_vault
        .current_node_public_keys()
        .expect("Failed to get current node public keys");
    let _third_idkg_pk = generate_idkg_dealing_encryption_key_pair(&csp_vault);
    assert!(csp_vault
        .pks_contains(current_node_public_keys)
        .expect("Error calling pks_contains"));
}

fn generate_idkg_dealing_encryption_key_pair(csp_vault: &Arc<dyn CspVault>) -> MEGaPublicKey {
    csp_vault
        .idkg_gen_dealing_encryption_key_pair()
        .expect("Failed to generate IDkg dealing encryption keys")
}

fn generate_all_keys(csp_vault: &Arc<dyn CspVault>) -> CurrentNodePublicKeys {
    let _node_signing_pk = csp_vault
        .gen_node_signing_key_pair()
        .expect("Failed to generate node signing key pair");
    let _committee_signing_pk = csp_vault
        .gen_committee_signing_key_pair()
        .expect("Failed to generate committee signing key pair");
    let _dkg_dealing_encryption_pk = csp_vault
        .gen_dealing_encryption_key_pair(node_test_id(NODE_1))
        .expect("Failed to generate NI-DKG dealing encryption key pair");
    let _tls_certificate = csp_vault
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("Failed to generate TLS certificate");
    let _idkg_dealing_encryption_key = csp_vault
        .idkg_gen_dealing_encryption_key_pair()
        .expect("Failed to generate iDKG dealing encryption keys");
    csp_vault
        .current_node_public_keys()
        .expect("Failed to get current node public keys")
}
