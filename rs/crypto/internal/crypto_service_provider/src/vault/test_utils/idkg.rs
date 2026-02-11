use crate::CspVault;
use crate::api::CspCreateMEGaKeyError;
use crate::key_id::KeyId;
use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use assert_matches::assert_matches;
use std::collections::HashSet;
use std::sync::Arc;

pub fn should_generate_and_store_dealing_encryption_key_pair_multiple_times(
    csp_vault: Arc<dyn CspVault>,
) {
    let mut key_ids = HashSet::new();
    for _ in 1..=5 {
        let public_key = csp_vault
            .idkg_gen_dealing_encryption_key_pair()
            .expect("error generating IDKG key pair");

        assert_eq!(
            csp_vault
                .current_node_public_keys()
                .expect("missing public keys")
                .idkg_dealing_encryption_public_key
                .expect("missing IDKG public key"),
            idkg_dealing_encryption_pk_to_proto(public_key.clone())
        );
        let key_id = KeyId::from(&public_key);
        assert!(csp_vault.sks_contains(key_id).expect("error reading SKS"));

        assert!(key_ids.insert(key_id));
    }
    // Ensure that previously generated secret keys were not
    // deleted/overwritten by the generation of new keys.
    for key_id in key_ids {
        assert!(csp_vault.sks_contains(key_id).expect("error reading SKS"));
    }
}

// The given `csp_vault` is expected to return an IO error on add_idkg_dealing_encryption_pubkey
pub fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.idkg_gen_dealing_encryption_key_pair();

    assert_matches!(result,
        Err(CspCreateMEGaKeyError::TransientInternalError { internal_error })
        if internal_error.contains("failed to add iDKG")
    );
}
