use crate::api::CspCreateMEGaKeyError;
use crate::key_id::KeyId;
use crate::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use crate::CspVault;
use std::sync::Arc;

pub fn should_generate_and_store_dealing_encryption_key_pair_multiple_times(
    csp_vault: Arc<dyn CspVault>,
) {
    for _ in 1..=5 {
        let generated_idkg_dealing_encryption_public_key = csp_vault
            .idkg_gen_dealing_encryption_key_pair()
            .expect("error generating IDKG key pair");

        assert_eq!(
            csp_vault
                .current_node_public_keys()
                .expect("missing public keys")
                .idkg_dealing_encryption_public_key
                .expect("missing IDKG public key"),
            idkg_dealing_encryption_pk_to_proto(
                generated_idkg_dealing_encryption_public_key.clone()
            )
        );

        let key_id =
            KeyId::try_from(&generated_idkg_dealing_encryption_public_key).expect("invalid key ID");
        assert!(csp_vault.sks_contains(&key_id).expect("error reading SKS"));
    }
}

// The given `csp_vault` is expected to return an IO error on set_idkg_dealing_encryption_pubkeys
pub fn should_fail_with_transient_internal_error_if_storing_idkg_public_key_fails(
    csp_vault: Arc<dyn CspVault>,
) {
    let result = csp_vault.idkg_gen_dealing_encryption_key_pair();

    assert!(matches!(result,
        Err(CspCreateMEGaKeyError::TransientInternalError { internal_error })
        if internal_error.contains("IO error")
    ));
}
