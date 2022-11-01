use crate::vault::api::CspPublicKeyStoreError;
use crate::vault::api::CspVault;
use std::sync::Arc;

pub fn should_fail_on_unimplemented_get_current_node_public_keys(csp_vault: Arc<dyn CspVault>) {
    assert_eq!(
        csp_vault.current_node_public_keys().unwrap_err(),
        CspPublicKeyStoreError::TransientInternalError("TODO: As part of CRP-1719, implement the functionality for returning the current node public keys".to_string())
    );
}
