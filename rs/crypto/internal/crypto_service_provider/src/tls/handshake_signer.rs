use crate::api::CspTlsHandshakeSignerProvider;
use crate::key_id::KeyId;
use crate::types::CspSignature;
use crate::vault::api::{CspTlsKeygenError, CspTlsSignError, CspVault};
use crate::{Csp, TlsHandshakeCspVault};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::NodeId;

use std::sync::Arc;

impl CspTlsHandshakeSignerProvider for Csp {
    fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault> {
        Arc::new(CspTlsHandshakeSignerImpl {
            csp_vault: Arc::clone(&self.csp_vault),
        })
    }
}

struct CspTlsHandshakeSignerImpl {
    csp_vault: Arc<dyn CspVault>,
}

impl TlsHandshakeCspVault for CspTlsHandshakeSignerImpl {
    fn gen_tls_key_pair(
        &self,
        _node: NodeId,
        _not_after: &str,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        unimplemented!("CspTlsHandshakeSigner on purpose supports only tls_sign()-operation")
    }

    fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError> {
        self.csp_vault.tls_sign(message, key_id)
    }
}
