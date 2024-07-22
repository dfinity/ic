use ic_crypto_internal_csp::{key_id::KeyId, TlsHandshakeCspVault};
use ic_interfaces_registry::RegistryClient;
use ic_types::NodeId;
use rustls::{
    client::ResolvesClientCert,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    SignatureScheme,
};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use crate::tls::tls_cert_from_registry;

use super::{certified_key, csp_server_signing_key::CspServerEd25519SigningKey};

#[cfg(test)]
mod tests;

/// A certificate resolver that resolves to a static/fixed certified key.
///
/// The only relevant factor for choosing the certified key is the signature
/// scheme. All other factors factors such as server-supplied acceptable issuers
/// on the client side or details of the `ClientHello` on the server side are
/// ignored.
pub struct RegistryCertResolver {
    node_id: NodeId,
    registry_client: Arc<dyn RegistryClient>,
    tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
}

impl Debug for RegistryCertResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegistryCertResolver")
    }
}

impl RegistryCertResolver {
    /// Creates a new `StaticCertResolver`.
    ///
    /// Returns an error if `certified_key` is incompatible with `sig_scheme`.
    pub fn new(
        node_id: NodeId,
        registry_client: Arc<dyn RegistryClient>,
        tls_csp_vault: Arc<dyn TlsHandshakeCspVault>,
    ) -> Self {
        Self {
            node_id,
            registry_client,
            tls_csp_vault,
        }
    }
}

impl ResolvesClientCert for RegistryCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if !sigschemes.contains(&SignatureScheme::ED25519) {
            return None;
        }
        let self_tls_cert = tls_cert_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            self.registry_client.get_latest_version(),
        )
        .ok()?;
        let self_tls_cert_key_id = KeyId::try_from(&self_tls_cert).ok()?;
        let ed25519_signing_key =
            CspServerEd25519SigningKey::new(self_tls_cert_key_id, self.tls_csp_vault.clone());
        let certified_key = certified_key(self_tls_cert, ed25519_signing_key);
        Some(Arc::new(certified_key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for RegistryCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if !client_hello
            .signature_schemes()
            .contains(&SignatureScheme::ED25519)
        {
            return None;
        }
        let self_tls_cert = tls_cert_from_registry(
            self.registry_client.as_ref(),
            self.node_id,
            self.registry_client.get_latest_version(),
        )
        .ok()?;
        let self_tls_cert_key_id = KeyId::try_from(&self_tls_cert).ok()?;
        let ed25519_signing_key =
            CspServerEd25519SigningKey::new(self_tls_cert_key_id, self.tls_csp_vault.clone());
        let certified_key = certified_key(self_tls_cert, ed25519_signing_key);
        Some(Arc::new(certified_key))
    }
}
