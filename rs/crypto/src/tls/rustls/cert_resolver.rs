use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// A certificate resolver that resolves to a static/fixed certified key.
///
/// The only relevant factor for choosing the certified key is the signature
/// scheme. All other factors factors such as server-supplied acceptable issuers
/// on the client side or details of the `ClientHello` on the server side are
/// ignored.
pub struct StaticCertResolver {
    certified_key: Arc<CertifiedKey>,
    sig_scheme: SignatureScheme,
}

impl StaticCertResolver {
    /// Creates a new `StaticCertResolver`.
    ///
    /// Returns an error if `certified_key` is incompatible with `sig_scheme`.
    pub fn new(
        certified_key: CertifiedKey,
        sig_scheme: SignatureScheme,
    ) -> Result<Self, KeyIncompatibleWithSigSchemeError> {
        if certified_key.key.choose_scheme(&[sig_scheme]).is_none() {
            return Err(KeyIncompatibleWithSigSchemeError {});
        }
        Ok(Self {
            certified_key: Arc::new(certified_key),
            sig_scheme,
        })
    }
}

/// Occurs if a certified key is incompatible with a signature scheme.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct KeyIncompatibleWithSigSchemeError {}

impl ResolvesClientCert for StaticCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if !sigschemes.contains(&self.sig_scheme) {
            return None;
        }
        Some(Arc::clone(&self.certified_key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if !client_hello.signature_schemes().contains(&self.sig_scheme) {
            return None;
        }
        Some(Arc::clone(&self.certified_key))
    }
}

impl Debug for StaticCertResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StaticCertResolver{{ \
                certified_key: CertifiedKey{{ cert: {:?}, key: OMITTED, ocsp: {:?} }}, \
                sig_scheme: {:?} \
            }}",
            self.certified_key.cert, self.certified_key.ocsp, self.sig_scheme
        )
    }
}
