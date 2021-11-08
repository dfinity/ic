use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{ClientHello, ResolvesClientCert, ResolvesServerCert, SignatureScheme};

#[cfg(test)]
mod tests;

/// A certificate resolver that resolves to a static/fixed certified key.
///
/// The only relevant factor for choosing the certified key is the signature
/// scheme. All other factors factors such as server-supplied acceptable issuers
/// on the client side or details of the `ClientHello` on the server side are
/// ignored.
pub struct StaticCertResolver {
    certified_key: CertifiedKey,
    sig_scheme: SignatureScheme,
}

impl StaticCertResolver {
    #[allow(unused)]
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
            certified_key,
            sig_scheme,
        })
    }
}

/// Occurs if a certified key is incompatible with a signature scheme.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyIncompatibleWithSigSchemeError {}

impl ResolvesClientCert for StaticCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedKey> {
        if !sigschemes.contains(&self.sig_scheme) {
            return None;
        }
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if !client_hello.sigschemes().contains(&self.sig_scheme) {
            return None;
        }
        Some(self.certified_key.clone())
    }
}
