use crate::tls::rustls::cert_resolver::KeyIncompatibleWithSigSchemeError;
use crate::tls::rustls::cert_resolver::StaticCertResolver;
use assert_matches::assert_matches;
use rustls::{
    Error as TLSError, SignatureAlgorithm, SignatureScheme,
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
};
use std::sync::Arc;

mod instantiation {
    use super::*;

    #[test]
    fn should_fail_on_new_new_with_incompatible_sig_schemes() {
        let cert_chain = vec![CertificateDer::from(b"certificate".to_vec())];
        let certified_key_ecdsa = CertifiedKey::new(
            cert_chain,
            Arc::new(DummySigningKey::new(SignatureScheme::ECDSA_NISTP256_SHA256)),
        );
        let result = StaticCertResolver::new(certified_key_ecdsa, SignatureScheme::ED25519);
        assert_matches!(result, Err(KeyIncompatibleWithSigSchemeError {}));
    }
}

mod client_side {
    use super::*;
    use rustls::{SignatureScheme, client::ResolvesClientCert};

    #[test]
    fn should_resolve_to_static_certified_key() {
        let cert_chain = vec![CertificateDer::from(b"certificate".to_vec())];
        let certified_key =
            CertifiedKey::new(cert_chain.clone(), Arc::new(DummySigningKey::new_ed25519()));
        let sig_scheme = SignatureScheme::ED25519;
        let resolver = StaticCertResolver::new(certified_key.clone(), sig_scheme).unwrap();

        let result = resolver
            .resolve(&[b"acceptable_issuers"], &[sig_scheme])
            .unwrap();

        // not using assert_matches because CertifiedKey does not implement Debug
        // comparing the fields of CertifiedKey because it does not implement Eq
        assert_eq!(result.cert, cert_chain);
        assert_eq!(result.ocsp, certified_key.ocsp);
        // key omitted because SigningKey cannot be compared and also is irrelevant here
    }

    #[test]
    fn should_have_certs() {
        let certified_key = CertifiedKey::new(
            vec![CertificateDer::from(b"certificate".to_vec())],
            Arc::new(DummySigningKey::new_ed25519()),
        );
        let resolver = StaticCertResolver::new(certified_key, SignatureScheme::ED25519).unwrap();

        assert!(resolver.has_certs());
    }

    #[test]
    fn should_resolve_to_none_if_sig_schemes_do_not_match() {
        let certified_key = CertifiedKey::new(
            vec![CertificateDer::from(b"certificate".to_vec())],
            Arc::new(DummySigningKey::new_ed25519()),
        );
        let resolver = StaticCertResolver::new(certified_key, SignatureScheme::ED25519).unwrap();

        let result = resolver.resolve(
            &[b"acceptable_issuers"],
            &[SignatureScheme::ECDSA_NISTP256_SHA256],
        );

        assert!(result.is_none());
    }
}

mod server_side {
    // Unfortunately we cannot test the server side of the StaticCertResolver
    // because the `ClientHello` struct, which is a parameter in the
    // `ResolvesServerCert::resolve`, cannot be instantiated (`new` is private).
}

#[derive(Debug)]
struct DummySigningKey {
    signer: DummySigner,
}

impl DummySigningKey {
    pub fn new(sig_scheme: SignatureScheme) -> Self {
        Self {
            signer: DummySigner { sig_scheme },
        }
    }

    pub fn new_ed25519() -> Self {
        Self::new(SignatureScheme::ED25519)
    }
}

impl SigningKey for DummySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.signer.sig_scheme) {
            Some(Box::new(self.signer.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        unimplemented!()
    }
}

#[derive(Clone, Debug)]
struct DummySigner {
    sig_scheme: SignatureScheme,
}

impl Signer for DummySigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, TLSError> {
        Ok(b"dummy signature".to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.sig_scheme
    }
}
