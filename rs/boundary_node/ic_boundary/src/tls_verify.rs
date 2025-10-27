use std::sync::Arc;

use anyhow::anyhow;
use arc_swap::ArcSwapOption;
use ic_crypto_utils_tls::{NodeIdFromCertificateDerError, node_id_from_certificate_der};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as RustlsError,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    time::ASN1Time,
};

use crate::snapshot::RegistrySnapshot;

#[derive(Debug)]
pub struct TlsVerifier {
    rs: Arc<ArcSwapOption<RegistrySnapshot>>,
}

impl TlsVerifier {
    pub fn new(rs: Arc<ArcSwapOption<RegistrySnapshot>>) -> Self {
        Self { rs }
    }
}

// Implement the certificate verifier which ensures that the certificate
// that was provided by node during TLS handshake matches its public key from the registry
// This trait is used by Rustls in reqwest under the hood
impl ServerCertVerifier for TlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !intermediates.is_empty() {
            return Err(RustlsError::General(format!(
                "The peer must send exactly one self signed certificate, but it sent {} certificates.",
                intermediates.len() + 1
            )));
        }

        // Check if the CommonName in the certificate can be parsed into a Principal
        let node_id =
            node_id_from_certificate_der(end_entity.as_ref()).map_err(|err| match err {
                NodeIdFromCertificateDerError::InvalidCertificate(_) => {
                    RustlsError::InvalidCertificate(CertificateError::BadEncoding)
                }
                NodeIdFromCertificateDerError::UnexpectedContent(e) => {
                    RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(
                        Arc::from(Box::from(anyhow!("unexpected certificate content: {e:#}"))),
                    )))
                }
            })?;
        // Load a routing table if we have one
        let rs = self
            .rs
            .load_full()
            .ok_or_else(|| RustlsError::General("no routing table published".into()))?;

        // Look up a node in the routing table based on the hostname provided by rustls
        let node = match server_name {
            // Currently support only DnsName
            ServerName::DnsName(v) => {
                // Check if certificate CommonName matches the DNS name
                if node_id.to_string() != v.as_ref() {
                    return Err(RustlsError::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ));
                }

                match rs.nodes.get(v.as_ref()) {
                    // If the requested node is not in the routing table
                    None => {
                        return Err(RustlsError::General(format!(
                            "Node '{}' not found in a routing table",
                            v.as_ref()
                        )));
                    }

                    // Found
                    Some(v) => v,
                }
            }

            // Unsupported for now, can be removed later if not needed at all
            ServerName::IpAddress(_) => return Err(RustlsError::UnsupportedNameType),

            // Enum is marked non_exhaustive
            &_ => return Err(RustlsError::UnsupportedNameType),
        };

        // Cert is parsed & checked when we read it from the registry - if we got here then it's correct
        // It's a zero-copy view over byte array
        // Storing X509Certificate directly in Node is problematic since it does not own the data
        let (_, node_cert) = X509Certificate::from_der(&node.tls_certificate).unwrap();

        // Parse the certificate provided by server
        let (_, provided_cert) = X509Certificate::from_der(end_entity)
            .map_err(|_x| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Verify the provided self-signed certificate using the public key from registry
        let node_tls_pubkey_from_registry = ic_ed25519::PublicKey::deserialize_raw(
            &node_cert
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data,
        )
        .map_err(|e| {
            RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::from(
                Box::from(anyhow!("node cert: invalid Ed25519 public key: {e:?}")),
            ))))
        })?;

        let provided_cert_sig = <[u8; 64]>::try_from(provided_cert.signature_value.data.as_ref())
            .map_err(|e| {
            RustlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::from(
                Box::from(anyhow!("node cert: invalid Ed25519 signature: {:?}", e)),
            ))))
        })?;

        node_tls_pubkey_from_registry
            .verify_signature(provided_cert.tbs_certificate.as_ref(), &provided_cert_sig)
            .map_err(|_x| RustlsError::InvalidCertificate(CertificateError::BadSignature))?;

        // Check if the certificate is valid at provided `now` time
        if !provided_cert
            .validity
            .is_valid_at(ASN1Time::from_timestamp(now.as_secs() as i64).unwrap())
        {
            return Err(RustlsError::InvalidCertificate(CertificateError::Expired));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{str::FromStr, time::Duration};

    use anyhow::Error;
    use ic_types::{NodeId, PrincipalId};
    use rustls::{
        CertificateError, Error as RustlsError,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    use crate::{
        snapshot::{Snapshot, Snapshotter},
        test_utils::{create_fake_registry_client, valid_tls_certificate_and_validation_time},
    };

    // CN = s52il-lowsg-eip4y-pt5lv-sbdpb-vg4gg-4iasu-egajp-yluji-znfz3-2qe
    const TEST_CERTIFICATE: &str = "3082015530820107a00302010202136abf05c1260364e09ad5f4ad0e9cb90a6e0edb300506032b6570304a3148304606035504030c3f733532696c2d6c6f7773672d\
                                65697034792d7074356c762d73626470622d76673467672d34696173752d6567616a702d796c756a692d7a6e667a332d3271653020170d3232313131343135303230\
                                345a180f39393939313233313233353935395a304a3148304606035504030c3f733532696c2d6c6f7773672d65697034792d7074356c762d73626470622d76673467\
                                672d34696173752d6567616a702d796c756a692d7a6e667a332d327165302a300506032b65700321002b5c5af2776114a400d71995cf9cdb72ca1a26b59b875a3d70\
                                c79bf48b5f210b300506032b6570034100f3ded920aa535295c69fd97c8da2d73ce525370456cdaacc4863b25e19b0d2af1961454ac5ff9a9e182ea54034ceed0dd0\
                                2a7bd9421ae1f844c894544bca9602";

    fn test_certificate() -> Vec<u8> {
        hex::decode(TEST_CERTIFICATE).unwrap()
    }

    fn check_certificate_verification(
        tls_verifier: &TlsVerifier,
        name: &str,
        der: Vec<u8>,
    ) -> Result<(), RustlsError> {
        let crt = CertificateDer::from(der);
        let intermediates: Vec<CertificateDer> = vec![];
        let server_name = ServerName::try_from(name).unwrap();
        let ocsp_response: Vec<u8> = vec![];

        tls_verifier.verify_server_cert(
            &crt,
            intermediates.as_slice(),
            &server_name,
            ocsp_response.as_slice(),
            UnixTime::now(),
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn test_verify_tls_certificate() -> Result<(), Error> {
        let snapshot = Arc::new(ArcSwapOption::empty());

        // Same node_id that valid_tls_certificate_and_validation_time() is valid for
        let node_id = NodeId::from(
            PrincipalId::from_str(
                "4inqb-2zcvk-f6yql-sowol-vg3es-z24jd-jrkow-mhnsd-ukvfp-fak5p-aae",
            )
            .unwrap(),
        );

        let (reg, _, _) = create_fake_registry_client(1, 1, Some(node_id));
        let reg = Arc::new(reg);
        let (channel_send, _) = tokio::sync::watch::channel(None);
        let snapshotter = Snapshotter::new(snapshot.clone(), channel_send, reg, Duration::ZERO);
        let verifier = TlsVerifier::new(snapshot.clone());
        snapshotter.snapshot()?;

        let snapshot = snapshot.load_full().unwrap();
        let node_name = snapshot.subnets[0].nodes[0].id.to_string();

        // Check valid certificate
        check_certificate_verification(
            &verifier,
            node_name.as_str(),
            valid_tls_certificate_and_validation_time()
                .0
                .certificate_der,
        )?;

        // Check with different cert -> should fail
        let r = check_certificate_verification(&verifier, node_name.as_str(), test_certificate());
        matches!(
            r,
            Err(RustlsError::InvalidCertificate(
                CertificateError::NotValidForName
            ))
        );

        // Check different DnsName -> should fail
        let r = check_certificate_verification(
            &verifier,
            "blah-blah-foo-bar",
            valid_tls_certificate_and_validation_time()
                .0
                .certificate_der,
        );
        matches!(
            r,
            Err(RustlsError::InvalidCertificate(
                CertificateError::NotValidForName
            ))
        );

        Ok(())
    }
}
