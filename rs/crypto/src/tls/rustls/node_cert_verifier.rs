use crate::tls::tls_cert_from_registry;
use ic_crypto_tls_cert_validation::ValidTlsCertificate;
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsPublicKeyCert};
use ic_crypto_utils_tls::{NodeIdFromCertificateDerError, node_id_from_certificate_der};
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::{NodeId, RegistryVersion, Time};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TLSError, OtherError,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::{fmt, sync::Arc};

#[cfg(test)]
mod tests;

/// Implements `ServerCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * No intermediate certificates.
/// * The end entity certificate can be parsed from DER.
/// * The end entity certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the end entity's subject CN is
///   contained in `allowed_nodes` (as passed to `new`).
/// * The end entity certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the end entity certificate. (The `registry_client` and
///   `registry_version` are passed to `new`.)
///
/// If any of these conditions does not hold, a `TLSError` is returned.
pub struct NodeServerCertVerifier {
    allowed_nodes: SomeOrAllNodes,
    registry_client: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
}

impl NodeServerCertVerifier {
    /// Creates a verifier that considers only certificates for the
    /// `allowed_nodes` fetched from the `registry_client` at registry version
    /// `registry_version` as trusted.
    pub fn new(
        allowed_nodes: SomeOrAllNodes,
        registry_client: Arc<dyn RegistryClient>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            allowed_nodes,
            registry_client,
            registry_version,
        }
    }
}

impl fmt::Debug for NodeServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeServerCertVerifier{{ allowed_nodes: {:?}, registry_version: {} }}",
            self.allowed_nodes, self.registry_version
        )
    }
}

/// Implements `ClientCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * No intermediate certificates.
/// * The end entity certificate can be parsed from DER.
/// * The end entity certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the end entity's subject CN is
///   contained in `allowed_nodes` (as passed to the constructors).
/// * The end entity certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the end entity certificate. (The `registry_client` and
///   `registry_version` are passed to the constructors.)
///
/// If any of these conditions does not hold, a `TLSError` is returned.
///
/// This verifier always offers client authentication, see `offer_client_auth`.
pub struct NodeClientCertVerifier {
    allowed_nodes: SomeOrAllNodes,
    registry_client: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
}

impl fmt::Debug for NodeClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeClientCertVerifier{{ allowed_nodes: {:?}, registry_version: {} }}",
            self.allowed_nodes, self.registry_version
        )
    }
}

impl NodeClientCertVerifier {
    /// Creates a verifier that considers only certificates for the
    /// `allowed_nodes` fetched from the `registry_client` at registry version
    /// `registry_version` as trusted.
    ///
    /// Client authentication is mandatory.
    pub fn new_with_mandatory_client_auth(
        allowed_nodes: SomeOrAllNodes,
        registry_client: Arc<dyn RegistryClient>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            allowed_nodes,
            registry_client,
            registry_version,
        }
    }
}

impl ServerCertVerifier for NodeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        verify_node_cert(
            end_entity,
            intermediates,
            &self.allowed_nodes,
            self.registry_client.as_ref(),
            self.registry_version,
            unix_time_to_ic_time(now)?,
        )
        .map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Err(TLSError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for NodeClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TLSError> {
        verify_node_cert(
            end_entity,
            intermediates,
            &self.allowed_nodes,
            self.registry_client.as_ref(),
            self.registry_version,
            unix_time_to_ic_time(now)?,
        )
        .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Err(TLSError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
}

fn verify_node_cert(
    end_entity_der: &CertificateDer,
    intermediates: &[CertificateDer],
    allowed_nodes: &SomeOrAllNodes,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
    current_time: Time,
) -> Result<(), TLSError> {
    ensure_intermediate_certs_empty(intermediates)?;
    let end_entity_node_id =
        node_id_from_certificate_der(end_entity_der.as_ref()).map_err(|err| match err {
            NodeIdFromCertificateDerError::InvalidCertificate(_) => {
                TLSError::InvalidCertificate(CertificateError::BadEncoding)
            }
            NodeIdFromCertificateDerError::UnexpectedContent(e) => TLSError::InvalidCertificate(
                CertificateError::Other(OtherError(Arc::from(Box::from(e)))),
            ),
        })?;

    ensure_node_id_in_allowed_nodes(end_entity_node_id, allowed_nodes)?;
    let node_cert_from_registry =
        node_cert_from_registry(end_entity_node_id, registry_client, registry_version)?;
    ensure_certificates_equal(
        end_entity_der.as_ref(),
        end_entity_node_id,
        node_cert_from_registry.as_der(),
    )?;
    // It's important to do the validity check after checking equality to the
    // registry cert because the cert validation uses a different parser
    // (`x509_parser` as opposed to OpenSSL that is used above) and it is safer
    // to not just pass any untrusted data to it. We consider the DER here trusted
    // because it is equal to the certificate DER stored in the registry, as checked
    // above.
    ensure_node_certificate_is_valid(end_entity_der.to_vec(), end_entity_node_id, current_time)?;
    Ok(())
}

fn ensure_intermediate_certs_empty(intermediates: &[CertificateDer]) -> Result<(), TLSError> {
    if !intermediates.is_empty() {
        return Err(TLSError::General(format!(
            "The peer must send exactly one self signed certificate, but it sent {} certificates.",
            intermediates.len() + 1
        )));
    }
    Ok(())
}

fn ensure_node_id_in_allowed_nodes(
    node_id: NodeId,
    allowed_nodes: &SomeOrAllNodes,
) -> Result<(), TLSError> {
    if !allowed_nodes.contains(node_id) {
        return Err(TLSError::General(format!(
            "The peer certificate with node ID {node_id} is not allowed. Allowed node IDs: {allowed_nodes:?}"
        )));
    }
    Ok(())
}

fn node_cert_from_registry(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<TlsPublicKeyCert, TLSError> {
    tls_cert_from_registry(registry_client, node_id, registry_version).map_err(|e| {
        TLSError::General(format!(
            "Failed to retrieve TLS certificate for node ID {node_id} from the registry at registry version {registry_version}: {e:?}"
        ))
    })
}

fn ensure_certificates_equal(
    end_entity_cert: &[u8],
    node_id: NodeId,
    node_cert_from_registry: &Vec<u8>,
) -> Result<(), TLSError> {
    if node_cert_from_registry != end_entity_cert {
        return Err(TLSError::General(format!(
            "The peer certificate is not trusted since it differs from the registry certificate. NodeId of presented cert: {node_id}"
        )));
    }
    Ok(())
}

fn ensure_node_certificate_is_valid(
    certificate_der: Vec<u8>,
    cert_node_id: NodeId,
    current_time: Time,
) -> Result<(), TLSError> {
    ValidTlsCertificate::try_from((
        X509PublicKeyCert { certificate_der },
        cert_node_id,
        current_time,
    ))
    .map_err(|e| TLSError::General(format!("The peer certificate is invalid: {e}")))?;
    Ok(())
}

fn unix_time_to_ic_time(now: UnixTime) -> Result<Time, TLSError> {
    let secs = now.as_secs();
    Time::from_secs_since_unix_epoch(secs).map_err(|_| TLSError::FailedToGetCurrentTime)
}
