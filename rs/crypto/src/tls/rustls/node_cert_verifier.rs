use crate::tls::{node_id_from_cert_subject_common_name, tls_cert_from_registry};
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsPublicKeyCert};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;
use tokio_rustls::rustls::{
    Certificate, ClientCertVerified, ClientCertVerifier, DistinguishedNames, RootCertStore,
    ServerCertVerified, ServerCertVerifier, TLSError,
};
use tokio_rustls::webpki;
use tokio_rustls::webpki::DNSNameRef;

#[cfg(test)]
mod tests;

/// Implements `ServerCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * Exactly one certificate (i.e. no chain with more than one certificate) is
///   presented by the peer in `presented_certs` (as passed to
///   `verify_server_cert`).
/// * The presented certificate can be parsed from DER.
/// * The presented certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the presented certificate's subject CN is
///   contained in `allowed_nodes` (as passed to `new`).
/// * The presented certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the presented certificate. (The `registry_client` and
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

/// Implements `ClientCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * Exactly one certificate (i.e. no chain with more than one certificate) is
///   presented by the peer in `presented_certs` (as passed to
///   `verify_client_cert`).
/// * The presented certificate can be parsed from DER.
/// * The presented certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the presented certificate's subject CN is
///   contained in `allowed_nodes` (as passed to the constructors).
/// * The presented certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the presented certificate. (The `registry_client` and
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
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        _dns_name: DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        verify_node_cert(
            presented_certs,
            &self.allowed_nodes,
            &self.registry_client,
            self.registry_version,
        )
        .map(|_| ServerCertVerified::assertion())
    }
}

impl ClientCertVerifier for NodeClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self, _sni: Option<&webpki::DNSName>) -> Option<bool> {
        Some(true)
    }

    fn client_auth_root_subjects(
        &self,
        _sni: Option<&webpki::DNSName>,
    ) -> Option<DistinguishedNames> {
        // If `None` is returned, the connection would be aborted, see the rust doc of
        // `client_auth_root_subjects`.
        Some(DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        verify_node_cert(
            presented_certs,
            &self.allowed_nodes,
            &self.registry_client,
            self.registry_version,
        )
        .map(|_| ClientCertVerified::assertion())
    }
}

fn verify_node_cert(
    presented_certs: &[Certificate],
    allowed_nodes: &SomeOrAllNodes,
    registry_client: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<(), TLSError> {
    ensure_exactly_one_presented_cert(presented_certs)?;
    let presented_cert_der = presented_certs[0].0.clone();
    let presented_cert = cert_from_der(presented_cert_der.clone())?;
    let presented_cert_node_id = node_id_from_subject_cn(&presented_cert)?;
    ensure_node_id_in_allowed_nodes(presented_cert_node_id, allowed_nodes)?;
    let node_cert_from_registry =
        node_cert_from_registry(presented_cert_node_id, registry_client, registry_version)?;
    ensure_certificates_equal(
        presented_cert,
        presented_cert_node_id,
        node_cert_from_registry,
    )?;
    // It's important to do the validity check after checking equality to the
    // registry cert because the cert validation uses a different parser
    // (`x509_parser` as opposed to OpenSSL that is used above) and it is safer
    // to not just pass any untrusted data to it. We consider the DER here trusted
    // because it is equal to the certificate DER stored in the registry, as checked
    // above.
    ensure_node_certificate_is_valid(presented_cert_der, presented_cert_node_id)
}

fn ensure_exactly_one_presented_cert(presented_certs: &[Certificate]) -> Result<(), TLSError> {
    if presented_certs.len() != 1 {
        return Err(TLSError::General(format!(
            "The peer must send exactly one self signed certificate, but it sent {} certificates.",
            presented_certs.len()
        )));
    }
    Ok(())
}

fn cert_from_der(cert_der: Vec<u8>) -> Result<TlsPublicKeyCert, TLSError> {
    TlsPublicKeyCert::new_from_der(cert_der).map_err(|e| {
        TLSError::General(format!(
            "The presented certificate could not be parsed as DER: {}",
            e
        ))
    })
}

fn node_id_from_subject_cn(cert: &TlsPublicKeyCert) -> Result<NodeId, TLSError> {
    node_id_from_cert_subject_common_name(cert).map_err(|e| {
        TLSError::General(format!(
            "The presented certificate subject CN could not be parsed as node ID: {:?}",
            e
        ))
    })
}

fn ensure_node_id_in_allowed_nodes(
    node_id: NodeId,
    allowed_nodes: &SomeOrAllNodes,
) -> Result<(), TLSError> {
    if !allowed_nodes.contains(node_id) {
        return Err(TLSError::General(format!(
            "The peer certificate with node ID {} is not allowed. Allowed node IDs: {:?}",
            node_id, allowed_nodes
        )));
    }
    Ok(())
}

fn node_cert_from_registry(
    node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<TlsPublicKeyCert, TLSError> {
    tls_cert_from_registry(registry_client, node_id, registry_version).map_err(|e| {
        TLSError::General(format!(
            "Failed to retrieve TLS certificate for node ID {} from the registry at registry version {}: {:?}",
            node_id, registry_version, e
        ))
    })
}

fn ensure_certificates_equal(
    presented_cert: TlsPublicKeyCert,
    node_id: NodeId,
    node_cert_from_registry: TlsPublicKeyCert,
) -> Result<(), TLSError> {
    if node_cert_from_registry != presented_cert {
        return Err(TLSError::General(
            format!("The peer certificate is not trusted since it differs from the registry certificate. NodeId of presented cert: {}", node_id),
        ));
    }
    Ok(())
}

fn ensure_node_certificate_is_valid(
    certificate_der: Vec<u8>,
    cert_node_id: NodeId,
) -> Result<(), TLSError> {
    ic_crypto_tls_cert_validation::validate_tls_certificate(
        &X509PublicKeyCert { certificate_der },
        cert_node_id,
    )
    .map_err(|e| TLSError::General(format!("The peer certificate is invalid: {}", e)))
}
