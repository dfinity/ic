/*!

References:
  https://github.com/virtee/sev

*/

use crate::{load_certs, pem_to_der, SnpError};
use crate::{ValidateAttestationError, ValidateAttestedStream};
use async_trait::async_trait;
use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, ReplicaLogger};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_client_helpers::{crypto::CryptoRegistry, node::NodeRegistry};
use serde::{Deserialize, Serialize};
use sev::certs::snp;
use sev::certs::snp::Verifiable;
use sev::firmware::guest::AttestationReport;
use sha2::Digest;

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Deserialize, Serialize)]
pub struct AttestationPackage {
    pub report: AttestationReport,
    pub ask_der: Vec<u8>,
    pub vcek_der: Vec<u8>,
}

pub struct Sev {
    pub node_id: NodeId,
    pub subnet_id: SubnetId,
    pub registry: Arc<dyn RegistryClient>,
    log: ReplicaLogger,
}

impl Sev {
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        registry: Arc<dyn RegistryClient>,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            subnet_id,
            registry,
            log,
        }
    }
}

#[async_trait]
impl<S> ValidateAttestedStream<S> for Sev
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn perform_attestation_validation(
        &self,
        mut stream: S,
        peer: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        // If sev_enabled is None or false in the subnet registry, just return and do not perform attestation.
        if !self
            .registry
            .get_features(self.subnet_id, registry_version)
            .map_err(ValidateAttestationError::RegistryError)?
            .unwrap_or_default()
            .sev_enabled
        {
            info!(
                self.log,
                "SEV is not enabled for the subnet. No SEV attestation is performed."
            );
            return Ok(stream);
        }

        // Read seed_id, peer_tls_certificate, my tls_certificate from registry.
        let transport_info = self
            .registry
            .get_node_record(peer, registry_version)
            .map_err(ValidateAttestationError::RegistryError)?
            .ok_or(ValidateAttestationError::RegistryDataMissing {
                node_id: peer,
                registry_version,
                description: "transport_info missing".into(),
            })?;

        let node_operator_id = transport_info.node_operator_id;
        if node_operator_id.is_empty() {
            return Err(ValidateAttestationError::HandshakeError {
                description: "missing node_operator_id".into(),
            });
        }
        let chip_id = transport_info.chip_id;
        if chip_id.is_none() {
            return Err(ValidateAttestationError::HandshakeError {
                description: "missing chip_id.".into(),
            });
        }
        let peer_tls_certificate = self
            .registry
            .get_tls_certificate(peer, registry_version)
            .map_err(ValidateAttestationError::RegistryError)?
            .ok_or(ValidateAttestationError::RegistryDataMissing {
                node_id: peer,
                registry_version,
                description: "peer tls_certificate missing".into(),
            })?;
        let tls_certificate = self
            .registry
            .get_tls_certificate(self.node_id, registry_version)
            .map_err(ValidateAttestationError::RegistryError)?
            .ok_or(ValidateAttestationError::RegistryDataMissing {
                node_id: self.node_id,
                registry_version,
                description: "tls_certificate missing".into(),
            })?;

        // Get an attestation report with the hash of the tls certificate as report data.
        let mut guest_firmware = sev::firmware::guest::Firmware::open().map_err(|_| {
            ValidateAttestationError::HandshakeError {
                description: "unable to open sev guest firmware".into(),
            }
        })?;
        let tls_cert_hash = sha2::Sha256::digest(tls_certificate.certificate_der.as_slice());
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(tls_cert_hash.as_slice());
        let report = guest_firmware
            .get_report(None, Some(report_data), Some(0) /* VMPL0 */)
            .map_err(|_| ValidateAttestationError::HandshakeError {
                description: "unable to get attestation report".into(),
            })?;
        let measurement = report.measurement;

        // Load the certs required to send with the report
        let certs = load_certs().map_err(|e| ValidateAttestationError::CertificatesError {
            description: format!("{}", e),
        })?;

        // Create my attestation package to send to the peer
        let package = AttestationPackage {
            report,
            ask_der: pem_to_der(&certs.ask),
            vcek_der: pem_to_der(&certs.vcek),
        };

        // Write my attestation package to peer.
        let serialized =
            serde_cbor::to_vec(&package).map_err(|e| ValidateAttestationError::HandshakeError {
                description: format!("unable to serialize attestation report {:?}", e),
            })?;
        let len = serialized.len() as u32;
        let serialized_len = len.to_le_bytes();
        stream.write_all(&serialized_len).await.map_err(|e| {
            ValidateAttestationError::HandshakeError {
                description: format!("unable to write attestation report len {:?}", e),
            }
        })?;
        stream.write_all(&serialized).await.map_err(|e| {
            ValidateAttestationError::HandshakeError {
                description: format!("unable to write attestation report {:?}", e),
            }
        })?;

        // Read peer attestation package.
        let mut serialized_len = vec![0u8; 4];
        read_into_buffer(&mut stream, &mut serialized_len).await?;
        let len = u32::from_le_bytes(serialized_len.try_into().map_err(|e| {
            ValidateAttestationError::HandshakeError {
                description: format!("unable to convert serialized length {:?}", e),
            }
        })?);
        let mut buffer: Vec<u8> = vec![0; len as usize];
        read_into_buffer(&mut stream, &mut buffer).await?;
        let peer_package: AttestationPackage =
            serde_cbor::from_slice(buffer.as_slice()).map_err(|e| {
                ValidateAttestationError::HandshakeError {
                    description: format!("unable to deserialize attestation {:?}", e),
                }
            })?;
        let peer_ask = snp::Certificate::from_der(&peer_package.ask_der).map_err(|e| {
            ValidateAttestationError::HandshakeError {
                description: format!("bad peer ask certificate {:?}", e),
            }
        })?;
        let peer_vcek = snp::Certificate::from_der(&peer_package.vcek_der).map_err(|e| {
            ValidateAttestationError::HandshakeError {
                description: format!("bad peer vcek certificate {:?}", e),
            }
        })?;
        let ca_chain = snp::ca::Chain {
            ark: certs.ark.clone().expect("missing ark"),
            ask: peer_ask,
        };
        let chain = snp::Chain {
            ca: ca_chain,
            vcek: peer_vcek,
        };

        // Validate peer attestation package.
        if !is_cert_chain_valid(&chain) {
            return Err(ValidateAttestationError::HandshakeError {
                description: "attestation cert chain invalid".to_string(),
            });
        }
        if !is_report_valid(&peer_package.report, &chain) {
            return Err(ValidateAttestationError::HandshakeError {
                description: "attestation report invalid".to_string(),
            });
        }
        if chip_id != Some(peer_package.report.chip_id.to_vec()) {
            return Err(ValidateAttestationError::HandshakeError {
                description: "Peer package chip_id does not match chip_id from registry"
                    .to_string(),
            });
        }
        let peer_tls_cert_hash = peer_package.report.report_data;
        let peer_cert_hash = sha2::Sha256::digest(peer_tls_certificate.certificate_der.as_slice());
        if &peer_tls_cert_hash.as_slice()[0..32] != peer_cert_hash.as_slice() {
            return Err(ValidateAttestationError::HandshakeError {
                description: "tls certificate sha mismatch".to_string(),
            });
        }
        if measurement != peer_package.report.measurement {
            return Err(ValidateAttestationError::HandshakeError {
                description: "measurement mismatch".to_string(),
            });
        }
        Ok(stream)
    }
}

fn is_report_valid(report: &AttestationReport, chain: &snp::Chain) -> bool {
    (chain, report).verify().ok() == Some(())
}

fn is_cert_chain_valid(chain: &snp::Chain) -> bool {
    chain.verify().ok() == Some(&chain.vcek)
}

async fn read_into_buffer<T: AsyncRead + Unpin>(
    reader: &mut T,
    buf: &mut [u8],
) -> Result<(), ValidateAttestationError> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) => Err(ValidateAttestationError::HandshakeError {
            description: format!("read error {:?}", e),
        }),
    }
}

pub fn get_chip_id() -> Result<Vec<u8>, SnpError> {
    // Check if /dev/sev-guest exists
    let sev_guest_device = Path::new("/dev/sev-guest");
    if !sev_guest_device.exists() {
        return Err(SnpError::SnpNotEnabled {
            description: "/dev/sev-guest does not exist. Snp is not enabled on this Guest".into(),
        });
    }

    let mut guest_firmware =
        sev::firmware::guest::Firmware::open().map_err(|error| SnpError::FirmwareError {
            description: format!("unable to open sev guest firmware: {}", error),
        })?;

    let report = guest_firmware
        .get_report(None, None, Some(0))
        .map_err(|error| SnpError::ReportError {
            description: format!("unable to fetch snp report: {}", error),
        })?;

    Ok(report.chip_id.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    static ARK_PEM: &[u8] = include_bytes!("data/ark.pem");
    static ASK_PEM: &[u8] = include_bytes!("data/ask_milan.pem");
    static VCEK_PEM: &[u8] = include_bytes!("data/vcek_test.pem");
    static ATTESTATION_REPORT: &[u8] = include_bytes!("data/report.bin");

    #[test]
    fn test_is_cert_chain_valid() {
        let ark = snp::Certificate::from_pem(ARK_PEM).expect("invalid ark PEM");
        let ask = snp::Certificate::from_pem(ASK_PEM).expect("invalid ask PEM");
        let vcek = snp::Certificate::from_pem(VCEK_PEM).expect("invalid vcek PEM");

        let ca_chain = snp::ca::Chain { ark, ask };
        let chain = snp::Chain { ca: ca_chain, vcek };

        assert!(is_cert_chain_valid(&chain));
    }

    #[test]
    fn test_not_is_cert_chain_valid() {
        let ark = snp::Certificate::from_pem(ARK_PEM).expect("invalid ark PEM");
        let ask = snp::Certificate::from_pem(ASK_PEM).expect("invalid ask PEM");
        let vcek = snp::Certificate::from_pem(VCEK_PEM).expect("invalid vcek PEM");

        let ca_chain = snp::ca::Chain { ark: ask, ask: ark }; // Argument order wrong!
        let chain = snp::Chain { ca: ca_chain, vcek };

        assert!(!is_cert_chain_valid(&chain));
    }

    #[test]
    fn test_is_report_valid() {
        let ark = snp::Certificate::from_pem(ARK_PEM).expect("invalid ark PEM");
        let ask = snp::Certificate::from_pem(ASK_PEM).expect("invalid ask PEM");
        let vcek = snp::Certificate::from_pem(VCEK_PEM).expect("invalid vcek PEM");

        let ca_chain = snp::ca::Chain { ark, ask };
        let chain = snp::Chain { ca: ca_chain, vcek };

        let attestation_report: AttestationReport =
            unsafe { std::ptr::read(ATTESTATION_REPORT.as_ptr() as *const _) };
        assert!(is_report_valid(&attestation_report, &chain));
    }

    #[test]
    fn test_not_is_report_valid() {
        let ark = snp::Certificate::from_pem(ARK_PEM).expect("invalid ark PEM");
        let ask = snp::Certificate::from_pem(ASK_PEM).expect("invalid ask PEM");
        let vcek = snp::Certificate::from_pem(VCEK_PEM).expect("invalid vcek PEM");

        let ca_chain = snp::ca::Chain { ark, ask };
        let chain = snp::Chain { ca: ca_chain, vcek };

        let attestation_report_invalid: AttestationReport = {
            let mut buf = ATTESTATION_REPORT.to_vec();
            buf[0] ^= 0x80; // flip first bit
            unsafe { std::ptr::read(buf.as_ptr() as *const _) }
        };
        assert!(!is_report_valid(&attestation_report_invalid, &chain));
        assert!(!is_report_valid(&AttestationReport::default(), &chain));
    }

    #[test]
    fn test_get_chip_id_snp_not_enabled_fails() {
        assert_matches!(get_chip_id(), Err(SnpError::SnpNotEnabled { description })
        if description.contains("Snp is not enabled on this Guest"));
    }
}
