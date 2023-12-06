use crate::{SnpError, ValidateAttestationError, ValidateAttestedStream};
use async_trait::async_trait;
use ic_base_types::{NodeId, RegistryVersion, SubnetId};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{info, ReplicaLogger};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Sev {
    log: ReplicaLogger,
}

impl Sev {
    pub fn new(
        _node_id: NodeId,
        _subnet_id: SubnetId,
        _registry: Arc<dyn RegistryClient>,
        log: ReplicaLogger,
    ) -> Self {
        Sev { log }
    }
}

#[async_trait]
impl<S> ValidateAttestedStream<S> for Sev
where
    for<'b> S: AsyncRead + AsyncWrite + Send + Unpin + 'b,
{
    async fn perform_attestation_validation(
        &self,
        stream: S,
        _peer: NodeId,
        _registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        info!(
            self.log,
            "SEV only works on linux. No SEV attestation is performed."
        );
        Ok(stream)
    }
}

/// For non linux version of guest, return None
pub fn get_chip_id() -> Result<Vec<u8>, SnpError> {
    Err(SnpError::SnpNotEnabled {
        description: "Sev-snp is only available on linux".into(),
    })
}
