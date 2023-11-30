use crate::{SnpError, ValidateAttestationError, ValidateAttestedStream};
use async_trait::async_trait;
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_registry::RegistryClient;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Sev {}

impl Sev {
    pub fn new(_node_id: NodeId, _registry: Arc<dyn RegistryClient>) -> Self {
        Sev {}
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
        Ok(stream)
    }
}

/// For non linux version of guest, return None
pub fn get_chip_id() -> Result<Vec<u8>, SnpError> {
    Err(SnpError::SnpNotEnabled {
        description: "Sev-snp is only available on linux".into(),
    })
}
