use async_trait::async_trait;
use ic_icos_sev_interfaces::{ValidateAttestationError, ValidateAttestedStream};
use ic_interfaces_registry::RegistryClient;
use ic_types::{NodeId, RegistryVersion};
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
        _latest_registry_version: RegistryVersion,
        _earliest_registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        Ok(stream)
    }
}
