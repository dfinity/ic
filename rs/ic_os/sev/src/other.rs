use async_trait::async_trait;
use ic_icos_sev_interfaces::{ValidateAttestationError, ValidateAttestedStream};
use ic_types::{NodeId, RegistryVersion};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;

pub struct Sev {}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[async_trait]
impl ValidateAttestedStream for Sev {
    async fn perform_attestation_validation<S>(
        &self,
        stream: S,
        _peer: NodeId,
        _timeout: Duration,
        _registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        Ok(stream)
    }
}
