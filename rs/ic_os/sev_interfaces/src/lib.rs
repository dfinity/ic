use async_trait::async_trait;
use core::fmt;
use ic_types::registry::RegistryClientError;
use ic_types::{NodeId, RegistryVersion};
use std::fmt::{Display, Formatter};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidateAttestationError {
    RegistryError(RegistryClientError),
    RegistryDataMissing {
        node_id: NodeId,
        registry_version: RegistryVersion,
        description: String,
    },
    HandshakeError {
        description: String,
    },
}

impl Display for ValidateAttestationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[async_trait]
pub trait ValidateAttestedStream {
    async fn perform_attestation_validation<S>(
        &self,
        mut stream: S,
        peer: NodeId,
        timeout: Duration,
        registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin;
}
