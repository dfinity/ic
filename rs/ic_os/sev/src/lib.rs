// Select our platform.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux_amd64::*;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod other;
use core::fmt;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use other::*;

use async_trait::async_trait;
use ic_types::registry::RegistryClientError;
use ic_types::{NodeId, RegistryVersion};
use std::fmt::{Display, Formatter};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod certs;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use certs::*;

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
    CertificatesError {
        description: String,
    },
}

impl Display for ValidateAttestationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Perform mutual attestation over a stream.
// The registry_version is that of the latest CUP and is used
// to determine if SEV-SNP is enabled on the subnet.
#[async_trait]
pub trait ValidateAttestedStream<S> {
    async fn perform_attestation_validation(
        &self,
        mut stream: S,
        peer: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError>;
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnpError {
    SnpNotEnabled { description: String },
    FirmwareError { description: String },
    ReportError { description: String },
}

impl Display for SnpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
