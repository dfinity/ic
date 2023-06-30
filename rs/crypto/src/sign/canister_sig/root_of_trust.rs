use ic_base_types::RegistryVersion;
use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider};
use ic_types::registry::RegistryClientError;
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub struct RegistryRootOfTrustProvider {
    registry_client: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
}

impl RegistryRootOfTrustProvider {
    #[allow(dead_code)]
    //TODO CRP-2046: use this to instantiate provider
    fn new(registry_client: Arc<dyn RegistryClient>, registry_version: RegistryVersion) -> Self {
        Self {
            registry_client,
            registry_version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryRootOfTrustProviderError {
    RegistryError(RegistryClientError),
    RootSubnetNotFound { registry_version: RegistryVersion },
    RootSubnetPublicKeyNotFound { registry_version: RegistryVersion },
}

impl RootOfTrustProvider for RegistryRootOfTrustProvider {
    type Error = RegistryRootOfTrustProviderError;

    fn root_of_trust(&self) -> Result<IcRootOfTrust, Self::Error> {
        let root_subnet_id = self
            .registry_client
            .get_root_subnet_id(self.registry_version)
            .map_err(RegistryRootOfTrustProviderError::RegistryError)?
            .ok_or(RegistryRootOfTrustProviderError::RootSubnetNotFound {
                registry_version: self.registry_version,
            })?;
        self.registry_client
            .get_threshold_signing_public_key_for_subnet(root_subnet_id, self.registry_version)
            .map_err(RegistryRootOfTrustProviderError::RegistryError)?
            .ok_or(
                RegistryRootOfTrustProviderError::RootSubnetPublicKeyNotFound {
                    registry_version: self.registry_version,
                },
            )
            .map(IcRootOfTrust::from)
    }
}
