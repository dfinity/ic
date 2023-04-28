use ic_base_types::SubnetId;
use ic_registry_client::client::RegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// Checks registry to see whether feature flag is enabled to run the adapter.
// This should be run periodically in case feature flag is turned on/off.
// If feature flag is disabled, the registry client will be queried poll_duration secs until flag is enabled.
pub async fn poll_until_reporting_enabled(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    poll_duration: Duration,
) {
    loop {
        if let Ok(Some(true)) = registry_client
            .get_features(subnet_id, registry_client.get_latest_version())
            .map(|features| features.unwrap_or_default().onchain_observability)
        {
            return;
        }
        sleep(poll_duration).await;
    }
}

// TODO - Migrate other functions from main
