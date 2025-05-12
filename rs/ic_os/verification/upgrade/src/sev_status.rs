use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_types::NodeId;
use thiserror::Error;

/// Status of AMD SEV (Secure Encrypted Virtualization) for this node
#[derive(Debug, Clone, PartialEq)]
pub enum SevStatus {
    /// SEV firmware is not available
    Unavailable,
    /// SEV firmware is available, but SEV is not enabled in the registry
    Disabled,
    /// SEV is both available and enabled
    Enabled,
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum SevStatusError {
    /// Error when interacting with the registry
    #[error("Registry error: {0}")]
    RegistryError(String),

    /// Error when node record is not found
    #[error("Node record not found for node ID {0}")]
    NodeRecordNotFound(NodeId),

    /// Error when accessing SEV firmware
    #[cfg(target_os = "linux")]
    #[error("SEV firmware error: {0}")]
    FirmwareError(#[source] std::io::Error),
}

/// Get the node's SEV status by checking:
/// 1. If SEV firmware is available on Linux (always false on non-Linux)
/// 2. If SEV is enabled for this node in the registry
pub fn get_sev_status(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
) -> Result<SevStatus, SevStatusError> {
    let firmware_available = is_sev_firmware_available()?;
    if !firmware_available {
        return Ok(SevStatus::Unavailable);
    }

    let enabled_in_registry = is_sev_enabled_for_node(node_id, registry_client)?;
    Ok(if enabled_in_registry {
        SevStatus::Enabled
    } else {
        SevStatus::Disabled
    })
}

fn is_sev_firmware_available() -> Result<bool, SevStatusError> {
    #[cfg(target_os = "linux")]
    {
        use sev::firmware::guest::Firmware;
        use std::path::Path;

        // Check if the device file exists
        if !Path::new("/dev/sev-guest").exists() {
            return Ok(false);
        }

        // Try to open the firmware if it exists to see if it works
        Firmware::open().map_err(SevStatusError::FirmwareError)?;

        Ok(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // We don't support SEV on non-Linux platforms
        Ok(false)
    }
}

/// Check if SEV is enabled for this node in the registry
fn is_sev_enabled_for_node(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
) -> Result<bool, SevStatusError> {
    let latest_version = registry_client.get_latest_version();

    let node_record = registry_client
        .get_node_record(node_id, latest_version)
        .map_err(|e| SevStatusError::RegistryError(e.to_string()))?
        .ok_or_else(|| SevStatusError::NodeRecordNotFound(node_id))?;

    Ok(node_record
        .trusted_execution_environment
        .unwrap_or_default()
        .enabled
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::node::v1::{NodeRecord, TrustedExecutionEnvironment};
    use ic_registry_keys::make_node_record_key;
    use ic_types::registry::RegistryClientError;
    use ic_types::{PrincipalId, RegistryVersion};
    use mockall::predicate::eq;
    use prost::Message;

    #[test]
    fn test_sev_enabled() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        let registry_version = RegistryVersion::from(1);

        let node_record = NodeRecord {
            trusted_execution_environment: Some(TrustedExecutionEnvironment {
                enabled: Some(true),
            }),
            ..NodeRecord::default()
        };

        let mock_registry =
            setup_mock_registry_with_node_record(registry_version, node_id, node_record);

        assert_eq!(is_sev_enabled_for_node(node_id, &mock_registry), Ok(true));
    }

    #[test]
    fn test_sev_disabled() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(2));
        let registry_version = RegistryVersion::from(1);

        // Create node record without chip_id
        let node_record = NodeRecord::default();

        let mock_registry =
            setup_mock_registry_with_node_record(registry_version, node_id, node_record);

        assert_eq!(is_sev_enabled_for_node(node_id, &mock_registry), Ok(false));
    }

    #[test]
    fn test_missing_node() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(3));
        let registry_version = RegistryVersion::from(1);

        let mut mock_client = MockRegistryClient::new();
        mock_client
            .expect_get_latest_version()
            .return_const(registry_version);

        mock_client
            .expect_get_value()
            .with(eq(make_node_record_key(node_id)), eq(registry_version))
            .return_once(move |_, _| Ok(None));

        assert_eq!(
            is_sev_enabled_for_node(node_id, &mock_client),
            Err(SevStatusError::NodeRecordNotFound(node_id))
        );
    }

    #[test]
    fn test_registry_error() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(4));
        let registry_version = RegistryVersion::from(1);

        let mut mock_client = MockRegistryClient::new();
        mock_client
            .expect_get_latest_version()
            .return_const(registry_version);

        mock_client
            .expect_get_value()
            .with(eq(make_node_record_key(node_id)), eq(registry_version))
            .return_once(move |_, _| {
                Err(RegistryClientError::DecodeError {
                    error: "Test error".into(),
                })
            });

        assert_eq!(
            is_sev_enabled_for_node(node_id, &mock_client),
            Err(SevStatusError::RegistryError(
                "failed to decode registry contents: Test error".into()
            ))
        );
    }

    fn setup_mock_registry_with_node_record(
        version: RegistryVersion,
        node_id: NodeId,
        node_record: NodeRecord,
    ) -> MockRegistryClient {
        let mut mock_client = MockRegistryClient::new();

        mock_client
            .expect_get_latest_version()
            .return_const(version);

        let encoded_record = node_record.encode_to_vec();
        mock_client
            .expect_get_value()
            .with(eq(make_node_record_key(node_id)), eq(version))
            .return_once(move |_, _| Ok(Some(encoded_record)));

        mock_client
    }
}
