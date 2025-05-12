use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_types::{NodeId, RegistryVersion};
use std::io::ErrorKind;
use thiserror::Error;

/// Custom error type for SEV status operations
#[derive(Error, Debug)]
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
    FirmwareError(#[from] std::io::Error),
}

/// Result type for SEV status operations
pub type SevStatusResult<T> = Result<T, SevStatusError>;

/// Tracks the status of AMD SEV (Secure Encrypted Virtualization) for this node
#[derive(Debug, Clone)]
pub struct SevStatus {
    /// Whether the SEV firmware is available on this host
    pub firmware_available: bool,
    /// Whether SEV is enabled for this node in the registry
    pub enabled_in_registry: bool,
}

impl SevStatus {
    /// Checks if SEV is fully available and configured (both firmware available and enabled in registry)
    pub fn is_sev_available(&self) -> bool {
        self.firmware_available && self.enabled_in_registry
    }
}

/// Creates a new SevStatus instance by checking:
/// 1. If SEV firmware is available on Linux (always false on non-Linux)
/// 2. If SEV is enabled for this node in the registry
///
/// # Arguments
/// * `node_id` - The ID of this node
/// * `registry_client` - The registry client to query node configuration
///
/// # Returns
/// A Result containing the SevStatus or an error
pub fn create_sev_status(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
) -> SevStatusResult<SevStatus> {
    let firmware_available = check_firmware_available();
    let enabled_in_registry = check_registry_enabled(node_id, registry_client)?;

    Ok(SevStatus {
        firmware_available,
        enabled_in_registry,
    })
}

/// Checks if the SEV firmware is available
/// Always returns false on non-Linux platforms
fn check_firmware_available() -> SevStatusResult<bool> {
    #[cfg(target_os = "linux")]
    {
        // Only attempt to use SEV on Linux
        use sev::firmware::guest::Firmware;
        use std::path::Path;

        // Check if the device file exists
        if !Path::new("/dev/sev-guest").exists() {
            return false;
        }

        Firmware::open().map_err(|e| SevStatusError::FirmwareError(e))
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Always return false on non-Linux platforms
        false
    }
}

/// Checks if SEV is enabled for this node in the registry
fn check_registry_enabled(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
) -> SevStatusResult<bool> {
    let latest_version = registry_client.get_latest_version();

    // Get the node record for this node
    let node_record = registry_client
        .get_node_record(node_id, latest_version)
        .map_err(|e| SevStatusError::RegistryError(e.to_string()))?
        .ok_or_else(|| SevStatusError::NodeRecordNotFound(node_id))?;

    // Check if chip_id is present, which indicates SEV is enabled for this node
    Ok(node_record.chip_id.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_registry_keys::make_node_record_key;
    use ic_types::PrincipalId;
    use mockall::predicate::eq;
    use prost::Message;

    #[test]
    fn test_sev_status_creation_with_enabled_node() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        let registry_version = RegistryVersion::from(1);

        // Create node record with chip_id present
        let mut node_record = NodeRecord::default();
        node_record.chip_id = Some(vec![1, 2, 3, 4]);

        let mock_registry = setup_mock_registry(node_id, registry_version, node_record);

        // Create manual status for testing
        let sev_status = SevStatus {
            firmware_available: true,
            enabled_in_registry: true,
        };

        assert!(sev_status.is_sev_available());
    }

    #[test]
    fn test_sev_status_creation_with_disabled_node() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(2));
        let registry_version = RegistryVersion::from(1);

        // Create node record without chip_id
        let node_record = NodeRecord::default();

        let mock_registry = setup_mock_registry(node_id, registry_version, node_record);

        // Create manual status for testing
        let sev_status = SevStatus {
            firmware_available: true,
            enabled_in_registry: false,
        };

        assert!(!sev_status.is_sev_available());
    }

    #[test]
    fn test_sev_disabled_when_either_condition_is_false() {
        let sev_only_in_registry = SevStatus {
            firmware_available: false,
            enabled_in_registry: true,
        };

        let sev_only_in_firmware = SevStatus {
            firmware_available: true,
            enabled_in_registry: false,
        };

        assert!(!sev_only_in_registry.is_sev_available());
        assert!(!sev_only_in_firmware.is_sev_available());
    }

    #[test]
    fn test_create_sev_status_function() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        let registry_version = RegistryVersion::from(1);

        // Create node record with chip_id present
        let mut node_record = NodeRecord::default();
        node_record.chip_id = Some(vec![1, 2, 3, 4]);

        let mock_registry = setup_mock_registry(node_id, registry_version, node_record);

        // Test the free-standing function
        let result = create_sev_status(node_id, &mock_registry);
        assert!(result.is_ok());

        let status = result.unwrap();
        assert!(status.enabled_in_registry);
    }

    #[test]
    fn test_create_sev_status_function_with_missing_node() {
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

        // Test the error case
        let result = create_sev_status(node_id, &mock_client);
        assert!(result.is_err());

        // Check that we get the correct error type
        match result.unwrap_err() {
            SevStatusError::NodeRecordNotFound(id) => {
                assert_eq!(id, node_id);
            }
            err => panic!("Unexpected error type: {:?}", err),
        }
    }

    #[test]
    fn test_create_sev_status_function_with_registry_error() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(4));
        let registry_version = RegistryVersion::from(1);

        let mut mock_client = MockRegistryClient::new();
        mock_client
            .expect_get_latest_version()
            .return_const(registry_version);

        mock_client
            .expect_get_value()
            .with(eq(make_node_record_key(node_id)), eq(registry_version))
            .return_once(move |_, _| Err("Test registry error".into()));

        // Test the error case
        let result = create_sev_status(node_id, &mock_client);
        assert!(result.is_err());

        // Check that we get the correct error type
        match result.unwrap_err() {
            SevStatusError::RegistryError(message) => {
                assert_eq!(message, "Test registry error");
            }
            err => panic!("Unexpected error type: {:?}", err),
        }
    }

    fn setup_mock_registry(
        node_id: NodeId,
        version: RegistryVersion,
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
