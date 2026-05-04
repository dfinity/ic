use crate::governance::tests::{MockEnvironment, StubCMC, StubIcpLedger};
use crate::test_utils::MockRandomness;
use crate::{
    governance::Governance,
    pb::v1::{UpdateNodeProvider, governance_error::ErrorType},
};
use ic_base_types::PrincipalId;
use ic_nns_governance_api::NodeProvider;
use icp_ledger::AccountIdentifier;
use std::sync::Arc;

#[test]
fn test_update_node_provider_with_valid_but_non_crc_account() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let valid_account = AccountIdentifier::new(node_provider_id, None);

    let mut governance = create_governance_with_node_provider(node_provider_id);

    let update = UpdateNodeProvider {
        reward_account: Some(valid_account.into()),
    };

    // Act
    let result = governance.update_node_provider(&node_provider_id, update);

    // Assert
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type(), ErrorType::PreconditionFailed);
    assert!(error.error_message.contains("Invalid reward_account"));
    assert!(error.error_message.contains("must be 32 bytes long"));
}

#[test]
fn test_update_node_provider_with_valid_reward_account_right_length() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let valid_account = AccountIdentifier::new(node_provider_id, None);

    let mut governance = create_governance_with_node_provider(node_provider_id);

    let update = UpdateNodeProvider {
        reward_account: Some(icp_ledger::protobuf::AccountIdentifier {
            hash: valid_account.to_vec(),
        }),
    };

    // Act
    let result = governance.update_node_provider(&node_provider_id, update);

    // Assert
    assert!(result.is_ok(), "Expected update to succeed: {result:?}");

    // Verify the reward account was updated
    let updated_node_provider = governance.get_node_provider(&node_provider_id).unwrap();
    assert_eq!(
        updated_node_provider.reward_account.unwrap().hash,
        valid_account.to_vec()
    );
}

#[test]
fn test_update_node_provider_with_invalid_reward_account_bad_checksum() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let mut governance = create_governance_with_node_provider(node_provider_id);

    // Create an account identifier with wrong checksum
    let invalid_account = icp_ledger::protobuf::AccountIdentifier {
        hash: vec![0; 32], // Wrong checksum
    };

    let update = UpdateNodeProvider {
        reward_account: Some(invalid_account),
    };

    // Act
    let result = governance.update_node_provider(&node_provider_id, update);

    // Assert
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type(), ErrorType::PreconditionFailed);
    assert!(error.error_message.contains("Invalid reward_account"));
    assert!(
        error
            .error_message
            .contains("account identifier is not valid")
    );
}

#[test]
fn test_update_node_provider_with_no_reward_account() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let mut governance = create_governance_with_node_provider(node_provider_id);

    let update = UpdateNodeProvider {
        reward_account: None,
    };

    // Act
    let result = governance.update_node_provider(&node_provider_id, update);

    // Assert
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type(), ErrorType::PreconditionFailed);
    assert!(error.error_message.contains("reward_account not specified"));
}

#[test]
fn test_update_node_provider_not_found() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let unknown_node_provider_id = PrincipalId::new_user_test_id(999);
    let mut governance = create_governance_with_node_provider(node_provider_id);

    let valid_account = AccountIdentifier::new(unknown_node_provider_id, None);
    let update = UpdateNodeProvider {
        reward_account: Some(valid_account.into()),
    };

    // Act
    let result = governance.update_node_provider(&unknown_node_provider_id, update);

    // Assert
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type(), ErrorType::NotFound);
    assert!(error.error_message.contains("is not known by the NNS"));
}

// Helper function to create governance with a node provider
fn create_governance_with_node_provider(node_provider_id: PrincipalId) -> Governance {
    let initial_governance = ic_nns_governance_api::Governance {
        node_providers: vec![NodeProvider {
            id: Some(node_provider_id),
            reward_account: None,
        }],
        ..Default::default()
    };

    Governance::new(
        initial_governance,
        Arc::new(MockEnvironment::new(vec![], 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}
