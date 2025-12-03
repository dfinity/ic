use super::*;
use crate::pb::v1::{AddOrRemoveNodeProvider, NodeProvider, add_or_remove_node_provider::Change};
use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use icp_ledger::protobuf::AccountIdentifier as AccountIdentifierProto;

fn create_test_node_provider(id: u64) -> NodeProvider {
    NodeProvider {
        id: Some(PrincipalId::new_user_test_id(id)),
        reward_account: None,
    }
}

fn create_test_node_provider_with_account(id: u64) -> NodeProvider {
    let account = AccountIdentifier::new(PrincipalId::new_user_test_id(id), None);
    NodeProvider {
        id: Some(PrincipalId::new_user_test_id(id)),
        reward_account: Some(account.into_proto_with_checksum()),
    }
}

fn create_test_node_providers() -> Vec<NodeProvider> {
    vec![create_test_node_provider(1), create_test_node_provider(2)]
}

#[test]
fn test_try_from_success_to_add() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(3))),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert!(result.is_ok(), "Expected TryFrom to succeed for ToAdd");
}

#[test]
fn test_try_from_success_to_remove() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(1))),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert!(result.is_ok(), "Expected TryFrom to succeed for ToRemove");
}

#[test]
fn test_try_from_missing_change() {
    let proposal = AddOrRemoveNodeProvider { change: None };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("must have a change field")
    );
}

#[test]
fn test_try_from_missing_node_provider_id_to_add() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(NodeProvider {
            id: None,
            reward_account: None,
        })),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("must have a node provider id")
    );
}

#[test]
fn test_try_from_missing_node_provider_id_to_remove() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(NodeProvider {
            id: None,
            reward_account: None,
        })),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("must have a node provider id")
    );
}

#[test]
fn test_try_from_invalid_reward_account() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(NodeProvider {
            id: Some(PrincipalId::new_user_test_id(3)),
            reward_account: Some(AccountIdentifierProto {
                hash: vec![1, 2, 3], // Invalid: too short
            }),
        })),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("account_identifier field is invalid")
    );
}

#[test]
fn test_try_from_invalid_reward_account_28_bytes() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(NodeProvider {
            id: Some(PrincipalId::new_user_test_id(3)),
            reward_account: Some(AccountIdentifierProto {
                hash: vec![1; 28], // Invalid: must be 32 bytes
            }),
        })),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("account_identifier field is invalid")
            && error.error_message.contains("32 bytes")
    );
}

#[test]
fn test_try_from_valid_reward_account() {
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider_with_account(3))),
    };

    let result = ValidAddOrRemoveNodeProvider::try_from(proposal);
    assert!(
        result.is_ok(),
        "Expected TryFrom to succeed with valid reward account"
    );
}

#[test]
fn test_validate_add_new_node_provider_success() {
    let node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(3))),
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.validate(&node_providers);
    assert!(
        result.is_ok(),
        "Expected validation to succeed for new node provider"
    );
}

#[test]
fn test_validate_add_existing_node_provider_fails() {
    let node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(1))), // Already exists
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.validate(&node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("cannot add already existing Node Provider")
    );
}

#[test]
fn test_validate_remove_existing_node_provider_success() {
    let node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(1))),
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.validate(&node_providers);
    assert!(
        result.is_ok(),
        "Expected validation to succeed for existing node provider"
    );
}

#[test]
fn test_validate_remove_non_existing_node_provider_fails() {
    let node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(999))), // Doesn't exist
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.validate(&node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::InvalidProposal as i32
            && error.error_message.contains("must target an existing Node Provider")
    );
}

#[test]
fn test_execute_add_node_provider_success() {
    let mut node_providers = create_test_node_providers();
    let new_provider = create_test_node_provider(3);
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(new_provider.clone())),
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.execute(&mut node_providers);
    assert!(result.is_ok(), "Expected execution to succeed");
    assert_eq!(
        node_providers.len(),
        3,
        "Expected 3 node providers after adding"
    );
    assert!(
        node_providers.iter().any(|np| np.id == new_provider.id),
        "Expected new node provider to be in the list"
    );
}

#[test]
fn test_execute_add_existing_node_provider_fails() {
    let mut node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(1))), // Already exists
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.execute(&mut node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("already exists")
    );
}

#[test]
fn test_execute_remove_node_provider_success() {
    let mut node_providers = create_test_node_providers();
    let provider_to_remove = create_test_node_provider(1);
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(provider_to_remove.clone())),
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.execute(&mut node_providers);
    assert!(result.is_ok(), "Expected execution to succeed");
    assert_eq!(
        node_providers.len(),
        1,
        "Expected 1 node provider after removing"
    );
    assert!(
        !node_providers
            .iter()
            .any(|np| np.id == provider_to_remove.id),
        "Expected removed node provider to not be in the list"
    );
}

#[test]
fn test_execute_remove_non_existing_node_provider_fails() {
    let mut node_providers = create_test_node_providers();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(999))), // Doesn't exist
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    let result = valid_proposal.execute(&mut node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::NotFound as i32
            && error.error_message.contains("Can't find a NodeProvider")
    );
}

#[test]
fn test_execute_preserves_other_node_providers() {
    let mut node_providers = create_test_node_providers();
    let original_count = node_providers.len();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(1))),
    };
    let valid_proposal =
        ValidAddOrRemoveNodeProvider::try_from(proposal).expect("Should create valid proposal");

    valid_proposal
        .execute(&mut node_providers)
        .expect("Execute should succeed");

    // Verify that the other node provider is still there
    assert_eq!(node_providers.len(), original_count - 1);
    assert!(
        node_providers
            .iter()
            .any(|np| np.id == Some(PrincipalId::new_user_test_id(2))),
        "Expected node provider 2 to still be in the list"
    );
}
