use super::*;

use crate::pb::v1::{AddOrRemoveNodeProvider, NodeProvider, add_or_remove_node_provider::Change};

use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_nns_governance_api::SelfDescribingValue;
use icp_ledger::{
    AccountIdentifier, Subaccount, protobuf::AccountIdentifier as AccountIdentifierProto,
};
use maplit::hashmap;

fn create_test_node_provider(id: u64) -> NodeProvider {
    NodeProvider {
        id: Some(PrincipalId::new_user_test_id(id)),
        reward_account: None,
    }
}

fn create_test_node_provider_with_account(id: u64) -> NodeProvider {
    let account =
        AccountIdentifier::new(PrincipalId::new_user_test_id(id), Some(Subaccount([1; 32])));
    NodeProvider {
        id: Some(PrincipalId::new_user_test_id(id)),
        reward_account: Some(account.into_proto_with_checksum()),
    }
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
fn test_add_new_node_provider() {
    let mut node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let new_provider = create_test_node_provider(3);
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(new_provider.clone())),
    };

    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    valid_proposal.validate(&node_providers).unwrap();

    valid_proposal.execute(&mut node_providers).unwrap();

    // The ordering doesn't matter, so ideally we should either sort or convert to a set before
    // comparing. On the other hand, it's very unlikely that we want to change the ordering of node
    // providers when adding a new one. Therefore, we simply compare, assuming the new node provider
    // is added to the end.
    assert_eq!(
        node_providers,
        vec![
            create_test_node_provider(1),
            create_test_node_provider(2),
            new_provider
        ]
    );
}

#[test]
fn test_add_node_provider_with_reward_account() {
    let mut node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let new_provider = create_test_node_provider_with_account(3);
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(new_provider.clone())),
    };

    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    valid_proposal.validate(&node_providers).unwrap();

    valid_proposal.execute(&mut node_providers).unwrap();

    // The ordering doesn't matter, so ideally we should either sort or convert to a set before
    // comparing. On the other hand, it's very unlikely that we want to change the ordering of node
    // providers when adding a new one. Therefore, we simply compare, assuming the new node provider
    // is added to the end.
    assert_eq!(
        node_providers,
        vec![
            create_test_node_provider(1),
            create_test_node_provider(2),
            new_provider
        ]
    );
}

#[test]
fn test_validate_add_existing_node_provider_fails() {
    let node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(1))), // Already exists
    };
    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    let result = valid_proposal.validate(&node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("already exists")
    );
}

#[test]
fn test_remove_existing_node_provider() {
    let mut node_providers = vec![
        create_test_node_provider(1),
        create_test_node_provider(2),
        create_test_node_provider(3),
    ];
    let provider_to_remove = create_test_node_provider(2);
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(provider_to_remove.clone())),
    };

    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    valid_proposal.validate(&node_providers).unwrap();

    valid_proposal.execute(&mut node_providers).unwrap();

    assert_eq!(
        node_providers,
        vec![create_test_node_provider(1), create_test_node_provider(3)]
    );
}

#[test]
fn test_validate_remove_non_existing_node_provider_fails() {
    let node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(999))), // Doesn't exist
    };
    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    let result = valid_proposal.validate(&node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("must target an existing Node Provider")
    );
}

#[test]
fn test_execute_add_existing_node_provider_fails() {
    let mut node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let original_node_providers = node_providers.clone();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(create_test_node_provider(1))), // Already exists
    };
    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    let result = valid_proposal.execute(&mut node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("already exists")
    );

    assert_eq!(node_providers, original_node_providers);
}

#[test]
fn test_execute_remove_non_existing_node_provider_fails() {
    let mut node_providers = vec![create_test_node_provider(1), create_test_node_provider(2)];
    let original_node_providers = node_providers.clone();
    let proposal = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(create_test_node_provider(999))), // Doesn't exist
    };
    let valid_proposal = ValidAddOrRemoveNodeProvider::try_from(proposal).unwrap();

    let result = valid_proposal.execute(&mut node_providers);
    assert_matches!(
        result,
        Err(error) if error.error_type == ErrorType::PreconditionFailed as i32
            && error.error_message.contains("must target an existing Node Provider")
    );

    assert_eq!(node_providers, original_node_providers);
}

#[test]
fn test_to_self_describing_value() {
    let account =
        AccountIdentifier::new(PrincipalId::new_user_test_id(2), Some(Subaccount([1; 32])));
    let add_node_provider = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(NodeProvider {
            id: Some(PrincipalId::new_user_test_id(1)),
            reward_account: Some(account.into_proto_with_checksum()),
        })),
    };

    assert_eq!(
        SelfDescribingValue::from(
            ValidAddOrRemoveNodeProvider::try_from(add_node_provider)
                .unwrap()
                .to_self_describing_value()
        ),
        SelfDescribingValue::Map(hashmap! {
            "ToAdd".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Text("6fyp7-3ibaa-aaaaa-aaaap-4ai".to_string()),
                "reward_account".to_string() => SelfDescribingValue::Text(account.to_hex())
            })
        })
    );

    let remove_node_provider = AddOrRemoveNodeProvider {
        change: Some(Change::ToRemove(NodeProvider {
            id: Some(PrincipalId::new_user_test_id(1)),
            reward_account: None,
        })),
    };

    assert_eq!(
        SelfDescribingValue::from(
            ValidAddOrRemoveNodeProvider::try_from(remove_node_provider)
                .unwrap()
                .to_self_describing_value()
        ),
        SelfDescribingValue::Map(hashmap! {
            "ToRemove".to_string() => SelfDescribingValue::Map(hashmap! {
                "id".to_string() => SelfDescribingValue::Text("6fyp7-3ibaa-aaaaa-aaaap-4ai".to_string())
            })
        })
    );
}
