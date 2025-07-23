use super::*;
use ic_base_types::PrincipalId;
use icp_ledger::protobuf::AccountIdentifier;

#[test]
fn test_node_provider_conversions_always_create_32_byte_account_identifier() {
    // Arrange

    let node_provider_id = PrincipalId::new_user_test_id(1);
    let account_identifier = AccountIdentifier {
        hash: vec![0; 28], // 32 bytes of zeros
    };

    let node_provider = pb::NodeProvider {
        id: Some(node_provider_id),
        reward_account: Some(account_identifier),
    };

    // Act
    let converted_node_provider = pb_api::NodeProvider::from(node_provider);

    // Assert the length is now 32 bytes
    assert_eq!(
        converted_node_provider
            .reward_account
            .as_ref()
            .unwrap()
            .hash
            .len(),
        32
    );

    // Assert when we convert reward_account into the non-protobuf format, it's 28 bytes (i.e. validates)
    icp_ledger::AccountIdentifier::try_from(&converted_node_provider.reward_account.unwrap())
        .expect("Should succeed!");
}

#[test]
fn test_if_invalid_account_identifier_just_return_what_is_stored() {
    // Arrange
    let node_provider_id = PrincipalId::new_user_test_id(1);
    let account_identifier = AccountIdentifier {
        hash: vec![0; 27], // 28 bytes of zeros, which is invalid for our conversion
    };

    let node_provider = pb::NodeProvider {
        id: Some(node_provider_id),
        reward_account: Some(account_identifier),
    };

    // Act
    let converted_node_provider = pb_api::NodeProvider::from(node_provider);

    // Assert the length is still 28 bytes
    assert_eq!(
        converted_node_provider
            .reward_account
            .as_ref()
            .unwrap()
            .hash
            .len(),
        27
    );

    // Assert that the conversion does fail, even with an invalid length
    icp_ledger::AccountIdentifier::try_from(&converted_node_provider.reward_account.unwrap())
        .expect_err("Should fail!");
}
