use super::*;
use candid::{Int, Nat};
use ic_base_types::PrincipalId;
use icp_ledger::protobuf::AccountIdentifier;
use maplit::hashmap;

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

#[test]
fn test_reward_to_account_conversions_always_create_32_byte_account_identifier() {
    // Arrange
    let account_identifier = AccountIdentifier {
        hash: vec![0; 28], // 28 bytes of zeros
    };

    let reward_to_account = pb::reward_node_provider::RewardToAccount {
        to_account: Some(account_identifier),
    };

    // Act
    let converted_reward_to_account =
        pb_api::reward_node_provider::RewardToAccount::from(reward_to_account);

    // Assert the length is now 32 bytes
    assert_eq!(
        converted_reward_to_account
            .to_account
            .as_ref()
            .unwrap()
            .hash
            .len(),
        32
    );

    // Assert when we convert to_account into the non-protobuf format, it's 28 bytes (i.e. validates)
    icp_ledger::AccountIdentifier::try_from(&converted_reward_to_account.to_account.unwrap())
        .expect("Should succeed!");
}

#[test]
fn test_reward_to_account_invalid_account_identifier_just_return_what_is_stored() {
    // Arrange
    let account_identifier = AccountIdentifier {
        hash: vec![0; 27], // 27 bytes of zeros, which is invalid for our conversion
    };

    let reward_to_account = pb::reward_node_provider::RewardToAccount {
        to_account: Some(account_identifier),
    };

    // Act
    let converted_reward_to_account =
        pb_api::reward_node_provider::RewardToAccount::from(reward_to_account);

    // Assert the length is still 27 bytes
    assert_eq!(
        converted_reward_to_account
            .to_account
            .as_ref()
            .unwrap()
            .hash
            .len(),
        27
    );

    // Assert that the conversion does fail, even with an invalid length
    icp_ledger::AccountIdentifier::try_from(&converted_reward_to_account.to_account.unwrap())
        .expect_err("Should fail!");
}

#[test]
fn test_value_conversions() {
    // Prepare test data for all value types
    let nat_value = Nat::from(12345u64);
    let int_value = Int::from(-9876i64);

    // Encode Nat and Int to bytes
    let mut nat_bytes = Vec::new();
    nat_value.encode(&mut nat_bytes).unwrap();

    let mut int_bytes = Vec::new();
    int_value.encode(&mut int_bytes).unwrap();

    // Create a comprehensive map with all possible SelfDescribingValue types
    let value_pb = pb::SelfDescribingValue {
        value: Some(pb::self_describing_value::Value::Map(
            pb::SelfDescribingValueMap {
                values: hashmap! {
                    // Test Text type
                    "text_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Text("some text".to_string())),
                    },
                    // Test Blob type
                    "blob_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Blob(vec![1, 2, 3, 4, 5])),
                    },
                    // Test Nat type
                    "nat_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Nat(nat_bytes.clone())),
                    },
                    // Test Int type
                    "int_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Int(int_bytes.clone())),
                    },
                    // Test Array type with various elements
                    "array_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                            values: vec![
                                pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Text("first".to_string())),
                                },
                                pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Text("second".to_string())),
                                },
                                pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Blob(vec![10, 20, 30])),
                                },
                            ],
                        })),
                    },
                    // Test nested Map type
                    "nested_map_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                            values: hashmap! {
                                "nested_text".to_string() => pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Text("nested value".to_string())),
                                },
                                "nested_blob".to_string() => pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Blob(vec![255, 254, 253])),
                                },
                                "nested_nat".to_string() => pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Nat(nat_bytes.clone())),
                                },
                            },
                        })),
                    },
                    // Test empty Array
                    "empty_array_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                            values: vec![],
                        })),
                    },
                    // Test empty Map
                    "empty_map_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                            values: hashmap! {},
                        })),
                    },
                    // Test Array containing Maps
                    "array_of_maps_field".to_string() => pb::SelfDescribingValue {
                        value: Some(pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                            values: vec![
                                pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                        values: hashmap! {
                                            "key1".to_string() => pb::SelfDescribingValue {
                                                value: Some(pb::self_describing_value::Value::Text("value1".to_string())),
                                            },
                                        },
                                    })),
                                },
                                pb::SelfDescribingValue {
                                    value: Some(pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                                        values: hashmap! {
                                            "key2".to_string() => pb::SelfDescribingValue {
                                                value: Some(pb::self_describing_value::Value::Text("value2".to_string())),
                                            },
                                        },
                                    })),
                                },
                            ],
                        })),
                    },
                },
            },
        )),
    };

    let value_pb_api = pb_api::SelfDescribingValue::from(value_pb);

    assert_eq!(
        value_pb_api,
        pb_api::SelfDescribingValue::Map(hashmap! {
            "text_field".to_string() => pb_api::SelfDescribingValue::Text("some text".to_string()),
            "blob_field".to_string() => pb_api::SelfDescribingValue::Blob(vec![1, 2, 3, 4, 5]),
            "nat_field".to_string() => pb_api::SelfDescribingValue::Nat(nat_value.clone()),
            "int_field".to_string() => pb_api::SelfDescribingValue::Int(int_value.clone()),
            "array_field".to_string() => pb_api::SelfDescribingValue::Array(vec![
                pb_api::SelfDescribingValue::Text("first".to_string()),
                pb_api::SelfDescribingValue::Text("second".to_string()),
                pb_api::SelfDescribingValue::Blob(vec![10, 20, 30]),
            ]),
            "nested_map_field".to_string() => pb_api::SelfDescribingValue::Map(hashmap! {
                "nested_text".to_string() => pb_api::SelfDescribingValue::Text("nested value".to_string()),
                "nested_blob".to_string() => pb_api::SelfDescribingValue::Blob(vec![255, 254, 253]),
                "nested_nat".to_string() => pb_api::SelfDescribingValue::Nat(nat_value.clone()),
            }),
            "empty_array_field".to_string() => pb_api::SelfDescribingValue::Array(vec![]),
            "empty_map_field".to_string() => pb_api::SelfDescribingValue::Map(hashmap! {}),
            "array_of_maps_field".to_string() => pb_api::SelfDescribingValue::Array(vec![
                pb_api::SelfDescribingValue::Map(hashmap! {
                    "key1".to_string() => pb_api::SelfDescribingValue::Text("value1".to_string()),
                }),
                pb_api::SelfDescribingValue::Map(hashmap! {
                    "key2".to_string() => pb_api::SelfDescribingValue::Text("value2".to_string()),
                }),
            ]),
        })
    );
}
