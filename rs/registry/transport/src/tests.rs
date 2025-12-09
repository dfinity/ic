use super::*;
use crate::pb::v1::{
    HighCapacityRegistryAtomicMutateRequest, HighCapacityRegistryGetChangesSinceResponse,
    HighCapacityRegistryMutation, RegistryAtomicMutateRequest,
    high_capacity_registry_get_value_response, high_capacity_registry_mutation,
    registry_mutation,
};
use pretty_assertions::assert_eq;

#[test]
fn test_serde_get_value_request() {
    let key = vec![1, 2, 3, 4];
    let key_clone = key.clone();
    let bytes = serialize_get_value_request(key, Some(10)).unwrap();
    let (key, version) = deserialize_get_value_request(bytes).unwrap();
    assert_eq!(key, key_clone);
    assert_eq!(version, Some(10));
}

#[test]
fn test_serde_get_value_request_no_version() {
    let key = vec![1, 2, 3, 4];
    let key_clone = key.clone();
    let bytes = serialize_get_value_request(key, None).unwrap();
    let (key, version) = deserialize_get_value_request(bytes).unwrap();
    assert_eq!(key, key_clone);
    assert_eq!(version, None);
}

#[test]
fn test_serde_get_value_response() {
    let value = vec![1, 2, 3, 4];
    let version = 10;
    let original = pb::v1::HighCapacityRegistryGetValueResponse {
        version,
        content: Some(high_capacity_registry_get_value_response::Content::Value(
            value.clone(),
        )),
        timestamp_nanoseconds: 42,
        error: None,
    };

    let bytes = serialize_get_value_response(original.clone()).unwrap();
    let deserialized = deserialize_get_value_response(bytes).unwrap();
    assert_eq!(deserialized, original);
}

#[test]
#[should_panic]
fn test_serde_get_value_response_with_error() {
    let mut response = pb::v1::HighCapacityRegistryGetValueResponse::default();
    let error = RegistryError {
        code: 1,
        ..Default::default()
    };
    response.error = Some(error);
    let bytes = serialize_get_value_response(response).unwrap();
    // Should panic on the unwrap because this returns an error.
    deserialize_get_value_response(bytes).unwrap();
}

#[test]
fn test_serde_atomic_mutate() {
    let mutations = vec![insert("cow", "mammal"), insert("ostrich", "bird")];
    let preconditions = vec![precondition("ostrich", 56), precondition("t-rex", 33)];
    assert_eq!(
        deserialize_atomic_mutate_request(serialize_atomic_mutate_request(
            mutations.clone(),
            preconditions.clone()
        )),
        Ok(pb::v1::RegistryAtomicMutateRequest {
            mutations,
            preconditions
        })
    );
}

#[test]
fn test_display_atomic_mutate_request() {
    let req = RegistryAtomicMutateRequest {
        mutations: vec![
            insert("italy", "europe"),
            upsert("bolivia", "south america"),
            update("guatemala", "north america"),
            delete("someone is going to get offended if i put a real country here"),
        ],
        preconditions: vec![precondition("africa", 23), precondition("asia", 51)],
    };
    // Not everything is displayed: in particular, the values are dropped.
    assert_eq!(
        req.to_string(),
        "RegistryAtomicMutateRequest{ \
        mutations: [\
        RegistryMutation { mutation_type: insert, key: italy, value: europe }, \
        RegistryMutation { mutation_type: upsert, key: bolivia, value: south america }, \
        RegistryMutation { mutation_type: update, key: guatemala, value: north america }, \
        RegistryMutation { mutation_type: delete, key: someone is going to get offended if i put a real country here, value:  }], \
        preconditions on keys: [africa, asia] }"
    )
}

#[test]
fn test_deserialize_get_changes_since_response_with_error() {
    let response = HighCapacityRegistryGetChangesSinceResponse {
        error: Some(RegistryError {
            code: Code::Authorization as i32,
            reason: "You are not welcome here.".to_string(),
            key: vec![],
        }),
        deltas: vec![],
        version: 0,
    };

    let response = response.encode_to_vec();

    let result = deserialize_get_changes_since_response(response);

    assert_eq!(
        result,
        Err(Error::UnknownError(
            "5: You are not welcome here.".to_string()
        )),
    );
}

#[test]
fn test_atomic_mutate_requests_compatible() {
    let mutation_types = [
        registry_mutation::Type::Insert,
        registry_mutation::Type::Update,
        registry_mutation::Type::Delete,
        registry_mutation::Type::Upsert,
    ];

    let preconditions = vec![
        Precondition {
            expected_version: 147,
            key: b"herp".to_vec(),
        },
        Precondition {
            expected_version: 950,
            key: b"derp".to_vec(),
        },
    ];

    let legacy_response = {
        let preconditions = preconditions.clone();

        RegistryAtomicMutateRequest {
            preconditions,
            mutations: mutation_types
                .iter()
                .map(|mutation_type| {
                    let mutation_type = *mutation_type as i32;
                    let key = format!("key_{mutation_type}").into_bytes();
                    let value = format!("value {mutation_type}").into_bytes();

                    RegistryMutation {
                        mutation_type,
                        key,
                        value,
                    }
                })
                .collect(),
        }
    };

    let high_capacity_response = HighCapacityRegistryAtomicMutateRequest {
        preconditions,
        mutations: mutation_types
            .iter()
            .map(|mutation_type| {
                let mutation_type = *mutation_type as i32;
                let key = format!("key_{mutation_type}").into_bytes();
                let value = format!("value {mutation_type}").into_bytes();
                let content = Some(high_capacity_registry_mutation::Content::Value(value));

                HighCapacityRegistryMutation {
                    mutation_type,
                    key,
                    content,
                }
            })
            .collect(),
        timestamp_nanoseconds: 0,
    };

    // Ok if client starts using HighCapacity before server.
    let upgraded = {
        let encoded: &[u8] = &legacy_response.encode_to_vec();
        HighCapacityRegistryAtomicMutateRequest::decode(encoded).unwrap()
    };
    assert_eq!(upgraded, high_capacity_response);

    // OK if server starts using HighCapacity before client.
    let downgraded = {
        let encoded: &[u8] = &high_capacity_response.encode_to_vec();
        RegistryAtomicMutateRequest::decode(encoded).unwrap()
    };
    assert_eq!(downgraded, legacy_response);
}

