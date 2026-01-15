mod common;

use assert_matches::assert_matches;
use candid::Encode;
use canister_test::{Canister, Project, Runtime};
use ic_nns_test_utils::{
    itest_helpers::local_test_on_nns_subnet, registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_registry_transport::{
    insert,
    pb::v1::{
        HighCapacityRegistryGetValueResponse, RegistryAtomicMutateRequest,
        RegistryAtomicMutateResponse, RegistryGetValueRequest,
        high_capacity_registry_get_value_response,
    },
    precondition, upsert,
};
use registry_canister::{
    init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder},
    proto_on_wire::protobuf,
};
use std::time::{Duration, SystemTime};

pub async fn install_registry_canister(
    runtime: &Runtime,
    init_payload: RegistryCanisterInitPayload,
) -> Canister<'_> {
    try_to_install_registry_canister(runtime, init_payload)
        .await
        .expect("Installing Registry canister failed")
}

async fn try_to_install_registry_canister(
    runtime: &Runtime,
    init_payload: RegistryCanisterInitPayload,
) -> Result<Canister<'_>, String> {
    let encoded = Encode!(&init_payload).unwrap();
    let proj = Project::new();
    proj.cargo_bin("registry-canister", &[])
        .install(runtime)
        .bytes(encoded)
        .await
}

fn get_value_request(key: impl AsRef<[u8]>, version: Option<u64>) -> RegistryGetValueRequest {
    RegistryGetValueRequest {
        version,
        key: key.as_ref().to_vec(),
    }
}

#[test]
fn test_canister_installation_traps_on_bad_init_payload() {
    local_test_on_nns_subnet(|runtime| async move {
        assert_matches!(
            Project::new()
            .cargo_bin("registry-canister", &[])
                .install(&runtime)
                .bytes(b"This is not legal candid".to_vec())
                .await,
                Err(msg) if msg.contains("must be a Candid-encoded RegistryCanisterInitPayload"));
        Ok(())
    });
}

#[test]
fn test_mutations_are_rejected_from_non_authorized_sources() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut canister = install_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let mutation_request = RegistryAtomicMutateRequest {
            mutations: vec![insert("key1", "value1")],
            preconditions: vec![],
        };
        let response: Result<RegistryAtomicMutateResponse, String> = canister
            .update_("atomic_mutate", protobuf, mutation_request.clone())
            .await;
        assert_matches!(response,
                Err(s) if s.contains("not authorized"));

        // Go through an upgrade cycle, and verify that it still works the same
        canister.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<RegistryAtomicMutateResponse, String> = canister
            .update_("atomic_mutate", protobuf, mutation_request.clone())
            .await;
        assert_matches!(response,
                Err(s) if s.contains("not authorized"));

        Ok(())
    });
}

/// Tests that the state of the registry after initialization includes what
/// was set by the initial mutations, when they all succeed.
#[test]
fn test_initial_mutations_ok() {
    local_test_on_nns_subnet(|runtime| async move {
        let init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![
                    upsert(b"dufourspitze", b"4634 m"),
                    upsert(b"dom", b"4545 m"),
                ],
                preconditions: vec![],
            })
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![upsert(b"matterhorn", b"4478 m")],
                preconditions: vec![precondition(b"dom", 1)],
            })
            .build();
        let canister = install_registry_canister(&runtime, init_payload).await;

        let read_result: HighCapacityRegistryGetValueResponse = canister
            .query_(
                "get_value",
                protobuf,
                get_value_request("dufourspitze", None),
            )
            .await
            .unwrap();
        assert_eq!(
            read_result,
            HighCapacityRegistryGetValueResponse {
                error: None,
                version: 2_u64,
                content: Some(high_capacity_registry_get_value_response::Content::Value(
                    b"4634 m".to_vec()
                )),
                timestamp_nanoseconds: read_result.timestamp_nanoseconds,
            },
        );
        assert_a_short_while_ago(&read_result);

        let read_result: HighCapacityRegistryGetValueResponse = canister
            .query_("get_value", protobuf, get_value_request("dom", None))
            .await
            .unwrap();
        assert_eq!(
            read_result,
            HighCapacityRegistryGetValueResponse {
                error: None,
                version: 2_u64,
                content: Some(high_capacity_registry_get_value_response::Content::Value(
                    b"4545 m".to_vec()
                )),
                timestamp_nanoseconds: read_result.timestamp_nanoseconds,
            },
        );
        assert_a_short_while_ago(&read_result);

        let read_result: HighCapacityRegistryGetValueResponse = canister
            .query_("get_value", protobuf, get_value_request("matterhorn", None))
            .await
            .unwrap();
        assert_eq!(
            read_result,
            HighCapacityRegistryGetValueResponse {
                error: None,
                version: 3_u64,
                content: Some(high_capacity_registry_get_value_response::Content::Value(
                    b"4478 m".to_vec()
                )),
                timestamp_nanoseconds: read_result.timestamp_nanoseconds,
            },
        );
        assert_a_short_while_ago(&read_result);

        Ok(())
    });
}

/// Tests that the canister init traps if any initial mutation fails, even
/// if previous ones have succeeded
#[test]
fn test_that_init_traps_if_any_init_mutation_fails() {
    local_test_on_nns_subnet(|runtime| async move {
        let init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![
                    upsert(b"rock steady", b"jamaica"),
                    upsert(b"jazz", b"usa"),
                    upsert(b"dub", b"uk"),
                ],
                preconditions: vec![],
            })
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![insert(b"dub", b"uk")],
                preconditions: vec![],
            })
            .build();
        assert_matches!(
                try_to_install_registry_canister(&runtime, init_payload).await,
                Err(msg) if msg.contains("Verification of the mutation type failed"));
        Ok(())
    });
}

#[track_caller]
fn assert_a_short_while_ago(read_result: &HighCapacityRegistryGetValueResponse) {
    let value_set_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_nanos(read_result.timestamp_nanoseconds))
        .unwrap();
    let now = SystemTime::now();
    assert!(
        now.duration_since(value_set_at).unwrap() < Duration::from_secs(60),
        "now={:?} vs. value_set_at={:?}",
        now,
        value_set_at,
    );
}
