#[path = "./integration_tests/mod.rs"]
mod integration_tests;

use assert_matches::assert_matches;
use candid::Encode;
use canister_test::{Canister, Project, Runtime};
use ic_crypto_tree_hash::{flatmap, lookup_path, Label, LabeledTree, MixedHashTree};
use ic_interfaces::registry::RegistryTransportRecord;
use ic_nns_common::registry::encode_or_panic;

use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_universal_canister,
};

use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, maybe_upgrade_to_self, UpgradeTestingScenario},
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_nns_test_utils_macros::parameterized_upgrades;

use ic_registry_common::certification::decode_hash_tree;

use ic_registry_transport::{
    insert,
    pb::v1::{
        registry_error::Code, CertifiedResponse, RegistryAtomicMutateRequest,
        RegistryAtomicMutateResponse, RegistryError, RegistryGetChangesSinceRequest,
        RegistryGetLatestVersionResponse, RegistryGetValueRequest, RegistryGetValueResponse,
    },
    precondition, update, upsert,
};
use ic_types::RegistryVersion;
use registry_canister::{
    init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder},
    proto_on_wire::protobuf,
};
use std::convert::TryInto;

pub async fn install_registry_canister(
    runtime: &Runtime,
    init_payload: RegistryCanisterInitPayload,
) -> Canister<'_> {
    try_to_install_registry_canister(runtime, init_payload)
        .await
        .unwrap()
}

async fn try_to_install_registry_canister(
    runtime: &Runtime,
    init_payload: RegistryCanisterInitPayload,
) -> Result<Canister<'_>, String> {
    let encoded = Encode!(&init_payload).unwrap();
    let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
    proj.cargo_bin("registry-canister", &[])
        .install(runtime)
        .bytes(encoded)
        .await
}

async fn query_certified_changes_since(
    canister: &Canister<'_>,
    version: u64,
) -> (Vec<RegistryTransportRecord>, RegistryVersion) {
    let certified_response: CertifiedResponse = canister
        .query_(
            "get_certified_changes_since",
            protobuf,
            changes_since(version),
        )
        .await
        .expect("failed to query certified changes");

    decode_hash_tree(
        version,
        certified_response
            .hash_tree
            .expect("no hash tree in a certified response")
            .try_into()
            .expect("failed to decode hash tree from protobuf"),
    )
    .expect("failed to decode registry deltas")
}

fn get_value_request(key: impl AsRef<[u8]>, version: Option<u64>) -> RegistryGetValueRequest {
    RegistryGetValueRequest {
        version,
        key: key.as_ref().to_vec(),
    }
}

fn changes_since(version: u64) -> RegistryGetChangesSinceRequest {
    RegistryGetChangesSinceRequest { version }
}

fn data_part(certified_response: &CertifiedResponse) -> LabeledTree<Vec<u8>> {
    let tree: MixedHashTree = certified_response
        .hash_tree
        .clone()
        .expect("certified response doesn't include a hash tree")
        .try_into()
        .expect("failed to decode mixed hash tree");
    let data_part: LabeledTree<Vec<u8>> = tree
        .try_into()
        .expect("failed to convert mixed hash tree into a labeled tree");
    data_part
}

/// This is a simple end-to-end test of the Registry canister, in which
/// key/value pairs are first inserted, and in a second time the value
/// for one key is retrieved.
#[parameterized_upgrades]
async fn registry(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    // Set up: install the registry canister
    let mut canister = install_registry_canister(
        runtime,
        RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            .build(),
    )
    .await;

    // Sets up a universal canister in lieu of the governance canister so it can
    // impersonate it.
    let fake_governance_canister = set_up_universal_canister(runtime).await;
    assert_eq!(
        fake_governance_canister.canister_id(),
        GOVERNANCE_CANISTER_ID
    );

    // Exercise the "atomic_mutate" method
    let mutation_request = RegistryAtomicMutateRequest {
        mutations: vec![
            insert("zurich", "switzerland"),
            insert("coimbra", "portugal"),
        ],
        preconditions: vec![],
    };
    assert!(
        forward_call_via_universal_canister(
            &fake_governance_canister,
            &canister,
            "atomic_mutate",
            encode_or_panic(&mutation_request)
        )
        .await
    );

    maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

    // Exercise the "get_value" method
    let get_value_res: RegistryGetValueResponse = canister
        .query_("get_value", protobuf, get_value_request("coimbra", None))
        .await
        .unwrap();
    assert_eq!(
        get_value_res,
        RegistryGetValueResponse {
            error: None,
            version: 2_u64,
            value: b"portugal".to_vec()
        }
    );

    // Exercise the "get_latest_version" method
    let get_latest_version_resp: RegistryGetLatestVersionResponse = canister
        .query_("get_latest_version", protobuf, vec![])
        .await
        .unwrap();
    assert_eq!(
        get_latest_version_resp,
        RegistryGetLatestVersionResponse { version: 2_u64 }
    );

    // Mutate an existing key to be able to test the existence of several values for
    // one key.
    assert!(
        forward_call_via_universal_canister(
            &fake_governance_canister,
            &canister,
            "atomic_mutate",
            encode_or_panic(&RegistryAtomicMutateRequest {
                mutations: vec![update("zurich", "die Schweiz")],
                preconditions: vec![],
            })
        )
        .await
    );

    maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

    // We can still access both values
    let get_value_v1_resp: RegistryGetValueResponse = canister
        .query_("get_value", protobuf, get_value_request("zurich", Some(2)))
        .await
        .unwrap();
    let get_value_v2_resp: RegistryGetValueResponse = canister
        .query_("get_value", protobuf, get_value_request("zurich", Some(3)))
        .await
        .unwrap();

    assert_eq!(get_value_v1_resp.value, b"switzerland");
    assert_eq!(get_value_v2_resp.value, b"die Schweiz");

    // Exercise the "get_latest_version" method again
    let get_latest_version_res: RegistryGetLatestVersionResponse = canister
        .query_("get_latest_version", protobuf, vec![])
        .await
        .unwrap();

    assert_eq!(
        get_latest_version_res,
        RegistryGetLatestVersionResponse { version: 3_u64 }
    );

    // Try to get a non-existing key
    let get_value_resp_non_existent: RegistryGetValueResponse = canister
        .query_(
            "get_value",
            protobuf,
            get_value_request("Oh no, that key does not exist!", None),
        )
        .await
        .unwrap();

    assert_eq!(
        get_value_resp_non_existent,
        RegistryGetValueResponse {
            error: Some(RegistryError {
                code: Code::KeyNotPresent as i32,
                key: b"Oh no, that key does not exist!".to_vec(),
                reason: "".to_string()
            }),
            version: 3,
            value: vec![]
        }
    );
}

#[parameterized_upgrades]
async fn get_latest_version_certified(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    type T = LabeledTree<Vec<u8>>;

    let mut canister = install_registry_canister(
        runtime,
        RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            .build(),
    )
    .await;

    // Sets up a universal canister in lieu of the governance canister so it can
    // impersonate it.
    let fake_governance_canister = set_up_universal_canister(runtime).await;
    assert_eq!(
        fake_governance_canister.canister_id(),
        GOVERNANCE_CANISTER_ID
    );

    let mutation_request = RegistryAtomicMutateRequest {
        mutations: vec![insert("key1", "value1")],
        preconditions: vec![],
    };
    assert!(
        forward_call_via_universal_canister(
            &fake_governance_canister,
            &canister,
            "atomic_mutate",
            encode_or_panic(&mutation_request)
        )
        .await
    );

    maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

    let certified_response: CertifiedResponse = canister
        .query_("get_certified_latest_version", protobuf, vec![])
        .await
        .unwrap();

    assert_eq!(
        data_part(&certified_response),
        T::SubTree(flatmap!(Label::from("current_version") => T::Leaf(vec![0x02])))
    );
}

#[parameterized_upgrades]
async fn get_changes_since_certified(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    let mut canister = install_registry_canister(
        runtime,
        RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            .build(),
    )
    .await;

    // Sets up a universal canister in lieu of the governance canister so it can
    // impersonate it.
    let fake_governance_canister = set_up_universal_canister(runtime).await;
    assert_eq!(
        fake_governance_canister.canister_id(),
        GOVERNANCE_CANISTER_ID
    );

    let (deltas, version) = query_certified_changes_since(&canister, 1).await;
    assert_eq!(version, RegistryVersion::from(1));
    assert!(deltas.is_empty());

    let mutation_request = RegistryAtomicMutateRequest {
        mutations: vec![insert("key1", "value1")],
        preconditions: vec![],
    };
    assert!(
        forward_call_via_universal_canister(
            &fake_governance_canister,
            &canister,
            "atomic_mutate",
            encode_or_panic(&mutation_request)
        )
        .await
    );

    maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

    let (deltas, version) = query_certified_changes_since(&canister, 1).await;
    assert_eq!(version, RegistryVersion::from(2));
    assert_eq!(deltas.len(), 1);

    let (deltas, version) = query_certified_changes_since(&canister, 2).await;
    assert_eq!(version, RegistryVersion::from(2));
    assert!(deltas.is_empty());
}

#[test]
fn test_does_not_return_more_than_1000_certified_deltas() {
    fn count_deltas(tree: &LabeledTree<Vec<u8>>) -> usize {
        match lookup_path(tree, &[&b"delta"[..]]).unwrap() {
            LabeledTree::SubTree(children) => children.len(),
            _ => panic!("unexpected data tree shape: {:?}", tree),
        }
    }
    fn has_delta(tree: &LabeledTree<Vec<u8>>, version: u64) -> bool {
        lookup_path(tree, &[&b"delta"[..], &version.to_be_bytes()[..]]).is_some()
    }

    local_test_on_nns_subnet(|runtime| async move {
        const MAX_VERSIONS_PER_QUERY: u64 = 1000;

        let canister = install_registry_canister(&runtime, {
            let mut builder = RegistryCanisterInitPayloadBuilder::new();
            builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req());
            for v in 1..(3 * MAX_VERSIONS_PER_QUERY / 2) {
                let mutation_request = RegistryAtomicMutateRequest {
                    mutations: vec![insert(format!("key{}", v), "value")],
                    preconditions: vec![],
                };
                builder.push_init_mutate_request(mutation_request);
            }
            builder.build()
        })
        .await;

        let certified_response: CertifiedResponse = canister
            .query_("get_certified_changes_since", protobuf, changes_since(0))
            .await
            .unwrap();

        let tree = data_part(&certified_response);
        assert_eq!(count_deltas(&tree), MAX_VERSIONS_PER_QUERY as usize);
        assert!(has_delta(&tree, 1));
        assert!(has_delta(&tree, MAX_VERSIONS_PER_QUERY));
        decode_hash_tree(0, certified_response.hash_tree.unwrap().try_into().unwrap()).unwrap();

        let certified_response: CertifiedResponse = canister
            .query_(
                "get_certified_changes_since",
                protobuf,
                changes_since(MAX_VERSIONS_PER_QUERY),
            )
            .await
            .unwrap();

        let tree = data_part(&certified_response);
        assert_eq!(count_deltas(&tree), MAX_VERSIONS_PER_QUERY as usize / 2);
        assert!(has_delta(&tree, MAX_VERSIONS_PER_QUERY + 1));
        assert!(has_delta(&tree, 3 * MAX_VERSIONS_PER_QUERY / 2));
        decode_hash_tree(
            MAX_VERSIONS_PER_QUERY,
            certified_response.hash_tree.unwrap().try_into().unwrap(),
        )
        .unwrap();

        Ok(())
    });
}

#[test]
fn test_canister_installation_traps_on_bad_init_payload() {
    local_test_on_nns_subnet(|runtime| async move {
        assert_matches!(
            Project::new(env!("CARGO_MANIFEST_DIR"))
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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
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
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
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
        // The following assert_eq have the expected value first and expression second,
        // otherwise type inference does not work
        assert_eq!(
            RegistryGetValueResponse {
                error: None,
                version: 2_u64,
                value: b"4634 m".to_vec()
            },
            canister
                .query_(
                    "get_value",
                    protobuf,
                    get_value_request("dufourspitze", None)
                )
                .await
                .unwrap()
        );
        assert_eq!(
            RegistryGetValueResponse {
                error: None,
                version: 2_u64,
                value: b"4545 m".to_vec()
            },
            canister
                .query_("get_value", protobuf, get_value_request("dom", None))
                .await
                .unwrap(),
        );
        assert_eq!(
            RegistryGetValueResponse {
                error: None,
                version: 3_u64,
                value: b"4478 m".to_vec()
            },
            canister
                .query_("get_value", protobuf, get_value_request("matterhorn", None))
                .await
                .unwrap(),
        );
        Ok(())
    });
}

/// Tests that the canister init traps if any initial mutation fails, even
/// if previous ones have succeeded
#[test]
fn test_that_init_traps_if_any_init_mutation_fails() {
    local_test_on_nns_subnet(|runtime| async move {
        let init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
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
                Err(msg) if msg.contains("Transaction rejected"));
        Ok(())
    });
}
