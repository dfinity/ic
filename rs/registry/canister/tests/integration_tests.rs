mod common;

use candid::Encode;
use canister_test::{Canister, Project, Runtime};
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, MixedHashTree};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_universal_canister,
};
use ic_nns_test_utils::{
    itest_helpers::{maybe_upgrade_to_self, UpgradeTestingScenario},
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_nns_test_utils_macros::parameterized_upgrades;
use ic_registry_transport::{
    insert,
    pb::v1::{
        registry_error::Code, CertifiedResponse, RegistryAtomicMutateRequest, RegistryError,
        RegistryGetLatestVersionResponse, RegistryGetValueRequest, RegistryGetValueResponse,
    },
    update,
};
use prost::Message;
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

// TODO(NNS1-2271): re-join/re-organise the integration tests from separate files.

/// This is a simple end-to-end test of the Registry canister, in which
/// key/value pairs are first inserted, and in a second time the value
/// for one key is retrieved.
#[parameterized_upgrades]
async fn registry(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
    // Set up: install the registry canister
    let mut canister = install_registry_canister(
        runtime,
        RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
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
            mutation_request.encode_to_vec()
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
            RegistryAtomicMutateRequest {
                mutations: vec![update("zurich", "die Schweiz")],
                preconditions: vec![],
            }
            .encode_to_vec()
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
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
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
            mutation_request.encode_to_vec()
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
