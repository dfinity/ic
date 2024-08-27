mod common;

use candid::Encode;
use canister_test::{Canister, Project, Runtime};
use ic_crypto_tree_hash::{lookup_path, LabeledTree, MixedHashTree};
use ic_interfaces_registry::RegistryTransportRecord;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_universal_canister,
};
use ic_nns_test_utils::{
    itest_helpers::{local_test_on_nns_subnet, maybe_upgrade_to_self, UpgradeTestingScenario},
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_nns_test_utils_macros::parameterized_upgrades;
use ic_registry_nns_data_provider::certification::decode_hash_tree;
use ic_registry_transport::{
    insert,
    pb::v1::{CertifiedResponse, RegistryAtomicMutateRequest, RegistryGetChangesSinceRequest},
};
use ic_types::RegistryVersion;
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

#[parameterized_upgrades]
async fn get_changes_since_certified(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
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
            mutation_request.encode_to_vec()
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
            builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
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
