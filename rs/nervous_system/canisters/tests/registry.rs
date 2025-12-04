use candid::{CandidType, Encode};
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_agent::{CallCanisters, Request, pocketic_impl::PocketIcAgent};
use ic_nervous_system_chunks::test_data::MEGA_BLOB;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_canister_api::mutate_test_high_capacity_records;
use ic_registry_fetch_large_record_test_canister::ContentSummary;
use pocket_ic::PocketIcBuilder;
use serde::Deserialize;

// This is copied from fetch_large_record_test_canister. We do this so that we
// can make it implement the `Request` trait (from `nervous_system/agent`).
// There are a couple of alternatives locations where such an implementation
// might want to live:
//
//     1. agent (where the trait is defined) - This has the disadvantage that
//        agent must then depend on fetch_large_record_test_canister. This is
//        not good, because that prevents fetch_large_record_test_canister from
//        being testonly.
//
//     2. fetch_large_record_test_canister - This would require that
//        fetch_large_record_test_canister depends on agent. This breaks the
//        build, because a canister (namely fetch_large_record_test_canister)
//        then depends on agent. This is not allowed, because agent requires
//        that the platform support TCP, and WASM does not support TCP.
//
// It was deemed that this is the least bad option. Another way is to chop up
// agent so that it does not require the platform support TCP. This is probably
// the best way, but such a change would seriously inflate the scope of the
// change where this test was added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct CallRegistryGetChangesSinceRequest {}

impl Request for CallRegistryGetChangesSinceRequest {
    fn method(&self) -> &'static str {
        "call_registry_get_changes_since"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = Option<ContentSummary>;
}

#[tokio::test]
async fn test_registry_get_changes_since() {
    // Step 1: Prepare the world.

    // Step 1.1: Create a simulated ICP (to wit, PocketIc).
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    // Step 1.2: Install Registry canister on PocketIc.
    let mut nns_configuration = NnsInitPayloadsBuilder::new();
    let registry_init_args = nns_configuration
        .with_initial_invariant_compliant_mutations()
        .build()
        .registry;
    install_canister(
        &pocket_ic,
        "Registry",
        REGISTRY_CANISTER_ID,
        Encode!(&registry_init_args).unwrap(),
        build_test_registry_wasm(),
        Some(REGISTRY_CANISTER_ID.get()),
    )
    .await;

    // Step 1.3: Add some (chunked) test data to the Registry canister.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::UpsertLarge,
            },
        )
        .await
        .unwrap();

    // Step 1.4: Install a canister that calls registry_changes_since (the code
    // under test).
    // The following canister ID must belong to the canister ranges
    // of a subnet on the ICP mainnet.
    let fetch_large_record_test_canister_id = CanisterId::from(29_767_024);
    install_canister(
        &pocket_ic,
        "fetch_large_record_test_canister_id",
        fetch_large_record_test_canister_id,
        vec![], // arg
        Project::cargo_bin_maybe_from_env("fetch_large_record_test_canister", &[]),
        Some(fetch_large_record_test_canister_id.get()), // controller
    )
    .await;

    // Step 2: Call the code under test.

    // Step 2.1: Originally, the record is large. This is the interesting case.
    let large_content_summary = pocket_ic
        .call(
            fetch_large_record_test_canister_id,
            CallRegistryGetChangesSinceRequest {},
        )
        .await
        .unwrap()
        .unwrap();

    // Step 2.2: See what happens in case of small records.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::UpsertSmall,
            },
        )
        .await
        .unwrap();
    let small_content_summary = pocket_ic
        .call(
            fetch_large_record_test_canister_id,
            CallRegistryGetChangesSinceRequest {},
        )
        .await
        .unwrap()
        .unwrap();

    // Step 2.3: See what happens in case of delete.
    PocketIcAgent::new(&pocket_ic, GOVERNANCE_CANISTER_ID)
        .call(
            REGISTRY_CANISTER_ID,
            mutate_test_high_capacity_records::Request {
                id: 42,
                operation: mutate_test_high_capacity_records::Operation::Delete,
            },
        )
        .await
        .unwrap();
    let delete_reply = pocket_ic
        .call(
            fetch_large_record_test_canister_id,
            CallRegistryGetChangesSinceRequest {},
        )
        .await
        .unwrap();

    // Step 3: Verify the result(s)

    assert_eq!(
        large_content_summary,
        ContentSummary {
            key: b"daniel_wong_42".to_vec(),
            len: MEGA_BLOB.len() as u64,
            sha256: Sha256::hash(&MEGA_BLOB).to_vec(),
        },
    );

    assert_eq!(
        small_content_summary,
        ContentSummary {
            key: b"daniel_wong_42".to_vec(),
            len: "small value".len() as u64,
            sha256: Sha256::hash(b"small value").to_vec(),
        },
    );

    assert_eq!(delete_reply, None);
}
