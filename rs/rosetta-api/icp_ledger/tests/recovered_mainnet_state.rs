use candid::Decode;
use candid::Encode;
use ic_base_types::CanisterId;
use ic_ledger_test_utils::statemachine_helpers::assert_ledger_index_parity_query_blocks_and_query_encoded_blocks;
use ic_ledger_test_utils::{
    build_ledger_archive_wasm, build_ledger_index_wasm, build_ledger_wasm,
    build_mainnet_ledger_archive_wasm, build_mainnet_ledger_index_wasm, build_mainnet_ledger_wasm,
};
use ic_nns_constants::LEDGER_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_nns_test_utils_golden_nns_state::{
    new_state_machine_with_golden_nns_state_or_panic, GoldenStateLocation,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{Archives, FeatureFlags, LedgerCanisterUpgradePayload};
use std::path::PathBuf;

const LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
const INDEX_CANISTER_ID: CanisterId = CanisterId::from_u64(11);

#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic(
        GoldenStateLocation::Local(PathBuf::from(
            // "/Users/mathias/projects/crypto/workspaces/ic-FI-1301-golden-mainnet-nns-state-icp-ledger-suite-upgrade-test/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst"
            // "/tmp/nns_state.tar.zst",
            "/home/mathias/projects/crypto/workspaces/ic/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst",
        )),
    );

    assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
        &state_machine,
        LEDGER_CANISTER_ID,
        INDEX_CANISTER_ID,
    );

    // 1. Create a bunch of transactions
    //  1.1. Mint
    //  1.2. Transfer
    //  1.3. Burn
    //  1.4. Approve
    //  1.5. Transfer From
    // 2. Verify that the ledger, archives, and index have the same blocks (start from before step 1.)
    // 3. Upgrade the index canister
    //  3.1. Perform steps 1 and 2 again
    // 4. Upgrade the ledger canister
    //  4.1. Perform steps 1 and 2 again
    // 5. Upgrade the first archive canister
    //  5.1. Perform steps 1 and 2 again
    // 6. Upgrade the second archive canister
    //  6.1. Perform steps 1 and 2 again
    // 7. Downgrade the second archive canister
    //  7.1. Perform steps 1 and 2 again
    // 8. Downgrade the first archive canister
    //  8.1. Perform steps 1 and 2 again
    // 9. Downgrade the ledger canister
    //  9.1. Perform steps 1 and 2 again
    // 10. Downgrade the index canister
    //  10.1. Perform steps 1 and 2 again

    let archives = Decode!(
        &state_machine
            .query(LEDGER_CANISTER_ID, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Archives
    )
    .expect("failed to decode archives response");

    // Upgrade index
    upgrade_index(&state_machine, build_ledger_index_wasm().bytes());

    // Upgrade ledger
    upgrade_ledger(&state_machine, build_ledger_wasm().bytes());

    // Upgrade archives
    for archive_info in &archives.archives {
        upgrade_archive(
            &state_machine,
            archive_info.canister_id,
            build_ledger_archive_wasm().bytes(),
        );
    }

    // Downgrade archives
    for archive_info in &archives.archives {
        upgrade_archive(
            &state_machine,
            archive_info.canister_id,
            build_mainnet_ledger_archive_wasm().bytes(),
        );
    }

    // Downgrade ledger
    upgrade_ledger(&state_machine, build_mainnet_ledger_wasm().bytes());

    // Downgrade index
    upgrade_index(&state_machine, build_mainnet_ledger_index_wasm().bytes());

    assert_eq!(93, archives.archives.len());
}

fn upgrade_archive(
    state_machine: &StateMachine,
    archive_canister_id: CanisterId,
    wasm_bytes: Vec<u8>,
) {
    state_machine
        .upgrade_canister(archive_canister_id, wasm_bytes, vec![])
        .unwrap_or_else(|e| {
            panic!(
                "should successfully upgrade archive '{}' to new local version: {}",
                archive_canister_id, e
            )
        });
}

fn upgrade_index(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    state_machine
        .upgrade_canister(INDEX_CANISTER_ID, wasm_bytes, vec![])
        .expect("should successfully upgrade index to new local version");
}

fn upgrade_ledger(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    let ledger_upgrade_args = LedgerCanisterUpgradePayload::builder()
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();

    state_machine
        .upgrade_canister(
            LEDGER_CANISTER_ID,
            wasm_bytes,
            Encode!(&ledger_upgrade_args).unwrap(),
        )
        .expect("should successfully upgrade ledger to new local version");
}
