use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_ledger_test_utils::{
    build_ledger_archive_wasm, build_ledger_index_wasm, build_ledger_wasm,
    build_mainnet_ledger_archive_wasm, build_mainnet_ledger_index_wasm, build_mainnet_ledger_wasm,
};
use ic_nns_constants::{
    LEDGER_CANISTER_INDEX_IN_NNS_SUBNET, LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET,
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{Archives, FeatureFlags, LedgerCanisterPayload, UpgradeArgs};

const LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET);
const INDEX_CANISTER_ID: CanisterId =
    CanisterId::from_u64(LEDGER_INDEX_CANISTER_INDEX_IN_NNS_SUBNET);

/// Create a state machine with the golden NNS state, then upgrade and downgrade the ICP
/// ledger canister suite.
#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Upgrade all the canisters to the latest version
    upgrade_index(&state_machine, build_ledger_index_wasm().bytes());
    upgrade_ledger(&state_machine, build_ledger_wasm().bytes());
    upgrade_archive_canisters(&state_machine, build_ledger_archive_wasm().bytes());

    // Downgrade all the canisters to the mainnet version
    upgrade_archive_canisters(&state_machine, build_mainnet_ledger_archive_wasm().bytes());
    upgrade_ledger(&state_machine, build_mainnet_ledger_wasm().bytes());
    upgrade_index(&state_machine, build_mainnet_ledger_index_wasm().bytes());
}

fn list_archives(state_machine: &StateMachine) -> Archives {
    Decode!(
        &state_machine
            .query(LEDGER_CANISTER_ID, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Archives
    )
    .expect("failed to decode archives response")
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

fn upgrade_archive_canisters(state_machine: &StateMachine, archive_wasm_bytes: Vec<u8>) {
    let archives = list_archives(state_machine).archives;
    for archive_info in &archives {
        upgrade_archive(
            state_machine,
            archive_info.canister_id,
            archive_wasm_bytes.clone(),
        );
    }
}

fn upgrade_index(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    state_machine
        .upgrade_canister(INDEX_CANISTER_ID, wasm_bytes, vec![])
        .expect("should successfully upgrade index to new local version");
}

fn upgrade_ledger(state_machine: &StateMachine, wasm_bytes: Vec<u8>) {
    let ledger_upgrade_args: LedgerCanisterPayload =
        LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
            icrc1_minting_account: None,
            feature_flags: Some(FeatureFlags { icrc2: true }),
        }));

    state_machine
        .upgrade_canister(
            LEDGER_CANISTER_ID,
            wasm_bytes,
            Encode!(&ledger_upgrade_args).unwrap(),
        )
        .expect("should successfully upgrade ledger to new local version");
}
