use candid::Decode;
use candid::Encode;
use ic_base_types::CanisterId;
use ic_ledger_test_utils::statemachine_helpers::assert_ledger_index_parity_query_blocks_and_query_encoded_blocks;
use ic_nns_constants::LEDGER_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_nns_test_utils_golden_nns_state::{
    new_state_machine_with_golden_nns_state_or_panic, GoldenStateLocation,
};
use icp_ledger::Archives;
use std::path::PathBuf;

#[test]
fn should_create_state_machine_with_golden_nns_state() {
    let state_machine = new_state_machine_with_golden_nns_state_or_panic(
        GoldenStateLocation::Local(PathBuf::from(
            // "/Users/mathias/projects/crypto/workspaces/ic-FI-1301-golden-mainnet-nns-state-icp-ledger-suite-upgrade-test/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst"
            // "/tmp/nns_state.tar.zst",
            "/home/mathias/projects/crypto/workspaces/ic/rs/rosetta-api/icp_ledger/test_resources/nns_state.tar.zst",
        )),
    );

    let archives = Decode!(
        &state_machine
            .query(
                CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET),
                "archives",
                Encode!().unwrap()
            )
            .expect("failed to query archives")
            .bytes(),
        Archives
    )
    .expect("failed to decode archives response");

    assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
        &state_machine,
        CanisterId::from_u64(LEDGER_CANISTER_INDEX_IN_NNS_SUBNET),
        CanisterId::from_u64(11),
    );

    assert_eq!(93, archives.archives.len());
}
