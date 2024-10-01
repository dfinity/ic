use crate::state_machine_helpers::ledger::icp_ledger_tip;
use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_icp_index::Status;
use ic_state_machine_tests::StateMachine;
use std::time::Duration;

const SYNC_STEP_SECONDS: Duration = Duration::from_secs(60);

/// Helper function that calls tick on env until either
/// the index canister has synced all the blocks up to the
/// last one in the ledger or enough attempts passed and therefore
/// it fails
pub fn wait_until_sync_is_completed(
    env: &StateMachine,
    index_id: CanisterId,
    ledger_id: CanisterId,
) {
    const MAX_ATTEMPTS: u8 = 100; // no reason for this number
    let mut num_blocks_synced = u64::MAX;
    let mut chain_length = u64::MAX;
    for _i in 0..MAX_ATTEMPTS {
        env.advance_time(SYNC_STEP_SECONDS);
        env.tick();
        num_blocks_synced = status(env, index_id).num_blocks_synced;
        chain_length = icp_ledger_tip(env, ledger_id) + 1;
        if num_blocks_synced == chain_length {
            return;
        }
    }
    panic!("The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {} but the Ledger chain length is {}", num_blocks_synced, chain_length);
}

fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    Decode!(&res, Status).expect("Failed to decode status response")
}
