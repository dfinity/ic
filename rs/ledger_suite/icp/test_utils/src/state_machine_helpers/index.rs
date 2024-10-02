use crate::state_machine_helpers::ledger::icp_ledger_tip;
use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_icp_index::Status;
use ic_ledger_core::block::BlockType;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use std::time::Duration;

const SYNC_STEP_SECONDS: Duration = Duration::from_secs(60);

pub fn call_index_get_blocks(
    query_or_update: &dyn Fn(Vec<u8>) -> Vec<u8>,
) -> Vec<icp_ledger::Block> {
    let req = GetBlocksRequest {
        start: 0u8.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = query_or_update(req);
    Decode!(&res, ic_icp_index::GetBlocksResponse)
        .expect("Failed to decode ic_icp_index::GetBlocksResponse")
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

pub fn index_get_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let query = |req: Vec<u8>| {
        env.query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes()
    };
    call_index_get_blocks(&query)
}

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
