use crate::state_machine_helpers::ledger::icp_ledger_tip;
use candid::{Decode, Encode, Nat};
use ic_base_types::CanisterId;
use ic_icp_index::{GetBlocksResponse, Status};
use ic_state_machine_tests::{StateMachine, WasmResult};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use std::time::Duration;

pub const SYNC_STEP_SECONDS: Duration = Duration::from_secs(2);

pub fn get_all_blocks(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    let res = get_blocks(state_machine, canister_id, 0_u64, 0_u64);
    let length = length.min(res.chain_length);
    let mut blocks: Vec<_> = vec![];
    let mut curr_start = start;
    while length > blocks.len() as u64 {
        let new_blocks = get_blocks(
            state_machine,
            canister_id,
            curr_start,
            length - (curr_start - start),
        )
        .blocks;
        assert!(!new_blocks.is_empty());
        curr_start += new_blocks.len() as u64;
        blocks.extend(new_blocks);
    }
    GetBlocksResponse { blocks, ..res }
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
    panic!(
        "The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {num_blocks_synced} but the Ledger chain length is {chain_length}"
    );
}

fn get_blocks<I>(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    start: I,
    length: I,
) -> GetBlocksResponse
where
    I: Into<Nat>,
{
    let result = state_machine
        .query(
            canister_id,
            "get_blocks",
            Encode!(&GetBlocksRequest {
                start: start.into(),
                length: length.into(),
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => panic!("Call to get_blocks failed: {s:#?}"),
    };
    Decode!(&result, GetBlocksResponse).unwrap()
}

fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    Decode!(&res, Status).expect("Failed to decode status response")
}
