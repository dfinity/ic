use candid::types::number::Nat;
use ic_icp_index::Status;
use ic_ledger_core::block::BlockType;
use icp_ledger::{LEDGER_INDEX_CANISTER_ID, MAX_BLOCKS_PER_REQUEST};
use icrc_ledger_types::icrc1::transfer::BlockIndex;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use pocket_ic::PocketIc;
use std::time::Duration;

const SYNC_STEP_SECONDS: Duration = Duration::from_secs(60);

pub fn get_blocks(pocket_ic: &PocketIc) -> Vec<icp_ledger::Block> {
    let req = GetBlocksRequest {
        start: BlockIndex::from(0u64),
        length: Nat::from(MAX_BLOCKS_PER_REQUEST),
    };
    let get_blocks_response: ic_icp_index::GetBlocksResponse = super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_INDEX_CANISTER_ID),
        candid::Principal::anonymous(),
        "get_blocks",
        req,
    );
    get_blocks_response
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn status(pocket_ic: &PocketIc) -> Status {
    super::query_or_panic(
        pocket_ic,
        candid::Principal::from(LEDGER_INDEX_CANISTER_ID),
        candid::Principal::anonymous(),
        "status",
        (),
    )
}

// Helper function that calls tick on env until either
// the index canister has synced all the blocks up to the
// last one in the ledger or enough attempts passed and therefore
// it fails
pub fn wait_until_sync_is_completed(pocket_ic: &PocketIc) {
    const MAX_ATTEMPTS: u8 = 100; // no reason for this number
    let mut num_blocks_synced = u64::MAX;
    let mut chain_length = u64::MAX;
    for _i in 0..MAX_ATTEMPTS {
        pocket_ic.advance_time(SYNC_STEP_SECONDS);
        pocket_ic.tick();
        num_blocks_synced = status(pocket_ic).num_blocks_synced;
        chain_length = super::ledger::query_encoded_blocks(pocket_ic, true).len() as u64;
        if num_blocks_synced == chain_length {
            return;
        }
    }
    panic!(
        "The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {num_blocks_synced} but the Ledger chain length is {chain_length}"
    );
}
