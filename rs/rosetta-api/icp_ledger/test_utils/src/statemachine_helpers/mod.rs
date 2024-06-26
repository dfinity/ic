use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_index::Status;
use ic_ledger_core::block::BlockType;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    GetBlocksArgs, QueryBlocksResponse, QueryEncodedBlocksResponse, Transaction,
    MAX_BLOCKS_PER_REQUEST,
};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use on_wire::FromWire;
use std::time::Duration;

/// Assert that the index canister contains the same blocks as the ledger, by querying both the
/// `query_blocks` and `query_encoded_blocks` endpoints of the ledger.
pub fn assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    index_id: CanisterId,
) {
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // TODO: The performance of the parity check may be improved by not first getting all the blocks
    //  and then comparing, but instead comparing the blocks one batch at a time.
    let ledger_blocks = icp_get_blocks(env, ledger_id);
    println!(
        "retrieved {} blocks from the ledger using get_blocks",
        ledger_blocks.len()
    );
    let index_blocks = index_get_all_blocks(env, index_id);
    println!(
        "retrieved {} blocks from the index using get_blocks",
        index_blocks.len()
    );
    assert_eq!(ledger_blocks.len(), index_blocks.len());
    let ledger_unencoded_blocks = icp_query_blocks(env, ledger_id);
    println!(
        "retrieved {} blocks from the ledger using query_blocks",
        ledger_unencoded_blocks.len()
    );
    assert_eq!(ledger_blocks.len(), ledger_unencoded_blocks.len());
    assert_eq!(ledger_blocks, index_blocks);
    if ledger_blocks != ledger_unencoded_blocks {
        // If the ledger blocks are not equal, we need some special handling to compare them.
        // If the client did not specify the `created_at_time` field when creating a transaction,
        // the ledger populates the `created_at_time` field with the value of the `timestamp` field
        // of the block, for blocks returned from the `query_blocks` endpoint. Blocks returned from
        // the `query_encoded_blocks` endpoint do not have the `created_at_time` field set.
        // Therefore, if the blocks do not match, verify that:
        //  - the `created_at_time` field of the encoded block is set `None`
        //  - the `created_at_time` field of the unencoded block is set to the `timestamp` field
        //    of the block
        //  - all the other fields of the blocks match
        for (ledger_block, unencoded_ledger_block) in ledger_blocks
            .into_iter()
            .zip(ledger_unencoded_blocks.into_iter())
        {
            if ledger_block != unencoded_ledger_block {
                if ledger_block.transaction.created_at_time.is_none() {
                    assert_eq!(
                        Some(unencoded_ledger_block.timestamp),
                        unencoded_ledger_block.transaction.created_at_time
                    );
                    let unencoded_ledger_block_without_created_at_time_in_tx = icp_ledger::Block {
                        transaction: Transaction {
                            created_at_time: None,
                            ..unencoded_ledger_block.transaction
                        },
                        ..unencoded_ledger_block
                    };
                    assert_eq!(
                        unencoded_ledger_block_without_created_at_time_in_tx,
                        ledger_block
                    )
                } else {
                    assert_eq!(ledger_block, unencoded_ledger_block);
                }
            }
        }
    }
}

pub fn icp_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
    // Try to get all the blocks. As long as MAX_BLOCKS_PER_REQUEST >= ARCHIVE_TRIGGER_THRESHOLD,
    // we should receive all the blocks from the ledger, and we can retrieve the archived blocks
    // from the archive up to MAX_BLOCKS_PER_REQUEST at a time.
    let req = GetBlocksArgs {
        start: 0u64,
        length: u32::MAX as usize,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksArgs");
    let res = env
        .query(ledger_id, "query_encoded_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res =
        Decode!(&res, QueryEncodedBlocksResponse).expect("Failed to decode GetBlocksResponse");
    let mut blocks = vec![];
    println!("chain length: {}", res.chain_length);
    for archived in res.archived_blocks {
        for i in 0..=archived.length / MAX_BLOCKS_PER_REQUEST as u64 {
            let req = GetBlocksArgs {
                start: archived.start + i * MAX_BLOCKS_PER_REQUEST as u64,
                length: MAX_BLOCKS_PER_REQUEST,
            };
            let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
            let canister_id = archived.callback.canister_id;
            let res = env
                .query(
                    CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                    archived.callback.method.clone(),
                    req,
                )
                .expect("Failed to send get_blocks request to archive")
                .bytes();
            let res = Decode!(&res, icp_ledger::GetEncodedBlocksResult)
                .unwrap()
                .unwrap();
            blocks.extend(res);
        }
    }
    blocks.extend(res.blocks);
    blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn icp_query_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksArgs {
        start: 0u64,
        length: u32::MAX as usize,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksArgs");
    let res = env
        .query(ledger_id, "query_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, QueryBlocksResponse).expect("Failed to decode QueryBlocksResponse");
    let mut blocks = vec![];
    println!("chain length: {}", res.chain_length);
    for archived in res.archived_blocks {
        for i in 0..=archived.length / MAX_BLOCKS_PER_REQUEST as u64 {
            let req = GetBlocksArgs {
                start: archived.start + i * MAX_BLOCKS_PER_REQUEST as u64,
                length: MAX_BLOCKS_PER_REQUEST,
            };
            let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
            let canister_id = archived.callback.canister_id;
            let res = env
                .query(
                    CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                    archived.callback.method.clone(),
                    req,
                )
                .expect("Failed to send get_blocks request to archive")
                .bytes();
            let res = Decode!(&res, icp_ledger::GetBlocksResult).unwrap().unwrap();
            blocks.extend(
                res.blocks
                    .into_iter()
                    .map(icp_ledger::Block::try_from)
                    .collect::<Result<Vec<icp_ledger::Block>, String>>()
                    .unwrap(),
            );
        }
    }
    blocks.extend(
        res.blocks
            .into_iter()
            .map(icp_ledger::Block::try_from)
            .collect::<Result<Vec<icp_ledger::Block>, String>>()
            .unwrap(),
    );
    blocks
}

fn index_get_all_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let mut blocks = vec![];
    let mut start = 0u64;
    loop {
        let req = GetBlocksRequest {
            start: icrc_ledger_types::icrc1::transfer::BlockIndex::from(start),
            length: Nat::from(MAX_BLOCKS_PER_REQUEST),
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
        let res = env
            .query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes();
        let res = Decode!(&res, ic_icp_index::GetBlocksResponse)
            .expect("Failed to decode ic_icp_index::GetBlocksResponse");
        start += res.blocks.len() as u64;
        blocks.extend(res.blocks);
        if res.chain_length == blocks.len() as u64 {
            break;
        }
    }
    blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

const SYNC_STEP_SECONDS: Duration = Duration::from_secs(60);

// Helper function that calls tick on env until either
// the index canister has synced all the blocks up to the
// last one in the ledger or enough attempts passed and therefore
// it fails
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

fn icp_ledger_tip(env: &StateMachine, ledger_id: CanisterId) -> u64 {
    let res = env
        .query(ledger_id, "tip_of_chain_pb", vec![])
        .expect("Failed to send tip_of_chain_pb request")
        .bytes();
    let tip: icp_ledger::TipOfChainRes = dfn_protobuf::ProtoBuf::from_bytes(res)
        .map(|c| c.0)
        .expect("failed to decode tip_of_chain_pb result");
    tip.tip_index
}
