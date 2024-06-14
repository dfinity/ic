use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::block::BlockType;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    GetBlocksArgs, QueryBlocksResponse, QueryEncodedBlocksResponse, Transaction,
    MAX_BLOCKS_PER_REQUEST,
};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;

/// Assert that the index canister contains the same blocks as the ledger, by querying both the
/// `query_blocks` and `query_encoded_blocks` endpoints of the ledger.
pub fn assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    index_id: CanisterId,
) {
    let ledger_blocks = icp_get_blocks(env, ledger_id);
    let index_blocks = index_get_blocks(env, index_id);
    let ledger_unencoded_blocks = icp_query_blocks(env, ledger_id);
    assert_eq!(ledger_blocks, index_blocks);
    assert_eq!(ledger_blocks.len(), ledger_unencoded_blocks.len());
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

pub fn icp_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksArgs {
        start: 0u64,
        length: MAX_BLOCKS_PER_REQUEST,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .query(ledger_id, "query_encoded_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res =
        Decode!(&res, QueryEncodedBlocksResponse).expect("Failed to decode GetBlocksResponse");
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let req = GetBlocksArgs {
            start: archived.start,
            length: archived.length as usize,
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
        let canister_id = archived.callback.canister_id;
        let res = env
            .query(
                CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                archived.callback.method,
                req,
            )
            .expect("Failed to send get_blocks request to archive")
            .bytes();
        let res = Decode!(&res, icp_ledger::GetEncodedBlocksResult)
            .unwrap()
            .unwrap();
        blocks.extend(res);
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
        length: MAX_BLOCKS_PER_REQUEST,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksArgs");
    let res = env
        .query(ledger_id, "query_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, QueryBlocksResponse).expect("Failed to decode QueryBlocksResponse");
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let req = GetBlocksArgs {
            start: archived.start,
            length: archived.length as usize,
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
        let canister_id = archived.callback.canister_id;
        let res = env
            .query(
                CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                archived.callback.method,
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
    blocks.extend(
        res.blocks
            .into_iter()
            .map(icp_ledger::Block::try_from)
            .collect::<Result<Vec<icp_ledger::Block>, String>>()
            .unwrap(),
    );
    blocks
}

pub fn index_get_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let query = |req: Vec<u8>| {
        env.query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes()
    };
    call_index_get_blocks(&query)
}
