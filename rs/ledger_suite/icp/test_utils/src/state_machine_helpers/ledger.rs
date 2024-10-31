use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::block::BlockType;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    GetBlocksArgs, QueryBlocksResponse, QueryEncodedBlocksResponse, MAX_BLOCKS_PER_REQUEST,
};
use on_wire::FromWire;

pub fn icp_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
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
    // Assume that all blocks in the ledger can be retrieved in a single call. This should hold for
    // most tests.
    let blocks_in_ledger = res.chain_length.saturating_sub(res.first_block_index);
    assert!(
        blocks_in_ledger <= MAX_BLOCKS_PER_REQUEST as u64,
        "Chain length: {}, first block index: {}, max blocks per request: {}",
        res.chain_length,
        res.first_block_index,
        MAX_BLOCKS_PER_REQUEST
    );
    let mut blocks = vec![];
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

pub fn icp_query_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
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

pub(crate) fn icp_ledger_tip(env: &StateMachine, ledger_id: CanisterId) -> u64 {
    let res = env
        .query(ledger_id, "tip_of_chain_pb", vec![])
        .expect("Failed to send tip_of_chain_pb request")
        .bytes();
    let tip: icp_ledger::TipOfChainRes = dfn_protobuf::ProtoBuf::from_bytes(res)
        .map(|c| c.0)
        .expect("failed to decode tip_of_chain_pb result");
    tip.tip_index
}
