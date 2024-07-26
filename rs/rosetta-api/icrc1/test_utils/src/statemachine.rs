use crate::in_memory_ledger::InMemoryLedger;
use candid::Nat;
use candid::{Decode, Encode};
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use icrc_ledger_types::icrc1::transfer::BlockIndex;
use icrc_ledger_types::icrc3::blocks::{BlockRange, GetBlocksRequest, GetBlocksResponse};
use icrc_ledger_types::icrc3::transactions::GetTransactionsRequest;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

// Copied from ic_icrc1_ledger::MAX_TRANSACTIONS_PER_REQUEST
const MAX_TRANSACTIONS_PER_REQUEST: usize = 2_000;

pub fn get_all_ledger_and_archive_blocks(
    state_machine: &StateMachine,
    ledger_id: CanisterId,
) -> Vec<ic_icrc1::Block<Tokens>> {
    let req = GetBlocksRequest {
        start: BlockIndex::from(0u64),
        length: Nat::from(u32::MAX),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = state_machine
        .query(ledger_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, GetBlocksResponse).expect("Failed to decode GetBlocksResponse");
    // Assume that all blocks in the ledger can be retrieved in a single call. This should hold for
    // most tests.
    // let blocks_in_ledger = res.chain_length.saturating_sub(res.first_index);
    // assert!(
    //     blocks_in_ledger <= MAX_TRANSACTIONS_PER_REQUEST as u64,
    //     "Chain length: {}, first block index: {}, max blocks per request: {}",
    //     res.chain_length,
    //     res.first_index,
    //     MAX_TRANSACTIONS_PER_REQUEST
    // );
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        println!("getting archived blocks");
        let mut remaining = archived.length.clone();
        let mut next_archived_txid = archived.start.clone();
        while remaining > 0u32 {
            let req = GetTransactionsRequest {
                start: next_archived_txid.clone(),
                length: remaining.clone(),
            };
            let req =
                Encode!(&req).expect("Failed to encode GetTransactionsRequest for archive node");
            let canister_id = archived.callback.canister_id;
            println!(
                "getting archived blocks using method {}",
                &archived.callback.method
            );
            let res = state_machine
                .query(
                    CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                    archived.callback.method.clone(),
                    req,
                )
                .expect("Failed to send get_blocks request to archive")
                .bytes();
            let res = Decode!(&res, BlockRange).unwrap();
            next_archived_txid += res.blocks.len() as u64;
            remaining -= res.blocks.len() as u32;
            blocks.extend(res.blocks);
        }
    }
    blocks.extend(res.blocks);
    for block in &blocks {
        println!("found block: {:?}", block);
        let res: Result<ic_icrc1::Block<Tokens>, String> = ic_icrc1::Block::try_from(block.clone());
        match res {
            Ok(icrc1_block) => {
                println!("transaction: {:?}", icrc1_block.transaction);
            }
            Err(e) => {
                println!("error converting block: {:?}", e);
            }
        }
    }
    blocks
        .into_iter()
        .map(ic_icrc1::Block::try_from)
        .collect::<Result<Vec<ic_icrc1::Block<Tokens>>, String>>()
        .expect("should convert generic blocks to ICRC1 blocks")
}

pub fn get_all_ledger_and_archive_blocks_using_icrc3(
    state_machine: &StateMachine,
    ledger_id: CanisterId,
) -> Vec<ic_icrc1::Block<Tokens>> {
    let req = GetBlocksRequest {
        start: BlockIndex::from(0u64),
        length: Nat::from(u32::MAX),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = state_machine
        .query(ledger_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res = Decode!(&res, GetBlocksResponse).expect("Failed to decode GetBlocksResponse");
    // Assume that all blocks in the ledger can be retrieved in a single call. This should hold for
    // most tests.
    // let blocks_in_ledger = res.chain_length.saturating_sub(res.first_index);
    // assert!(
    //     blocks_in_ledger <= MAX_TRANSACTIONS_PER_REQUEST as u64,
    //     "Chain length: {}, first block index: {}, max blocks per request: {}",
    //     res.chain_length,
    //     res.first_index,
    //     MAX_TRANSACTIONS_PER_REQUEST
    // );
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        println!("getting archived blocks");
        let mut remaining = archived.length.clone();
        let mut next_archived_txid = archived.start.clone();
        while remaining > 0u32 {
            let req = GetTransactionsRequest {
                start: next_archived_txid.clone(),
                length: remaining.clone(),
            };
            let req =
                Encode!(&req).expect("Failed to encode GetTransactionsRequest for archive node");
            let canister_id = archived.callback.canister_id;
            println!(
                "getting archived blocks using method {}",
                &archived.callback.method
            );
            let res = state_machine
                .query(
                    CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                    archived.callback.method.clone(),
                    req,
                )
                .expect("Failed to send get_blocks request to archive")
                .bytes();
            let res = Decode!(&res, BlockRange).unwrap();
            next_archived_txid += res.blocks.len() as u64;
            remaining -= res.blocks.len() as u32;
            blocks.extend(res.blocks);
        }
    }
    blocks.extend(res.blocks);
    // for block in &blocks {
    //     println!("found block: {:?}", block);
    //     let res: Result<ic_icrc1::Block<Tokens>, String> = ic_icrc1::Block::try_from(block.clone());
    //     match res {
    //         Ok(icrc1_block) => {
    //             println!("transaction: {:?}", icrc1_block.transaction);
    //         }
    //         Err(e) => {
    //             println!("error converting block: {:?}", e);
    //         }
    //     }
    // }
    blocks
        .into_iter()
        .map(ic_icrc1::Block::try_from)
        .collect::<Result<Vec<ic_icrc1::Block<Tokens>>, String>>()
        .expect("should convert generic blocks to ICRC1 blocks")
}
