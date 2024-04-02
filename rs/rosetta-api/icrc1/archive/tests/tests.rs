use candid::{Decode, Encode, Nat, Principal};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_ledger_core::block::BlockType;
use ic_state_machine_tests::{CanisterId, StateMachine};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::{
    ArchivedBlocks, BlockWithId, GetBlocksRequest, GetBlocksResult,
};
use std::{path::PathBuf, time::UNIX_EPOCH};

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

type Block = ic_icrc1::Block<Tokens>;
type Transaction = ic_icrc1::Transaction<Tokens>;
type Operation = ic_icrc1::Operation<Tokens>;

fn archive_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("archive"),
        "ic-icrc1-archive",
        &[],
    )
}

fn icrc3_get_blocks(
    env: &StateMachine,
    archive_id: CanisterId,
    arg: Vec<GetBlocksRequest>,
) -> GetBlocksResult {
    let payload = Encode!(&arg).unwrap();
    let res = env.query(archive_id, "icrc3_get_blocks", payload).unwrap();
    Decode!(&res.bytes(), GetBlocksResult).unwrap()
}

#[test]
fn test_icrc3_get_blocks() {
    let env = StateMachine::new();
    let payload = Encode!(
        /* The Principal that can send blocks to the archive */
        &Principal::anonymous(),
        /* block_index_offset */ &0u64,
        /* max_memory_size_bytes */ &None::<u64>,
        /* max_transactions_per_response */ &None::<u64>
    )
    .unwrap();
    let archive_id = env.install_canister(archive_wasm(), payload, None).unwrap();

    let block = |parent: Option<Block>, operation: Operation| -> Block {
        let parent_hash = parent.map(|block| Block::block_hash(&block.encode()));
        let timestamp = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        Block {
            parent_hash,
            effective_fee: None,
            timestamp,
            fee_collector: None,
            fee_collector_block_index: None,
            transaction: Transaction {
                operation,
                created_at_time: None,
                memo: None,
            },
        }
    };

    fn block_with_id(id: u64, block: Block) -> BlockWithId {
        let block = encoded_block_to_generic_block(&block.encode());
        BlockWithId {
            id: Nat::from(id),
            block: ICRC3Value::from(block),
        }
    }

    // add some blocks to the archive
    let block0 = block(
        None,
        Operation::Mint {
            to: Account::from(Principal::anonymous()),
            amount: Tokens::from(1_000_000_000u64),
        },
    );
    let blockid0 = block_with_id(0, block0.clone());
    let block1 = block(
        Some(block0.clone()),
        Operation::Transfer {
            from: Account::from(Principal::anonymous()),
            to: Account {
                owner: Principal::anonymous(),
                subaccount: Some([1; 32]),
            },
            amount: Tokens::from(1u64),
            fee: None,
            spender: None,
        },
    );
    let blockid1 = block_with_id(1, block1.clone());
    let block2 = block(
        Some(block1.clone()),
        Operation::Approve {
            from: Account::from(Principal::anonymous()),
            spender: Account {
                owner: Principal::anonymous(),
                subaccount: Some([1; 32]),
            },
            amount: Tokens::from(1_000_000u64),
            fee: None,
            expected_allowance: None,
            expires_at: None,
        },
    );
    let blockid2 = block_with_id(2, block2.clone());
    let block3 = block(
        Some(block2.clone()),
        Operation::Transfer {
            from: Account::from(Principal::anonymous()),
            spender: Some(Account {
                owner: Principal::anonymous(),
                subaccount: Some([1; 32]),
            }),
            to: Account {
                owner: Principal::anonymous(),
                subaccount: Some([1; 32]),
            },
            amount: Tokens::from(100_000u64),
            fee: None,
        },
    );
    let blockid3 = block_with_id(3, block3.clone());
    let blocks = vec![
        block0.encode(),
        block1.encode(),
        block2.encode(),
        block3.encode(),
    ];
    let blockids = vec![blockid0, blockid1, blockid2, blockid3];
    let payload = Encode!(&blocks).unwrap();
    let _ = env
        .execute_ingress(archive_id, "append_blocks", payload)
        .unwrap();

    let check_icrc3_get_blocks =
        |requested_start_lengths: Vec<(usize, usize)>,
         expected_start_lengths: Vec<(usize, usize)>| {
            let req = requested_start_lengths
                .into_iter()
                .map(|(start, length)| GetBlocksRequest {
                    start: Nat::from(start),
                    length: Nat::from(length),
                })
                .collect::<Vec<_>>();
            let blocks_found = icrc3_get_blocks(&env, archive_id, req);
            assert_eq!(blocks_found.log_length, 4u64);
            assert_eq!(blocks_found.archived_blocks, Vec::<ArchivedBlocks>::new());
            let mut expected = vec![];
            for (start, length) in expected_start_lengths {
                expected.push(&blockids[start..start + length]);
            }
            assert_eq!(&blocks_found.blocks, &expected.concat());
        };

    // query no ranges returns no blocks
    check_icrc3_get_blocks(vec![], vec![]);

    // query an empty ranges returns no blocks
    check_icrc3_get_blocks(vec![(0, 0)], vec![]);
    check_icrc3_get_blocks(vec![(0, 0), (0, 0)], vec![]);

    // // query the first block
    check_icrc3_get_blocks(vec![(0, 1)], vec![(0, 1)]);

    // query the second and third blocks
    check_icrc3_get_blocks(vec![(1, 3)], vec![(1, 3)]);

    // query all the blocks
    check_icrc3_get_blocks(vec![(0, 4)], vec![(0, 4)]);

    // query an empty range and a non-empty range
    check_icrc3_get_blocks(vec![(0, 0), (0, 1)], vec![(0, 1)]);
    check_icrc3_get_blocks(vec![(0, 1), (0, 0)], vec![(0, 1)]);
    check_icrc3_get_blocks(vec![(0, 0), (0, 1), (0, 0)], vec![(0, 1)]);

    // query the same range twice
    check_icrc3_get_blocks(vec![(1, 2), (1, 2)], vec![(1, 2), (1, 2)]);

    // query two different ranges
    check_icrc3_get_blocks(vec![(0, 1), (2, 2)], vec![(0, 1), (2, 2)]);

    // query out of range
    check_icrc3_get_blocks(vec![(4, 1)], vec![]);

    // query partially out of range
    check_icrc3_get_blocks(vec![(0, 100)], vec![(0, 4)]);
}
