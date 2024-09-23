use candid::{Decode, Encode, Nat, Principal};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_rosetta_test_utils::test_http_request_decoding_quota;
use ic_state_machine_tests::{CanisterId, StateMachine, WasmResult};
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

struct Setup {
    state_machine: StateMachine,
    archive_id: CanisterId,
}

impl Setup {
    fn new(
        /* The Principal that can send blocks to the archive */
        archiver_id: &Principal,
        block_index_offset: &u64,
        max_memory_size_bytes: &Option<u64>,
        max_transactions_per_response: &Option<u64>,
    ) -> Self {
        let state_machine = StateMachine::new();
        let payload = Encode!(
            archiver_id,
            block_index_offset,
            max_memory_size_bytes,
            max_transactions_per_response
        )
        .unwrap();
        let archive_id = state_machine
            .install_canister(archive_wasm(), payload, None)
            .unwrap();
        Self {
            state_machine,
            archive_id,
        }
    }

    fn nanos_since_epoch(&self) -> u64 {
        self.state_machine
            .time()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn append_blocks(&self, blocks: Vec<EncodedBlock>) -> WasmResult {
        let payload = Encode!(&blocks).unwrap();
        self.state_machine
            .execute_ingress(self.archive_id, "append_blocks", payload)
            .unwrap()
    }

    fn icrc3_get_blocks(&self, arg: Vec<GetBlocksRequest>) -> GetBlocksResult {
        let payload = Encode!(&arg).unwrap();
        let res = self
            .state_machine
            .query(self.archive_id, "icrc3_get_blocks", payload)
            .unwrap();
        Decode!(&res.bytes(), GetBlocksResult).unwrap()
    }
}

impl Default for Setup {
    fn default() -> Self {
        Self::new(&Principal::anonymous(), &0u64, &None, &None)
    }
}

#[test]
fn test_icrc3_get_blocks() {
    let setup = Setup::default();

    let block = |parent: Option<Block>, operation: Operation| -> Block {
        let parent_hash = parent.map(|block| Block::block_hash(&block.encode()));
        let timestamp = setup.nanos_since_epoch();
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
    let _ = setup.append_blocks(blocks);

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
            let blocks_found = setup.icrc3_get_blocks(req);
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

#[test]
fn test_icrc3_get_blocks_number_of_blocks_limit() {
    // add 101 blocks to archive and checks that
    // icrc3_get_blocks returns at most 100 blocks
    // even with multiple ranges.

    let setup = Setup::default();
    fn new_encoded_block(amount: usize) -> EncodedBlock {
        // create a mint block with amount set to the parameter
        Block {
            parent_hash: None,
            effective_fee: None,
            timestamp: 0,
            fee_collector: None,
            fee_collector_block_index: None,
            transaction: Transaction {
                operation: Operation::Mint {
                    to: Account::from(Principal::anonymous()),
                    amount: Tokens::from(amount as u64),
                },
                created_at_time: None,
                memo: None,
            },
        }
        .encode()
    }
    let encoded_blocks = (0..101).map(new_encoded_block).collect::<Vec<_>>();
    let _ = setup.append_blocks(encoded_blocks.clone());

    let blocks = encoded_blocks
        .into_iter()
        .enumerate()
        .map(|(id, encoded_block)| BlockWithId {
            id: Nat::from(id),
            block: ICRC3Value::from(encoded_block_to_generic_block(&encoded_block)),
        })
        .collect::<Vec<_>>();

    let check_icrc3_get_blocks =
        |requested_start_lengths: Vec<(usize, usize)>,
         expected_start_lengths: Vec<(usize, usize)>| {
            let req = requested_start_lengths
                .iter()
                .map(|(start, length)| GetBlocksRequest {
                    start: Nat::from(*start),
                    length: Nat::from(*length),
                })
                .collect::<Vec<_>>();
            let blocks_found = setup.icrc3_get_blocks(req);
            assert_eq!(
                blocks_found.log_length, 101u64,
                "{requested_start_lengths:?}"
            );
            assert_eq!(
                blocks_found.archived_blocks,
                Vec::<ArchivedBlocks>::new(),
                "{requested_start_lengths:?}"
            );
            let mut expected_blocks = vec![];
            for (start, length) in expected_start_lengths {
                expected_blocks.push(&blocks[start..start + length]);
            }
            let expected_blocks = expected_blocks.concat();
            assert_eq!(blocks_found.blocks.len(), expected_blocks.len());
            for (id, (block_found, block_expected)) in blocks_found
                .blocks
                .into_iter()
                .zip(expected_blocks)
                .enumerate()
            {
                assert_eq!(
                    block_found, block_expected,
                    "{requested_start_lengths:?} {id}"
                );
            }
        };

    // max blocks returned should be 100
    check_icrc3_get_blocks(vec![(0, 1)], vec![(0, 1)]);
    check_icrc3_get_blocks(vec![(1, 1)], vec![(1, 1)]);
    check_icrc3_get_blocks(vec![(50, 1)], vec![(50, 1)]);
    check_icrc3_get_blocks(vec![(99, 1)], vec![(99, 1)]);
    check_icrc3_get_blocks(vec![(0, 10)], vec![(0, 10)]);
    check_icrc3_get_blocks(vec![(1, 10)], vec![(1, 10)]);
    check_icrc3_get_blocks(vec![(50, 10)], vec![(50, 10)]);
    check_icrc3_get_blocks(vec![(90, 10)], vec![(90, 10)]);
    check_icrc3_get_blocks(vec![(0, 50)], vec![(0, 50)]);
    check_icrc3_get_blocks(vec![(1, 50)], vec![(1, 50)]);
    check_icrc3_get_blocks(vec![(50, 50)], vec![(50, 50)]);
    check_icrc3_get_blocks(vec![(0, 99)], vec![(0, 99)]);
    check_icrc3_get_blocks(vec![(0, 100)], vec![(0, 100)]);
    check_icrc3_get_blocks(vec![(0, 101)], vec![(0, 100)]);
    check_icrc3_get_blocks(vec![(1, 102)], vec![(1, 100)]);
    check_icrc3_get_blocks(vec![(0, 101), (0, 101)], vec![(0, 100)]);
    check_icrc3_get_blocks(
        vec![(0, 101), (0, 101), (1, 101), (100, 101)],
        vec![(0, 100)],
    );
    check_icrc3_get_blocks(vec![(0, 10), (20, 10)], vec![(0, 10), (20, 10)]);
    check_icrc3_get_blocks(vec![(0, 10), (5, 10)], vec![(0, 10), (5, 10)]);
}

#[test]
fn test_archive_http_request_decoding_quota() {
    let setup = Setup::default();

    test_http_request_decoding_quota(&setup.state_machine, setup.archive_id);
}
