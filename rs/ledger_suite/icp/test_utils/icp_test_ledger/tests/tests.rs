use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_test_ledger::AddBlockResult;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Tokens;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, Block, CandidBlock, GetBlocksArgs, Memo, Operation, QueryBlocksResponse,
    QueryEncodedBlocksResponse, Transaction,
};
use serde_bytes::ByteBuf;
use std::path::PathBuf;

fn icp_test_ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_utils/icp_test_ledger"),
        "ic-icp-test-ledger",
        &[],
    )
}

fn setup_icp_test_ledger() -> (StateMachine, CanisterId) {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(icp_test_ledger_wasm(), vec![], None)
        .unwrap();
    (env, canister_id)
}

fn add_block(env: &StateMachine, canister_id: CanisterId, block: &Block) -> Result<Nat, String> {
    // Convert Block to CandidBlock for the Candid interface
    let candid_block = CandidBlock::from(block.clone());
    let req = Encode!(&candid_block).expect("Failed to encode block");
    let res = env
        .execute_ingress(canister_id, "add_block", req)
        .expect("Failed to call add_block")
        .bytes();
    Decode!(&res, AddBlockResult).expect("Failed to decode AddBlockResult")
}

fn add_raw_block(
    env: &StateMachine,
    canister_id: CanisterId,
    encoded_block: &EncodedBlock,
) -> Result<Nat, String> {
    let blob: ByteBuf = ByteBuf::from(encoded_block.as_slice().to_vec());
    let req = Encode!(&blob).expect("Failed to encode blob");
    let res = env
        .execute_ingress(canister_id, "add_raw_block", req)
        .expect("Failed to call add_raw_block")
        .bytes();
    Decode!(&res, AddBlockResult).expect("Failed to decode AddBlockResult")
}

fn query_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    args: GetBlocksArgs,
) -> QueryBlocksResponse {
    let req = Encode!(&args).expect("Failed to encode GetBlocksArgs");
    let res = env
        .query(canister_id, "query_blocks", req)
        .expect("Failed to query blocks")
        .bytes();
    Decode!(&res, QueryBlocksResponse).expect("Failed to decode QueryBlocksResponse")
}

fn query_encoded_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    args: GetBlocksArgs,
) -> QueryEncodedBlocksResponse {
    let req = Encode!(&args).expect("Failed to encode GetBlocksArgs");
    let res = env
        .query(canister_id, "query_encoded_blocks", req)
        .expect("Failed to query encoded blocks")
        .bytes();
    Decode!(&res, QueryEncodedBlocksResponse).expect("Failed to decode QueryEncodedBlocksResponse")
}

fn create_test_account(id: u8) -> AccountIdentifier {
    AccountIdentifier::new(PrincipalId::new_user_test_id(id as u64), None)
}

fn create_mint_block(to: AccountIdentifier, amount: u64, timestamp: TimeStamp) -> Block {
    Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Mint {
                to,
                amount: Tokens::from_e8s(amount),
            },
            memo: Memo(0),
            icrc1_memo: None,
            created_at_time: Some(timestamp),
        },
        timestamp,
    }
}

fn create_transfer_block(
    from: AccountIdentifier,
    to: AccountIdentifier,
    amount: u64,
    fee: u64,
    timestamp: TimeStamp,
    parent_encoded: Option<EncodedBlock>,
) -> Block {
    let parent_hash = parent_encoded.as_ref().map(Block::block_hash);
    Block {
        parent_hash,
        transaction: Transaction {
            operation: Operation::Transfer {
                from,
                to,
                amount: Tokens::from_e8s(amount),
                fee: Tokens::from_e8s(fee),
                spender: None,
            },
            memo: Memo(0),
            icrc1_memo: None,
            created_at_time: Some(timestamp),
        },
        timestamp,
    }
}

#[test]
fn test_basic_add_and_query_blocks() {
    let (env, canister_id) = setup_icp_test_ledger();

    let account1 = create_test_account(1);
    let timestamp = TimeStamp::from_nanos_since_unix_epoch(1_000_000_000);

    // Create and add a mint block
    let mint_block = create_mint_block(account1, 1_000_000_000, timestamp);
    let result = add_block(&env, canister_id, &mint_block).expect("Failed to add block");
    assert_eq!(result, Nat::from(0u64));

    // Query blocks
    let response = query_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 0,
            length: 1,
        },
    );

    assert_eq!(response.chain_length, 1);
    assert_eq!(response.blocks.len(), 1);
    assert_eq!(response.first_block_index, 0);
    assert!(response.archived_blocks.is_empty());

    // Verify the block content
    let returned_block = &response.blocks[0];
    assert_eq!(returned_block.timestamp, timestamp);
    match &returned_block.transaction.operation {
        Some(icp_ledger::CandidOperation::Mint { to, amount }) => {
            assert_eq!(*to, account1.to_address());
            assert_eq!(amount.get_e8s(), 1_000_000_000);
        }
        _ => panic!("Expected Mint operation"),
    }
}

#[test]
fn test_add_raw_block_and_query_encoded_blocks() {
    let (env, canister_id) = setup_icp_test_ledger();

    let account1 = create_test_account(1);
    let timestamp = TimeStamp::from_nanos_since_unix_epoch(1_000_000_000);

    // Create a block and encode it
    let block = create_mint_block(account1, 1_000_000_000, timestamp);
    let encoded_block = block.encode();

    // Add the encoded block
    let result = add_raw_block(&env, canister_id, &encoded_block).expect("Failed to add raw block");
    assert_eq!(result, Nat::from(0u64));

    // Query encoded blocks
    let response = query_encoded_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 0,
            length: 1,
        },
    );

    assert_eq!(response.chain_length, 1);
    assert_eq!(response.blocks.len(), 1);
    assert_eq!(response.first_block_index, 0);
    assert!(response.archived_blocks.is_empty());

    // Verify we can decode the returned block
    let returned_encoded = EncodedBlock::from_vec(response.blocks[0].clone().into_vec());
    let decoded_block =
        Block::decode(returned_encoded).expect("Failed to decode returned encoded block");
    assert_eq!(decoded_block.timestamp, timestamp);
}

#[test]
#[should_panic(expected = "bug: failed to decode encoded block")]
fn test_add_raw_bad_block_and_query_blocks() {
    let (env, canister_id) = setup_icp_test_ledger();

    // Add an encoded bad block
    let bad_encoded_block = EncodedBlock::from_vec(vec![0, 1, 2, 3, 4, 5]); // Invalid block data
    let result =
        add_raw_block(&env, canister_id, &bad_encoded_block).expect("Failed to add raw block");
    assert_eq!(result, Nat::from(0u64));

    // Query the bad block
    query_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 0,
            length: 1,
        },
    );
}

#[test]
fn test_query_blocks_with_different_ranges() {
    let (env, canister_id) = setup_icp_test_ledger();

    let account1 = create_test_account(1);
    let account2 = create_test_account(2);
    let base_timestamp = TimeStamp::from_nanos_since_unix_epoch(1_000_000_000);

    // Add 5 blocks
    for i in 0..5 {
        let timestamp = TimeStamp::from_nanos_since_unix_epoch(
            base_timestamp.as_nanos_since_unix_epoch() + i * 1_000_000,
        );
        let block = if i == 0 {
            create_mint_block(account1, 1_000_000_000, timestamp)
        } else {
            create_transfer_block(account1, account2, 100_000, 10_000, timestamp, None)
        };
        add_block(&env, canister_id, &block).expect("Failed to add block");
    }

    // Test getting first 2 blocks
    let response = query_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 0,
            length: 2,
        },
    );
    assert_eq!(response.blocks.len(), 2);
    assert_eq!(response.first_block_index, 0);

    // Test getting blocks 2-4
    let response = query_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 2,
            length: 3,
        },
    );
    assert_eq!(response.blocks.len(), 3);
    assert_eq!(response.first_block_index, 2);

    // Test getting non-existent blocks
    let response = query_blocks(
        &env,
        canister_id,
        GetBlocksArgs {
            start: 10,
            length: 2,
        },
    );
    assert_eq!(response.blocks.len(), 0);
    assert_eq!(response.chain_length, 5);
}

#[test]
fn test_archives_endpoint() {
    let (env, canister_id) = setup_icp_test_ledger();

    let req = Encode!().expect("Failed to encode empty args");
    let res = env
        .query(canister_id, "archives", req)
        .expect("Failed to query archives")
        .bytes();
    let archives: icp_ledger::Archives =
        Decode!(&res, icp_ledger::Archives).expect("Failed to decode Archives");
    assert!(archives.archives.is_empty());
}
