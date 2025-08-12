use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc3_test_ledger::AddBlockResult;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::path::PathBuf;

const TEST_USER_1: PrincipalId = PrincipalId::new_user_test_id(1);
const TEST_USER_2: PrincipalId = PrincipalId::new_user_test_id(2);

fn icrc3_test_ledger_wasm() -> Vec<u8> {
    load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("icrc3_test_ledger"),
        "icrc3_test_ledger_canister",
        &[],
    )
}

fn setup_icrc3_test_ledger() -> (StateMachine, CanisterId) {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();
    (env, canister_id)
}

fn add_block(
    env: &StateMachine,
    canister_id: CanisterId,
    block: ICRC3Value,
) -> Result<Nat, String> {
    let result = Decode!(
        &env.execute_ingress(canister_id, "add_block", Encode!(&block).unwrap())
            .expect("failed to add block")
            .bytes(),
        AddBlockResult
    )
    .expect("failed to decode add_block response");

    result
}

fn icrc3_get_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    requests: Vec<GetBlocksRequest>,
) -> GetBlocksResult {
    Decode!(
        &env.query(canister_id, "icrc3_get_blocks", Encode!(&requests).unwrap())
            .expect("failed to get blocks")
            .bytes(),
        GetBlocksResult
    )
    .expect("failed to decode icrc3_get_blocks response")
}

fn create_test_transfer_block(block_id: u64, amount: u64, timestamp: u64) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("xfer".to_string()));

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(TEST_USER_1))]),
    );
    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(TEST_USER_2))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

fn create_test_mint_block(block_id: u64, amount: u64, timestamp: u64) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("mint".to_string()));

    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(TEST_USER_1))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

#[test]
fn test_basic_add_and_get_blocks() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Create some test blocks
    let block0 = create_test_mint_block(0, 1_000_000, 1000);
    let block1 = create_test_transfer_block(1, 100_000, 2000);
    let block2 = create_test_mint_block(2, 500_000, 3000);

    // Add blocks to the ledger
    let result0 = add_block(&env, canister_id, block0.clone()).expect("Failed to add block 0");
    assert_eq!(result0, Nat::from(0u64));

    let result1 = add_block(&env, canister_id, block1.clone()).expect("Failed to add block 1");
    assert_eq!(result1, Nat::from(1u64));

    let result2 = add_block(&env, canister_id, block2.clone()).expect("Failed to add block 2");
    assert_eq!(result2, Nat::from(2u64));

    // Test retrieving blocks
    let get_blocks_result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(3u64),
        }],
    );

    assert_eq!(get_blocks_result.log_length, Nat::from(3u64));
    assert_eq!(get_blocks_result.blocks.len(), 3);
    assert!(get_blocks_result.archived_blocks.is_empty());

    // Verify the blocks are returned in the correct order
    assert_eq!(get_blocks_result.blocks[0].id, Nat::from(0u64));
    assert_eq!(get_blocks_result.blocks[0].block, block0);

    assert_eq!(get_blocks_result.blocks[1].id, Nat::from(1u64));
    assert_eq!(get_blocks_result.blocks[1].block, block1);

    assert_eq!(get_blocks_result.blocks[2].id, Nat::from(2u64));
    assert_eq!(get_blocks_result.blocks[2].block, block2);
}

#[test]
fn test_get_blocks_with_different_ranges() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Add 5 blocks
    let mut added_blocks = Vec::new();
    for i in 0..5 {
        let block = create_test_transfer_block(i, 1000 + i * 100, 1000 + i * 1000);
        add_block(&env, canister_id, block.clone()).expect("Failed to add block");
        added_blocks.push(block);
    }

    // Test getting first 2 blocks
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(2u64),
        }],
    );
    assert_eq!(result.blocks.len(), 2);
    assert_eq!(result.blocks[0].id, Nat::from(0u64));
    assert_eq!(result.blocks[1].id, Nat::from(1u64));

    // Test getting blocks 2-4
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(2u64),
            length: Nat::from(3u64),
        }],
    );
    assert_eq!(result.blocks.len(), 3);
    assert_eq!(result.blocks[0].id, Nat::from(2u64));
    assert_eq!(result.blocks[1].id, Nat::from(3u64));
    assert_eq!(result.blocks[2].id, Nat::from(4u64));

    // Test getting non-existent blocks
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(10u64),
            length: Nat::from(2u64),
        }],
    );
    assert_eq!(result.blocks.len(), 0);
    assert_eq!(result.log_length, Nat::from(5u64));
}

#[test]
fn test_get_blocks_with_multiple_requests() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Add 5 blocks
    for i in 0..5 {
        let block = create_test_transfer_block(i, 1000 + i * 100, 1000 + i * 1000);
        add_block(&env, canister_id, block).expect("Failed to add block");
    }

    // Test multiple requests in a single call
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![
            GetBlocksRequest {
                start: Nat::from(0u64),
                length: Nat::from(2u64),
            },
            GetBlocksRequest {
                start: Nat::from(3u64),
                length: Nat::from(2u64),
            },
        ],
    );

    // Should return 4 blocks total (blocks 0, 1, 3, 4)
    assert_eq!(result.blocks.len(), 4);
    assert_eq!(result.blocks[0].id, Nat::from(0u64));
    assert_eq!(result.blocks[1].id, Nat::from(1u64));
    assert_eq!(result.blocks[2].id, Nat::from(3u64));
    assert_eq!(result.blocks[3].id, Nat::from(4u64));
}

#[test]
fn test_get_blocks_empty_request() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Test getting blocks when no blocks exist
    let result = icrc3_get_blocks(&env, canister_id, vec![]);
    assert_eq!(result.blocks.len(), 0);
    assert_eq!(result.log_length, Nat::from(0u64));

    // Add a block
    let block = create_test_mint_block(0, 1_000_000, 1000);
    add_block(&env, canister_id, block).expect("Failed to add block");

    // Test empty request with blocks present
    let result = icrc3_get_blocks(&env, canister_id, vec![]);
    assert_eq!(result.blocks.len(), 0);
    assert_eq!(result.log_length, Nat::from(1u64));
}

#[test]
fn test_get_blocks_zero_length() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Add a block
    let block = create_test_mint_block(0, 1_000_000, 1000);
    add_block(&env, canister_id, block).expect("Failed to add block");

    // Test zero-length request
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(0u64),
        }],
    );
    assert_eq!(result.blocks.len(), 0);
    assert_eq!(result.log_length, Nat::from(1u64));
}

#[test]
fn test_add_complex_block() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Create a complex block with multiple fields
    let mut block_map = BTreeMap::new();
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(1000u64)));
    block_map.insert("fee".to_string(), ICRC3Value::Nat(Nat::from(10000u64)));

    // Add a complex transaction with memo
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("xfer".to_string()));
    tx_map.insert(
        "memo".to_string(),
        ICRC3Value::Blob(ByteBuf::from(b"test memo".to_vec())),
    );

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(TEST_USER_1))]),
    );
    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(TEST_USER_2))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(500000u64)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    let complex_block = ICRC3Value::Map(block_map);

    // Add the complex block
    let result =
        add_block(&env, canister_id, complex_block.clone()).expect("Failed to add complex block");
    assert_eq!(result, Nat::from(0u64));

    // Retrieve and verify the complex block
    let get_result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(1u64),
        }],
    );

    assert_eq!(get_result.blocks.len(), 1);
    assert_eq!(get_result.blocks[0].block, complex_block);
}
