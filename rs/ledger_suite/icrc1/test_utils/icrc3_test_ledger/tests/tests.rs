use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::Tokens;
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_icrc3_test_ledger::AddBlockResult;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::path::PathBuf;

const TEST_USER_1: PrincipalId = PrincipalId::new_user_test_id(1);
const TEST_USER_2: PrincipalId = PrincipalId::new_user_test_id(2);
const TEST_ACCOUNT_1: Account = Account {
    owner: TEST_USER_1.0,
    subaccount: None,
};
const TEST_ACCOUNT_2: Account = Account {
    owner: TEST_USER_2.0,
    subaccount: None,
};

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
    block: &ICRC3Value,
) -> Result<Nat, String> {
    let result = Decode!(
        &env.execute_ingress(canister_id, "add_block", Encode!(block).unwrap())
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

#[test]
fn test_basic_add_and_get_blocks() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Create some test blocks
    let block0 = BlockBuilder::new(0, 1000)
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000))
        .build();
    let block1 = BlockBuilder::new(1, 2000)
        .transfer(TEST_ACCOUNT_1, TEST_ACCOUNT_2, Tokens::from(100_000))
        .build();
    let block2 = BlockBuilder::new(2, 3000)
        .mint(TEST_ACCOUNT_1, Tokens::from(500_000))
        .build();
    let block3 = BlockBuilder::new(3, 4000)
        .burn(TEST_ACCOUNT_1, Tokens::from(50_000))
        .build();

    // Add blocks to the ledger
    let result0 = add_block(&env, canister_id, &block0).expect("Failed to add block 0");
    assert_eq!(result0, Nat::from(0u64));

    let result1 = add_block(&env, canister_id, &block1).expect("Failed to add block 1");
    assert_eq!(result1, Nat::from(1u64));

    let result2 = add_block(&env, canister_id, &block2).expect("Failed to add block 2");
    assert_eq!(result2, Nat::from(2u64));

    let result3 = add_block(&env, canister_id, &block3).expect("Failed to add block 3");
    assert_eq!(result3, Nat::from(3u64));

    // Test retrieving blocks
    let get_blocks_result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(4u64),
        }],
    );

    assert_eq!(get_blocks_result.log_length, Nat::from(4u64));
    assert_eq!(get_blocks_result.blocks.len(), 4);
    assert!(get_blocks_result.archived_blocks.is_empty());

    // Verify the blocks are returned in the correct order
    assert_eq!(get_blocks_result.blocks[0].id, Nat::from(0u64));
    assert_eq!(get_blocks_result.blocks[0].block, block0);

    assert_eq!(get_blocks_result.blocks[1].id, Nat::from(1u64));
    assert_eq!(get_blocks_result.blocks[1].block, block1);

    assert_eq!(get_blocks_result.blocks[2].id, Nat::from(2u64));
    assert_eq!(get_blocks_result.blocks[2].block, block2);

    assert_eq!(get_blocks_result.blocks[3].id, Nat::from(3u64));
    assert_eq!(get_blocks_result.blocks[3].block, block3);
}

#[test]
fn test_get_blocks_with_different_ranges() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Add 5 blocks
    let mut added_blocks = Vec::new();
    for i in 0..5 {
        let block = BlockBuilder::new(i, 1000 + i * 1000)
            .transfer(TEST_ACCOUNT_1, TEST_ACCOUNT_2, Tokens::from(1000 + i * 100))
            .build();
        add_block(&env, canister_id, &block).expect("Failed to add block");
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
        let block = BlockBuilder::new(i, 1000 + i * 1000)
            .transfer(TEST_ACCOUNT_1, TEST_ACCOUNT_2, Tokens::from(1000 + i * 100))
            .build();
        add_block(&env, canister_id, &block).expect("Failed to add block");
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
    let block = BlockBuilder::new(0, 1000)
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000))
        .build();
    add_block(&env, canister_id, &block).expect("Failed to add block");

    // Test empty request with blocks present
    let result = icrc3_get_blocks(&env, canister_id, vec![]);
    assert_eq!(result.blocks.len(), 0);
    assert_eq!(result.log_length, Nat::from(1u64));
}

#[test]
fn test_get_blocks_zero_length() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Add a block
    let block = BlockBuilder::new(0, 1000)
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000))
        .build();
    add_block(&env, canister_id, &block).expect("Failed to add block");

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
    let result = add_block(&env, canister_id, &complex_block).expect("Failed to add complex block");
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

fn production_ledger_wasm() -> Vec<u8> {
    std::fs::read(
        std::env::var("IC_ICRC1_LEDGER_WASM_PATH")
            .expect("IC_ICRC1_LEDGER_WASM_PATH environment variable not set"),
    )
    .expect("failed to read production ledger wasm")
}

#[test]
fn test_icrc3_blocks_compatibility_with_production_ledger() {
    use ic_ledger_suite_state_machine_tests::test_icrc3_blocks_compatibility_with_production_ledger;
    use ic_ledger_suite_state_machine_tests::InitArgs;

    fn encode_init_args(args: InitArgs) -> ic_icrc1_ledger::LedgerArgument {
        use ic_icrc1_ledger::{
            InitArgs as ProductionInitArgs, LedgerArgument as ProductionLedgerArgument,
        };

        ProductionLedgerArgument::Init(ProductionInitArgs {
            minting_account: args.minting_account,
            fee_collector_account: args.fee_collector_account,
            initial_balances: args.initial_balances,
            transfer_fee: args.transfer_fee,
            token_name: args.token_name,
            decimals: args.decimals,
            token_symbol: args.token_symbol,
            metadata: args.metadata,
            archive_options: args.archive_options,
            max_memo_length: None,
            feature_flags: None,
            index_principal: args.index_principal,
        })
    }

    test_icrc3_blocks_compatibility_with_production_ledger(
        production_ledger_wasm(),
        encode_init_args,
        icrc3_test_ledger_wasm(),
    );
}
