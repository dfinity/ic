use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cbor::CertificateToCbor;
use ic_certification::{
    Certificate, HashTree,
    hash_tree::{HashTreeNode, Label, LookupResult, SubtreeLookupResult, empty},
};
use ic_icrc1::endpoints::StandardRecord;
use ic_icrc1_index_ng::{IndexArg, InitArg};
use ic_icrc1_ledger::Tokens;
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_ledger_suite_state_machine_helpers::{
    add_block, archive_blocks, balance_of, icrc3_get_blocks as icrc3_get_blocks_helper,
    set_icrc3_enabled,
};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate;
use icrc_ledger_types::icrc3::blocks::{
    BlockWithId, GetBlocksRequest, GetBlocksResponse, GetBlocksResult,
};
use num_traits::cast::ToPrimitive;
use serde_bytes::ByteBuf;
use std::path::PathBuf;
use std::{collections::BTreeMap, time::Duration};

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

pub fn index_ng_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_INDEX_NG_WASM_PATH").unwrap()).unwrap()
}

fn setup_icrc3_test_ledger() -> (StateMachine, CanisterId) {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();
    (env, canister_id)
}

fn icrc3_get_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    requests: Vec<GetBlocksRequest>,
) -> GetBlocksResult {
    let result = Decode!(
        &env.query(canister_id, "icrc3_get_blocks", Encode!(&requests).unwrap())
            .expect("failed to get blocks")
            .bytes(),
        GetBlocksResult
    )
    .expect("failed to decode icrc3_get_blocks response");
    if requests.len() == 1 {
        check_legacy_get_blocks(env, canister_id, &result, &requests[0]);
    }
    result
}

fn get_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    request: &GetBlocksRequest,
) -> GetBlocksResponse {
    Decode!(
        &env.query(canister_id, "get_blocks", Encode!(request).unwrap())
            .expect("failed to get blocks")
            .bytes(),
        GetBlocksResponse
    )
    .expect("failed to decode icrc3_get_blocks response")
}

fn check_legacy_get_blocks(
    env: &StateMachine,
    canister_id: CanisterId,
    result: &GetBlocksResult,
    request: &GetBlocksRequest,
) {
    let legacy_response = get_blocks(env, canister_id, request);

    assert_eq!(result.log_length, legacy_response.chain_length);
    assert_eq!(result.archived_blocks, vec![]);
    assert_eq!(legacy_response.archived_blocks, vec![]);

    let mut legacy_response_blocks = vec![];
    let start = legacy_response.first_index.0.to_u64().unwrap();
    for (index, value) in legacy_response.blocks.iter().enumerate() {
        legacy_response_blocks.push(BlockWithId {
            id: Nat::from(start + index as u64),
            block: ICRC3Value::from(value.clone()),
        });
    }
    assert_eq!(result.blocks, legacy_response_blocks);
}

#[test]
fn test_basic_add_and_get_blocks() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // Create some test blocks
    let block0 = BlockBuilder::new(0, 1000)
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000u64))
        .build();
    let block1 = BlockBuilder::new(1, 2000)
        .transfer(TEST_ACCOUNT_1, TEST_ACCOUNT_2, Tokens::from(100_000u64))
        .build();
    let block2 = BlockBuilder::new(2, 3000)
        .mint(TEST_ACCOUNT_1, Tokens::from(500_000u64))
        .build();
    let block3 = BlockBuilder::new(3, 4000)
        .burn(TEST_ACCOUNT_1, Tokens::from(50_000u64))
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
            .transfer(
                TEST_ACCOUNT_1,
                TEST_ACCOUNT_2,
                Tokens::from(1000u64 + i * 100u64),
            )
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
            .transfer(
                TEST_ACCOUNT_1,
                TEST_ACCOUNT_2,
                Tokens::from(1000u64 + i * 100u64),
            )
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

    // Test multiple requests with overlapping ranges
    let result = icrc3_get_blocks(
        &env,
        canister_id,
        vec![
            // Request blocks 1, 2, 3
            GetBlocksRequest {
                start: Nat::from(1u64),
                length: Nat::from(3u64),
            },
            // Request blocks 2, 3
            GetBlocksRequest {
                start: Nat::from(2u64),
                length: Nat::from(2u64),
            },
        ],
    );

    // Should return blocks 1, 2, 3, 2, 3 (two blocks twice)
    assert_eq!(result.blocks.len(), 5);
    assert_eq!(result.blocks[0].id, Nat::from(1u64));
    assert_eq!(result.blocks[1].id, Nat::from(2u64));
    assert_eq!(result.blocks[2].id, Nat::from(3u64));
    assert_eq!(result.blocks[3].id, Nat::from(2u64));
    assert_eq!(result.blocks[4].id, Nat::from(3u64));
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
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000u64))
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
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000u64))
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
    use ic_ledger_suite_state_machine_tests::InitArgs;
    use ic_ledger_suite_state_machine_tests::test_icrc3_blocks_compatibility_with_production_ledger;

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

fn get_icrc3_get_tip_certificate(
    env: &StateMachine,
    canister_id: CanisterId,
) -> Option<ICRC3DataCertificate> {
    Decode!(
        &env.query(
            canister_id,
            "icrc3_get_tip_certificate",
            Encode!(&()).unwrap()
        )
        .expect("failed to get tip certificate")
        .bytes(),
        Option<ICRC3DataCertificate>
    )
    .expect("failed to decode tip certificate response")
}

fn lookup_hashtree(hash_tree: &HashTree, leaf_name: &str) -> Result<Vec<u8>, String> {
    match hash_tree.lookup_subtree([leaf_name.as_bytes()]) {
        SubtreeLookupResult::Found(tree) => match tree.as_ref() {
            HashTreeNode::Leaf(result) => Ok(result.clone()),
            _ => Err("Expected a leaf node".to_string()),
        },
        _ => Err(format!(
            "Expected to find a leaf node: Hash tree: {hash_tree:?}, leaf_name: {leaf_name}"
        )
        .to_string()),
    }
}

fn check_tip_certificate(
    cert: ICRC3DataCertificate,
    canister_id: CanisterId,
    block_index_and_hash: Option<(u64, Vec<u8>)>,
) {
    let certified_data_path: [Label<Vec<u8>>; 3] = [
        "canister".into(),
        canister_id.get().0.as_slice().into(),
        "certified_data".into(),
    ];
    let certificate = Certificate::from_cbor(cert.certificate.as_slice()).unwrap();
    let certified_data = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(v) => v,
        _ => panic!("could not find certified data in certificate"),
    };

    let hash_tree: HashTree = ciborium::de::from_reader(cert.hash_tree.as_slice()).unwrap();

    assert_eq!(certified_data, hash_tree.digest());

    match block_index_and_hash {
        None => assert_eq!(hash_tree, empty()),
        Some((block_index, block_hash)) => {
            let tree_block_index = leb128::read::unsigned(&mut std::io::Cursor::new(
                lookup_hashtree(&hash_tree, "last_block_index").unwrap(),
            ))
            .unwrap();
            assert_eq!(tree_block_index, block_index);

            let tree_block_hash = lookup_hashtree(&hash_tree, "last_block_hash").unwrap();
            assert_eq!(tree_block_hash, block_hash);
        }
    }
}

#[test]
fn test_icrc3_get_tip_certificate() {
    let (env, canister_id) = setup_icrc3_test_ledger();
    // Check the certificate for empty ledger.
    let cert = get_icrc3_get_tip_certificate(&env, canister_id).unwrap();
    check_tip_certificate(cert, canister_id, None);

    // Create some test blocks, we only care that they are different.
    let block0 = BlockBuilder::new(0, 1000)
        .mint(TEST_ACCOUNT_1, Tokens::from(1_000_000u64))
        .build();
    let block1 = BlockBuilder::new(1, 2000)
        .transfer(TEST_ACCOUNT_1, TEST_ACCOUNT_2, Tokens::from(100_000u64))
        .build();
    assert_ne!(block0.clone().hash(), block1.clone().hash());

    // Add block and check if it is reflected in the certificate.
    let result0 = add_block(&env, canister_id, &block0).expect("Failed to add block 0");
    assert_eq!(result0, Nat::from(0u64));
    let cert = get_icrc3_get_tip_certificate(&env, canister_id).unwrap();
    check_tip_certificate(cert, canister_id, Some((0, block0.clone().hash().to_vec())));

    // Add another block and check if it is reflected in the certificate.
    let result1 = add_block(&env, canister_id, &block1).expect("Failed to add block 1");
    assert_eq!(result1, Nat::from(1u64));
    let cert = get_icrc3_get_tip_certificate(&env, canister_id).unwrap();
    check_tip_certificate(cert, canister_id, Some((1, block1.clone().hash().to_vec())));
}

fn get_supported_standards(env: &StateMachine, canister_id: CanisterId) -> Vec<StandardRecord> {
    Decode!(
        &env.query(
            canister_id,
            "icrc1_supported_standards",
            Encode!(&()).unwrap()
        )
        .expect("failed to get supported standards")
        .bytes(),
        Vec<StandardRecord>
    )
    .expect("failed to decode icrc1_supported_standards response")
}

#[test]
fn test_supported_standards() {
    let (env, canister_id) = setup_icrc3_test_ledger();

    // By default icrc3 should be enabled
    let standards = get_supported_standards(&env, canister_id);
    assert_eq!(standards.len(), 2);
    assert_eq!(standards[0].name, "ICRC-3");
    assert_eq!(standards[1].name, "ICRC-10");

    set_icrc3_enabled(&env, canister_id, false);
    let standards = get_supported_standards(&env, canister_id);
    assert_eq!(standards.len(), 1);
    assert_eq!(standards[0].name, "ICRC-10");

    set_icrc3_enabled(&env, canister_id, true);
    let standards = get_supported_standards(&env, canister_id);
    assert_eq!(standards.len(), 2);
    assert_eq!(standards[0].name, "ICRC-3");
    assert_eq!(standards[1].name, "ICRC-10");
}

fn verify_blocks_in_ledger(env: &StateMachine, canister_id: CanisterId, start: u64, length: u64) {
    let result = icrc3_get_blocks_helper(env, canister_id, 0, usize::MAX);
    if length == 0 {
        assert!(result.blocks.is_empty());
    } else {
        assert_eq!(result.blocks.first().unwrap().id, start);
        assert_eq!(result.blocks.last().unwrap().id, start + length - 1);
    }
}

#[test]
fn test_archiving() {
    let (env, ledger_id) = setup_icrc3_test_ledger();

    const NUM_BLOCKS: u32 = 20;

    for block_id in 0..NUM_BLOCKS {
        let block = BlockBuilder::new(block_id as u64, block_id as u64)
            .mint(TEST_ACCOUNT_1, Tokens::from(2u64.pow(block_id)))
            .build();
        let result = add_block(&env, ledger_id, &block).expect("Failed to add block");
        assert_eq!(result, Nat::from(block_id));
    }

    verify_blocks_in_ledger(&env, ledger_id, 0, 20);

    let archive1 = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();

    let archived_count = archive_blocks(&env, ledger_id, archive1, 2);
    assert_eq!(archived_count, 2);
    env.advance_time(Duration::from_secs(60));
    env.tick();

    verify_blocks_in_ledger(&env, archive1, 0, 2);
    verify_blocks_in_ledger(&env, ledger_id, 2, 18);

    let archive2 = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();

    let archived_count = archive_blocks(&env, ledger_id, archive2, 2);
    assert_eq!(archived_count, 2);
    env.advance_time(Duration::from_secs(60));
    env.tick();

    verify_blocks_in_ledger(&env, archive1, 0, 2);
    verify_blocks_in_ledger(&env, archive2, 2, 2);
    verify_blocks_in_ledger(&env, ledger_id, 4, 16);

    let archived_count = archive_blocks(&env, ledger_id, archive2, 2);
    assert_eq!(archived_count, 2);
    env.advance_time(Duration::from_secs(60));
    env.tick();

    verify_blocks_in_ledger(&env, archive1, 0, 2);
    verify_blocks_in_ledger(&env, archive2, 2, 4);
    verify_blocks_in_ledger(&env, ledger_id, 6, 14);

    let archive3 = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();

    let archived_count = archive_blocks(&env, ledger_id, archive3, 10);
    assert_eq!(archived_count, 10);
    env.advance_time(Duration::from_secs(60));
    env.tick();

    verify_blocks_in_ledger(&env, archive1, 0, 2);
    verify_blocks_in_ledger(&env, archive2, 2, 4);
    verify_blocks_in_ledger(&env, archive3, 6, 10);
    verify_blocks_in_ledger(&env, ledger_id, 16, 4);

    let test_blocks_with_index = || {
        let index_init_arg = IndexArg::Init(InitArg {
            ledger_id: Principal::from(ledger_id),
            retrieve_blocks_from_ledger_interval_seconds: None,
        });
        let index = env
            .install_canister(index_ng_wasm(), Encode!(&index_init_arg).unwrap(), None)
            .unwrap();
        env.advance_time(Duration::from_secs(60));
        env.tick();
        let balance = balance_of(&env, index, TEST_ACCOUNT_1);
        assert_eq!(balance, 2u64.pow(NUM_BLOCKS) - 1);
    };

    test_blocks_with_index();

    set_icrc3_enabled(&env, ledger_id, false);

    test_blocks_with_index();
}

#[test]
fn test_archiving_all_blocks() {
    let (env, ledger_id) = setup_icrc3_test_ledger();

    const NUM_BLOCKS: u64 = 5;

    for block_id in 0..NUM_BLOCKS {
        let block = BlockBuilder::new(block_id, block_id)
            .mint(TEST_ACCOUNT_1, Tokens::from(2u64.pow(block_id as u32)))
            .build();
        let result = add_block(&env, ledger_id, &block).expect("Failed to add block");
        assert_eq!(result, Nat::from(block_id));
    }

    verify_blocks_in_ledger(&env, ledger_id, 0, NUM_BLOCKS);

    let archive1 = env
        .install_canister(icrc3_test_ledger_wasm(), vec![], None)
        .unwrap();

    let archived_count = archive_blocks(&env, ledger_id, archive1, u64::MAX);
    assert_eq!(archived_count, NUM_BLOCKS);
    env.advance_time(Duration::from_secs(60));
    env.tick();

    verify_blocks_in_ledger(&env, archive1, 0, NUM_BLOCKS);
    verify_blocks_in_ledger(&env, ledger_id, 0, 0);

    let blocks_req = GetBlocksRequest {
        start: Nat::from(0u64),
        length: Nat::from(u64::MAX),
    };

    let blocks = get_blocks(&env, ledger_id, &blocks_req);
    assert_eq!(blocks.first_index, NUM_BLOCKS);
    assert_eq!(blocks.chain_length, NUM_BLOCKS);
    assert!(blocks.blocks.is_empty());

    let index_init_arg = IndexArg::Init(InitArg {
        ledger_id: Principal::from(ledger_id),
        retrieve_blocks_from_ledger_interval_seconds: None,
    });
    let index = env
        .install_canister(index_ng_wasm(), Encode!(&index_init_arg).unwrap(), None)
        .unwrap();
    env.advance_time(Duration::from_secs(60));
    env.tick();
    let balance = balance_of(&env, index, TEST_ACCOUNT_1);
    assert_eq!(balance, 2u64.pow(NUM_BLOCKS as u32) - 1);

    let block = BlockBuilder::new(NUM_BLOCKS, NUM_BLOCKS)
        .mint(TEST_ACCOUNT_1, Tokens::from(2u64.pow(NUM_BLOCKS as u32)))
        .build();
    let result = add_block(&env, ledger_id, &block).expect("Failed to add block");
    assert_eq!(result, Nat::from(NUM_BLOCKS));

    env.advance_time(Duration::from_secs(60));
    env.tick();
    let balance = balance_of(&env, index, TEST_ACCOUNT_1);
    assert_eq!(balance, 2u64.pow((NUM_BLOCKS + 1) as u32) - 1);

    let blocks = get_blocks(&env, ledger_id, &blocks_req);
    assert_eq!(blocks.first_index, NUM_BLOCKS);
    assert_eq!(blocks.chain_length, NUM_BLOCKS + 1);
    assert_eq!(blocks.blocks.len(), 1);
}
