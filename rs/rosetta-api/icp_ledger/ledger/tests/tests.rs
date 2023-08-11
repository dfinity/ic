use candid::Principal;
use candid::{Decode, Encode, Nat};
use dfn_protobuf::ProtoBuf;
use ic_base_types::CanisterId;
use ic_icrc1_ledger_sm_tests::{
    default_approve_args, expect_icrc2_disabled, get_allowance, send_approval, supported_standards,
    transfer, MINTER,
};
use ic_ledger_core::{block::BlockType, Tokens};
use ic_state_machine_tests::{ErrorCode, PrincipalId, StateMachine, UserError};
use icp_ledger::{
    AccountIdentifier, ArchiveOptions, Block, CandidBlock, FeatureFlags, GetBlocksArgs,
    GetBlocksRes, InitArgs, LedgerCanisterInitPayload, LedgerCanisterPayload, Operation,
    QueryBlocksResponse, QueryEncodedBlocksResponse, UpgradeArgs,
};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError},
};
use icrc_ledger_types::icrc2::allowance::AllowanceArgs;
use on_wire::{FromWire, IntoWire};
use serde_bytes::ByteBuf;
use std::collections::{HashMap, HashSet};

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister",
        &[],
    )
}

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> LedgerCanisterInitPayload {
    let initial_values = args
        .initial_balances
        .into_iter()
        .map(|(account, amount)| (account.into(), Tokens::try_from(amount).unwrap()))
        .collect();
    LedgerCanisterInitPayload::builder()
        .initial_values(initial_values)
        .minting_account(args.minting_account.into())
        .icrc1_minting_account(args.minting_account)
        .archive_options(args.archive_options)
        .transfer_fee(Tokens::try_from(args.transfer_fee).unwrap())
        .token_symbol_and_name(&args.token_symbol, &args.token_name)
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap()
}

fn query_blocks(
    env: &StateMachine,
    caller: Principal,
    ledger: CanisterId,
    start: u64,
    length: u64,
) -> QueryBlocksResponse {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(caller),
            ledger,
            "query_blocks",
            Encode!(&GetBlocksArgs {
                start,
                length: length as usize
            })
            .unwrap()
        )
        .expect("failed to query blocks")
        .bytes(),
        QueryBlocksResponse
    )
    .expect("failed to decode transfer response")
}

fn query_encoded_blocks(
    env: &StateMachine,
    caller: Principal,
    ledger: CanisterId,
    start: u64,
    length: u64,
) -> QueryEncodedBlocksResponse {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(caller),
            ledger,
            "query_encoded_blocks",
            Encode!(&GetBlocksArgs {
                start,
                length: length as usize
            })
            .unwrap()
        )
        .expect("failed to query blocks")
        .bytes(),
        QueryEncodedBlocksResponse
    )
    .expect("failed to decode transfer response")
}

fn get_blocks_pb(
    env: &StateMachine,
    caller: Principal,
    ledger: CanisterId,
    start: u64,
    length: usize,
) -> GetBlocksRes {
    let bytes = env
        .execute_ingress_as(
            PrincipalId(caller),
            ledger,
            "get_blocks_pb",
            ProtoBuf(GetBlocksArgs { start, length })
                .into_bytes()
                .unwrap(),
        )
        .expect("failed to query blocks")
        .bytes();
    let result: GetBlocksRes = ProtoBuf::from_bytes(bytes).map(|c| c.0).unwrap();
    result
}

#[test]
fn test_balance_of() {
    ic_icrc1_ledger_sm_tests::test_balance_of(ledger_wasm(), encode_init_args)
}

#[test]
fn test_metadata() {
    ic_icrc1_ledger_sm_tests::test_metadata_icp_ledger(ledger_wasm(), encode_init_args)
}

#[test]
fn test_total_supply() {
    ic_icrc1_ledger_sm_tests::test_total_supply(ledger_wasm(), encode_init_args)
}

#[test]
fn test_minting_account() {
    ic_icrc1_ledger_sm_tests::test_minting_account(ledger_wasm(), encode_init_args)
}

#[test]
fn test_single_transfer() {
    ic_icrc1_ledger_sm_tests::test_single_transfer(ledger_wasm(), encode_init_args);
}

#[ignore = "requires fix for FI-541"]
#[test]
fn test_tx_deduplication() {
    ic_icrc1_ledger_sm_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_icrc1_ledger_sm_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_account_canonicalization() {
    ic_icrc1_ledger_sm_tests::test_account_canonicalization(ledger_wasm(), encode_init_args);
}

#[test]
fn test_tx_time_bounds() {
    ic_icrc1_ledger_sm_tests::test_tx_time_bounds(ledger_wasm(), encode_init_args);
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::transaction_hashes_are_unique();
}

#[test]
fn block_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_unique();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_stable();
}

#[test]
fn check_transfer_model() {
    ic_icrc1_ledger_sm_tests::check_transfer_model(ledger_wasm(), encode_init_args);
}

#[test]
fn check_old_init() {
    let env = StateMachine::new();
    let old_init = Encode!(&InitArgs {
        archive_options: None,
        minting_account: AccountIdentifier::new(PrincipalId::new_user_test_id(1), None),
        icrc1_minting_account: None,
        initial_values: HashMap::new(),
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: None,
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    })
    .unwrap();
    env.install_canister(ledger_wasm(), old_init, None)
        .expect("Unable to install the Ledger canister with the old init");
}

#[test]
fn check_new_init() {
    let env = StateMachine::new();
    let new_init = Encode!(&LedgerCanisterPayload::Init(InitArgs {
        archive_options: None,
        minting_account: AccountIdentifier::new(PrincipalId::new_user_test_id(1), None),
        icrc1_minting_account: None,
        initial_values: HashMap::new(),
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: None,
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    }))
    .unwrap();
    env.install_canister(ledger_wasm(), new_init, None)
        .expect("Unable to install the Ledger canister with the new init");
}

#[test]
fn check_memo() {
    let env = StateMachine::new();
    let new_init = Encode!(&LedgerCanisterPayload::Init(InitArgs {
        archive_options: None,
        minting_account: MINTER.into(),
        icrc1_minting_account: None,
        initial_values: HashMap::new(),
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: None,
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    }))
    .unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), new_init, None)
        .expect("Unable to install the Ledger canister with the new init");

    let mint_with_memo = |memo_size_bytes: usize| -> Result<Result<Nat, TransferError>, UserError> {
        let req = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: PrincipalId::new_user_test_id(10).0,
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: Some(Memo(ByteBuf::from(vec![0; memo_size_bytes]))),
            amount: 100_000_000.into(),
        };
        let req = Encode!(&req).unwrap();
        env.execute_ingress_as(PrincipalId(MINTER.owner), ledger_id, "icrc1_transfer", req)
            .map(|res| Decode!(&res.bytes(), Result<Nat, TransferError>).unwrap())
    };

    for memo_size_bytes in 0..=32 {
        assert_eq!(
            Ok(Ok(memo_size_bytes.into())),
            mint_with_memo(memo_size_bytes)
        );
    }

    for memo_size_bytes in 33..40 {
        assert_eq!(Err(UserError::new(ErrorCode::CanisterCalledTrap, "Canister rwlgt-iiaaa-aaaaa-aaaaa-cai trapped explicitly: the memo field is too large")),
            mint_with_memo(memo_size_bytes));
    }
}

fn assert_candid_block_equals_icp_ledger_block(
    candid_blocks: Vec<CandidBlock>,
    icp_ledger_blocks: Vec<Block>,
) {
    assert_eq!(candid_blocks.len(), icp_ledger_blocks.len());
    for (cb, lb) in candid_blocks.into_iter().zip(icp_ledger_blocks.into_iter()) {
        assert_eq!(
            cb.parent_hash.map(|x| x.to_vec()),
            lb.parent_hash.map(|x| x.as_slice().to_vec())
        );
        assert_eq!(cb.timestamp, lb.timestamp);
        assert_eq!(cb.transaction.icrc1_memo, lb.transaction.icrc1_memo);
        assert_eq!(cb.transaction.memo, lb.transaction.memo);
        assert_eq!(
            Operation::try_from(cb.transaction.operation.unwrap()).unwrap(),
            lb.transaction.operation
        );
    }
}

#[test]
fn check_query_blocks_coherence() {
    let ledger_wasm_current = ledger_wasm();

    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let p3 = PrincipalId::new_user_test_id(3);

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    initial_balances.insert(Account::from(p1.0).into(), Tokens::from_e8s(10_000_000));
    initial_balances.insert(Account::from(p2.0).into(), Tokens::from_e8s(10_000_000));
    initial_balances.insert(Account::from(p3.0).into(), Tokens::from_e8s(10_000_000));
    let init_args = Encode!(&LedgerCanisterPayload::Init(InitArgs {
        archive_options: Some(ArchiveOptions {
            trigger_threshold: 5,
            num_blocks_to_archive: 2,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_anonymous(),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None
        }),
        minting_account: MINTER.into(),
        icrc1_minting_account: Some(MINTER),
        initial_values: initial_balances,
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: Some(Tokens::from_e8s(10_000)),
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    }))
    .unwrap();
    let canister_id = env
        .install_canister(ledger_wasm_current, init_args, None)
        .expect("Unable to install the Ledger canister with the new init");

    transfer(&env, canister_id, p1.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p1.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p1.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p1.0, 1_000_000).expect("transfer failed");

    let query_blocks_res = query_blocks(&env, p1.0, canister_id, 0, u32::MAX.into());
    let query_encoded_blocks_res =
        query_encoded_blocks(&env, p1.0, canister_id, 0, u32::MAX.into());

    assert_eq!(
        query_blocks_res.certificate,
        query_encoded_blocks_res.certificate
    );
    assert_eq!(
        query_blocks_res.chain_length,
        query_encoded_blocks_res.chain_length
    );
    assert_eq!(
        query_blocks_res.first_block_index,
        query_encoded_blocks_res.first_block_index
    );
    assert_eq!(
        query_blocks_res
            .archived_blocks
            .clone()
            .into_iter()
            .map(|x| x.start)
            .collect::<Vec<u64>>(),
        query_encoded_blocks_res
            .archived_blocks
            .clone()
            .into_iter()
            .map(|x| x.start)
            .collect::<Vec<u64>>()
    );
    assert_eq!(
        query_blocks_res
            .archived_blocks
            .into_iter()
            .map(|x| x.length)
            .collect::<Vec<u64>>(),
        query_encoded_blocks_res
            .archived_blocks
            .into_iter()
            .map(|x| x.length)
            .collect::<Vec<u64>>()
    );
    assert_candid_block_equals_icp_ledger_block(
        query_blocks_res.blocks,
        query_encoded_blocks_res
            .blocks
            .into_iter()
            .map(|x| Block::decode(x).unwrap())
            .collect::<Vec<Block>>(),
    );
}

#[test]
fn test_block_transformation() {
    let ledger_wasm_mainnet =
        std::fs::read(std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap()).unwrap();
    let ledger_wasm_current = ledger_wasm();

    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let p3 = PrincipalId::new_user_test_id(3);

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    initial_balances.insert(Account::from(p1.0).into(), Tokens::from_e8s(10_000_000));
    initial_balances.insert(Account::from(p2.0).into(), Tokens::from_e8s(10_000_000));
    initial_balances.insert(Account::from(p3.0).into(), Tokens::from_e8s(10_000_000));
    let init_args = Encode!(&LedgerCanisterPayload::Init(InitArgs {
        archive_options: None,
        minting_account: MINTER.into(),
        icrc1_minting_account: Some(MINTER),
        initial_values: initial_balances,
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: Some(Tokens::from_e8s(10_000)),
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    }))
    .unwrap();
    let canister_id = env
        .install_canister(ledger_wasm_mainnet, init_args, None)
        .expect("Unable to install the Ledger canister with the new init");

    transfer(&env, canister_id, p1.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p1.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p1.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p1.0, 1_000_000).expect("transfer failed");

    // Fetch all blocks before the upgrade
    let resp_pre_upgrade = get_blocks_pb(&env, p1.0, canister_id, 0, 8).0.unwrap();
    let pre_upgrade_query_blocks = query_blocks(&env, p1.0, canister_id, 0, u32::MAX.into());
    let certificate_pre_upgrade = pre_upgrade_query_blocks.certificate;

    // Now upgrade the ledger to the new canister wasm
    env.upgrade_canister(
        canister_id,
        ledger_wasm_current,
        Encode!(&LedgerCanisterPayload::Upgrade(None)).unwrap(),
    )
    .unwrap();

    // Fetch all blocks after the upgrade
    let resp_post_upgrade = get_blocks_pb(&env, p1.0, canister_id, 0, 8).0.unwrap();
    let post_upgrade_query_blocks = query_blocks(&env, p1.0, canister_id, 0, u32::MAX.into());
    let certificate_post_upgrade = post_upgrade_query_blocks.certificate;

    assert_eq!(
        query_encoded_blocks(&env, p1.0, canister_id, 0, u32::MAX.into()).certificate,
        certificate_post_upgrade
    );

    // Make sure the same number of blocks were fetched before and after the upgrade
    assert_eq!(resp_pre_upgrade.len(), resp_post_upgrade.len());

    // Make sure the certificates are the same
    assert_eq!(certificate_pre_upgrade, certificate_post_upgrade);

    //Go through all blocks and make sure the blocks fetched before the upgrade are the same as after the upgrade
    for (block_pre_upgrade, block_post_upgrade) in resp_pre_upgrade
        .into_iter()
        .zip(resp_post_upgrade.into_iter())
    {
        assert_eq!(block_pre_upgrade, block_post_upgrade);
        assert_eq!(
            Block::decode(block_pre_upgrade.clone()).unwrap(),
            Block::decode(block_post_upgrade.clone()).unwrap()
        );
        assert_eq!(
            Block::decode(block_pre_upgrade.clone()).unwrap().encode(),
            Block::decode(block_post_upgrade.clone()).unwrap().encode()
        );
        assert_eq!(
            Block::block_hash(&block_pre_upgrade),
            Block::block_hash(&block_post_upgrade)
        );
    }
}

#[test]
fn test_approve_smoke() {
    ic_icrc1_ledger_sm_tests::test_approve_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expiration() {
    ic_icrc1_ledger_sm_tests::test_approve_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_self() {
    ic_icrc1_ledger_sm_tests::test_approve_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expected_allowance() {
    ic_icrc1_ledger_sm_tests::test_approve_expected_allowance(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cant_pay_fee() {
    ic_icrc1_ledger_sm_tests::test_approve_cant_pay_fee(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cap() {
    ic_icrc1_ledger_sm_tests::test_approve_cap(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_pruning() {
    ic_icrc1_ledger_sm_tests::test_approve_pruning(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_from_minter() {
    ic_icrc1_ledger_sm_tests::test_approve_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_feature_flags() {
    let ledger_wasm = ledger_wasm();

    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    initial_balances.insert(Account::from(from.0).into(), Tokens::from_e8s(100_000));
    let init_args = Encode!(&LedgerCanisterPayload::Init(InitArgs {
        archive_options: None,
        minting_account: MINTER.into(),
        icrc1_minting_account: Some(MINTER),
        initial_values: initial_balances,
        max_message_size_bytes: None,
        transaction_window: None,
        send_whitelist: HashSet::new(),
        transfer_fee: Some(Tokens::from_e8s(10_000)),
        token_symbol: Some("ICP".into()),
        token_name: Some("Internet Computer".into()),
        feature_flags: None,
    }))
    .unwrap();
    let canister_id = env
        .install_canister(ledger_wasm.clone(), init_args, None)
        .expect("Unable to install the Ledger canister with the new init");

    let approve_args = default_approve_args(spender.0, 150_000);
    let allowance_args = AllowanceArgs {
        account: from.0.into(),
        spender: spender.0.into(),
    };

    expect_icrc2_disabled(
        &env,
        from,
        canister_id,
        &approve_args,
        &allowance_args,
        None,
    );

    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
            maximum_number_of_accounts: None,
            icrc1_minting_account: None,
            feature_flags: None,
        })))
        .unwrap(),
    )
    .unwrap();

    expect_icrc2_disabled(
        &env,
        from,
        canister_id,
        &approve_args,
        &allowance_args,
        None,
    );

    env.upgrade_canister(
        canister_id,
        ledger_wasm,
        Encode!(&LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
            maximum_number_of_accounts: None,
            icrc1_minting_account: None,
            feature_flags: Some(FeatureFlags { icrc2: true }),
        })))
        .unwrap(),
    )
    .unwrap();

    let mut standards = vec![];
    for standard in supported_standards(&env, canister_id) {
        standards.push(standard.name);
    }
    standards.sort();
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2"]);

    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    use num_traits::cast::ToPrimitive;
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
}
