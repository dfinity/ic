use candid::Principal;
use candid::{Decode, Encode, Nat};
use dfn_candid::CandidOne;
use dfn_protobuf::ProtoBuf;
use ic_agent::identity::Identity;
use ic_base_types::CanisterId;
use ic_icrc1_ledger_sm_tests::{
    balance_of, default_approve_args, default_transfer_from_args, expect_icrc2_disabled,
    get_allowance, send_approval, send_transfer_from, supported_standards, transfer, MINTER,
};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_core::{block::BlockType, Tokens};
use ic_state_machine_tests::{ErrorCode, PrincipalId, StateMachine, UserError};
use icp_ledger::{
    AccountIdBlob, AccountIdentifier, ArchiveOptions, ArchivedBlocksRange, Block, CandidBlock,
    CandidOperation, CandidTransaction, FeatureFlags, GetBlocksArgs, GetBlocksRes, GetBlocksResult,
    GetEncodedBlocksResult, InitArgs, IterBlocksArgs, IterBlocksRes, LedgerCanisterInitPayload,
    LedgerCanisterPayload, LedgerCanisterUpgradePayload, Operation, QueryBlocksResponse,
    QueryEncodedBlocksResponse, TimeStamp, UpgradeArgs, DEFAULT_TRANSFER_FEE,
    MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST, MAX_BLOCKS_PER_REQUEST,
};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError},
};
use icrc_ledger_types::icrc2::allowance::AllowanceArgs;
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use num_traits::cast::ToPrimitive;
use on_wire::{FromWire, IntoWire};
use serde_bytes::ByteBuf;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister",
        &[],
    )
}

fn ledger_wasm_upgradetomemorymanager() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister-upgrade-to-memory-manager",
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
        .maximum_number_of_accounts(args.maximum_number_of_accounts)
        .accounts_overflow_trim_quantity(args.accounts_overflow_trim_quantity)
        .build()
        .unwrap()
}

fn encode_upgrade_args() -> LedgerCanisterUpgradePayload {
    LedgerCanisterUpgradePayload(LedgerCanisterPayload::Upgrade(None))
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
    .expect("failed to decode query blocks")
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

fn iter_blocks_pb(
    env: &StateMachine,
    caller: Principal,
    ledger: CanisterId,
    start: usize,
    length: usize,
) -> IterBlocksRes {
    let bytes = env
        .execute_ingress_as(
            PrincipalId(caller),
            ledger,
            "iter_blocks_pb",
            ProtoBuf(IterBlocksArgs { start, length })
                .into_bytes()
                .unwrap(),
        )
        .expect("failed to query blocks")
        .bytes();
    let result: IterBlocksRes = ProtoBuf::from_bytes(bytes).map(|c| c.0).unwrap();
    result
}

fn account_identifier(env: &StateMachine, ledger: CanisterId, account: Account) -> AccountIdBlob {
    let bytes = env
        .query(ledger, "account_identifier", Encode!(&account).unwrap())
        .expect("failed to calculate account identifier")
        .bytes();
    Decode!(&bytes, AccountIdBlob).expect("Unable to decode account_identifier endpoint result")
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
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    })
    .unwrap();
    env.install_canister(ledger_wasm(), old_init, None)
        .expect("Unable to install the Ledger canister with the old init");
}

#[test]
fn check_new_init() {
    let env = StateMachine::new();
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(
            PrincipalId::new_user_test_id(1),
            None,
        ))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    env.install_canister(
        ledger_wasm(),
        CandidOne(payload).into_bytes().unwrap(),
        None,
    )
    .expect("Unable to install the Ledger canister with the new init");
}

#[test]
fn check_memo() {
    let env = StateMachine::new();
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    let ledger_id = env
        .install_canister(
            ledger_wasm(),
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
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
            amount: 100_000_000_u32.into(),
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
        mint_with_memo(memo_size_bytes)
            .unwrap_err()
            .assert_contains(
                ErrorCode::CanisterCalledTrap,
                "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister called \
                `ic0.trap` with message: the memo field is too large",
            );
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
    let payload = LedgerCanisterInitPayload::builder()
        .archive_options(ArchiveOptions {
            trigger_threshold: 5,
            num_blocks_to_archive: 2,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_anonymous(),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        })
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(
            ledger_wasm_current,
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
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
fn check_block_endpoint_limits() {
    let ledger_wasm_current = ledger_wasm();

    let user_principal =
        Principal::from_text("luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe")
            .unwrap();
    let canister_principal = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    for i in 0..MAX_BLOCKS_PER_REQUEST + 1 {
        let p = PrincipalId::new_user_test_id(i as u64 + 1);
        initial_balances.insert(Account::from(p.0).into(), Tokens::from_e8s(1));
    }
    let payload = LedgerCanisterInitPayload::builder()
        .archive_options(ArchiveOptions {
            trigger_threshold: 50000,
            num_blocks_to_archive: 2,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_anonymous(),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        })
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(
            ledger_wasm_current,
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
        .expect("Unable to install the Ledger canister with the new init");

    let get_blocks_args = Encode!(&GetBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1
    })
    .unwrap();

    // query_blocks
    let ingress_update = query_blocks(&env, user_principal, canister_id, 0, u32::MAX.into());
    let canister_update = query_blocks(&env, canister_principal, canister_id, 0, u32::MAX.into());
    let query = Decode!(
        &env.query_as(
            PrincipalId(user_principal),
            canister_id,
            "query_blocks".to_string(),
            get_blocks_args.clone(),
        )
        .expect("query failed")
        .bytes(),
        QueryBlocksResponse
    )
    .expect("failed to decode response");

    assert_eq!(
        ingress_update.blocks.len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(canister_update.blocks.len(), MAX_BLOCKS_PER_REQUEST);
    assert_eq!(query.blocks.len(), MAX_BLOCKS_PER_REQUEST);

    // query_encoded_blocks
    let ingress_update =
        query_encoded_blocks(&env, user_principal, canister_id, 0, u32::MAX.into());
    let canister_update =
        query_encoded_blocks(&env, canister_principal, canister_id, 0, u32::MAX.into());
    let query = Decode!(
        &env.query_as(
            user_principal.into(),
            canister_id,
            "query_encoded_blocks".to_string(),
            get_blocks_args.clone(),
        )
        .expect("query failed")
        .bytes(),
        QueryEncodedBlocksResponse
    )
    .expect("failed to decode response");

    assert_eq!(
        ingress_update.blocks.len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(canister_update.blocks.len(), MAX_BLOCKS_PER_REQUEST);
    assert_eq!(query.blocks.len(), MAX_BLOCKS_PER_REQUEST);

    // get_blocks_pb
    let get_blocks_pb_args = ProtoBuf(GetBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1,
    })
    .into_bytes()
    .unwrap();

    let ingress_update = get_blocks_pb(
        &env,
        user_principal,
        canister_id,
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let canister_update = get_blocks_pb(
        &env,
        canister_principal,
        canister_id,
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let query: GetBlocksRes = ProtoBuf::from_bytes(
        env.query_as(
            user_principal.into(),
            canister_id,
            "get_blocks_pb".to_string(),
            get_blocks_pb_args.clone(),
        )
        .expect("query failed")
        .bytes(),
    )
    .map(|c| c.0)
    .unwrap();

    assert_eq!(
        ingress_update.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(
        canister_update.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_REQUEST
    );
    assert_eq!(
        query.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_REQUEST
    );

    // iter_blocks_pb
    let iter_blocks_pb_args = ProtoBuf(IterBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1,
    })
    .into_bytes()
    .unwrap();

    let ingress_update = iter_blocks_pb(
        &env,
        user_principal,
        canister_id,
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let canister_update = iter_blocks_pb(
        &env,
        canister_principal,
        canister_id,
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let query: IterBlocksRes = ProtoBuf::from_bytes(
        env.query_as(
            user_principal.into(),
            canister_id,
            "iter_blocks_pb".to_string(),
            iter_blocks_pb_args.clone(),
        )
        .expect("query failed")
        .bytes(),
    )
    .map(|c| c.0)
    .unwrap();

    assert_eq!(
        ingress_update.0.len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(canister_update.0.len(), MAX_BLOCKS_PER_REQUEST);
    assert_eq!(query.0.len(), MAX_BLOCKS_PER_REQUEST);
}

#[test]
fn check_archive_block_endpoint_limits() {
    let ledger_wasm_current = ledger_wasm();

    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let user_principal =
        Principal::from_text("luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe")
            .unwrap();
    let canister_principal = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    initial_balances.insert(Account::from(p1.0).into(), Tokens::from_e8s(1_000_000_000));

    let payload = LedgerCanisterInitPayload::builder()
        .archive_options(ArchiveOptions {
            trigger_threshold: MAX_BLOCKS_PER_REQUEST + 1,
            num_blocks_to_archive: MAX_BLOCKS_PER_REQUEST + 1,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_anonymous(),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        })
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(
            ledger_wasm_current,
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
        .expect("Unable to install the Ledger canister with the new init");

    for _ in 0..MAX_BLOCKS_PER_REQUEST {
        transfer(&env, canister_id, p1.0, p2.0, 1).expect("transfer failed");
    }

    let res = query_blocks(
        &env,
        canister_principal,
        canister_id,
        0,
        MAX_BLOCKS_PER_REQUEST as u64 + 1,
    );
    assert_eq!(res.chain_length, MAX_BLOCKS_PER_REQUEST as u64 + 1);
    assert_eq!(res.first_block_index, MAX_BLOCKS_PER_REQUEST as u64 + 1);
    assert_eq!(res.archived_blocks.len(), 1);
    let ArchivedBlocksRange {
        start,
        length,
        callback,
    } = res.archived_blocks.first().unwrap();
    assert_eq!(*start, 0);
    assert_eq!(*length, MAX_BLOCKS_PER_REQUEST as u64 + 1);

    let get_blocks_args = Encode!(&GetBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1
    })
    .unwrap();

    // get_blocks
    let query_blocks_len = Decode!(
        &env.query(
            CanisterId::unchecked_from_principal(callback.canister_id.into()),
            "get_blocks",
            get_blocks_args.clone()
        )
        .unwrap()
        .bytes(),
        GetBlocksResult
    )
    .unwrap()
    .unwrap()
    .blocks
    .len();

    let update_blocks_len = |caller: Principal| {
        Decode!(
            &env.execute_ingress_as(
                PrincipalId(caller),
                CanisterId::unchecked_from_principal(callback.canister_id.into()),
                "get_blocks",
                get_blocks_args.clone()
            )
            .unwrap()
            .bytes(),
            GetBlocksResult
        )
        .unwrap()
        .unwrap()
        .blocks
        .len()
    };

    assert_eq!(
        update_blocks_len(user_principal),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(
        update_blocks_len(canister_principal),
        MAX_BLOCKS_PER_REQUEST
    );
    assert_eq!(query_blocks_len, MAX_BLOCKS_PER_REQUEST);

    // get_encoded_blocks
    let query_blocks_len = Decode!(
        &env.query(
            CanisterId::unchecked_from_principal(callback.canister_id.into()),
            "get_encoded_blocks",
            get_blocks_args.clone()
        )
        .unwrap()
        .bytes(),
        GetEncodedBlocksResult
    )
    .unwrap()
    .unwrap()
    .len();

    let update_blocks_len = |caller: Principal| {
        Decode!(
            &env.execute_ingress_as(
                PrincipalId(caller),
                CanisterId::unchecked_from_principal(callback.canister_id.into()),
                "get_encoded_blocks",
                get_blocks_args.clone()
            )
            .unwrap()
            .bytes(),
            GetEncodedBlocksResult
        )
        .unwrap()
        .unwrap()
        .len()
    };

    assert_eq!(
        update_blocks_len(user_principal),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(
        update_blocks_len(canister_principal),
        MAX_BLOCKS_PER_REQUEST
    );
    assert_eq!(query_blocks_len, MAX_BLOCKS_PER_REQUEST);

    // get_blocks_pb
    let get_blocks_pb_args = ProtoBuf(GetBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1,
    })
    .into_bytes()
    .unwrap();

    let ingress_update = get_blocks_pb(
        &env,
        user_principal,
        CanisterId::unchecked_from_principal(callback.canister_id.into()),
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let canister_update = get_blocks_pb(
        &env,
        canister_principal,
        CanisterId::unchecked_from_principal(callback.canister_id.into()),
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let query: GetBlocksRes = ProtoBuf::from_bytes(
        env.query_as(
            user_principal.into(),
            CanisterId::unchecked_from_principal(callback.canister_id.into()),
            "get_blocks_pb".to_string(),
            get_blocks_pb_args.clone(),
        )
        .expect("query failed")
        .bytes(),
    )
    .map(|c| c.0)
    .unwrap();

    assert_eq!(
        ingress_update.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(
        canister_update.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_REQUEST
    );
    assert_eq!(
        query.0.expect("failed to get blocks").len(),
        MAX_BLOCKS_PER_REQUEST
    );

    // iter_blocks_pb
    let iter_blocks_pb_args = ProtoBuf(IterBlocksArgs {
        start: 0,
        length: MAX_BLOCKS_PER_REQUEST + 1,
    })
    .into_bytes()
    .unwrap();

    let ingress_update = iter_blocks_pb(
        &env,
        user_principal,
        CanisterId::unchecked_from_principal(callback.canister_id.into()),
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let canister_update = iter_blocks_pb(
        &env,
        canister_principal,
        CanisterId::unchecked_from_principal(callback.canister_id.into()),
        0,
        MAX_BLOCKS_PER_REQUEST + 1,
    );
    let query: IterBlocksRes = ProtoBuf::from_bytes(
        env.query_as(
            user_principal.into(),
            CanisterId::unchecked_from_principal(callback.canister_id.into()),
            "iter_blocks_pb".to_string(),
            iter_blocks_pb_args.clone(),
        )
        .expect("query failed")
        .bytes(),
    )
    .map(|c| c.0)
    .unwrap();

    assert_eq!(
        ingress_update.0.len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
    assert_eq!(canister_update.0.len(), MAX_BLOCKS_PER_REQUEST);
    assert_eq!(query.0.len(), MAX_BLOCKS_PER_REQUEST);
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

    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(
            ledger_wasm_mainnet,
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
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
fn test_upgrade_serialization() {
    let ledger_wasm_mainnet =
        std::fs::read(std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap()).unwrap();
    let ledger_wasm_current = ledger_wasm();

    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(minter_principal.into())
        .icrc1_minting_account(minter_principal.into())
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .build()
        .unwrap();

    let init_args = CandidOne(payload).into_bytes().unwrap();
    let upgrade_args = Encode!(&LedgerCanisterPayload::Upgrade(None)).unwrap();
    ic_icrc1_ledger_sm_tests::test_upgrade_serialization(
        ledger_wasm_mainnet,
        ledger_wasm_current,
        Some(ledger_wasm_upgradetomemorymanager()),
        init_args,
        upgrade_args,
        minter,
        false,
    );
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
    let to = PrincipalId::new_user_test_id(3);

    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    initial_balances.insert(Account::from(from.0).into(), Tokens::from_e8s(100_000));
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .initial_values(initial_balances)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .feature_flags(FeatureFlags { icrc2: false })
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(
            ledger_wasm.clone(),
            CandidOne(payload).into_bytes().unwrap(),
            None,
        )
        .expect("Unable to install the Ledger canister with the new init");

    let approve_args = default_approve_args(spender.0, 150_000);
    let allowance_args = AllowanceArgs {
        account: from.0.into(),
        spender: spender.0.into(),
    };
    let transfer_from_args = default_transfer_from_args(from.0, to.0, 10_000);

    expect_icrc2_disabled(
        &env,
        from,
        canister_id,
        &approve_args,
        &allowance_args,
        &transfer_from_args,
    );

    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
            icrc1_minting_account: None,
            feature_flags: Some(FeatureFlags { icrc2: false }),
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
        &transfer_from_args,
    );

    env.upgrade_canister(
        canister_id,
        ledger_wasm,
        Encode!(&LedgerCanisterPayload::Upgrade(Some(UpgradeArgs {
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
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2", "ICRC-21"]);

    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 2);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 130_000);
    assert_eq!(balance_of(&env, canister_id, from.0), 70_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 10_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

#[test]
fn test_transfer_from_smoke() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_self() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_minter() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_burn() {
    ic_icrc1_ledger_sm_tests::test_transfer_from_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_balances_overflow() {
    ic_icrc1_ledger_sm_tests::test_balances_overflow(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approval_trimming() {
    ic_icrc1_ledger_sm_tests::test_approval_trimming(ledger_wasm(), encode_init_args);
}

#[test]
fn account_identifier_test() {
    let env = StateMachine::new();
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .build()
        .unwrap();
    let ledger = env
        .install_canister(ledger_wasm(), Encode!(&payload).unwrap(), None)
        .expect("Unable to install the Ledger canister with the new init");

    let owner =
        Principal::try_from("aspvh-rnqud-zk2qo-4objq-d537b-j36qa-l74s3-jricy-57syn-tt5iq-bae")
            .unwrap();

    // default subaccount
    let expected_account_id =
        hex::decode("b43c3536fb53da333e8f93e1703d61b47cee3638103c0bd7ddff8cbdf04b5ca5").unwrap();
    let account_id = account_identifier(
        &env,
        ledger,
        Account {
            owner,
            subaccount: None,
        },
    );
    assert_eq!(expected_account_id, account_id);

    // subaccount 1
    let expected_account_id =
        hex::decode("c59f11aa439a50b084e6a28769ac2f43fb95f452f97351b2dd89060e284151e8").unwrap();
    let subaccount = Some(
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let account_id = account_identifier(&env, ledger, Account { owner, subaccount });
    assert_eq!(expected_account_id, account_id);

    // random subaccount
    let expected_account_id =
        hex::decode("95eee02ffd99469c20b0488dad381d0b71a97f9b3e4387ad11ad65c3055f10c5").unwrap();
    let subaccount = Some(
        hex::decode("C6EE2D822ED28BA50D807AE0969B422E181CD4484D93CD556923938355A4BAA7")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let account_id = account_identifier(&env, ledger, Account { owner, subaccount });
    assert_eq!(expected_account_id, account_id);
}

#[test]
fn test_query_archived_blocks() {
    let env = StateMachine::new();
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .icrc1_minting_account(MINTER)
        .transfer_fee(Tokens::from_e8s(10_000))
        .token_symbol_and_name("ICP", "Internet Computer")
        .archive_options(ArchiveOptions {
            trigger_threshold: 4,
            num_blocks_to_archive: 4usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_anonymous(),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        })
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();
    let ledger = env
        .install_canister(ledger_wasm(), Encode!(&payload).unwrap(), None)
        .expect("Unable to install the Ledger canister with the new init");

    let user1 = Principal::from_slice(&[1]);
    let user2 = Principal::from_slice(&[2]);

    // mint block
    let mint_time = system_time_to_nanos(env.time_of_next_round());
    transfer(&env, ledger, MINTER, user1, 2_000_000_000).unwrap();
    // burn block
    let burn_time = system_time_to_nanos(env.time_of_next_round());
    transfer(&env, ledger, user1, MINTER, 1_000_000_000).unwrap();
    // xfer block
    let xfer_time = system_time_to_nanos(env.time_of_next_round());
    transfer(&env, ledger, user1, user2, 100_000_000).unwrap();
    // approve block
    let approve_time = system_time_to_nanos(env.time_of_next_round());
    send_approval(
        &env,
        ledger,
        user2,
        &ApproveArgs {
            from_subaccount: None,
            spender: user1.into(),
            amount: 100_000_000_u32.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    )
    .unwrap();

    let res = query_blocks(&env, user1, ledger, 0, 1000);
    assert_eq!(res.chain_length, 4);
    assert_eq!(res.first_block_index, 4);
    assert_eq!(res.archived_blocks.len(), 1);
    let ArchivedBlocksRange {
        start,
        length,
        callback,
    } = res.archived_blocks.first().unwrap();
    // query the archive
    let block_range = Decode!(
        &env.query(
            CanisterId::unchecked_from_principal(callback.canister_id.into()),
            callback.method.to_owned(),
            Encode!(&GetBlocksArgs {
                start: *start,
                length: *length as usize
            })
            .unwrap()
        )
        .unwrap()
        .bytes(),
        GetBlocksResult
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        block_range
            .blocks
            .iter()
            .map(|b| b.transaction.to_owned())
            .collect::<Vec<_>>(),
        vec![
            CandidTransaction {
                memo: icp_ledger::Memo(0),
                created_at_time: TimeStamp::from_nanos_since_unix_epoch(mint_time),
                icrc1_memo: None,
                operation: Some(CandidOperation::Mint {
                    to: AccountIdentifier::from(user1).to_address(),
                    amount: Tokens::from_e8s(2_000_000_000)
                }),
            },
            CandidTransaction {
                memo: icp_ledger::Memo(0),
                created_at_time: TimeStamp::from_nanos_since_unix_epoch(burn_time),
                icrc1_memo: None,
                operation: Some(CandidOperation::Burn {
                    from: AccountIdentifier::from(user1).to_address(),
                    amount: Tokens::from_e8s(1_000_000_000),
                    spender: None
                }),
            },
            CandidTransaction {
                memo: icp_ledger::Memo(0),
                created_at_time: TimeStamp::from_nanos_since_unix_epoch(xfer_time),
                icrc1_memo: None,
                operation: Some(CandidOperation::Transfer {
                    from: AccountIdentifier::from(user1).to_address(),
                    to: AccountIdentifier::from(user2).to_address(),
                    amount: Tokens::from_e8s(100_000_000),
                    fee: DEFAULT_TRANSFER_FEE,
                    spender: None,
                }),
            },
            CandidTransaction {
                memo: icp_ledger::Memo(0),
                created_at_time: TimeStamp::from_nanos_since_unix_epoch(approve_time),
                icrc1_memo: None,
                operation: Some(CandidOperation::Approve {
                    from: AccountIdentifier::from(user2).to_address(),
                    spender: AccountIdentifier::from(user1).to_address(),
                    allowance: Tokens::from_e8s(100_000_000),
                    allowance_e8s: 100_000_000i128,
                    expected_allowance: None,
                    expires_at: None,
                    fee: DEFAULT_TRANSFER_FEE,
                }),
            },
        ]
    );
}

#[test]
fn test_icrc21_standard() {
    ic_icrc1_ledger_sm_tests::test_icrc21_standard(ledger_wasm(), encode_init_args);
}

mod metrics {
    use crate::{
        encode_init_args, encode_upgrade_args, ledger_wasm, ledger_wasm_upgradetomemorymanager,
    };
    use ic_icrc1_ledger_sm_tests::metrics::LedgerSuiteType;

    #[test]
    fn should_export_num_archives_metrics() {
        ic_icrc1_ledger_sm_tests::metrics::assert_existence_of_ledger_num_archives_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_total_memory_usage_metrics() {
        ic_icrc1_ledger_sm_tests::metrics::assert_existence_of_ledger_total_memory_bytes_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_ledger_total_blocks_metrics() {
        ic_icrc1_ledger_sm_tests::metrics::assert_existence_of_ledger_total_transactions_metric(
            ledger_wasm(),
            encode_init_args,
            LedgerSuiteType::ICP,
        );
    }

    #[test]
    fn should_set_ledger_upgrade_instructions_consumed_metric() {
        ic_icrc1_ledger_sm_tests::metrics::assert_ledger_upgrade_instructions_consumed_metric_set(
            ledger_wasm(),
            Some(ledger_wasm_upgradetomemorymanager()),
            encode_init_args,
            encode_upgrade_args,
        );
    }
}
