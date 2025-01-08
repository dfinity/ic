use candid::Principal;
use candid::{Decode, Encode, Nat};
use dfn_candid::CandidOne;
use dfn_protobuf::ProtoBuf;
use ic_agent::identity::Identity;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_core::block::BlockIndex;
use ic_ledger_core::{block::BlockType, Tokens};
use ic_ledger_suite_state_machine_tests::{
    balance_of, default_approve_args, default_transfer_from_args, expect_icrc2_disabled,
    send_approval, send_transfer_from, setup, supported_standards, total_supply, transfer,
    AllowanceProvider, FEE, MINTER,
};
use ic_state_machine_tests::{ErrorCode, StateMachine, UserError};
use icp_ledger::{
    AccountIdBlob, AccountIdentifier, AccountIdentifierByteBuf, ArchiveOptions,
    ArchivedBlocksRange, Block, CandidBlock, CandidOperation, CandidTransaction, FeatureFlags,
    GetBlocksArgs, GetBlocksRes, GetBlocksResult, GetEncodedBlocksResult, IcpAllowanceArgs,
    InitArgs, IterBlocksArgs, IterBlocksRes, LedgerCanisterInitPayload, LedgerCanisterPayload,
    LedgerCanisterUpgradePayload, Operation, QueryBlocksResponse, QueryEncodedBlocksResponse,
    SendArgs, TimeStamp, UpgradeArgs, DEFAULT_TRANSFER_FEE,
    MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST, MAX_BLOCKS_PER_REQUEST,
};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError},
};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use num_traits::cast::ToPrimitive;
use on_wire::{FromWire, IntoWire};
use serde_bytes::ByteBuf;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

fn ledger_wasm_next_version() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister-next-version",
        &[],
    )
}

fn ledger_wasm_mainnet() -> Vec<u8> {
    std::fs::read(std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap()).unwrap()
}

fn ledger_wasm_allowance_getter() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister-allowance-getter",
        &[],
    )
}

fn ledger_wasm_low_instruction_limits() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister-low-limits",
        &[],
    )
}

fn encode_init_args(
    args: ic_ledger_suite_state_machine_tests::InitArgs,
) -> LedgerCanisterInitPayload {
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
            Encode!(&GetBlocksArgs { start, length }).unwrap()
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
            Encode!(&GetBlocksArgs { start, length }).unwrap()
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
            ProtoBuf(GetBlocksArgs {
                start,
                length: length as u64,
            })
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
    ic_ledger_suite_state_machine_tests::test_balance_of(ledger_wasm(), encode_init_args)
}

#[test]
fn test_metadata() {
    ic_ledger_suite_state_machine_tests::test_metadata_icp_ledger(ledger_wasm(), encode_init_args)
}

#[test]
fn test_total_supply() {
    ic_ledger_suite_state_machine_tests::test_total_supply(ledger_wasm(), encode_init_args)
}

#[test]
fn test_minting_account() {
    ic_ledger_suite_state_machine_tests::test_minting_account(ledger_wasm(), encode_init_args)
}

#[test]
fn test_anonymous_transfers() {
    const INITIAL_BALANCE: u64 = 10_000_000;
    const TRANSFER_AMOUNT: u64 = 1_000_000;
    let p1 = PrincipalId::new_user_test_id(1);
    let anon = PrincipalId::new_anonymous();
    let (env, canister_id) = setup(
        ledger_wasm(),
        encode_init_args,
        vec![(Account::from(p1.0), INITIAL_BALANCE)],
    );

    assert_eq!(INITIAL_BALANCE, total_supply(&env, canister_id));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, p1.0));
    assert_eq!(0u64, balance_of(&env, canister_id, anon.0));

    // Transfer to the account of the anonymous principal using `icrc1_transfer` succeeds
    // The expected block index after the transfer is 1 (0 is the initial mint to `p1`).
    let mut expected_block_index = 1u64;
    assert_eq!(
        transfer(&env, canister_id, p1.0, anon.0, TRANSFER_AMOUNT).expect("transfer failed"),
        expected_block_index
    );
    expected_block_index += 1;

    // Transfer to the account of the anonymous principal using the ICP-specific `transfer` succeeds
    let transfer_args = icp_ledger::TransferArgs {
        memo: icp_ledger::Memo(0u64),
        amount: Tokens::from_e8s(TRANSFER_AMOUNT),
        fee: Tokens::from_e8s(FEE),
        from_subaccount: None,
        to: AccountIdentifier::new(anon, None).to_address(),
        created_at_time: None,
    };
    let response = env.execute_ingress_as(
        p1,
        canister_id,
        "transfer",
        Encode!(&transfer_args).unwrap(),
    );
    let result = Decode!(
        &response
        .expect("failed to transfer funds")
        .bytes(),
        Result<BlockIndex, TransferError>
    )
    .expect("failed to decode transfer response");
    assert_eq!(result, Ok(expected_block_index));

    // Transfer from the account of the anonymous principal using `icrc1_transfer` fails
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account::from(p1.0),
        fee: None,
        created_at_time: None,
        amount: Nat::from(TRANSFER_AMOUNT),
        memo: None,
    };
    let encoded_transfer_result = env
        .execute_ingress_as(
            anon,
            canister_id,
            "icrc1_transfer",
            Encode!(&transfer_arg).unwrap(),
        )
        .expect("failed to transfer funds")
        .bytes();
    let string_from_bytes_result = String::from_utf8(encoded_transfer_result.clone());
    assert_eq!(
        string_from_bytes_result,
        Ok("Anonymous principal cannot hold tokens on the ledger.".to_string())
    );

    // Transfer from the account of the anonymous principal using the ICP-specific `transfer` fails
    let transfer_args = icp_ledger::TransferArgs {
        memo: icp_ledger::Memo(0u64),
        amount: Tokens::from_e8s(TRANSFER_AMOUNT),
        fee: Tokens::from_e8s(FEE),
        from_subaccount: None,
        to: AccountIdentifier::new(p1, None).to_address(),
        created_at_time: None,
    };
    let response = env.execute_ingress_as(
        anon,
        canister_id,
        "transfer",
        Encode!(&transfer_args).unwrap(),
    );
    assert!(response.is_err());
    if let Err(err) = response {
        assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
        assert!(err.description().contains("Canister called `ic0.trap` with message: Panicked at 'Sending from 2vxsx-fae is not allowed'"));
    }

    assert_eq!(INITIAL_BALANCE - FEE * 2, total_supply(&env, canister_id));
    assert_eq!(
        INITIAL_BALANCE - (TRANSFER_AMOUNT + FEE) * 2,
        balance_of(&env, canister_id, p1.0)
    );
    assert_eq!(TRANSFER_AMOUNT * 2, balance_of(&env, canister_id, anon.0));
}

#[test]
fn test_anonymous_approval() {
    const INITIAL_BALANCE: u64 = 10_000_000;
    const APPROVE_AMOUNT: u64 = 1_000_000;
    let p1 = PrincipalId::new_user_test_id(1);
    let anon = PrincipalId::new_anonymous();
    let (env, canister_id) = setup(
        ledger_wasm(),
        encode_init_args,
        vec![(Account::from(anon.0), INITIAL_BALANCE)],
    );

    assert_eq!(INITIAL_BALANCE, total_supply(&env, canister_id));
    assert_eq!(0, balance_of(&env, canister_id, p1.0));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, anon.0));

    // Approve transfers for p1 from the account of the anonymous principal
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: p1.0.into(),
        amount: Nat::from(APPROVE_AMOUNT),
        fee: None,
        memo: None,
        expires_at: None,
        expected_allowance: None,
        created_at_time: None,
    };
    let encoded_transfer_result = env
        .execute_ingress_as(
            anon,
            canister_id,
            "icrc2_approve",
            Encode!(&approve_args).unwrap(),
        )
        .expect("failed to approve transfer")
        .bytes();
    let string_from_bytes_result = String::from_utf8(encoded_transfer_result.clone());
    assert_eq!(
        string_from_bytes_result,
        Ok("Anonymous principal cannot approve token transfers on the ledger.".to_string())
    );
}

#[test]
fn test_icp_allowance_getter_unavailable_in_prod() {
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(ledger_wasm(), encode_init_args, vec![]);
    let allowance_args = IcpAllowanceArgs {
        account: AccountIdentifier::from(p1.0),
        spender: AccountIdentifier::from(p2.0),
    };

    let response = env.execute_ingress_as(
        p1,
        canister_id,
        "allowance",
        Encode!(&allowance_args).unwrap(),
    );
    let error = response.unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterMethodNotFound);
}

#[test]
fn test_get_icp_approval() {
    const INITIAL_BALANCE: u64 = 10_000_000;
    const APPROVE_AMOUNT: u64 = 1_000_000;
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm_allowance_getter(),
        encode_init_args,
        vec![(Account::from(p1.0), INITIAL_BALANCE)],
    );
    assert_eq!(INITIAL_BALANCE, total_supply(&env, canister_id));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, p2.0));
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: p2.0.into(),
        amount: Nat::from(APPROVE_AMOUNT),
        fee: None,
        memo: None,
        expires_at: None,
        expected_allowance: None,
        created_at_time: None,
    };
    let response = env.execute_ingress_as(
        p1,
        canister_id,
        "icrc2_approve",
        Encode!(&approve_args).unwrap(),
    );
    assert!(response.is_ok());
    let allowance_args = IcpAllowanceArgs {
        account: AccountIdentifier::from(p1.0),
        spender: AccountIdentifier::from(p2.0),
    };

    let response = env.execute_ingress_as(
        p1,
        canister_id,
        "allowance",
        Encode!(&allowance_args).unwrap(),
    );

    let result = Decode!(
        &response.expect("failed to get allowance").bytes(),
        Allowance
    )
    .expect("failed to decode allowance response");
    assert_eq!(result.allowance.0.to_u64(), Some(APPROVE_AMOUNT));
}

#[test]
fn test_single_transfer() {
    ic_ledger_suite_state_machine_tests::test_single_transfer(ledger_wasm(), encode_init_args);
}

#[ignore = "requires fix for FI-541"]
#[test]
fn test_tx_deduplication() {
    ic_ledger_suite_state_machine_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_ledger_suite_state_machine_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_account_canonicalization() {
    ic_ledger_suite_state_machine_tests::test_account_canonicalization(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_tx_time_bounds() {
    ic_ledger_suite_state_machine_tests::test_tx_time_bounds(ledger_wasm(), encode_init_args);
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_ledger_suite_state_machine_tests::transaction_hashes_are_unique::<Tokens>();
}

#[test]
fn block_hashes_are_unique() {
    ic_ledger_suite_state_machine_tests::block_hashes_are_unique::<Tokens>();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    ic_ledger_suite_state_machine_tests::block_hashes_are_stable::<Tokens>();
}

#[test]
fn check_transfer_model() {
    ic_ledger_suite_state_machine_tests::check_transfer_model(ledger_wasm(), encode_init_args);
}

#[test]
fn test_ledger_http_request_decoding_quota() {
    ic_ledger_suite_state_machine_tests::test_ledger_http_request_decoding_quota(
        ledger_wasm(),
        encode_init_args,
    );
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
        length: (MAX_BLOCKS_PER_REQUEST + 1) as u64
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
        length: (MAX_BLOCKS_PER_REQUEST + 1) as u64,
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
        length: (MAX_BLOCKS_PER_REQUEST + 1) as u64
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
        length: (MAX_BLOCKS_PER_REQUEST + 1) as u64,
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
    let ledger_wasm_mainnet = ledger_wasm_mainnet();
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
    let ledger_wasm_mainnet = ledger_wasm_mainnet();
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
    ic_ledger_suite_state_machine_tests::test_upgrade_serialization::<Tokens>(
        ledger_wasm_mainnet,
        ledger_wasm_current,
        init_args,
        upgrade_args,
        minter,
        false,
        false,
    );
}

#[ignore] // TODO: Re-enable as part of FI-1440
#[test]
fn test_multi_step_migration() {
    ic_ledger_suite_state_machine_tests::icrc1_test_multi_step_migration(
        ledger_wasm_mainnet(),
        ledger_wasm_low_instruction_limits(),
        encode_init_args,
    );
}

#[test]
fn test_downgrade_from_incompatible_version() {
    ic_ledger_suite_state_machine_tests::test_downgrade_from_incompatible_version(
        ledger_wasm_mainnet(),
        ledger_wasm_next_version(),
        ledger_wasm(),
        encode_init_args,
        true,
    );
}

#[ignore] // TODO: Re-enable as part of FI-1440
#[test]
fn test_stable_migration_endpoints_disabled() {
    let send_args = SendArgs {
        memo: icp_ledger::Memo::default(),
        amount: Tokens::from_e8s(1),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: PrincipalId::new_user_test_id(2).into(),
        created_at_time: None,
    };

    let send_dfx_args = Encode!(&send_args).unwrap();
    let send_pb_args = ProtoBuf(send_args).into_bytes().unwrap();

    let ai = AccountIdentifier { hash: [1u8; 28] };
    let transfer_args = Encode!(&icp_ledger::TransferArgs {
        memo: icp_ledger::Memo::default(),
        amount: Tokens::from_e8s(1),
        fee: Tokens::from_e8s(10_000),
        from_subaccount: None,
        to: ai.to_address(),
        created_at_time: None,
    })
    .unwrap();

    ic_ledger_suite_state_machine_tests::icrc1_test_stable_migration_endpoints_disabled(
        ledger_wasm_mainnet(),
        ledger_wasm_low_instruction_limits(),
        encode_init_args,
        vec![
            ("send_pb", send_pb_args),
            ("send_dfx", send_dfx_args),
            ("transfer", transfer_args),
        ],
    );
}

#[ignore] // TODO: Re-enable as part of FI-1440
#[test]
fn test_incomplete_migration() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration(
        ledger_wasm_mainnet(),
        ledger_wasm_low_instruction_limits(),
        encode_init_args,
    );
}

#[ignore] // TODO: Re-enable as part of FI-1440
#[test]
fn test_incomplete_migration_to_current() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration_to_current(
        ledger_wasm_mainnet(),
        ledger_wasm_low_instruction_limits(),
        encode_init_args,
    );
}

#[ignore] // TODO: Re-enable as part of FI-1440
#[test]
fn test_metrics_while_migrating() {
    ic_ledger_suite_state_machine_tests::test_metrics_while_migrating(
        ledger_wasm_mainnet(),
        ledger_wasm_low_instruction_limits(),
        encode_init_args,
    );
}

#[test]
fn test_approve_smoke() {
    ic_ledger_suite_state_machine_tests::test_approve_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expiration() {
    ic_ledger_suite_state_machine_tests::test_approve_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_self() {
    ic_ledger_suite_state_machine_tests::test_approve_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expected_allowance() {
    ic_ledger_suite_state_machine_tests::test_approve_expected_allowance(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_approve_cant_pay_fee() {
    ic_ledger_suite_state_machine_tests::test_approve_cant_pay_fee(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cap() {
    ic_ledger_suite_state_machine_tests::test_approve_cap::<LedgerCanisterInitPayload, Tokens>(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_approve_pruning() {
    ic_ledger_suite_state_machine_tests::test_approve_pruning(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_from_minter() {
    ic_ledger_suite_state_machine_tests::test_approve_from_minter(ledger_wasm(), encode_init_args);
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
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 130_000);
    assert_eq!(balance_of(&env, canister_id, from.0), 70_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 10_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

#[test]
fn test_transfer_from_smoke() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_self() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_minter() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_burn() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_balances_overflow() {
    ic_ledger_suite_state_machine_tests::test_balances_overflow(ledger_wasm(), encode_init_args);
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

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // mint block
    let mint_time = system_time_to_nanos(env.time());
    transfer(&env, ledger, MINTER, user1, 2_000_000_000).unwrap();
    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // burn block
    let burn_time = system_time_to_nanos(env.time());
    transfer(&env, ledger, user1, MINTER, 1_000_000_000).unwrap();
    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // xfer block
    let xfer_time = system_time_to_nanos(env.time());
    transfer(&env, ledger, user1, user2, 100_000_000).unwrap();
    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    // approve block
    let approve_time = system_time_to_nanos(env.time());
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
                length: *length
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
    ic_ledger_suite_state_machine_tests::test_icrc21_standard(ledger_wasm(), encode_init_args);
}

#[test]
fn test_query_blocks_large_length() {
    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    for i in 0..MAX_BLOCKS_PER_REQUEST + 1 {
        let user = PrincipalId::new_user_test_id(i as u64);
        initial_balances.insert(Account::from(user.0).into(), Tokens::from_e8s(100_000));
    }
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .initial_values(initial_balances)
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(ledger_wasm(), Encode!(&payload).unwrap(), None)
        .expect("Unable to install the Ledger canister with the new init");

    // query_blocks
    let res = Decode!(
        &env.execute_ingress(
            canister_id,
            "query_blocks",
            Encode!(&GetBlocksArgs {
                start: 0,
                // If this is cast (in a wasm32 ledger) using `as usize`, it will overflow to 0u32.
                length: (u32::MAX as u64) + 1
            })
            .unwrap()
        )
        .expect("failed to query blocks")
        .bytes(),
        QueryBlocksResponse
    )
    .expect("should successfully decode QueryBlocksResponse");
    // Verify that we have more blocks in the ledger than can be returned in a single query.
    assert_eq!(res.chain_length, (MAX_BLOCKS_PER_REQUEST + 1) as u64);
    // Verify that the number of blocks in the response is limited to MAX_BLOCKS_PER_REQUEST.
    assert_eq!(res.blocks.len(), MAX_BLOCKS_PER_REQUEST);
    // Also verify that the maximum number of blocks per request is larger than 0, in case the
    // length `(u32::MAX as u64) + 1` in the request was incorrectly cast to a wasm32 `usize`
    // (`u32`)).
    if MAX_BLOCKS_PER_REQUEST == 0 {
        panic!("MAX_BLOCKS_PER_REQUEST should be larger than 0");
    }
}

#[test]
fn test_account_balance_non_standard_account_identifier_length() {
    let env = StateMachine::new();
    let mut initial_balances = HashMap::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let expected_balance = Tokens::from_e8s(100_000);
    initial_balances.insert(
        AccountIdentifier::from(Account::from(p1.0)),
        expected_balance,
    );
    let payload = LedgerCanisterInitPayload::builder()
        .minting_account(MINTER.into())
        .initial_values(initial_balances)
        .build()
        .unwrap();
    let canister_id = env
        .install_canister(ledger_wasm(), Encode!(&payload).unwrap(), None)
        .expect("Unable to install the Ledger canister with the new init");

    // account balance of account identifier of correct length
    let valid_account_identifier_bytes = ByteBuf::from(AccountIdentifier::from(p1.0).to_vec());
    assert_eq!(valid_account_identifier_bytes.len(), 32);
    let res = Decode!(
        &env.execute_ingress(
            canister_id,
            "account_balance",
            Encode!(&AccountIdentifierByteBuf {
                account: valid_account_identifier_bytes
            })
            .unwrap()
        )
        .expect("failed to query account_balance")
        .bytes(),
        Tokens
    )
    .expect("should successfully decode Tokens");
    assert_eq!(res, expected_balance);

    // account balance of account identifier of zero length
    let res = Decode!(
        &env.execute_ingress(
            canister_id,
            "account_balance",
            Encode!(&AccountIdentifierByteBuf {
                account: ByteBuf::from(vec![0; 0])
            })
            .unwrap()
        )
        .expect("failed to query account_balance")
        .bytes(),
        Tokens
    )
    .expect("should successfully decode Tokens");
    assert_eq!(res, Tokens::from_e8s(0));
}

mod metrics {
    use crate::{encode_init_args, encode_upgrade_args, ledger_wasm};
    use ic_ledger_suite_state_machine_tests::metrics::LedgerSuiteType;

    #[test]
    fn should_export_num_archives_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_ledger_num_archives_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_ledger_heap_memory_usage_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_heap_memory_bytes_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_ledger_total_blocks_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_ledger_total_transactions_metric(
            ledger_wasm(),
            encode_init_args,
            LedgerSuiteType::ICP,
        );
    }

    #[test]
    fn should_set_ledger_upgrade_instructions_consumed_metric() {
        ic_ledger_suite_state_machine_tests::metrics::assert_ledger_upgrade_instructions_consumed_metric_set(
            ledger_wasm(),
            encode_init_args,
            encode_upgrade_args,
        );
    }
}
