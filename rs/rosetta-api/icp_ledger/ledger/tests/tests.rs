use std::collections::{HashMap, HashSet};

use candid::{Decode, Encode, Nat};
use ic_icrc1_ledger_sm_tests::MINTER;
use ic_ledger_core::Tokens;
use ic_state_machine_tests::{ErrorCode, PrincipalId, StateMachine, UserError};
use icp_ledger::{AccountIdentifier, InitArgs, LedgerCanisterInitPayload, LedgerCanisterPayload};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg, TransferError},
};
use serde_bytes::ByteBuf;

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
        .map(|(account, amount)| (account.into(), Tokens::from_e8s(amount)))
        .collect();
    LedgerCanisterInitPayload::builder()
        .initial_values(initial_values)
        .minting_account(args.minting_account.into())
        .icrc1_minting_account(args.minting_account)
        .archive_options(args.archive_options)
        .transfer_fee(Tokens::from_e8s(args.transfer_fee))
        .token_symbol_and_name(&args.token_symbol, &args.token_name)
        .build()
        .unwrap()
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
fn test_memo_validation() {
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
            }
            .into(),
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
