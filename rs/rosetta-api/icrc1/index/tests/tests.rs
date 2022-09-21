use std::path::PathBuf;

use candid::{Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError, Value},
    Account, Subaccount,
};
use ic_icrc1_index::{
    GetAccountTransactionsArgs, GetTransactionsResult, InitArgs as IndexInitArgs,
    ListSubaccountsArgs, TransactionWithId,
};
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockIndex;
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::cast::ToPrimitive;

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: u64 = 5;
// const TX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]),
    subaccount: None,
};

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";
const TEXT_META_KEY: &str = "test:image";
const TEXT_META_VALUE: &str = "grumpy_cat.png";
const BLOB_META_KEY: &str = "test:blob";
const BLOB_META_VALUE: &[u8] = b"\xca\xfe\xba\xbe";
const NAT_META_KEY: &str = "test:nat";
const NAT_META_VALUE: u128 = u128::MAX;
const INT_META_KEY: &str = "test:int";
const INT_META_VALUE: i128 = i128::MIN;

fn index_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-index",
        &[],
    )
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("ledger"),
        "ic-icrc1-ledger",
        &[],
    )
}

fn install_ledger(env: &StateMachine, initial_balances: Vec<(Account, u64)>) -> CanisterId {
    let args = LedgerInitArgs {
        minting_account: MINTER.clone(),
        initial_balances,
        transfer_fee: FEE,
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            cycles_for_archive_creation: None,
        },
    };
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_index(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = IndexInitArgs { ledger_id };
    env.install_canister(index_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn send_transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: PrincipalId,
    arg: &TransferArg,
) -> Result<BlockIndex, TransferError> {
    Decode!(
        &env.execute_ingress_as(
            from,
            ledger,
            "icrc1_transfer",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to transfer funds")
        .bytes(),
        Result<Nat, TransferError>
    )
    .expect("failed to decode transfer response")
    .map(|n| n.0.to_u64().unwrap())
}

fn check_mint(id: u64, to: Account, amount: u64, transaction: &TransactionWithId) {
    assert_eq!("mint".to_string(), transaction.transaction.kind);
    let mint = transaction.transaction.mint.as_ref().unwrap();
    assert_eq!(
        (&transaction.id, &mint.to, &mint.amount, &mint.memo),
        (&Nat::from(id), &to, &Nat::from(amount), &None)
    )
}

fn check_burn(id: u64, from: Account, amount: u64, transaction: &TransactionWithId) {
    assert_eq!("burn".to_string(), transaction.transaction.kind);
    let burn = transaction.transaction.burn.as_ref().unwrap();
    assert_eq!(
        (&transaction.id, &burn.from, &burn.amount, &burn.memo),
        (&Nat::from(id), &from, &Nat::from(amount), &None)
    )
}

fn check_transfer(
    id: u64,
    from: Account,
    to: Account,
    amount: u64,
    transaction: &TransactionWithId,
) {
    assert_eq!("transfer".to_string(), transaction.transaction.kind);
    let transfer = transaction.transaction.transfer.as_ref().unwrap();
    assert_eq!(
        (
            &transaction.id,
            &transfer.from,
            &transfer.to,
            &transfer.amount,
            &transfer.memo
        ),
        (&Nat::from(id), &from, &to, &Nat::from(amount), &None)
    )
}

fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    send_transfer(
        env,
        ledger,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to,
            fee: None,
            created_at_time: None,
            amount: Nat::from(amount),
            memo: None,
        },
    )
    .unwrap()
}

fn burn(env: &StateMachine, ledger: CanisterId, from: Account, amount: u64) -> BlockIndex {
    transfer(env, ledger, from, MINTER, amount)
}

fn mint(env: &StateMachine, ledger: CanisterId, to: Account, amount: u64) -> BlockIndex {
    transfer(env, ledger, MINTER, to, amount)
}

fn get_account_transactions(
    env: &StateMachine,
    index: CanisterId,
    account: Account,
    start: Option<u64>,
    max_results: u64,
) -> Vec<TransactionWithId> {
    Decode!(
        &env.execute_ingress_as(
            account.owner,
            index,
            "get_account_transactions",
            Encode!(&GetAccountTransactionsArgs {
                account,
                start: start.map(Nat::from),
                max_results: Nat::from(max_results),
            })
            .unwrap()
        )
        .expect("failed to get_account_transactions")
        .bytes(),
        GetTransactionsResult
    )
    .expect("failed to decode get_account_transactions response")
    .expect("failed to get the range of transactions!")
    .transactions
}

fn list_subaccounts(
    env: &StateMachine,
    index: CanisterId,
    account: Account,
    start: Option<Subaccount>,
) -> Vec<Subaccount> {
    Decode!(
        &env.execute_ingress_as(
            account.owner,
            index,
            "list_subaccounts",
            Encode!(&ListSubaccountsArgs {
                owner: account.owner,
                start,
            })
            .unwrap()
        )
        .expect("failed to list_subaccounts")
        .bytes(),
        Vec<Subaccount>
    )
    .expect("failed to decode list_subaccounts response")
}

fn account(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n),
        subaccount: None,
    }
}

fn account_with_subaccount(n: u64, s: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&s.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(n),
        subaccount: Some(sub),
    }
}

#[test]
fn test() {
    //Adding tokens to 2_000 subaccounts of one principal
    let offset: u64 = 2_000; // The offset is the number of transactions we add to the ledger at initialization

    let initial_balances: Vec<_> = (0..2_000u128)
        .map(|i| (account_with_subaccount(10, i), 1))
        .collect();

    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, initial_balances);

    let index_id = install_index(&env, ledger_id);

    env.run_until_completion(10_000);

    // add some transactions
    mint(&env, ledger_id, account(1), 100000); // block=0
    mint(&env, ledger_id, account(2), 200000); // block=1
    transfer(&env, ledger_id, account(1), account(2), 1); // block=2
    transfer(&env, ledger_id, account(2), account(1), 10); // block=3
    transfer(&env, ledger_id, account(2), account(1), 20); // block=4
    burn(&env, ledger_id, account(1), 10000); // block=5

    env.tick(); // trigger index heartbeat

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    assert_eq!(5, txs.len());
    check_burn(5 + offset, account(1), 10000, txs.get(0).unwrap());
    check_transfer(4 + offset, account(2), account(1), 20, txs.get(1).unwrap());
    check_transfer(3 + offset, account(2), account(1), 10, txs.get(2).unwrap());
    check_transfer(2 + offset, account(1), account(2), 1, txs.get(3).unwrap());
    check_mint(offset, account(1), 100000, txs.get(4).unwrap());

    let txs = get_account_transactions(&env, index_id, account(2), None, u64::MAX);
    assert_eq!(4, txs.len());
    check_transfer(4 + offset, account(2), account(1), 20, txs.get(0).unwrap());
    check_transfer(3 + offset, account(2), account(1), 10, txs.get(1).unwrap());
    check_transfer(2 + offset, account(1), account(2), 1, txs.get(2).unwrap());
    check_mint(1 + offset, account(2), 200000, txs.get(3).unwrap());

    // // add more transactions
    transfer(&env, ledger_id, account(1), account(3), 6); // block=6
    transfer(&env, ledger_id, account(1), account(2), 7); // block=7

    env.tick(); // trigger index heartbeat

    // fetch the more recent transfers
    let txs = get_account_transactions(&env, index_id, account(1), Some(offset + 8), 2);
    check_transfer(7 + offset, account(1), account(2), 7, txs.get(0).unwrap());
    check_transfer(6 + offset, account(1), account(3), 6, txs.get(1).unwrap());

    // // fetch two older transaction by setting a start to the oldest tx id seen
    let txs = get_account_transactions(&env, index_id, account(1), Some(offset + 5), 2);
    check_burn(5 + offset, account(1), 10000, txs.get(0).unwrap());
    check_transfer(4 + offset, account(2), account(1), 20, txs.get(1).unwrap());

    // verify if we can query the first 1_000 subaccounts of a principal
    let subs: Vec<Subaccount> = list_subaccounts(&env, index_id, account(10), None);
    assert_eq!(1000, subs.len());

    //verify if we can query the 500 last subaccounts by adding a start parameter to the list_subaccounts call
    let start_sub: u128 = 1500;
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&start_sub.to_be_bytes());
    let subs: Vec<Subaccount> = list_subaccounts(&env, index_id, account(10), Some(sub));
    assert_eq!(500, subs.len());
}
