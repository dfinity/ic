use std::path::PathBuf;

use candid::{Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError, Value},
    Account,
};
use ic_icrc1_index::{
    GetAccountTransactionsArgs, GetTransactionsResult, InitArgs as IndexInitArgs, TransactionWithId,
};
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockHeight;
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
) -> Result<BlockHeight, TransferError> {
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
) -> BlockHeight {
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

fn burn(env: &StateMachine, ledger: CanisterId, from: Account, amount: u64) -> BlockHeight {
    transfer(env, ledger, from, MINTER, amount)
}

fn mint(env: &StateMachine, ledger: CanisterId, to: Account, amount: u64) -> BlockHeight {
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
                start: start.map(|x| Nat::from(x)),
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

fn account(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n),
        subaccount: None,
    }
}

#[test]
fn test() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, vec![]);
    let index_id = install_index(&env, ledger_id);

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
    check_burn(5, account(1), 10000, txs.get(0).unwrap());
    check_transfer(4, account(2), account(1), 20, txs.get(1).unwrap());
    check_transfer(3, account(2), account(1), 10, txs.get(2).unwrap());
    check_transfer(2, account(1), account(2), 1, txs.get(3).unwrap());
    check_mint(0, account(1), 100000, txs.get(4).unwrap());

    let txs = get_account_transactions(&env, index_id, account(2), None, u64::MAX);
    assert_eq!(4, txs.len());
    check_transfer(4, account(2), account(1), 20, txs.get(0).unwrap());
    check_transfer(3, account(2), account(1), 10, txs.get(1).unwrap());
    check_transfer(2, account(1), account(2), 1, txs.get(2).unwrap());
    check_mint(1, account(2), 200000, txs.get(3).unwrap());

    // add more transactions
    transfer(&env, ledger_id, account(1), account(3), 6); // block=6
    transfer(&env, ledger_id, account(1), account(2), 7); // block=7

    env.tick(); // trigger index heartbeat

    // fetch the more recent transfers
    let txs = get_account_transactions(&env, index_id, account(1), Some(8), 2);
    check_transfer(7, account(1), account(2), 7, txs.get(0).unwrap());
    check_transfer(6, account(1), account(3), 6, txs.get(1).unwrap());

    // fetch two older transaction by setting a start to the oldest tx id seen
    let txs = get_account_transactions(&env, index_id, account(1), Some(5), 2);
    check_burn(5, account(1), 10000, txs.get(0).unwrap());
    check_transfer(4, account(2), account(1), 20, txs.get(1).unwrap());
}
