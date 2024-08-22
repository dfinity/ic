use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1::{Block, Operation, Transaction};
use ic_icrc1_index::{
    GetAccountTransactionsArgs, GetTransactions, GetTransactionsResult, InitArgs as IndexInitArgs,
    ListSubaccountsArgs, TransactionWithId,
};
use ic_icrc1_ledger::{FeatureFlags, InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_icrc1_tokens_u64::U64;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::{
    block::{BlockIndex, BlockType, EncodedBlock},
    timestamp::TimeStamp,
    tokens::Zero,
};
use ic_ledger_hash_of::HashOf;
use ic_rosetta_test_utils::test_http_request_decoding_quota;
use ic_state_machine_tests::{CanisterId, StateMachine};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::{
    icrc1::account::Account, icrc1::account::Subaccount, icrc3::archive::ArchiveInfo,
};
use num_traits::cast::ToPrimitive;
use std::path::PathBuf;
use std::time::Duration;

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;
const MINT_BLOCKS_PER_ARCHIVE: u64 = 5;

const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]).0,
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

type Tokens = U64;

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

fn mint_block() -> EncodedBlock {
    Block::<Tokens>::from_transaction(
        Some(HashOf::new([0; 32])),
        Transaction {
            operation: Operation::Mint {
                to: account(0),
                amount: Tokens::new(1),
            },
            created_at_time: Some(1),
            memo: Some(Memo::from([1; 32].to_vec())),
        },
        TimeStamp::new(3, 4),
        Tokens::zero(),
        None,
    )
    .encode()
}

fn default_archive_options() -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
        num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_user_test_id(100),
        more_controller_ids: None,
        cycles_for_archive_creation: None,
        max_transactions_per_response: None,
    }
}

fn install_ledger(
    env: &StateMachine,
    initial_balances: Vec<(Account, u64)>,
    archive_options: ArchiveOptions,
) -> CanisterId {
    let mut builder = LedgerInitArgsBuilder::with_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .with_minting_account(MINTER)
        .with_transfer_fee(FEE)
        .with_metadata_entry(NAT_META_KEY, NAT_META_VALUE)
        .with_metadata_entry(INT_META_KEY, INT_META_VALUE)
        .with_metadata_entry(TEXT_META_KEY, TEXT_META_VALUE)
        .with_metadata_entry(BLOB_META_KEY, BLOB_META_VALUE)
        .with_archive_options(archive_options)
        .with_feature_flags(FeatureFlags { icrc2: true });
    for (account, amount) in initial_balances {
        builder = builder.with_initial_balance(account, amount);
    }

    env.install_canister(
        ledger_wasm(),
        Encode!(&LedgerArgument::Init(builder.build())).unwrap(),
        None,
    )
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

fn send_approval(
    env: &StateMachine,
    ledger: CanisterId,
    from: PrincipalId,
    arg: &ApproveArgs,
) -> Result<BlockIndex, ApproveError> {
    Decode!(
        &env.execute_ingress_as(
            from,
            ledger,
            "icrc2_approve",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to create an approval")
        .bytes(),
        Result<Nat, ApproveError>
    )
    .expect("failed to decode approve response")
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

fn check_approval(
    id: u64,
    from: Account,
    spender: Account,
    amount: u64,
    transaction: &TransactionWithId,
) {
    assert_eq!("approve".to_string(), transaction.transaction.kind);
    let approve = transaction.transaction.approve.as_ref().unwrap();
    assert_eq!(
        (
            &transaction.id,
            &approve.from,
            &approve.spender,
            &approve.amount,
            &approve.memo
        ),
        (&Nat::from(id), &from, &spender, &Nat::from(amount), &None)
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
        PrincipalId(from.owner),
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

fn approve(
    env: &StateMachine,
    ledger: CanisterId,
    from: Account,
    spender: Account,
    amount: u64,
) -> BlockIndex {
    send_approval(
        env,
        ledger,
        PrincipalId(from.owner),
        &ApproveArgs {
            from_subaccount: from.subaccount,
            spender,
            amount: Nat::from(amount),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    )
    .unwrap()
}

fn archives(env: &StateMachine, ledger: CanisterId) -> Vec<ArchiveInfo> {
    Decode!(
        &env.query(ledger, "archives", Encode!().unwrap())
            .expect("failed to transfer funds")
            .bytes(),
        Vec<ArchiveInfo>
    )
    .unwrap()
}

fn get_account_transactions(
    env: &StateMachine,
    index: CanisterId,
    account: Account,
    start: Option<u64>,
    max_results: u64,
) -> GetTransactions {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(account.owner),
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
}

fn list_subaccounts(
    env: &StateMachine,
    index: CanisterId,
    account: Account,
    start: Option<Subaccount>,
) -> Vec<Subaccount> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(account.owner),
            index,
            "list_subaccounts",
            Encode!(&ListSubaccountsArgs {
                owner: PrincipalId(account.owner),
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

fn index_ledger_id(env: &StateMachine, index: CanisterId) -> CanisterId {
    Decode!(
        &env.query(index, "ledger_id", Encode!().unwrap())
            .expect("Unable to query ledger_id from index")
            .bytes(),
        CanisterId
    )
    .expect("failed to decode ledger_id response")
}

fn account(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n).0,
        subaccount: None,
    }
}

fn account_with_subaccount(n: u64, s: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&s.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(n).0,
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

    let ledger_id = install_ledger(&env, initial_balances, default_archive_options());

    let index_id = install_index(&env, ledger_id);

    assert_eq!(ledger_id, index_ledger_id(&env, index_id));

    for _ in 0..100 {
        env.advance_time(Duration::from_secs(60));
        env.tick();
    }

    // add some transactions
    mint(&env, ledger_id, account(1), 100000); // block=0
    mint(&env, ledger_id, account(2), 200000); // block=1
    transfer(&env, ledger_id, account(1), account(2), 1); // block=2
    transfer(&env, ledger_id, account(2), account(1), 10); // block=3
    transfer(&env, ledger_id, account(2), account(1), 20); // block=4
    burn(&env, ledger_id, account(1), 10000); // block=5

    env.advance_time(Duration::from_secs(60));
    env.tick(); // trigger index heartbeat

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    assert_eq!(Some(Nat::from(offset)), txs.oldest_tx_id);
    let txs = txs.transactions;
    assert_eq!(5, txs.len());
    check_burn(5 + offset, account(1), 10000, txs.first().unwrap());
    check_transfer(4 + offset, account(2), account(1), 20, txs.get(1).unwrap());
    check_transfer(3 + offset, account(2), account(1), 10, txs.get(2).unwrap());
    check_transfer(2 + offset, account(1), account(2), 1, txs.get(3).unwrap());
    check_mint(offset, account(1), 100000, txs.get(4).unwrap());

    let txs = get_account_transactions(&env, index_id, account(2), None, u64::MAX);
    assert_eq!(Some(Nat::from(1 + offset)), txs.oldest_tx_id);
    let txs = txs.transactions;
    assert_eq!(4, txs.len());
    check_transfer(4 + offset, account(2), account(1), 20, txs.first().unwrap());
    check_transfer(3 + offset, account(2), account(1), 10, txs.get(1).unwrap());
    check_transfer(2 + offset, account(1), account(2), 1, txs.get(2).unwrap());
    check_mint(1 + offset, account(2), 200000, txs.get(3).unwrap());

    // // add more transactions
    transfer(&env, ledger_id, account(1), account(3), 6); // block=6
    transfer(&env, ledger_id, account(1), account(2), 7); // block=7

    // add an approval
    approve(&env, ledger_id, account(1), account(4), 10); // block=8

    env.advance_time(Duration::from_secs(60));
    env.tick(); // trigger index heartbeat

    // fetch the more recent transfers and approvals
    let txs = get_account_transactions(&env, index_id, account(1), Some(offset + 9), 3);
    assert_eq!(Some(Nat::from(offset)), txs.oldest_tx_id);
    let txs = txs.transactions;
    check_approval(8 + offset, account(1), account(4), 10, txs.first().unwrap());
    check_transfer(7 + offset, account(1), account(2), 7, txs.get(1).unwrap());
    check_transfer(6 + offset, account(1), account(3), 6, txs.get(2).unwrap());

    // fetch transactions for the receiver of the approval
    let txs = get_account_transactions(&env, index_id, account(4), Some(offset + 9), u64::MAX);
    assert_eq!(Some(Nat::from(offset + 8)), txs.oldest_tx_id);
    let txs = txs.transactions;
    assert_eq!(1, txs.len());
    check_approval(8 + offset, account(1), account(4), 10, txs.first().unwrap());

    // // fetch two older transaction by setting a start to the oldest tx id seen
    let txs = get_account_transactions(&env, index_id, account(1), Some(offset + 5), 2);
    assert_eq!(Some(Nat::from(offset)), txs.oldest_tx_id);
    let txs = txs.transactions;
    check_burn(5 + offset, account(1), 10000, txs.first().unwrap());
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

#[test]
fn test_wait_time() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, vec![], default_archive_options());
    let index_id = install_index(&env, ledger_id);

    env.tick();

    // add some transactions
    mint(&env, ledger_id, account(1), 100000); // block=0
    mint(&env, ledger_id, account(2), 200000); // block=1
    transfer(&env, ledger_id, account(1), account(2), 1); // block=2
    transfer(&env, ledger_id, account(2), account(1), 10); // block=3
    burn(&env, ledger_id, account(1), 10000); // block=4

    env.advance_time(Duration::from_secs(10));
    env.tick();

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    assert!(!txs.transactions.is_empty());

    // Next heartbeat should happen 60 seconds later, as we only indexed
    // 5 transactions.
    mint(&env, ledger_id, account(3), 100000); // block=5
    env.tick(); // trigger index heartbeat that shouldn't index new transactions.

    let txs = get_account_transactions(&env, index_id, account(3), None, u64::MAX);
    assert!(txs.transactions.is_empty());
    env.advance_time(Duration::from_secs(1));
    env.tick();

    let txs = get_account_transactions(&env, index_id, account(3), None, u64::MAX);
    assert!(txs.transactions.is_empty());

    env.advance_time(Duration::from_secs(1));
    env.tick();

    let txs = get_account_transactions(&env, index_id, account(3), None, u64::MAX);
    assert!(!txs.transactions.is_empty());
}

#[test]
fn test_upgrade() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, vec![], default_archive_options());
    let index_id = install_index(&env, ledger_id);

    // add some transactions
    mint(&env, ledger_id, account(1), 100000); // block=0
    transfer(&env, ledger_id, account(1), account(2), 1); // block=1

    env.advance_time(Duration::from_secs(60));
    env.tick();
    // upgrade the Index
    env.upgrade_canister(index_id, index_wasm(), vec![])
        .expect("Failed to upgrade the Index canister");

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    let txs = txs.transactions;
    check_mint(0, account(1), 100000, txs.get(1).unwrap());
    check_transfer(1, account(1), account(2), 1, txs.first().unwrap());
}

#[test]
fn test_ledger_stopped() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, vec![], default_archive_options());
    let index_id = install_index(&env, ledger_id);

    mint(&env, ledger_id, account(1), 100000); // block=0
    transfer(&env, ledger_id, account(1), account(2), 1); // block=1

    env.advance_time(Duration::from_secs(60));
    env.tick();

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    let txs = txs.transactions;
    check_mint(0, account(1), 100000, txs.get(1).unwrap());
    check_transfer(1, account(1), account(2), 1, txs.first().unwrap());

    let stop_result = env.stop_canister(ledger_id);
    assert_matches!(stop_result, Ok(_));

    env.advance_time(Duration::from_secs(60));
    env.tick();

    let start_result = env.start_canister(ledger_id);
    assert_matches!(start_result, Ok(_));

    mint(&env, ledger_id, account(1), 100000); // block=2
    transfer(&env, ledger_id, account(1), account(2), 1); // block=3
    env.advance_time(Duration::from_secs(60));
    env.tick();

    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    let txs = txs.transactions;
    check_mint(2, account(1), 100000, txs.get(1).unwrap());
    check_transfer(3, account(1), account(2), 1, txs.first().unwrap());
}

#[test]
fn test_index_archived_txs() {
    let env = StateMachine::new();

    // we want to create two archives. Each archive holds MINT_BLOCKS_PER_ARCHIVE mint blocks
    // and the trigger threshold is ARCHIVE_TRIGGER_THRESHOLD
    let num_txs = ARCHIVE_TRIGGER_THRESHOLD + MINT_BLOCKS_PER_ARCHIVE;

    // install the ledger and add enough transactions to create an archive
    let ledger_id = install_ledger(
        &env,
        vec![],
        ArchiveOptions {
            node_max_memory_size_bytes: Some(
                MINT_BLOCKS_PER_ARCHIVE * mint_block().size_bytes() as u64,
            ),
            ..default_archive_options()
        },
    );
    for idx in 0..num_txs {
        mint(&env, ledger_id, account(1), idx);
    }
    assert_eq!(2, archives(&env, ledger_id).len());

    // install the index and let it index all the transaction
    let index_id = install_index(&env, ledger_id);
    for _ in 0..10 {
        env.advance_time(Duration::from_secs(60));
        env.tick();
    }
    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    let txs = txs.transactions;
    assert_eq!(num_txs, txs.len() as u64);
    for idx in 0..num_txs {
        assert_eq!(
            Nat::from(idx),
            txs.get((num_txs - idx - 1) as usize)
                .unwrap_or_else(|| panic!("Transaction {} not found in index!", num_txs - idx - 1))
                .id
        );
    }
}

#[test]
fn test_index_archived_txs_paging() {
    // The archive node does paging when there are too many transactions.
    // This test verifies that the Index canister respects the paging.
    const MAX_TXS_PER_GET_TRANSACTIONS_RESPONSE: u64 = 1;
    const NUM_ARCHIVED_TXS: usize = 2;

    let env = StateMachine::new();

    // install the ledger and add enough transactions to create an archive
    let ledger_id = install_ledger(
        &env,
        vec![],
        ArchiveOptions {
            num_blocks_to_archive: NUM_ARCHIVED_TXS,
            max_transactions_per_response: Some(MAX_TXS_PER_GET_TRANSACTIONS_RESPONSE),
            ..default_archive_options()
        },
    );
    for idx in 0..ARCHIVE_TRIGGER_THRESHOLD {
        mint(&env, ledger_id, account(1), idx);
    }

    // install the index and let it index all the transaction
    let index_id = install_index(&env, ledger_id);
    for _ in 0..10 {
        env.advance_time(Duration::from_secs(60));
        env.tick();
    }

    // check that the index has exactly indexed num_txs transactions
    let txs = get_account_transactions(&env, index_id, account(1), None, u64::MAX);
    let txs = txs.transactions;
    let actual_txids: Vec<u64> = txs.iter().map(|tx| tx.id.0.to_u64().unwrap()).collect();
    let expected_txids: Vec<u64> = (0..ARCHIVE_TRIGGER_THRESHOLD).rev().collect();
    assert_eq!(expected_txids, actual_txids);
}

#[test]
fn test_index_http_request_decoding_quota() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env, vec![], default_archive_options());
    let index_id = install_index(&env, ledger_id);

    test_http_request_decoding_quota(&env, index_id);
}

mod metrics {
    use crate::index_wasm;
    use candid::Principal;
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1_index::InitArgs;

    #[test]
    fn should_export_total_memory_usage_bytes_metrics() {
        ic_icrc1_ledger_sm_tests::metrics::assert_existence_of_index_total_memory_bytes_metric(
            index_wasm(),
            encode_init_args,
        );
    }

    fn encode_init_args(ledger_id: Principal) -> InitArgs {
        InitArgs {
            ledger_id: CanisterId::unchecked_from_principal(PrincipalId(ledger_id)),
        }
    }
}
