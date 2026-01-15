use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_index::{
    GetAccountIdentifierTransactionsArgs, GetAccountIdentifierTransactionsResponse,
    GetAccountIdentifierTransactionsResult, SettledTransaction, SettledTransactionWithId,
};
use ic_icrc1_index_ng::GetAccountTransactionsArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_suite_state_machine_tests::test_http_request_decoding_quota;
use ic_ledger_test_utils::state_machine_helpers::index::{
    SYNC_STEP_SECONDS, wait_until_sync_is_completed,
};
use ic_ledger_test_utils::state_machine_helpers::ledger::{icp_get_blocks, icp_query_blocks};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST, MAX_BLOCKS_PER_REQUEST,
    Transaction,
};
use icp_ledger::{FeatureFlags, LedgerCanisterInitPayload, Memo, Operation};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, NumTokens, TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use num_traits::cast::ToPrimitive;
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;

const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";

#[derive(Clone, Debug)]
struct ApproveTestArgs(pub ApproveArgs);
impl ApproveTestArgs {
    fn new(from: Account, spender: Account, amount: u64) -> Self {
        Self(ApproveArgs {
            from_subaccount: from.subaccount,
            spender,
            amount: amount.into(),
            created_at_time: None,
            fee: None,
            memo: None,
            expected_allowance: None,
            expires_at: None,
        })
    }
    fn created_at_time(&mut self, created_at_time: Option<u64>) -> Self {
        self.0.created_at_time = created_at_time;
        self.clone()
    }
    fn fee(&mut self, fee: Option<Nat>) -> Self {
        self.0.fee = fee;
        self.clone()
    }
    fn memo(&mut self, memo: Option<Vec<u8>>) -> Self {
        self.0.memo = memo.map(|b| icrc_ledger_types::icrc1::transfer::Memo(ByteBuf::from(b)));
        self.clone()
    }
    fn expected_allowance(&mut self, expected_allowance: Option<Nat>) -> Self {
        self.0.expected_allowance = expected_allowance;
        self.clone()
    }
    fn expires_at(&mut self, expires_at: Option<u64>) -> Self {
        self.0.expires_at = expires_at;
        self.clone()
    }
}

fn index_wasm() -> Vec<u8> {
    println!("Getting Index Wasm");
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icp-index",
        &[],
    )
}

fn ledger_wasm() -> Vec<u8> {
    println!("Getting Ledger Wasm");
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("ledger"),
        "ledger-canister",
        &[],
    )
}

fn default_archive_options() -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
        num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_user_test_id(100),
        more_controller_ids: None,
        cycles_for_archive_creation: Some(0),
        max_transactions_per_response: None,
    }
}

fn install_ledger(
    env: &StateMachine,
    initial_balances: HashMap<AccountIdentifier, Tokens>,
    archive_options: ArchiveOptions,
) -> CanisterId {
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(MINTER_PRINCIPAL, None))
        .transfer_fee(Tokens::from_e8s(FEE))
        .token_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .archive_options(archive_options)
        .initial_values(initial_balances)
        .feature_flags(FeatureFlags { icrc2: true })
        .build()
        .unwrap();
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_index(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = ic_icp_index::InitArg {
        ledger_id: ledger_id.into(),
    };
    env.install_canister(index_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

fn icrc1_balance_of(env: &StateMachine, canister_id: CanisterId, account: Account) -> u64 {
    let res = env
        .query(canister_id, "icrc1_balance_of", Encode!(&account).unwrap())
        .expect("Failed to send icrc1_balance_of")
        .bytes();
    Decode!(&res, Nat)
        .expect("Failed to decode icrc1_balance_of response")
        .0
        .to_u64()
        .expect("Balance must be a u64!")
}

fn index_balance_of(env: &StateMachine, canister_id: CanisterId, account: Account) -> u64 {
    let res = env
        .query(canister_id, "icrc1_balance_of", Encode!(&account).unwrap())
        .expect("Failed to send icrc1_balance_of")
        .bytes();
    let account_balance =
        Decode!(&res, u64).expect("Failed to decode get_account_balance response");
    let res = env
        .query(
            canister_id,
            "get_account_identifier_balance",
            Encode!(&AccountIdentifier::from(account)).unwrap(),
        )
        .expect("Failed to send get_account_identifier_balance")
        .bytes();
    let accountidentifier_balance =
        Decode!(&res, u64).expect("Failed to decode get_account_identifier_balance response");
    assert_eq!(account_balance, accountidentifier_balance);
    accountidentifier_balance
}

fn index_get_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let query = |req: Vec<u8>| {
        env.query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes()
    };
    call_index_get_blocks(&query)
}

fn index_get_blocks_update(
    env: &StateMachine,
    index_id: CanisterId,
    caller: Principal,
) -> Vec<icp_ledger::Block> {
    let update = |req: Vec<u8>| {
        env.execute_ingress_as(PrincipalId(caller), index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes()
    };
    call_index_get_blocks(&update)
}

fn call_index_get_blocks(query_or_update: &dyn Fn(Vec<u8>) -> Vec<u8>) -> Vec<icp_ledger::Block> {
    let req = GetBlocksRequest {
        start: 0u8.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = query_or_update(req);
    Decode!(&res, ic_icp_index::GetBlocksResponse)
        .expect("Failed to decode ic_icp_index::GetBlocksResponse")
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn get_account_id_transactions_len(
    env: &StateMachine,
    index_id: CanisterId,
    account: &Account,
) -> usize {
    let query = |req: Vec<u8>| {
        env.query(index_id, "get_account_identifier_transactions", req)
            .expect("Failed to send get_account_identifier_transactions request")
            .bytes()
    };
    call_get_account_id_transactions(&query, account)
}

fn get_account_id_transactions_update_len(
    env: &StateMachine,
    index_id: CanisterId,
    caller: Principal,
    account: &Account,
) -> usize {
    let update = |req: Vec<u8>| {
        env.execute_ingress_as(
            PrincipalId(caller),
            index_id,
            "get_account_identifier_transactions",
            req,
        )
        .expect("Failed to send get_account_identifier_transactions request")
        .bytes()
    };
    call_get_account_id_transactions(&update, account)
}

fn call_get_account_id_transactions(
    query_or_update: &dyn Fn(Vec<u8>) -> Vec<u8>,
    account: &Account,
) -> usize {
    let req = GetAccountIdentifierTransactionsArgs {
        start: None,
        max_results: u64::MAX,
        account_identifier: (*account).into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountIdentifierTransactionsArgs");
    let res = query_or_update(req);
    Decode!(&res, ic_icp_index::GetAccountIdentifierTransactionsResult)
        .expect("Failed to decode ic_icp_index::GetAccountIdentifierTransactionsResult")
        .unwrap()
        .transactions
        .len()
}

fn get_account_transactions_len(
    env: &StateMachine,
    index_id: CanisterId,
    account: &Account,
) -> usize {
    let query = |req: Vec<u8>| {
        env.query(index_id, "get_account_transactions", req)
            .expect("Failed to send get_account_transactions request")
            .bytes()
    };
    call_get_account_transactions(&query, account)
}

fn get_account_transactions_update_len(
    env: &StateMachine,
    index_id: CanisterId,
    caller: Principal,
    account: &Account,
) -> usize {
    let update = |req: Vec<u8>| {
        env.execute_ingress_as(
            PrincipalId(caller),
            index_id,
            "get_account_transactions",
            req,
        )
        .expect("Failed to send get_account_transactions request")
        .bytes()
    };
    call_get_account_transactions(&update, account)
}

fn call_get_account_transactions(
    query_or_update: &dyn Fn(Vec<u8>) -> Vec<u8>,
    account: &Account,
) -> usize {
    let req = GetAccountTransactionsArgs {
        start: None,
        max_results: u64::MAX.into(),
        account: *account,
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountTransactionsArgs");
    let res = query_or_update(req);
    Decode!(&res, ic_icp_index::GetAccountTransactionsResult)
        .expect("Failed to decode ic_icp_index::GetAccountTransactionsResult")
        .unwrap()
        .transactions
        .len()
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    icrc1_transfer(env, ledger_id, from, to, amount, None, None, None)
}

fn icrc1_transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
    created_at_time: Option<TimeStamp>,
    fee: Option<u64>,
    memo: Option<Vec<u8>>,
) -> BlockIndex {
    let Account { owner, subaccount } = from;
    let req = TransferArg {
        from_subaccount: subaccount,
        to,
        amount: NumTokens::from(amount),
        created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
        fee: fee.map(NumTokens::from),
        memo: memo.map(icrc_ledger_types::icrc1::transfer::Memo::from),
    };
    let req = Encode!(&req).expect("Failed to encode TransferArg");
    let res = env
        .execute_ingress_as(owner.into(), ledger_id, "icrc1_transfer", req)
        .expect("Failed to transfer tokens")
        .bytes();
    Decode!(&res, Result<BlockIndex, TransferError>)
        .expect("Failed to decode Result<BlockIndex, TransferError>")
        .expect("Failed to transfer tokens")
}

fn icrc2_transfer_from(
    env: &StateMachine,
    ledger_id: CanisterId,
    spender: Account,
    from: Account,
    to: Account,
    amount: u64,
    created_at_time: Option<TimeStamp>,
    fee: Option<u64>,
    memo: Option<Vec<u8>>,
) -> Nat {
    let req = TransferFromArgs {
        spender_subaccount: spender.subaccount,
        from,
        to,
        amount: Nat::from(amount),
        created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
        fee: fee.map(Nat::from),
        memo: memo.map(icrc_ledger_types::icrc1::transfer::Memo::from),
    };
    let req = Encode!(&req).expect("Failed to encode TransferFromArgs");
    let res = env
        .execute_ingress_as(
            ic_base_types::PrincipalId::from(spender.owner),
            ledger_id,
            "icrc2_transfer_from",
            req,
        )
        .expect("Failed to transfer tokens")
        .bytes();
    Decode!(&res, Result<Nat, TransferFromError>)
        .expect("Failed to decode Result<Nat, TransferFromError>")
        .expect("Failed to transfer tokens")
}

fn approve(
    env: &StateMachine,
    ledger_id: CanisterId,
    sender: Account,
    args: ApproveTestArgs,
) -> BlockIndex {
    let req = Encode!(&args.0).expect("Failed to encode ApproveArgs");
    let res = env
        .execute_ingress_as(sender.owner.into(), ledger_id, "icrc2_approve", req)
        .expect("Failed to create an approval")
        .bytes();
    Decode!(&res, Result<BlockIndex, ApproveError>)
        .expect("Failed to decode Result<BlockIndex, ApproveError>")
        .expect("Failed to create an approval")
}

fn get_account_identifier_transactions(
    env: &StateMachine,
    index_id: CanisterId,
    account: Account,
    start: Option<u64>,
    max_results: u64,
) -> GetAccountIdentifierTransactionsResponse {
    let req = GetAccountTransactionsArgs {
        start: start.map(Nat::from),
        max_results: Nat::from(max_results),
        account,
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountTransactionsArgs");
    let res = env
        .query(index_id, "get_account_transactions", req)
        .expect("Failed to get_account_transactions")
        .bytes();
    let account_txs = Decode!(&res, GetAccountIdentifierTransactionsResult)
        .expect("Failed to decode GetAccountIdentifierTransactionsArgs")
        .expect("Failed to perform GetAccountIdentifierTransactionsArgs");

    let req = GetAccountIdentifierTransactionsArgs {
        start,
        max_results,
        account_identifier: account.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountIdentifierTransactionsArgs");
    let res = env
        .query(index_id, "get_account_identifier_transactions", req)
        .expect("Failed to get_account_identifier_transactions")
        .bytes();
    let accountidentifier_txs = Decode!(&res, GetAccountIdentifierTransactionsResult)
        .expect("Failed to decode GetAccountIdentifierTransactionsArgs")
        .expect("Failed to perform GetAccountIdentifierTransactionsArgs");
    assert_eq!(accountidentifier_txs.balance, account_txs.balance);
    assert_eq!(accountidentifier_txs.oldest_tx_id, account_txs.oldest_tx_id);
    assert_eq!(accountidentifier_txs.transactions, account_txs.transactions);
    accountidentifier_txs
}

#[track_caller]
fn assert_tx_eq(tx1: &SettledTransaction, tx2: &SettledTransaction) {
    assert_eq!(tx1.operation, tx2.operation);
    assert_eq!(tx1.memo, tx2.memo);
    assert_eq!(tx1.icrc1_memo, tx2.icrc1_memo);
    assert_eq!(tx1.timestamp, tx2.timestamp);
}

// checks that two txs are equal minus the fields set by the ledger (e.g. timestamp)
#[track_caller]
fn assert_tx_with_id_eq(tx1: &SettledTransactionWithId, tx2: &SettledTransactionWithId) {
    assert_eq!(tx1.id, tx2.id, "id");
    assert_tx_eq(&tx1.transaction, &tx2.transaction);
}

#[track_caller]
fn assert_txs_with_id_eq(txs1: Vec<SettledTransactionWithId>, txs2: Vec<SettledTransactionWithId>) {
    assert_eq!(
        txs1.len(),
        txs2.len(),
        "Different number of transactions!\ntxs1: {:?}\ntxs2: {:?}",
        txs1.iter().map(|tx| tx.id).collect::<Vec<u64>>(),
        txs2.iter().map(|tx| tx.id).collect::<Vec<u64>>()
    );
    for i in 0..txs1.len() {
        assert_tx_with_id_eq(&txs1[i], &txs2[i]);
    }
}

// Assert that the index canister contains the same blocks as the ledger
fn assert_ledger_index_parity(
    env: &StateMachine,
    ledger_id: CanisterId,
    index_id: CanisterId,
) -> usize {
    let ledger_blocks = icp_get_blocks(env, ledger_id, None, None);
    let index_blocks = index_get_blocks(env, index_id);
    assert_eq!(ledger_blocks, index_blocks);
    ledger_blocks.len()
}

/// Assert that the index canister contains the same blocks as the ledger, by querying both the
/// `query_blocks` and `query_encoded_blocks` endpoints of the ledger.
fn assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    index_id: CanisterId,
) {
    let ledger_blocks = icp_get_blocks(env, ledger_id, None, None);
    let index_blocks = index_get_blocks(env, index_id);
    let ledger_unencoded_blocks = icp_query_blocks(env, ledger_id);
    assert_eq!(ledger_blocks, index_blocks);
    assert_eq!(ledger_blocks.len(), ledger_unencoded_blocks.len());
    if ledger_blocks != ledger_unencoded_blocks {
        // If the ledger blocks are not equal, we need some special handling to compare them.
        // If the client did not specify the `created_at_time` field when creating a transaction,
        // the ledger populates the `created_at_time` field with the value of the `timestamp` field
        // of the block, for blocks returned from the `query_blocks` endpoint. Blocks returned from
        // the `query_encoded_blocks` endpoint do not have the `created_at_time` field set.
        // Therefore, if the blocks do not match, verify that:
        //  - the `created_at_time` field of the encoded block is set `None`
        //  - the `created_at_time` field of the unencoded block is set to the `timestamp` field
        //    of the block
        //  - all the other fields of the blocks match
        for (ledger_block, unencoded_ledger_block) in ledger_blocks
            .into_iter()
            .zip(ledger_unencoded_blocks.into_iter())
        {
            if ledger_block != unencoded_ledger_block {
                if ledger_block.transaction.created_at_time.is_none() {
                    assert_eq!(
                        Some(unencoded_ledger_block.timestamp),
                        unencoded_ledger_block.transaction.created_at_time
                    );
                    let unencoded_ledger_block_without_created_at_time_in_tx = icp_ledger::Block {
                        transaction: Transaction {
                            created_at_time: None,
                            ..unencoded_ledger_block.transaction
                        },
                        ..unencoded_ledger_block
                    };
                    assert_eq!(
                        unencoded_ledger_block_without_created_at_time_in_tx,
                        ledger_block
                    )
                } else {
                    assert_eq!(ledger_block, unencoded_ledger_block);
                }
            }
        }
    }
}

#[test]
fn test_ledger_growing() {
    // check that the index canister can incrementally get the blocks from the ledger.

    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(1, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    // test initial mint block
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_ledger_index_parity(env, ledger_id, index_id);

    // test first transfer block
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_ledger_index_parity(env, ledger_id, index_id);

    // test multiple blocks
    for (from, to, amount) in [
        (account(1, 0), account(1, 1), 1_000_000),
        (account(1, 0), account(2, 0), 1_000_001),
        (account(1, 1), account(2, 0), 1),
    ] {
        transfer(env, ledger_id, from, to, amount);
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // test archived blocks
    for _i in 0..(ARCHIVE_TRIGGER_THRESHOLD as usize + 1) {
        transfer(env, ledger_id, account(1, 0), account(1, 2), 1);
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);
}

#[test]
fn test_ledger_index_icrc1_mint_parity() {
    // Set up an environment with a ledger, and index, and a single mint transaction
    let setup = ParitySetup::new();
    // Create an ICRC1 Mint transaction with all fields set
    let minter_account = Account::from(MINTER_PRINCIPAL.0);
    let recipient_account = account(4, 0);
    let recipient_account_identifier = AccountIdentifier::from(recipient_account);
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    let created_at_time = TimeStamp::from(setup.env.time());
    let mint_block_index = icrc1_transfer(
        &setup.env,
        setup.ledger_id,
        minter_account,
        recipient_account,
        setup.mint_amount,
        Some(created_at_time),
        None,
        Some(setup.memo.clone()),
    );
    assert_eq!(mint_block_index, Nat::from(1u8));
    // Create the expected ledger block for the ICRC1 Mint transaction
    let expected_ledger_block = icp_ledger::Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Mint {
                to: recipient_account_identifier,
                amount: Tokens::from_e8s(setup.mint_amount),
            },
            memo: Memo(0),
            created_at_time: Some(created_at_time),
            icrc1_memo: Some(ByteBuf::from(setup.memo.clone())),
        },
        timestamp: created_at_time,
    };

    // Verify that the ledger and index return the same blocks for the ICRC1 Mint
    // transaction, and that the corresponding Transaction retrieved from the Index also matches.
    assert_ledger_index_block_transaction_parity(
        &setup,
        expected_ledger_block,
        1,
        recipient_account,
    );
}

#[test]
fn test_ledger_index_icrc1_transfer_parity() {
    // Set up an environment with a ledger, and index, and a single mint transaction
    let setup = ParitySetup::new();
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    // Create an ICRC1 Transfer transaction with all fields set
    let tx_timestamp = TimeStamp::from(setup.env.time());
    let tx_block_index = icrc1_transfer(
        &setup.env,
        setup.ledger_id,
        setup.from_account,
        setup.to_account,
        setup.transfer_amount,
        Some(tx_timestamp),
        None,
        Some(setup.memo.clone()),
    );
    assert_eq!(tx_block_index, Nat::from(1u8));
    // Create the expected ledger block for the ICRC1 Transfer transaction
    let expected_ledger_block = icp_ledger::Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Transfer {
                from: setup.from_account_identifier,
                to: setup.to_account_identifier,
                amount: Tokens::from_e8s(setup.transfer_amount),
                fee: Tokens::from_e8s(setup.fee),
                spender: None,
            },
            memo: Memo(0),
            created_at_time: Some(tx_timestamp),
            icrc1_memo: Some(ByteBuf::from(setup.memo.clone())),
        },
        timestamp: tx_timestamp,
    };

    // Verify that the ledger and index return the same blocks for the ICRC2 TransferFrom
    // transaction, and that the corresponding Transaction retrieved from the Index also matches.
    assert_ledger_index_block_transaction_parity(
        &setup,
        expected_ledger_block,
        1,
        setup.to_account,
    );
}

#[test]
fn test_ledger_index_icrc1_transfer_without_created_at_time_parity() {
    // Set up an environment with a ledger, and index, and a single mint transaction
    let setup = ParitySetup::new();
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    // Create an ICRC1 Transfer transaction with all fields set
    let tx_timestamp = TimeStamp::from(setup.env.time());
    let tx_block_index = icrc1_transfer(
        &setup.env,
        setup.ledger_id,
        setup.from_account,
        setup.to_account,
        setup.transfer_amount,
        None,
        None,
        Some(setup.memo.clone()),
    );
    assert_eq!(tx_block_index, Nat::from(1u8));
    // Create the expected ledger block for the ICRC1 Transfer transaction
    let expected_ledger_block = icp_ledger::Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Transfer {
                from: setup.from_account_identifier,
                to: setup.to_account_identifier,
                amount: Tokens::from_e8s(setup.transfer_amount),
                fee: Tokens::from_e8s(setup.fee),
                spender: None,
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: Some(ByteBuf::from(setup.memo.clone())),
        },
        timestamp: tx_timestamp,
    };

    // Verify that the ledger and index return the same blocks for the ICRC2 TransferFrom
    // transaction, and that the corresponding Transaction retrieved from the Index also matches.
    assert_ledger_index_block_transaction_parity(
        &setup,
        expected_ledger_block,
        1,
        setup.to_account,
    );
}

#[test]
fn test_ledger_index_icrc1_approve_parity() {
    // Set up an environment with a ledger, and index, and a single mint transaction
    let setup = ParitySetup::new();
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    // Create an ICRC1 Approve transaction with all fields set
    let tx_timestamp = TimeStamp::from(setup.env.time());
    let expires_at = tx_timestamp.as_nanos_since_unix_epoch() + 3600 * 1_000_000_000;
    let tx_block_index = approve(
        &setup.env,
        setup.ledger_id,
        setup.from_account,
        ApproveTestArgs::new(
            setup.from_account,
            setup.spender_account,
            setup.approve_amount,
        )
        .created_at_time(Some(tx_timestamp.as_nanos_since_unix_epoch()))
        .fee(Some(Nat::from(10_000u16)))
        .memo(Some(setup.memo.clone()))
        .expected_allowance(Some(Nat::from(0u8)))
        .expires_at(Some(expires_at)),
    );
    assert_eq!(tx_block_index, Nat::from(1u8));
    // Create the expected ledger block for the ICRC1 Approve transaction
    let expected_ledger_block = icp_ledger::Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Approve {
                from: setup.from_account_identifier,
                spender: setup.spender_account_identifier,
                allowance: Tokens::from_e8s(setup.approve_amount),
                expected_allowance: Some(Tokens::from_e8s(0)),
                expires_at: Some(TimeStamp::from_nanos_since_unix_epoch(expires_at)),
                fee: Tokens::from_e8s(setup.fee),
            },
            memo: Memo(0),
            created_at_time: Some(tx_timestamp),
            icrc1_memo: Some(ByteBuf::from(setup.memo.clone())),
        },
        timestamp: tx_timestamp,
    };

    // Verify that the ledger and index return the same blocks for the ICRC1 Approve
    // transaction, and that the corresponding Transaction retrieved from the Index also matches.
    assert_ledger_index_block_transaction_parity(
        &setup,
        expected_ledger_block,
        1,
        setup.spender_account,
    );
}

#[test]
fn test_ledger_index_icrc1_transfer_from_parity() {
    // Set up an environment with a ledger, and index, and a single mint transaction
    let setup = ParitySetup::new();
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    // Create an ICRC1 Approve transaction with all fields set
    let tx_timestamp = TimeStamp::from(setup.env.time());
    let expires_at = tx_timestamp.as_nanos_since_unix_epoch() + 3600 * 1_000_000_000;
    let tx_block_index = approve(
        &setup.env,
        setup.ledger_id,
        setup.from_account,
        ApproveTestArgs::new(
            setup.from_account,
            setup.spender_account,
            setup.approve_amount,
        )
        .created_at_time(Some(tx_timestamp.as_nanos_since_unix_epoch()))
        .fee(Some(Nat::from(10_000u16)))
        .memo(Some(setup.memo.clone()))
        .expected_allowance(Some(Nat::from(0u8)))
        .expires_at(Some(expires_at)),
    );
    assert_eq!(tx_block_index, Nat::from(1u8));
    // advance time so that time does not grow implicitly when executing a round
    setup.env.advance_time(Duration::from_secs(1));
    // Create an ICRC2 TransferFrom transaction with all fields set, based on the previously
    // executed ICRC1 Approve transaction
    let tx_timestamp = TimeStamp::from(setup.env.time());
    let tx_block_index = icrc2_transfer_from(
        &setup.env,
        setup.ledger_id,
        setup.spender_account,
        setup.from_account,
        setup.to_account,
        setup.transfer_amount,
        Some(tx_timestamp),
        Some(setup.fee),
        Some(setup.memo.clone()),
    );
    assert_eq!(tx_block_index, Nat::from(2u8));
    // Create the expected ledger block for the ICRC2 TransferFrom transaction
    let expected_ledger_block = icp_ledger::Block {
        parent_hash: None,
        transaction: Transaction {
            operation: Operation::Transfer {
                from: setup.from_account_identifier,
                to: setup.to_account_identifier,
                spender: Some(setup.spender_account_identifier),
                fee: Tokens::from_e8s(setup.fee),
                amount: Tokens::from_e8s(setup.transfer_amount),
            },
            memo: Memo(0),
            created_at_time: Some(tx_timestamp),
            icrc1_memo: Some(ByteBuf::from(setup.memo.clone())),
        },
        timestamp: tx_timestamp,
    };

    // Verify that the ledger and index return the same blocks for the ICRC2 TransferFrom
    // transaction, and that the corresponding Transaction retrieved from the Index also matches.
    assert_ledger_index_block_transaction_parity(
        &setup,
        expected_ledger_block,
        2,
        setup.to_account,
    );
}

struct ParitySetup {
    to_account: Account,
    to_account_identifier: AccountIdentifier,
    from_account: Account,
    from_account_identifier: AccountIdentifier,
    spender_account: Account,
    spender_account_identifier: AccountIdentifier,
    ledger_id: CanisterId,
    index_id: CanisterId,
    env: StateMachine,
    memo: Vec<u8>,
    mint_amount: u64,
    approve_amount: u64,
    transfer_amount: u64,
    fee: u64,
}

impl ParitySetup {
    fn new() -> Self {
        let to_account = account(1, 0);
        let from_account = account(2, 0);
        let from_account_identifier = AccountIdentifier::from(from_account);
        let spender_account = account(3, 0);
        let mut initial_balances = HashMap::new();
        let mint_amount = 1_000_000_000;
        initial_balances.insert(from_account_identifier, Tokens::from_e8s(mint_amount));
        let env = StateMachine::new();
        let ledger_id = install_ledger(&env, initial_balances, default_archive_options());
        let index_id = install_index(&env, ledger_id);
        wait_until_sync_is_completed(&env, index_id, ledger_id);
        Self {
            ledger_id,
            index_id,
            env,
            to_account,
            to_account_identifier: AccountIdentifier::from(to_account),
            from_account,
            from_account_identifier,
            spender_account,
            spender_account_identifier: AccountIdentifier::from(spender_account),
            memo: vec![1u8, 1u8, 1u8],
            mint_amount,
            approve_amount: 1_000_000,
            transfer_amount: 1_000,
            fee: 10_000,
        }
    }
}

fn assert_ledger_index_block_transaction_parity(
    setup: &ParitySetup,
    expected_ledger_block: icp_ledger::Block,
    expected_ledger_block_index: usize,
    index_account: Account,
) {
    wait_until_sync_is_completed(&setup.env, setup.index_id, setup.ledger_id);

    // verify that the blocks on the ledger and the index are the same
    assert_ledger_index_parity_query_blocks_and_query_encoded_blocks(
        &setup.env,
        setup.ledger_id,
        setup.index_id,
    );

    // verify that the ledger block is as expected
    let ledger_blocks = icp_get_blocks(&setup.env, setup.ledger_id, None, None);
    assert_eq!(ledger_blocks.len(), expected_ledger_block_index + 1);
    let ledger_parent_block = ledger_blocks
        .get(expected_ledger_block_index - 1)
        .expect("should contain a block")
        .clone();
    let expected_block_with_parent_hash = icp_ledger::Block {
        parent_hash: Some(icp_ledger::Block::block_hash(&ledger_parent_block.encode())),
        ..expected_ledger_block
    };
    let ledger_transfer_block = ledger_blocks
        .get(expected_ledger_block_index)
        .unwrap_or_else(|| panic!("should contain {} blocks", expected_ledger_block_index + 1));
    assert_eq!(ledger_transfer_block, &expected_block_with_parent_hash);

    // verify that the transaction retrieved from the index is the same as in the block
    let index_transactions =
        get_account_identifier_transactions(&setup.env, setup.index_id, index_account, None, 1)
            .transactions;
    assert_eq!(index_transactions.len(), 1);
    let transfer_transaction = index_transactions
        .first()
        .expect("should contain a transaction");
    let expected_settled_transfer_transaction =
        SettledTransaction::from(expected_block_with_parent_hash);
    assert_eq!(
        transfer_transaction.transaction,
        expected_settled_transfer_transaction
    );
}

#[test]
fn test_archive_indexing() {
    // test that the index canister can fetch the blocks from archive correctly.
    // We need a number of blocks equal to threshold + 2 * max num blocks in archive response.
    const MAX_TRANSACTIONS_PER_ARCHIVE_RESPONSE: u64 = 10;
    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(0, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
            max_transactions_per_response: Some(MAX_TRANSACTIONS_PER_ARCHIVE_RESPONSE),
            ..default_archive_options()
        },
    );
    let index_id = install_index(env, ledger_id);
    // To trigger archiving, we need transactions and not only initial balances
    for i in 1..(ARCHIVE_TRIGGER_THRESHOLD + 2 * MAX_TRANSACTIONS_PER_ARCHIVE_RESPONSE) {
        transfer(env, ledger_id, account(0, 0), account(i, 0), 1);
    }

    wait_until_sync_is_completed(env, index_id, ledger_id);
    let num_blocks = assert_ledger_index_parity(env, ledger_id, index_id);
    assert_eq!(
        (ARCHIVE_TRIGGER_THRESHOLD + 2 * MAX_TRANSACTIONS_PER_ARCHIVE_RESPONSE) as usize,
        num_blocks
    );
}

fn expected_block_timestamp(rounds: u32, phase: u32, start_time: SystemTime) -> Option<TimeStamp> {
    Some(TimeStamp::from(
        start_time
            .checked_add(Duration::from_nanos(rounds.into())) // timestamp increases by 1ns every round
            .expect("checked_add should not overflow")
            .checked_add(
                SYNC_STEP_SECONDS
                    .checked_mul(phase)
                    .expect("checked_mul should not overflow"),
            )
            .expect("checked_add should not overflow"),
    ))
}

#[test]
fn test_get_account_identifier_transactions() {
    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(1, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let time = env.time();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    // List of the transactions that the test is going to add. This exists to make
    // the test easier to read. The transactions are executed in separate phases, where the block
    // timestamp is a function of the phase.
    let mut rounds = 2u32; // ledger is created in 1st round and initialized in 2nd round
    let mut phase = 0u32;
    let tx0 = SettledTransactionWithId {
        id: 0u64,
        transaction: SettledTransaction {
            operation: Operation::Mint {
                to: account(1, 0).into(),
                amount: Tokens::from_e8s(1_000_000_000_000_u64),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
            timestamp: expected_block_timestamp(rounds, phase, time),
        },
    };
    rounds += 3; // it takes two more rounds to create and initialize index and one more round for the transfer
    phase = 1;
    let tx1 = SettledTransactionWithId {
        id: 1u64,
        transaction: SettledTransaction {
            operation: Operation::Transfer {
                to: account(2, 0).into(),
                from: account(1, 0).into(),
                spender: None,
                amount: Tokens::from_e8s(1_000_000u64),
                fee: Tokens::from_e8s(10_000),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
            timestamp: expected_block_timestamp(rounds, phase, time),
        },
    };
    rounds += 1; // it takes one more round for the transfer
    phase = 2;
    let tx2 = SettledTransactionWithId {
        id: 2u64,
        transaction: SettledTransaction {
            operation: Operation::Transfer {
                to: account(2, 0).into(),
                from: account(1, 0).into(),
                spender: None,
                amount: Tokens::from_e8s(2_000_000u64),
                fee: Tokens::from_e8s(10_000),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
            timestamp: expected_block_timestamp(rounds, phase, time),
        },
    };
    rounds += 1; // it takes one more round for the transfer
    let tx3 = SettledTransactionWithId {
        id: 3u64,
        transaction: SettledTransaction {
            operation: Operation::Transfer {
                to: account(1, 1).into(),
                from: account(2, 0).into(),
                spender: None,
                amount: Tokens::from_e8s(1_000_000u64),
                fee: Tokens::from_e8s(10_000),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
            timestamp: expected_block_timestamp(rounds, phase, time),
        },
    };
    rounds += 1; // it takes one more round for the transfer
    phase = 3;
    let expires_at = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        + Duration::from_secs(3600).as_nanos() as u64;
    let tx4 = SettledTransactionWithId {
        id: 4u64,
        transaction: SettledTransaction {
            operation: Operation::Approve {
                from: account(1, 0).into(),
                spender: account(4, 4).into(),
                allowance: Tokens::from_e8s(1_000_000u64),
                fee: Tokens::from_e8s(10_000),
                expected_allowance: None,
                expires_at: Some(TimeStamp::from_nanos_since_unix_epoch(expires_at)),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
            timestamp: expected_block_timestamp(rounds, phase, time),
        },
    };

    ////////////
    //// phase 1: only 1 mint to (1, 0)
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // account (1, 0) has one mint
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(1, 0), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx0.clone()]);

    // account (2, 0) has no transactions
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(2, 0), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![]);

    /////////////
    //// phase 2: transfer from (1, 0) to (2, 0)
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // account (1, 0) has one transfer and one mint
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(1, 0), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx1.clone(), tx0.clone()]);

    // account (2, 0) has one transfer only
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(2, 0), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx1.clone()]);

    // account (3, 0), (1, 1) and (2, 1) have no transactions
    for account in [account(3, 0), account(1, 1), account(2, 1)] {
        let actual_txs =
            get_account_identifier_transactions(env, index_id, account, None, u64::MAX)
                .transactions;
        assert_txs_with_id_eq(actual_txs, vec![]);
    }

    ////////////
    //// phase 3: transfer from (1, 0) to (2, 0)
    ////          transfer from (2, 0) to (1, 1)
    transfer(env, ledger_id, account(1, 0), account(2, 0), 2_000_000);
    transfer(env, ledger_id, account(2, 0), account(1, 1), 1_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // account (1, 0) has two transfers and one mint
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(1, 0), None, u64::MAX)
            .transactions;
    let expected_txs = vec![tx2.clone(), tx1.clone(), tx0];
    assert_txs_with_id_eq(actual_txs, expected_txs);

    // account (2, 0) has three transfers
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(2, 0), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx3.clone(), tx2, tx1]);

    // account (1, 1) has one transfer
    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(1, 1), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx3]);

    ////////////
    //// phase 4: approve from (1, 0) spender (4, 4)
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(4, 4), 1_000_000).expires_at(Some(expires_at)),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(1, 0), None, 1).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx4.clone()]);

    let actual_txs =
        get_account_identifier_transactions(env, index_id, account(4, 4), None, u64::MAX)
            .transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx4]);
}

#[test]
fn test_get_account_transactions_start_length() {
    let initial_balances = HashMap::new();

    // 10 mint transactions to index for the same account
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);
    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let time = env.time();
    for i in 0..10 {
        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(1, 0),
            i * 10_000,
        );
    }
    let expected_txs: Vec<_> = (0..10)
        .map(|i| SettledTransactionWithId {
            id: i,
            transaction: SettledTransaction {
                operation: Operation::Mint {
                    to: account(1, 0).into(),
                    amount: Tokens::from_e8s(i * 10_000),
                },
                memo: Memo(0),
                created_at_time: None,
                icrc1_memo: None,
                timestamp: Some(TimeStamp::from(
                    time.checked_add(Duration::from_nanos(i))
                        .expect("checked_add should not overflow"),
                )),
            },
        })
        .collect();

    wait_until_sync_is_completed(env, index_id, ledger_id);

    // get the most n recent transaction with start set to none
    for n in 1..10 {
        let actual_txs =
            get_account_identifier_transactions(env, index_id, account(1, 0), None, n).transactions;
        let expected_txs: Vec<_> = (0..10)
            .rev()
            .take(n as usize)
            .map(|i| expected_txs[i as usize].clone())
            .collect();
        assert_txs_with_id_eq(actual_txs, expected_txs.clone());
    }

    // get the most n recent transaction with start set to some index
    for start in 0..=10 {
        for n in 1..(10 - start) {
            let expected_txs: Vec<_> = (0..start)
                .rev()
                .take(n as usize)
                .map(|i| expected_txs[i as usize].clone())
                .collect();
            let actual_txs =
                get_account_identifier_transactions(env, index_id, account(1, 0), Some(start), n)
                    .transactions;
            assert_txs_with_id_eq(actual_txs, expected_txs);
        }
    }
}

#[test]
fn test_get_account_identifier_transactions_pagination() {
    // 10_000 mint transactions to index for the same account_identifier
    let initial_balances = HashMap::new();
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);
    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let time = env.time();
    for i in 0..10 {
        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(1, 0),
            i * 10_000,
        );
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // The index get_account_identifier_transactions endpoint returns batches of transactions
    // in descending order of index, i.e. the first index returned in the result
    // is the biggest id in the result while the last index is the lowest.
    // The start parameter of the function is the last seen index and the result
    // will contain the next batch of indexes after that one.
    let mut start = None; // the start id of the next batch request

    // if start == Some(0) then we can stop as there is no index that is smaller
    // than 0.
    while start != Some(0) {
        let res =
            get_account_identifier_transactions(env, index_id, account(1, 0), start, u64::MAX);

        // if the batch is empty then get_account_transactions
        // didn't return the expected batch for the given start
        if res.transactions.is_empty() {
            panic!(
                "get_account_identifier_transactions({start:?}, u64::MAX) returned an empty batch!"
            );
        }

        let mut last_seen_txid = start;
        for (i, SettledTransactionWithId { id, transaction }) in res.transactions.iter().enumerate()
        {
            // transactions ids must be unique and in descending order
            if let Some(last_seen_txid) = last_seen_txid {
                assert!(*id < last_seen_txid);
            }
            last_seen_txid = Some(*id);

            let j = res.transactions.len() - 1 - i; // transactions are in descending order

            // check the transaction itself
            assert_tx_eq(
                &SettledTransaction {
                    operation: Operation::Mint {
                        to: account(1, 0).into(),
                        amount: Tokens::from_e8s(*id * 10_000),
                    },
                    memo: Memo(0),
                    created_at_time: None,
                    icrc1_memo: None,
                    timestamp: Some(TimeStamp::from(
                        time.checked_add(Duration::from_nanos(j as u64))
                            .expect("checked_add should not overflow"),
                    )),
                },
                transaction,
            );
        }

        // !res.transactions.is_empty() and the check on descending
        // order guarantee that last_seen_txid < start
        start = last_seen_txid;
    }
}

#[test]
fn test_icp_balance_of() {
    let initial_balances = HashMap::new();
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);
    for i in 0..10 {
        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(1, 0),
            i * 10_000,
        );

        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(2, 0),
            i * 10_000,
        );
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Test Mint operations
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test burn operations
    transfer(
        env,
        ledger_id,
        account(1, 0),
        Account {
            owner: MINTER_PRINCIPAL.into(),
            subaccount: None,
        },
        10_000,
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );

    // Test transfer operations
    transfer(env, ledger_id, account(1, 0), account(2, 0), 10_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );
    transfer(env, ledger_id, account(2, 0), account(3, 0), 10_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(3, 0)),
        index_balance_of(env, index_id, account(3, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test approve operations
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );
}

#[test]
fn test_approve_args() {
    let initial_balances = HashMap::new();
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);
    for i in 0..10 {
        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(1, 0),
            i * 10_000,
        );

        transfer(
            env,
            ledger_id,
            Account {
                owner: MINTER_PRINCIPAL.into(),
                subaccount: None,
            },
            account(2, 0),
            i * 10_000,
        );
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Test approve operations with default args
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test approve operations with expected_allowance set
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000)
            .expected_allowance(Some(100_000u32.into())),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test approve operations with memo set
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000).memo(Some(b"memo".to_vec())),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test approve operations with fee set
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000).fee(Some(FEE.into())),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );

    // Test approve operations with fee created_at_time set
    approve(
        env,
        ledger_id,
        account(1, 0),
        ApproveTestArgs::new(account(1, 0), account(2, 0), 100_000).created_at_time(Some(
            env.time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        )),
    );
    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        index_balance_of(env, index_id, account(1, 0))
    );
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(2, 0)),
        index_balance_of(env, index_id, account(2, 0))
    );
}

#[test]
fn test_post_upgrade_start_timer() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        vec![(
            AccountIdentifier::from(account(1, 0)),
            Tokens::from_e8s(10_000_000),
        )]
        .into_iter()
        .collect(),
        default_archive_options(),
    );
    let index_id = install_index(env, ledger_id);

    wait_until_sync_is_completed(env, index_id, ledger_id);

    env.upgrade_canister(index_id, index_wasm(), Encode!(&()).unwrap())
        .unwrap();

    // Check that the index syncs the new block (wait_until_sync_is_completed fails
    // if the new block is not synced).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 2_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);
}

#[test]
fn check_block_endpoint_limits() {
    // check that the index canister can incrementally get the blocks from the ledger.

    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(1, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        ArchiveOptions {
            trigger_threshold: MAX_BLOCKS_PER_REQUEST,
            num_blocks_to_archive: MAX_BLOCKS_PER_REQUEST / 2,
            ..default_archive_options()
        },
    );
    let index_id = install_index(env, ledger_id);

    for _ in 0..MAX_BLOCKS_PER_REQUEST {
        transfer(env, ledger_id, account(1, 0), account(2, 0), 1);
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);

    let user_principal =
        Principal::from_text("luwgt-ouvkc-k5rx5-xcqkq-jx5hm-r2rj2-ymqjc-pjvhb-kij4p-n4vms-gqe")
            .unwrap();
    let canister_principal = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();

    // get_blocks
    let blocks = index_get_blocks(env, index_id);
    assert_eq!(blocks.len(), MAX_BLOCKS_PER_REQUEST);

    let blocks = index_get_blocks_update(env, index_id, canister_principal);
    assert_eq!(blocks.len(), MAX_BLOCKS_PER_REQUEST);

    let blocks = index_get_blocks_update(env, index_id, user_principal);
    assert_eq!(
        blocks.len(),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );

    // get_account_identifier_transactions
    assert_eq!(
        get_account_id_transactions_len(env, index_id, &account(2, 0)),
        MAX_BLOCKS_PER_REQUEST
    );

    assert_eq!(
        get_account_id_transactions_update_len(env, index_id, canister_principal, &account(2, 0)),
        MAX_BLOCKS_PER_REQUEST
    );

    assert_eq!(
        get_account_id_transactions_update_len(env, index_id, user_principal, &account(2, 0)),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );

    // get_account_transactions
    assert_eq!(
        get_account_transactions_len(env, index_id, &account(2, 0)),
        MAX_BLOCKS_PER_REQUEST
    );

    assert_eq!(
        get_account_transactions_update_len(env, index_id, canister_principal, &account(2, 0)),
        MAX_BLOCKS_PER_REQUEST
    );

    assert_eq!(
        get_account_transactions_update_len(env, index_id, user_principal, &account(2, 0)),
        MAX_BLOCKS_PER_INGRESS_REPLICATED_QUERY_REQUEST
    );
}

#[test]
fn test_index_http_request_decoding_quota() {
    // check that the index canister rejects large http requests.

    let mut initial_balances = HashMap::new();
    initial_balances.insert(
        AccountIdentifier::from(account(1, 0)),
        Tokens::from_e8s(1_000_000_000_000),
    );
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    wait_until_sync_is_completed(env, index_id, ledger_id);

    test_http_request_decoding_quota(env, index_id);
}

mod metrics {
    use crate::index_wasm;
    use candid::Principal;
    use ic_icp_index::InitArg;

    #[test]
    fn should_export_heap_memory_usage_bytes_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_index_heap_memory_bytes_metric(
            index_wasm(),
            encode_init_args,
        );
    }

    fn encode_init_args(ledger_id: Principal) -> InitArg {
        InitArg { ledger_id }
    }
}
