use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icp_index::{
    GetAccountIdentifierTransactionsArgs, GetAccountIdentifierTransactionsResponse,
    GetAccountIdentifierTransactionsResult, SettledTransaction, SettledTransactionWithId, Status,
};
use ic_icrc1_index_ng::GetAccountTransactionsArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::Tokens;
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountIdentifier, GetBlocksArgs, QueryEncodedBlocksResponse, MAX_BLOCKS_PER_REQUEST,
};
use icp_ledger::{FeatureFlags, LedgerCanisterInitPayload, Memo, Operation};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
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
        cycles_for_archive_creation: None,
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
        .execute_ingress(canister_id, "icrc1_balance_of", Encode!(&account).unwrap())
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
        .execute_ingress(canister_id, "icrc1_balance_of", Encode!(&account).unwrap())
        .expect("Failed to send icrc1_balance_of")
        .bytes();
    let account_balance =
        Decode!(&res, u64).expect("Failed to decode get_account_balance response");
    let res = env
        .execute_ingress(
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

fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    Decode!(&res, Status).expect("Failed to decode status response")
}

fn icp_get_blocks(env: &StateMachine, ledger_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksArgs {
        start: 0u64,
        length: MAX_BLOCKS_PER_REQUEST,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(ledger_id, "query_encoded_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    let res =
        Decode!(&res, QueryEncodedBlocksResponse).expect("Failed to decode GetBlocksResponse");
    let mut blocks = vec![];
    for archived in res.archived_blocks {
        let req = GetBlocksArgs {
            start: archived.start,
            length: archived.length as usize,
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksArgs for archive node");
        let canister_id = archived.callback.canister_id;
        let res = env
            .execute_ingress(
                CanisterId::unchecked_from_principal(PrincipalId(canister_id)),
                archived.callback.method,
                req,
            )
            .expect("Failed to send get_blocks request to archive")
            .bytes();
        let res = Decode!(&res, icp_ledger::GetEncodedBlocksResult)
            .unwrap()
            .unwrap();
        blocks.extend(res);
    }
    blocks.extend(res.blocks);
    blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn index_get_blocks(env: &StateMachine, index_id: CanisterId) -> Vec<icp_ledger::Block> {
    let req = GetBlocksRequest {
        start: 0u8.into(),
        length: u64::MAX.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(index_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    Decode!(&res, ic_icp_index::GetBlocksResponse)
        .expect("Failed to decode ic_icp_index::GetBlocksResponse")
        .blocks
        .into_iter()
        .map(icp_ledger::Block::decode)
        .collect::<Result<Vec<icp_ledger::Block>, String>>()
        .unwrap()
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    let Account { owner, subaccount } = from;
    let req = TransferArg {
        from_subaccount: subaccount,
        to,
        amount: amount.into(),
        created_at_time: None,
        fee: None,
        memo: None,
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
        .execute_ingress(index_id, "get_account_transactions", req)
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
        .execute_ingress(index_id, "get_account_identifier_transactions", req)
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

const SYNC_STEP_SECONDS: Duration = Duration::from_secs(60);

// Helper function that calls tick on env until either
// the index canister has synced all the blocks up to the
// last one in the ledger or enough attempts passed and therefore
// it fails
fn wait_until_sync_is_completed(env: &StateMachine, index_id: CanisterId, ledger_id: CanisterId) {
    const MAX_ATTEMPTS: u8 = 100; // no reason for this number
    let mut num_blocks_synced = u64::MAX;
    let mut chain_length = u64::MAX;
    for _i in 0..MAX_ATTEMPTS {
        env.advance_time(SYNC_STEP_SECONDS);
        env.tick();
        num_blocks_synced = status(env, index_id).num_blocks_synced;
        chain_length = icp_get_blocks(env, ledger_id).len() as u64;
        if num_blocks_synced == chain_length {
            return;
        }
    }
    panic!("The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {} but the Ledger chain length is {}", num_blocks_synced, chain_length);
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
fn assert_ledger_index_parity(env: &StateMachine, ledger_id: CanisterId, index_id: CanisterId) {
    let ledger_blocks = icp_get_blocks(env, ledger_id);
    let index_blocks = index_get_blocks(env, index_id);
    assert_eq!(ledger_blocks, index_blocks);
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
fn test_archive_indexing() {
    // test that the index canister can fetch the blocks from archive correctly.
    // To avoid having a slow test, we create the blocks as mints at ledger init time.
    // We need a number of blocks equal to threshold + 2 * max num blocks in archive response.
    let mut initial_balances = HashMap::new();
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD + 4000) {
        initial_balances.insert(
            AccountIdentifier::from(account(i, 0)),
            Tokens::from_e8s(1_000_000_000_000),
        );
    }
    let env = &StateMachine::new();
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);
}

fn expected_block_timestamp(phase: u32, start_time: SystemTime) -> Option<TimeStamp> {
    Some(TimeStamp::from(
        start_time
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
    let ledger_id = install_ledger(env, initial_balances, default_archive_options());
    let index_id = install_index(env, ledger_id);

    // List of the transactions that the test is going to add. This exists to make
    // the test easier to read. The transactions are executed in separate phases, where the block
    // timestamp is a function of the phase.
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
            timestamp: expected_block_timestamp(phase, env.time()),
        },
    };
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
            timestamp: expected_block_timestamp(phase, env.time()),
        },
    };
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
            timestamp: expected_block_timestamp(phase, env.time()),
        },
    };
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
            timestamp: expected_block_timestamp(phase, env.time()),
        },
    };
    phase = 3;
    let expires_at = env
        .time()
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
            timestamp: expected_block_timestamp(phase, env.time()),
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
                timestamp: Some(TimeStamp::from(env.time())),
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
                "get_account_identifier_transactions({:?}, u64::MAX) returned an empty batch!",
                start
            );
        }

        let mut last_seen_txid = start;
        for SettledTransactionWithId { id, transaction } in &res.transactions {
            // transactions ids must be unique and in descending order
            if let Some(last_seen_txid) = last_seen_txid {
                assert!(*id < last_seen_txid);
            }
            last_seen_txid = Some(*id);

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
                        env.time()
                            .checked_sub(SYNC_STEP_SECONDS)
                            .expect("should not underflow"),
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
