use candid::types::number::Nat;
use candid::{CandidType, Decode, Encode};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{
        ArchiveInfo, GetTransactionsRequest, GetTransactionsResponse, StandardRecord,
        Transaction as Tx, TransactionRange, Transfer, TransferArg, TransferError, Value,
    },
    Account, Block, Memo, Operation, Transaction,
};
use ic_icrc1_ledger::InitArgs;
use ic_icrc1_ledger_sm_tests::{
    balance_of, setup, supported_standards, total_supply, ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY,
    BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE, MINTER, NAT_META_KEY, NAT_META_VALUE,
    NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE, TOKEN_NAME, TOKEN_SYMBOL, TX_WINDOW,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType, HashOf};
use ic_state_machine_tests::{CanisterId, ErrorCode, StateMachine};
use num_traits::ToPrimitive;
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestCaseResult, TestRunner};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-ledger",
        &[],
    )
}

fn archive_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("archive"),
        "ic-icrc1-archive",
        &[],
    )
}

fn install_ledger(env: &StateMachine, initial_balances: Vec<(Account, u64)>) -> CanisterId {
    let args = InitArgs {
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
            max_transactions_per_response: None,
        },
    };
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn metadata(env: &StateMachine, ledger: CanisterId) -> BTreeMap<String, Value> {
    Decode!(
        &env.query(ledger, "icrc1_metadata", Encode!().unwrap())
            .expect("failed to query metadata")
            .bytes(),
        Vec<(String, Value)>
    )
    .expect("failed to decode metadata response")
    .into_iter()
    .collect()
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

fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: impl Into<Account>,
    to: impl Into<Account>,
    amount: u64,
) -> Result<BlockIndex, TransferError> {
    let from = from.into();
    send_transfer(
        env,
        ledger,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to: to.into(),
            fee: None,
            created_at_time: None,
            amount: Nat::from(amount),
            memo: None,
        },
    )
}

fn list_archives(env: &StateMachine, ledger: CanisterId) -> Vec<ArchiveInfo> {
    Decode!(
        &env.query(ledger, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Vec<ArchiveInfo>
    )
    .expect("failed to decode archives response")
}

fn get_archive_transaction(
    env: &StateMachine,
    archive: CanisterId,
    block_index: u64,
) -> Option<Tx> {
    Decode!(
        &env.query(archive, "get_transaction", Encode!(&block_index).unwrap())
            .expect("failed to get transaction")
            .bytes(),
        Option<Tx>
    )
    .expect("failed to decode get_transaction response")
}

fn get_transactions(
    env: &StateMachine,
    ledger: CanisterId,
    start: u64,
    length: usize,
) -> GetTransactionsResponse {
    Decode!(
        &env.query(
            ledger,
            "get_transactions",
            Encode!(&GetTransactionsRequest {
                start: Nat::from(start),
                length: Nat::from(length)
            })
            .unwrap()
        )
        .expect("failed to query ledger transactions")
        .bytes(),
        GetTransactionsResponse
    )
    .expect("failed to decode get_transactions response")
}

fn get_archive_transactions(
    env: &StateMachine,
    archive: CanisterId,
    start: u64,
    length: usize,
) -> TransactionRange {
    Decode!(
        &env.query(
            archive,
            "get_transactions",
            Encode!(&GetTransactionsRequest {
                start: Nat::from(start),
                length: Nat::from(length)
            })
            .unwrap()
        )
        .expect("failed to query archive transactions")
        .bytes(),
        TransactionRange
    )
    .expect("failed to decode get_transactions archive response")
}

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> InitArgs {
    InitArgs {
        minting_account: args.minting_account,
        initial_balances: args.initial_balances,
        transfer_fee: args.transfer_fee,
        token_name: args.token_name,
        token_symbol: args.token_symbol,
        metadata: args.metadata,
        archive_options: args.archive_options,
    }
}

#[test]
fn test_metadata() {
    fn lookup<'a>(metadata: &'a BTreeMap<String, Value>, key: &str) -> &'a Value {
        metadata
            .get(key)
            .unwrap_or_else(|| panic!("no metadata key {} in map {:?}", key, metadata))
    }

    let (env, canister_id) = setup(ledger_wasm(), encode_init_args, vec![]);

    assert_eq!(
        TOKEN_SYMBOL,
        Decode!(
            &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );

    assert_eq!(
        8,
        Decode!(
            &env.query(canister_id, "icrc1_decimals", Encode!().unwrap())
                .unwrap()
                .bytes(),
            u8
        )
        .unwrap()
    );

    let metadata = metadata(&env, canister_id);
    assert_eq!(lookup(&metadata, "icrc1:name"), &Value::from(TOKEN_NAME));
    assert_eq!(
        lookup(&metadata, "icrc1:symbol"),
        &Value::from(TOKEN_SYMBOL)
    );
    assert_eq!(lookup(&metadata, "icrc1:decimals"), &Value::from(8u64));
    assert_eq!(
        lookup(&metadata, NAT_META_KEY),
        &Value::from(NAT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, INT_META_KEY),
        &Value::from(INT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, TEXT_META_KEY),
        &Value::from(TEXT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, BLOB_META_KEY),
        &Value::from(BLOB_META_VALUE)
    );

    let standards = supported_standards(&env, canister_id);
    assert_eq!(
        standards,
        vec![StandardRecord {
            name: "ICRC-1".to_string(),
            url: "https://github.com/dfinity/ICRC-1".to_string(),
        }]
    );
}

#[test]
fn test_tx_deduplication() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(&env, vec![(Account::from(p1), 10_000_000)]);

    // No created_at_time => no deduplication
    let block_id = transfer(&env, canister_id, p1, p2, 10_000).expect("transfer failed");
    assert!(transfer(&env, canister_id, p1, p2, 10_000).expect("transfer failed") > block_id);

    let now = system_time_to_nanos(env.time());

    let transfer_args = TransferArg {
        from_subaccount: None,
        to: p2.into(),
        fee: None,
        amount: Nat::from(1_000_000),
        created_at_time: Some(now),
        memo: None,
    };

    let block_idx = send_transfer(&env, canister_id, p1, &transfer_args).expect("transfer failed");

    assert_eq!(
        send_transfer(&env, canister_id, p1, &transfer_args),
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        })
    );

    env.advance_time(TX_WINDOW + Duration::from_secs(5 * 60));
    let now = system_time_to_nanos(env.time());

    assert_eq!(
        send_transfer(&env, canister_id, p1, &transfer_args,),
        Err(TransferError::TooOld),
    );

    // Same transaction, but `created_at_time` specified explicitly.
    // The ledger should not deduplicate this request.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1,
        &TransferArg {
            from_subaccount: None,
            to: p2.into(),
            fee: None,
            amount: Nat::from(1_000_000),
            created_at_time: Some(now),
            memo: None,
        },
    )
    .expect("transfer failed");

    // This time the transaction is a duplicate.
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now),
                memo: None,
            }
        )
    );

    // Same transaction, but with "default" `memo`.
    // The ledger should not deduplicate because we set a new field explicitly.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1,
        &TransferArg {
            from_subaccount: None,
            to: p2.into(),
            fee: None,
            amount: Nat::from(1_000_000),
            created_at_time: Some(now),
            memo: Some(Memo::default()),
        },
    )
    .expect("transfer failed");

    // This time the transaction is a duplicate.
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now),
                memo: Some(Memo::default()),
            }
        )
    );
}

#[test]
fn test_mint_burn() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(&env, vec![]);

    assert_eq!(0, total_supply(&env, canister_id));
    assert_eq!(0, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, MINTER.clone(), p1, 10_000_000).expect("mint failed");

    assert_eq!(10_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, p1, MINTER.clone(), 1_000_000).expect("burn failed");

    assert_eq!(9_000_000, total_supply(&env, canister_id));
    assert_eq!(9_000_000, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    // You have at least FEE, you can burn at least FEE
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p1, MINTER.clone(), FEE / 2),
    );

    transfer(&env, canister_id, p1, p2, FEE / 2).expect("transfer failed");

    assert_eq!(FEE / 2, balance_of(&env, canister_id, p2));

    // If you have less than FEE, you can burn only the whole amount.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE / 2)
        }),
        transfer(&env, canister_id, p2, MINTER.clone(), FEE / 4),
    );
    transfer(&env, canister_id, p2, MINTER.clone(), FEE / 2).expect("burn failed");

    assert_eq!(0, balance_of(&env, canister_id, p2));

    // You cannot burn zero tokens, no matter what your balance is.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p2, MINTER.clone(), 0),
    );
}

#[test]
fn test_single_transfer() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(
        &env,
        vec![
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
        ],
    );

    assert_eq!(15_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2));

    transfer(&env, canister_id, p1, p2, 1_000_000).expect("transfer failed");

    assert_eq!(15_000_000 - FEE, total_supply(&env, canister_id));
    assert_eq!(9_000_000u64 - FEE, balance_of(&env, canister_id, p1));
    assert_eq!(6_000_000u64, balance_of(&env, canister_id, p2));
}

#[test]
fn test_account_canonicalization() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(
        &env,
        vec![
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
        ],
    );

    assert_eq!(
        10_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p1,
                subaccount: None
            }
        )
    );
    assert_eq!(
        10_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p1,
                subaccount: Some([0; 32])
            }
        )
    );

    transfer(
        &env,
        canister_id,
        p1,
        Account {
            owner: p2,
            subaccount: Some([0; 32]),
        },
        1_000_000,
    )
    .expect("transfer failed");

    assert_eq!(
        6_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p2,
                subaccount: None
            }
        )
    );
}

#[test]
fn test_memo_validation() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(&env, vec![(Account::from(p1), 10_000_000)]);

    // [ic_icrc1::endpoints::TransferArg] does not allow invalid memos by construction, we
    // need another type to check invalid inputs.
    #[derive(CandidType)]
    struct TransferArg {
        to: Account,
        amount: Nat,
        memo: Option<Vec<u8>>,
    }
    type TxResult = Result<Nat, TransferError>;

    // 8-byte memo should work
    Decode!(
        &env.execute_ingress_as(
            p1,
            canister_id,
            "icrc1_transfer",
            Encode!(&TransferArg {
                to: p2.into(),
                amount: Nat::from(10_000),
                memo: Some(vec![1u8; 8]),
            })
            .unwrap()
        )
        .expect("failed to call transfer")
        .bytes(),
        TxResult
    )
    .unwrap()
    .expect("transfer failed");

    // 32-byte memo should work
    Decode!(
        &env.execute_ingress_as(
            p1,
            canister_id,
            "icrc1_transfer",
            Encode!(&TransferArg {
                to: p2.into(),
                amount: Nat::from(10_000),
                memo: Some(vec![1u8; 32]),
            })
            .unwrap()
        )
        .expect("failed to call transfer")
        .bytes(),
        TxResult
    )
    .unwrap()
    .expect("transfer failed");

    // 33-byte memo should fail
    match env.execute_ingress_as(
        p1,
        canister_id,
        "icrc1_transfer",
        Encode!(&TransferArg {
            to: p2.into(),
            amount: Nat::from(10_000),
            memo: Some(vec![1u8; 33]),
        })
        .unwrap(),
    ) {
        Err(user_error) => assert_eq!(
            user_error.code(),
            ErrorCode::CanisterCalledTrap,
            "unexpected error: {}",
            user_error
        ),
        Ok(result) => panic!(
            "expected a reject for a 33-byte memo, got result {:?}",
            result
        ),
    }
}

#[test]
fn test_tx_time_bounds() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let canister_id = install_ledger(&env, vec![(Account::from(p1), 10_000_000)]);

    let now = system_time_to_nanos(env.time());
    let tx_window = TX_WINDOW.as_nanos() as u64;

    assert_eq!(
        Err(TransferError::TooOld),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now - tx_window - 1),
                memo: None,
            }
        )
    );

    assert_eq!(
        Err(TransferError::CreatedInFuture { ledger_time: now }),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now + Duration::from_secs(5 * 60).as_nanos() as u64),
                memo: None
            }
        )
    );

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1));
    assert_eq!(0u64, balance_of(&env, canister_id, p2));
}

#[test]
fn test_archiving() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let canister_id = install_ledger(&env, vec![(Account::from(p1), 10_000_000)]);

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, canister_id, p1, p2, 10_000 + i).expect("transfer failed");
    }

    env.run_until_completion(/*max_ticks=*/ 10);

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0);
    assert_eq!(archive_info[0].block_range_end, NUM_BLOCKS_TO_ARCHIVE - 1);

    let archive_canister_id = archive_info[0].canister_id;

    let resp = get_transactions(&env, canister_id, 0, 1_000_000);
    assert_eq!(resp.first_index, Nat::from(NUM_BLOCKS_TO_ARCHIVE));
    assert_eq!(
        resp.transactions.len(),
        (ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE + 1) as usize
    );
    assert_eq!(resp.archived_transactions.len(), 1);
    assert_eq!(resp.archived_transactions[0].start, Nat::from(0));
    assert_eq!(
        resp.archived_transactions[0].length,
        Nat::from(NUM_BLOCKS_TO_ARCHIVE)
    );

    let archived_transactions =
        get_archive_transactions(&env, archive_canister_id, 0, NUM_BLOCKS_TO_ARCHIVE as usize)
            .transactions;

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        let expected_tx = Transfer {
            from: p1.into(),
            to: p2.into(),
            amount: Nat::from(10_000 + i - 1),
            fee: Some(Nat::from(FEE)),
            memo: None,
            created_at_time: None,
        };
        assert_eq!(
            get_archive_transaction(&env, archive_canister_id, i)
                .unwrap()
                .transfer
                .as_ref(),
            Some(&expected_tx)
        );
        assert_eq!(
            archived_transactions[i as usize].transfer.as_ref(),
            Some(&expected_tx)
        );
    }

    // Check that requesting non-existing blocks does not crash the ledger.
    let missing_blocks_reply = get_transactions(&env, canister_id, 100, 5);
    assert_eq!(0, missing_blocks_reply.transactions.len());
    assert_eq!(0, missing_blocks_reply.archived_transactions.len());

    // Upgrade the archive and check that the data is still available.

    env.upgrade_canister(archive_canister_id, archive_wasm(), vec![])
        .expect("failed to upgrade the archive canister");

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        assert_eq!(
            get_archive_transaction(&env, archive_canister_id, i)
                .unwrap()
                .transfer,
            Some(Transfer {
                from: p1.into(),
                to: p2.into(),
                amount: Nat::from(10_000 + i - 1),
                fee: Some(Nat::from(FEE)),
                memo: None,
                created_at_time: None,
            })
        );
    }

    // Check that we can append more blocks after the upgrade.
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE) {
        transfer(&env, canister_id, p1, p2, 20_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0);
    assert_eq!(
        archive_info[0].block_range_end,
        2 * NUM_BLOCKS_TO_ARCHIVE - 1
    );

    // Check that the archive handles requested ranges correctly.
    let archived_transactions =
        get_archive_transactions(&env, archive_canister_id, 0, 1_000_000).transactions;
    let n = 2 * NUM_BLOCKS_TO_ARCHIVE as usize;
    assert_eq!(archived_transactions.len(), n);

    for start in 0..n {
        for end in start..n {
            let tx = get_archive_transactions(&env, archive_canister_id, start as u64, end - start)
                .transactions;
            assert_eq!(archived_transactions[start..end], tx);
        }
    }
}

fn arb_amount() -> impl Strategy<Value = u64> {
    any::<u64>()
}

fn arb_account() -> impl Strategy<Value = Account> {
    (
        proptest::collection::vec(any::<u8>(), 28),
        any::<Option<[u8; 32]>>(),
    )
        .prop_map(|(mut principal, subaccount)| {
            principal.push(0x00);
            Account {
                owner: PrincipalId::try_from(&principal[..]).unwrap(),
                subaccount,
            }
        })
}

fn arb_transfer() -> impl Strategy<Value = Operation> {
    (arb_account(), arb_account(), arb_amount(), arb_amount()).prop_map(
        |(from, to, amount, fee)| Operation::Transfer {
            from,
            to,
            amount,
            fee,
        },
    )
}

fn arb_mint() -> impl Strategy<Value = Operation> {
    (arb_account(), arb_amount()).prop_map(|(to, amount)| Operation::Mint { to, amount })
}

fn arb_burn() -> impl Strategy<Value = Operation> {
    (arb_account(), arb_amount()).prop_map(|(from, amount)| Operation::Burn { from, amount })
}

fn arb_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![arb_transfer(), arb_mint(), arb_burn()]
}

fn arb_transaction() -> impl Strategy<Value = Transaction> {
    (
        arb_operation(),
        any::<Option<u64>>(),
        any::<Option<[u8; 32]>>(),
    )
        .prop_map(|(operation, ts, memo)| Transaction {
            operation,
            created_at_time: ts,
            memo: memo.map(Memo::from),
        })
}

fn arb_block() -> impl Strategy<Value = Block> {
    (any::<Option<[u8; 32]>>(), arb_transaction(), any::<u64>()).prop_map(
        |(parent_hash, transaction, ts)| Block {
            parent_hash: parent_hash.map(HashOf::new),
            transaction,
            timestamp: ts,
        },
    )
}

// Generate random blocks and check that their CBOR encoding complies with the CDDL spec.
#[test]
fn block_encoding_agrees_with_the_schema() {
    use std::path::PathBuf;

    let block_cddl_path =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("block.cddl");
    let block_cddl =
        String::from_utf8(std::fs::read(&block_cddl_path).expect("failed to read block.cddl file"))
            .unwrap();

    let mut runner = TestRunner::default();
    runner
        .run(&arb_block(), |block| {
            let cbor_bytes = block.encode().into_vec();
            cddl::validate_cbor_from_slice(&block_cddl, &cbor_bytes, None).map_err(|e| {
                TestCaseError::fail(format!(
                    "Failed to validate CBOR: {} (inspect it on https://cbor.me), error: {}",
                    hex::encode(&cbor_bytes),
                    e
                ))
            })
        })
        .unwrap();
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    let mut runner = TestRunner::default();
    runner
        .run(&(arb_transaction(), arb_transaction()), |(lhs, rhs)| {
            use ic_ledger_canister_core::ledger::LedgerTransaction;

            prop_assume!(lhs != rhs);
            prop_assert_ne!(lhs.hash(), rhs.hash());

            Ok(())
        })
        .unwrap();
}

// Check that different blocks produce different hashes.
#[test]
fn block_hashes_are_unique() {
    let mut runner = TestRunner::default();
    runner
        .run(&(arb_block(), arb_block()), |(lhs, rhs)| {
            prop_assume!(lhs != rhs);

            let lhs_hash = Block::block_hash(&lhs.encode());
            let rhs_hash = Block::block_hash(&rhs.encode());

            prop_assert_ne!(lhs_hash, rhs_hash);
            Ok(())
        })
        .unwrap();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    let mut runner = TestRunner::default();
    runner
        .run(&arb_block(), |block| {
            let encoded_block = block.encode();
            let hash1 = Block::block_hash(&encoded_block);
            let decoded = Block::decode(encoded_block).unwrap();
            let hash2 = Block::block_hash(&decoded.encode());
            prop_assert_eq!(hash1, hash2);
            Ok(())
        })
        .unwrap();
}

#[test]
fn check_transfer_model() {
    use proptest::collection::vec as pvec;

    const NUM_ACCOUNTS: usize = 10;
    const MIN_TRANSACTIONS: usize = 5;
    const MAX_TRANSACTIONS: usize = 10;
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(5));
    runner
        .run(
            &(
                pvec(arb_account(), NUM_ACCOUNTS),
                pvec(0..10_000_000u64, NUM_ACCOUNTS),
                pvec(
                    (0..NUM_ACCOUNTS, 0..NUM_ACCOUNTS, 0..1_000_000_000u64),
                    MIN_TRANSACTIONS..MAX_TRANSACTIONS,
                ),
            ),
            |(accounts, mints, transfers)| test_transfer_model(accounts, mints, transfers),
        )
        .unwrap();
}

type BalancesModel = HashMap<Account, u64>;

fn model_transfer(
    balances: &mut BalancesModel,
    from: Account,
    to: Account,
    amount: u64,
) -> ((u64, u64), Option<TransferError>) {
    let from_balance = balances.get(&from).cloned().unwrap_or_default();
    if from_balance < amount + FEE {
        let to_balance = balances.get(&to).cloned().unwrap_or_default();
        return (
            (from_balance, to_balance),
            Some(TransferError::InsufficientFunds {
                balance: Nat::from(from_balance),
            }),
        );
    }
    balances.insert(from.clone(), from_balance - amount - FEE);

    let to_balance = balances.get(&to).cloned().unwrap_or_default();
    balances.insert(to.clone(), to_balance + amount);

    let from_balance = balances.get(&from).cloned().unwrap_or_default();
    let to_balance = balances.get(&to).cloned().unwrap_or_default();

    ((from_balance, to_balance), None)
}

fn test_transfer_model(
    accounts: Vec<Account>,
    mints: Vec<u64>,
    transfers: Vec<(usize, usize, u64)>,
) -> TestCaseResult {
    let initial_balances: Vec<_> = mints
        .into_iter()
        .enumerate()
        .map(|(i, amount)| (accounts[i].clone(), amount))
        .collect();
    let mut balances: BalancesModel = initial_balances.iter().cloned().collect();

    let env = StateMachine::new();
    let canister_id = install_ledger(&env, initial_balances);

    for (from_idx, to_idx, amount) in transfers.into_iter() {
        let from = accounts[from_idx].clone();
        let to = accounts[to_idx].clone();

        let ((from_balance, to_balance), maybe_error) =
            model_transfer(&mut balances, from.clone(), to.clone(), amount);

        let result = transfer(&env, canister_id, from.clone(), to.clone(), amount);

        prop_assert_eq!(result.is_err(), maybe_error.is_some());

        if let Err(err) = result {
            prop_assert_eq!(Some(err), maybe_error);
        }

        let actual_from_balance = balance_of(&env, canister_id, from);
        let actual_to_balance = balance_of(&env, canister_id, to);

        prop_assert_eq!(from_balance, actual_from_balance);
        prop_assert_eq!(to_balance, actual_to_balance);
    }
    Ok(())
}
