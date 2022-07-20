use candid::types::number::Nat;
use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{ArchiveInfo, StandardRecord, TransferArg, TransferError, Value},
    Account, Block, CandidBlock, CandidOperation, Operation, Transaction,
};
use ic_icrc1_ledger::InitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockHeight, BlockType, HashOf};
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::ToPrimitive;
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestCaseResult, TestRunner};
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: u64 = 5;
const TX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

const MINTER: Account = Account {
    of: PrincipalId::new(0, [0u8; 29]),
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

fn ledger_wasm() -> Vec<u8> {
    let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    proj.cargo_bin("ic-icrc1-ledger", &[]).bytes()
}

fn archive_wasm() -> Vec<u8> {
    Project::cargo_bin_maybe_use_path_relative_to_rs(
        "rosetta-api/icrc1/archive",
        "ic-icrc1-archive",
        &[],
    )
    .bytes()
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
        },
    };
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn balance_of(env: &StateMachine, ledger: CanisterId, acc: Account) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_balance_of", Encode!(&acc).unwrap())
            .expect("failed to query balance")
            .bytes(),
        Nat
    )
    .expect("failed to decode balance_of response")
    .0
    .to_u64()
    .unwrap()
}

fn total_supply(env: &StateMachine, ledger: CanisterId) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_total_supply", Encode!().unwrap())
            .expect("failed to query total supply")
            .bytes(),
        Nat
    )
    .expect("failed to decode totalSupply response")
    .0
    .to_u64()
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

fn supported_standards(env: &StateMachine, ledger: CanisterId) -> Vec<StandardRecord> {
    Decode!(
        &env.query(ledger, "icrc1_supported_standards", Encode!().unwrap())
            .expect("failed to query supported standards")
            .bytes(),
        Vec<StandardRecord>
    )
    .expect("failed to decode icrc1_supported_standards response")
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

fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> Result<BlockHeight, TransferError> {
    send_transfer(
        env,
        ledger,
        from.of,
        &TransferArg {
            from_subaccount: from.subaccount,
            to_principal: to.of,
            to_subaccount: to.subaccount,
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

fn get_archive_block(
    env: &StateMachine,
    archive: CanisterId,
    block_index: u64,
) -> Option<CandidBlock> {
    Decode!(
        &env.query(archive, "get_block", Encode!(&block_index).unwrap())
            .expect("failed to query block")
            .bytes(),
        Option<CandidBlock>
    )
    .expect("failed to decode get_block response")
}

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[test]
fn test_metadata() {
    fn lookup<'a>(metadata: &'a BTreeMap<String, Value>, key: &str) -> &'a Value {
        metadata
            .get(key)
            .unwrap_or_else(|| panic!("no metadata key {} in map {:?}", key, metadata))
    }

    let env = StateMachine::new();

    let canister_id = install_ledger(&env, vec![]);
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
        TOKEN_NAME,
        Decode!(
            &env.query(canister_id, "icrc1_name", Encode!().unwrap())
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

    let block_idx =
        transfer(&env, canister_id, p1.into(), p2.into(), 1_000_000).expect("transfer failed");

    assert_eq!(
        transfer(&env, canister_id, p1.into(), p2.into(), 1_000_000),
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        })
    );

    env.advance_time(TX_WINDOW + Duration::from_secs(5 * 60));

    // Check that we can send the same transaction after the deduplication window.
    assert!(
        transfer(&env, canister_id, p1.into(), p2.into(), 1_000_000).expect("transfer failed")
            > block_idx
    );

    let now = system_time_to_nanos(env.time());

    // Same transaction, but `created_at_time` specified explicitly.
    // The ledger should not deduplicate this request.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1,
        &TransferArg {
            from_subaccount: None,
            to_principal: p2,
            to_subaccount: None,
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
                to_principal: p2,
                to_subaccount: None,
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
            to_principal: p2,
            to_subaccount: None,
            fee: None,
            amount: Nat::from(1_000_000),
            created_at_time: Some(now),
            memo: Some(0),
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
                to_principal: p2,
                to_subaccount: None,
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now),
                memo: Some(0),
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
    assert_eq!(0, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, MINTER.clone(), p1.into(), 10_000_000).expect("mint failed");

    assert_eq!(10_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, p1.into(), MINTER.clone(), 1_000_000).expect("burn failed");

    assert_eq!(9_000_000, total_supply(&env, canister_id));
    assert_eq!(9_000_000, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    // You have at least FEE, you can burn at least FEE
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p1.into(), MINTER.clone(), FEE / 2),
    );

    transfer(&env, canister_id, p1.into(), p2.into(), FEE / 2).expect("transfer failed");

    assert_eq!(FEE / 2, balance_of(&env, canister_id, p2.into()));

    // If you have less than FEE, you can burn only the whole amount.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE / 2)
        }),
        transfer(&env, canister_id, p2.into(), MINTER.clone(), FEE / 4),
    );
    transfer(&env, canister_id, p2.into(), MINTER.clone(), FEE / 2).expect("burn failed");

    assert_eq!(0, balance_of(&env, canister_id, p2.into()));

    // You cannot burn zero tokens, no matter what your balance is.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p2.into(), MINTER.clone(), 0),
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
    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.into()));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2.into()));

    transfer(&env, canister_id, p1.into(), p2.into(), 1_000_000).expect("transfer failed");

    assert_eq!(15_000_000 - FEE, total_supply(&env, canister_id));
    assert_eq!(9_000_000u64 - FEE, balance_of(&env, canister_id, p1.into()));
    assert_eq!(6_000_000u64, balance_of(&env, canister_id, p2.into()));
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
        Err(TransferError::TooOld {
            allowed_window_nanos: tx_window
        }),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to_principal: p2,
                to_subaccount: None,
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now - tx_window - 1),
                memo: None,
            }
        )
    );

    assert_eq!(
        Err(TransferError::CreatedInFuture),
        send_transfer(
            &env,
            canister_id,
            p1,
            &TransferArg {
                from_subaccount: None,
                to_principal: p2,
                to_subaccount: None,
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now + Duration::from_secs(5 * 60).as_nanos() as u64),
                memo: None
            }
        )
    );

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0u64, balance_of(&env, canister_id, p2.into()));
}

#[test]
fn test_archiving() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let canister_id = install_ledger(&env, vec![(Account::from(p1), 10_000_000)]);

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, canister_id, p1.into(), p2.into(), 10_000 + i).expect("transfer failed");
    }

    env.run_until_completion(/*max_ticks=*/ 10);

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0);
    assert_eq!(archive_info[0].block_range_end, NUM_BLOCKS_TO_ARCHIVE - 1);

    let archive_canister_id = archive_info[0].canister_id;

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        assert_eq!(
            get_archive_block(&env, archive_canister_id, i)
                .unwrap()
                .transaction
                .operation,
            CandidOperation::Transfer {
                from: p1.into(),
                to: p2.into(),
                amount: 10_000 + i - 1,
                fee: FEE
            }
        );
    }

    // Upgrade the archive and check that the data is still available.

    env.upgrade_canister(archive_canister_id, archive_wasm(), vec![])
        .expect("failed to upgrade the archive canister");

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        assert_eq!(
            get_archive_block(&env, archive_canister_id, i)
                .unwrap()
                .transaction
                .operation,
            CandidOperation::Transfer {
                from: p1.into(),
                to: p2.into(),
                amount: 10_000 + i - 1,
                fee: FEE
            }
        );
    }

    // Check that we can append more blocks after the upgrade.
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE) {
        transfer(&env, canister_id, p1.into(), p2.into(), 20_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0);
    assert_eq!(
        archive_info[0].block_range_end,
        2 * NUM_BLOCKS_TO_ARCHIVE - 1
    );
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
                of: PrincipalId::try_from(&principal[..]).unwrap(),
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
    (arb_operation(), any::<Option<u64>>(), any::<Option<u64>>()).prop_map(
        |(operation, ts, memo)| Transaction {
            operation,
            created_at_time: ts,
            memo,
        },
    )
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
