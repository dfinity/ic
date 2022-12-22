use candid::types::number::Nat;
use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError, Value},
    Account, Block, Memo, Operation, Transaction,
};
use ic_icrc1_ledger::InitArgs;
use ic_icrc1_ledger_sm_tests::{
    balance_of, ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY,
    INT_META_VALUE, MINTER, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY,
    TEXT_META_VALUE, TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType, HashOf};
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::ToPrimitive;
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestCaseResult, TestRunner};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;

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

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> InitArgs {
    InitArgs {
        minting_account: MINTER.clone(),
        initial_balances: args.initial_balances,
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
    }
}

#[test]
fn test_metadata() {
    ic_icrc1_ledger_sm_tests::test_metadata_icp_ledger(ledger_wasm(), encode_init_args)
}

#[test]
fn test_tx_deduplication() {
    ic_icrc1_ledger_sm_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_icrc1_ledger_sm_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}
#[test]
fn test_single_transfer() {
    ic_icrc1_ledger_sm_tests::test_single_transfer(ledger_wasm(), encode_init_args);
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

#[test]
fn test_archiving() {
    ic_icrc1_ledger_sm_tests::test_archiving(ledger_wasm(), encode_init_args, archive_wasm());
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
    ic_icrc1_ledger_sm_tests::block_encoding_agrees_with_the_schema();
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::transaction_hashes_are_unique();
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
