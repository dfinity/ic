use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_ledger_core::{
    block::{BlockHeight, BlockType, HashOf},
    Tokens,
};
use ic_ledger_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account, Block, InitArgs, Operation, Transaction,
};
use ic_state_machine_tests::{CanisterId, StateMachine};
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestRunner};
use std::collections::HashMap;
use std::convert::TryFrom;

const FEE: u64 = 10_000;
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";
const MINTER: Account = Account {
    of: PrincipalId::new(0, [0u8; 29]),
    subaccount: None,
};

fn ledger_wasm() -> Vec<u8> {
    let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    proj.cargo_bin("ic-ledger-icrc1", &[]).bytes()
}

fn install_ledger(env: &StateMachine, initial_balances: Vec<(Account, u64)>) -> CanisterId {
    let args = InitArgs {
        minting_account: MINTER.clone(),
        initial_balances,
        transfer_fee: Tokens::from_e8s(FEE),
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
    };

    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn balance_of(env: &StateMachine, ledger: CanisterId, acc: Account) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_balanceOf", Encode!(&acc).unwrap())
            .expect("failed to query balance")
            .bytes(),
        u64
    )
    .expect("failed to decode balanceOf response")
}

fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> Result<BlockHeight, TransferError> {
    Decode!(
        &env.execute_ingress_as(
            from.of,
            ledger,
            "icrc1_transfer",
            Encode!(&TransferArg {
                from_subaccount: from.subaccount,
                to_principal: to.of,
                to_subaccount: to.subaccount,
                fee: None,
                amount,
            })
            .unwrap()
        )
        .expect("failed to tranfer funds")
        .bytes(),
        Result<BlockHeight, TransferError>
    )
    .expect("failed to decode transfer response")
}

#[test]
fn test_symbol_and_name() {
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
}

#[test]
fn test_mint_burn() {
    let env = StateMachine::new();
    let p1 = PrincipalId::new_user_test_id(1);
    let canister_id = install_ledger(&env, vec![]);

    assert_eq!(0, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, MINTER.clone(), p1.into(), 10_000_000).expect("mint failed");

    assert_eq!(10_000_000, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, p1.into(), MINTER.clone(), 1_000_000).expect("mint failed");

    assert_eq!(9_000_000, balance_of(&env, canister_id, p1.into()));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));
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

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.into()));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2.into()));

    transfer(&env, canister_id, p1.into(), p2.into(), 1_000_000).expect("transfer failed");

    assert_eq!(9_000_000u64 - FEE, balance_of(&env, canister_id, p1.into()));
    assert_eq!(6_000_000u64, balance_of(&env, canister_id, p2.into()));
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
    (arb_operation(), any::<u64>()).prop_map(|(operation, ts)| Transaction {
        operation,
        created_at_time: ts,
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
            use ic_ledger_core::ledger::LedgerTransaction;

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

    type BalancesModel = HashMap<Account, u64>;

    fn model_transfer(
        balances: &mut BalancesModel,
        from: Account,
        to: Account,
        amount: u64,
    ) -> ((u64, u64), Option<TransferError>) {
        let from_balance = balances.get(&from).cloned().unwrap_or_default();
        let to_balance = balances.get(&to).cloned().unwrap_or_default();
        if from_balance < amount + FEE {
            return (
                (from_balance, to_balance),
                Some(TransferError::InsufficientFunds {
                    balance: from_balance,
                }),
            );
        }
        let new_from = from_balance - amount - FEE;
        let new_to = to_balance + amount;
        balances.insert(from, new_from);
        balances.insert(to, new_to);
        ((new_from, new_to), None)
    }

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
            |(accounts, mints, transfers)| {
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

                    prop_assert_eq!(from_balance, balance_of(&env, canister_id, from.clone()));
                    prop_assert_eq!(to_balance, balance_of(&env, canister_id, to.clone()));
                }
                Ok(())
            },
        )
        .unwrap();
}
