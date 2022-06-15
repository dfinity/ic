use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_ledger_core::{
    block::{BlockType, HashOf},
    Tokens,
};
use ic_ledger_icrc1::{Account, Block, InitArgs, Operation, Transaction};
use ic_state_machine_tests::StateMachine;
use proptest::prelude::*;
use std::convert::TryFrom;

fn ledger_wasm() -> Vec<u8> {
    let proj = Project::new(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    proj.cargo_bin("ic-ledger-icrc1", &[]).bytes()
}

#[test]
fn test_symbol_and_name() {
    let env = StateMachine::new();
    let canister_id = env
        .install_canister(
            ledger_wasm(),
            Encode!(&InitArgs {
                minting_account: Account {
                    of: PrincipalId::new_anonymous(),
                    subaccount: None,
                },
                transfer_fee: Tokens::from_e8s(10_000),
                token_name: "Test".to_string(),
                token_symbol: "TST".to_string(),
            })
            .unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(
        "TST",
        Decode!(
            &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );

    assert_eq!(
        "Test",
        Decode!(
            &env.query(canister_id, "icrc1_name", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
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
fn check_block_encoding() {
    use proptest::test_runner::TestRunner;
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
