use std::collections::HashMap;

use candid::{Decode, Encode};
use ic_ledger_core::tokens::Tokens;
use ic_nns_test_utils::sns_wasm::{build_governance_sns_wasm, build_mainnet_ledger_sns_wasm};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use icp_ledger::{
    AccountIdentifier, LedgerCanisterInitPayload, LedgerCanisterInitPayloadBuilder, TimeStamp,
};
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{BlockIndex, NumTokens},
};

const FEE: u64 = 10_000;
const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;

const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";

fn install_ledger(
    env: &StateMachine,
    initial_balances: HashMap<AccountIdentifier, Tokens>,
) -> CanisterId {
    let args = LedgerCanisterInitPayload::builder()
        .minting_account(AccountIdentifier::new(MINTER_PRINCIPAL, None))
        .transfer_fee(Tokens::from(FEE))
        .token_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .initial_values(initial_balances)
        .build()
        .unwrap();
    let ledger = build_mainnet_ledger_sns_wasm().wasm;
    env.install_canister(ledger, Encode!(&args).unwrap(), None)
        .unwrap()
}

fn get_account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

fn add_balance(
    initial_balances: &mut HashMap<AccountIdentifier, Tokens>,
    account: Account,
    balance: u64,
) {
    initial_balances.insert(AccountIdentifier::from(account), Tokens::from(balance));
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

#[test]
fn test_sns_metrics() {
    let state_machine = state_machine_builder_for_sns_tests().build();
    let alice = get_account(1, 0);
    let bob = get_account(2, 0);

    let ledger_canister_id = {
        let mut initial_balances = HashMap::new();
        add_balance(&mut initial_balances, alice, 1_000_000_000);
        add_balance(&mut initial_balances, bob, 1_000_000_000);
        install_ledger(&state_machine, initial_balances)
    };

    // make transfers to create blocks
    {
        let block_index = icrc1_transfer(
            &state_machine,
            ledger_canister_id,
            alice,
            bob,
            1_000_000,
            None, // @todo
            Some(0),
            Some(vec![]),
        );
        panic!("{}", block_index);
    }

    let governance_canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let governance = GovernanceCanisterInitPayloadBuilder::new()
            .with_ledger_canister_id(ledger_canister_id.into())
            .build();

        let args = Encode!(&governance).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    // run_canister_reset_timers_test(&state_machine, governance_canister_id, 600, 60);
}
