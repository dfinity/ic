use ic_icrc1_ledger_sm_tests::setup_and_test_name;
use ic_ledger_core::Tokens;
use icp_ledger::LedgerCanisterInitPayload as InitArgs;
use std::collections::HashSet;

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ledger-canister",
        &[],
    )
}

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> InitArgs {
    let initial_values = args
        .initial_balances
        .into_iter()
        .map(|(account, amount)| (account.into(), Tokens::from_e8s(amount)))
        .collect();
    InitArgs {
        minting_account: args.minting_account.into(),
        initial_values,
        max_message_size_bytes: None,
        transaction_window: None,
        archive_options: Some(args.archive_options),
        send_whitelist: HashSet::new(),
        transfer_fee: Some(Tokens::from_e8s(args.transfer_fee)),
        token_symbol: Some(args.token_symbol),
        token_name: Some(args.token_name),
    }
}

#[test]
fn test_name() {
    let _ = setup_and_test_name(ledger_wasm(), encode_init_args, vec![]);
}
