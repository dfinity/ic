use std::collections::HashMap;

use candid::{Decode, Encode};
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Tokens;
use ic_nns_test_utils::sns_wasm::{build_governance_sns_wasm, build_mainnet_ledger_sns_wasm};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance_api::pb::v1::{get_metrics_response, GetMetricsRequest};
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{BlockIndex, NumTokens},
};
const FEE: u64 = 10_000;

// const MINTER_PRINCIPAL: PrincipalId = PrincipalId::new(0, [0u8; 29]);

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";

fn install_ledger(env: &StateMachine, initial_balances: HashMap<Account, Tokens>) -> CanisterId {
    let mut init = InitArgsBuilder::with_symbol_and_name(TOKEN_NAME, TOKEN_SYMBOL);

    for (account, token) in initial_balances {
        init = init.with_initial_balance(account, token);
    }

    let init = init.build();
    let args = LedgerArgument::Init(init);
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

fn add_balance(initial_balances: &mut HashMap<Account, Tokens>, account: Account, balance: u64) {
    initial_balances.insert(account, Tokens::from(balance));
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

fn try_get_metrics(
    state_machine: &StateMachine,
    governance_canister_id: CanisterId,
    payload: GetMetricsRequest,
) -> Result<get_metrics_response::GetMetricsResponse, String> {
    let payload = Encode!(&payload).unwrap();
    let response = state_machine.query(governance_canister_id, "get_metrics", payload);

    match response {
        Ok(response) => {
            let response = response.bytes();
            let get_metrics_response =
                Decode!(&response, get_metrics_response::GetMetricsResponse).unwrap();
            Ok(get_metrics_response)
        }
        Err(err) => Err(err.to_string()),
    }
}

#[test]
fn test_sns_metrics() {
    let state_machine = state_machine_builder_for_sns_tests().build();
    let alice = get_account(1, 0);
    let bob = get_account(2, 0);
    let now = 1_748_854_120;

    let ledger_canister_id = {
        let mut initial_balances = HashMap::new();
        add_balance(&mut initial_balances, alice, 1_000_000_000);
        add_balance(&mut initial_balances, bob, 1_000_000_000);
        install_ledger(&state_machine, initial_balances)
    };

    // make transfers to create blocks
    {
        let created_at_time = TimeStamp::new(now, 0);

        let block_index = icrc1_transfer(
            &state_machine,
            ledger_canister_id,
            alice,
            bob,
            1_000_000,
            Some(created_at_time),
            Some(FEE),
            Some(vec![]),
        );
    }

    let governance_canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let governance = GovernanceCanisterInitPayloadBuilder::new()
            .with_root_canister_id(PrincipalId::new_anonymous())
            .with_swap_canister_id(PrincipalId::new_anonymous())
            .with_ledger_canister_id(ledger_canister_id.into())
            .build();

        let args = Encode!(&governance).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    {
        // Prepare the payload:
        let time_window_seconds = 30 * 24 * 3600;
        let payload = GetMetricsRequest {
            time_window_seconds: Some(time_window_seconds),
        };

        let observed_result =
            try_get_metrics(&state_machine, governance_canister_id, payload).unwrap();
        let get_metrics_response::GetMetricsResponse { get_metrics_result } = observed_result
        else {
            panic!("Unexpected get_metrics response");
        };

        let Some(get_metrics_result) = get_metrics_result else {
            panic!("Expected a non-empty response");
        };

        let get_metrics_response::GetMetricsResult::Ok(metrics) = get_metrics_result else {
            panic!("Expected to get an Ok() from the response");
        };

        // TODO
        // assertions on the received fields
    }
}
