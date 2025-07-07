use candid::{Decode, Encode};
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Tokens;
use ic_nns_test_utils::sns_wasm::{build_governance_sns_wasm, build_mainnet_ledger_sns_wasm};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::{ProposalData, ProposalId};
use ic_sns_governance_api::pb::v1::{get_metrics_response, GetMetricsRequest};
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{BlockIndex, NumTokens},
};
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

const FEE: u64 = 10_000;

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";

const TRANSFER_AMOUNT: u64 = 1_000_000;

const ALICE: u64 = 1;
const BOB: u64 = 2;
const INITIAL_BALANCE: u64 = 1_000_000_000;

const ONE_DAY: u64 = 24 * 3600;
const ONE_WEEK: u64 = 7 * ONE_DAY;
const ONE_MONTH: u64 = 4 * ONE_WEEK;

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
    use_replicated_mode: bool,
) -> Result<get_metrics_response::GetMetricsResponse, String> {
    let payload = Encode!(&payload).unwrap();

    let response = if use_replicated_mode {
        state_machine.execute_ingress(governance_canister_id, "get_metrics_replicated", payload)
    } else {
        state_machine.query(governance_canister_id, "get_metrics", payload)
    };

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
    // Prepare the world
    let state_machine = state_machine_builder_for_sns_tests().build();
    let alice = get_account(ALICE, 0);
    let bob = get_account(BOB, 0);

    // Prepare the world:
    // 1. create the ledger canister and add two accounts
    // for ALICE and BOB with INITIAL_BALANCE.
    let ledger_canister_id = {
        let mut initial_balances = HashMap::new();
        add_balance(&mut initial_balances, alice, INITIAL_BALANCE);
        add_balance(&mut initial_balances, bob, INITIAL_BALANCE);
        install_ledger(&state_machine, initial_balances)
    };

    let governance_canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let mut governance = GovernanceCanisterInitPayloadBuilder::new()
            .with_root_canister_id(PrincipalId::new_anonymous())
            .with_swap_canister_id(PrincipalId::new_anonymous())
            .with_ledger_canister_id(ledger_canister_id.into())
            .build();

        // Create proposals.
        {
            let state_machine_time = state_machine
                .time()
                .duration_since(UNIX_EPOCH)
                .expect("Time goes backward! Breaking the second law of thermodynamics")
                .as_secs();

            // Make 2 proposals, one for t0 + 2 * ONE_MONTH, one for t0,
            // where t0 ic the current time of the state machine.
            let proposal1_id = 1;
            #[allow(clippy::identity_op)]
            let proposal1 = ProposalData {
                id: Some(ProposalId { id: proposal1_id }),
                proposal_creation_timestamp_seconds: state_machine_time,
                executed_timestamp_seconds: state_machine_time + 1 * ONE_MONTH,
                ..Default::default()
            };

            governance.proposals.insert(proposal1_id, proposal1);

            let proposal2_id = 2;
            let proposal2 = ProposalData {
                id: Some(ProposalId { id: proposal2_id }),
                proposal_creation_timestamp_seconds: state_machine_time + 2 * ONE_MONTH,
                ..Default::default()
            };

            governance.proposals.insert(proposal2_id, proposal2);
        }

        // Create the transactions.
        {
            // We have 2 transactions: one at t0 and the other one after one month
            let _ = icrc1_transfer(
                &state_machine,
                ledger_canister_id,
                alice,
                bob,
                TRANSFER_AMOUNT,
                None,
                Some(FEE),
                Some(vec![]),
            );

            state_machine.advance_time(Duration::from_secs(ONE_MONTH));
            state_machine.tick();

            let _ = icrc1_transfer(
                &state_machine,
                ledger_canister_id,
                alice,
                bob,
                TRANSFER_AMOUNT,
                None,
                Some(FEE),
                Some(vec![]),
            );
        }

        let args = Encode!(&governance).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    state_machine.advance_time(Duration::from_secs(ONE_MONTH));
    state_machine.tick();
    {
        // Prepare the payload to get metrics during the last month.
        let time_window_seconds = 2 * ONE_MONTH;
        let payload = GetMetricsRequest {
            time_window_seconds: Some(time_window_seconds),
        };

        let observed_result =
            try_get_metrics(&state_machine, governance_canister_id, payload, true).unwrap();
        let observed_result_1 =
            try_get_metrics(&state_machine, governance_canister_id, payload, false).unwrap();

        assert_eq!(observed_result_1, observed_result);

        let Some(get_metrics_result) = observed_result.get_metrics_result else {
            panic!("Expected a non-empty response");
        };

        let get_metrics_response::GetMetricsResult::Ok(Metrics {
            num_recently_submitted_proposals,
            num_recently_executed_proposals,
            last_ledger_block_timestamp,
        }) = get_metrics_result else {
            panic!(
                "Expected to get an Ok() from the response, got {:?}",
                get_metrics_result
            );
        };

        {
            let Some(num_recently_submitted_proposals) = num_recently_submitted_proposals
            else {
                panic!("Expected `num_recently_submitted_proposals` to be Some(_)");
            };

            assert_eq!(
                num_recently_submitted_proposals, 2,
                "Expected 1 proposals to be submitted, got {}",
                num_recently_submitted_proposals
            );
        }

        {
            let Some(num_recently_executed_proposals) = num_recently_executed_proposals
            else {
                panic!("Expected `num_recently_executed_proposals` to be Some(_)");
            };

            assert_eq!(
                num_recently_executed_proposals, 1,
                "Expected 1 proposals to be executed, got {}",
                num_recently_executed_proposals
            );
        }

        {
            let Some(last_ledger_block_timestamp) = last_ledger_block_timestamp else {
                panic!("Expected `num_recently_submitted_proposals` to be Some(_)");
            };

            let now = state_machine
                .time()
                .duration_since(UNIX_EPOCH)
                .expect("Time goes backward! Breaking the second law of thermodynamics")
                .as_secs();

            assert_eq!(
                last_ledger_block_timestamp,
                now - ONE_MONTH,
                "Expected last ledger block timestamp to be {}, got {}",
                now,
                last_ledger_block_timestamp
            );
        }
    }
}
