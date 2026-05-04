use candid::{Decode, Encode};
use ic_icrc1_ledger::{InitArgsBuilder, LedgerArgument};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Tokens;
use ic_nervous_system_common::ledger::compute_distribution_subaccount;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_constants::NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_mainnet_ledger_sns_wasm, build_swap_sns_wasm,
};
use ic_nns_test_utils::state_test_helpers::setup_nns_canisters;
use ic_sns_governance::governance::TREASURY_SUBACCOUNT_NONCE;
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::neuron;
use ic_sns_governance::pb::v1::{Neuron, NeuronId, ProposalData, ProposalId};
use ic_sns_governance_api::pb::v1::{self as sns_gov, GetMetricsRequest, get_metrics_response};
use ic_sns_test_utils::{
    itest_helpers::SnsTestsInitPayloadBuilder,
    state_test_helpers::state_machine_builder_for_sns_tests,
};
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use icp_ledger::AccountIdentifier;
use icp_ledger::Subaccount as IcpSubaccount;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{BlockIndex, NumTokens},
};
use maplit::btreemap;
use pretty_assertions::assert_eq;
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

lazy_static::lazy_static! {
    static ref SNS_LEDGER_CANISTER_ID: CanisterId = CanisterId::from(NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET + 2);
}

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

fn install_swap(env: &StateMachine) -> CanisterId {
    let swap = build_swap_sns_wasm().wasm;
    let mut swap_arg = SnsTestsInitPayloadBuilder::new().build().swap;

    swap_arg.sns_root_canister_id = PrincipalId::new_anonymous().to_string();
    swap_arg.sns_governance_canister_id = PrincipalId::new_anonymous().to_string();
    swap_arg.sns_ledger_canister_id = PrincipalId::new_anonymous().to_string();

    swap_arg.nns_governance_canister_id = PrincipalId::new_anonymous().to_string();
    swap_arg.icp_ledger_canister_id = PrincipalId::new_anonymous().to_string();

    env.install_canister(swap, Encode!(&swap_arg).unwrap(), None)
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

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(
        PrincipalId(account.owner),
        account.subaccount.map(IcpSubaccount),
    )
}

#[test]
fn test_sns_metrics() {
    // Prepare the world
    let state_machine = state_machine_builder_for_sns_tests().build();

    // NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET is the last index used by `setup_nns_canisters`.
    let first_sns_canister_id = NODE_REWARDS_CANISTER_INDEX_IN_NNS_SUBNET + 1;

    // In this test, we install SNS Ledger, Swap, then SNS Governance canister.
    let governance = CanisterId::from(first_sns_canister_id + 2);

    let sns_treasury_account_nns = Account {
        owner: governance.get().0,
        subaccount: None,
    };

    let _sns_treasury_account_sns = Account {
        owner: governance.get().0,
        subaccount: Some(
            compute_distribution_subaccount(governance.get(), TREASURY_SUBACCOUNT_NONCE).0,
        ),
    };

    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![(
            icrc1_account_to_icp_accountidentifier(sns_treasury_account_nns),
            Tokens::new(10000, 0).unwrap(),
        )])
        .with_test_neurons()
        .build();

    setup_nns_canisters(&state_machine, nns_init_payloads);

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

    let swap_canister_id = install_swap(&state_machine);

    let expected_genesis_timestamp_seconds = 123456789; // Arbitrary value for testing

    let governance_canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let mut governance = GovernanceCanisterInitPayloadBuilder::new()
            .with_root_canister_id(CanisterId::from(42).get())
            .with_swap_canister_id(swap_canister_id.into())
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

        // Add a neuron.
        let neuron = Neuron {
            id: Some(NeuronId::new_test_neuron_id(1)),
            created_timestamp_seconds: 0,
            cached_neuron_stake_e8s: 1_000_000_000_000,
            voting_power_percentage_multiplier: 100,
            dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(12 * ONE_MONTH)),
            ..Default::default()
        };
        governance.neurons = btreemap! {
            NeuronId::new_test_neuron_id(1).to_string() => neuron,
        };

        // Ensure we have an expectation for `genesis_timestamp_seconds`.
        governance.genesis_timestamp_seconds = expected_genesis_timestamp_seconds;

        let args = Encode!(&governance).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    assert_eq!(governance, governance_canister_id);

    state_machine.advance_time(Duration::from_secs(ONE_MONTH));
    state_machine.tick();
    state_machine
        .execute_ingress(
            governance_canister_id,
            "run_periodic_tasks_now",
            Encode!(&()).unwrap(),
        )
        .unwrap();

    {
        // Prepare the payload to get metrics during the last month.
        let time_window_seconds = 2 * ONE_MONTH;
        let payload = GetMetricsRequest {
            time_window_seconds: Some(time_window_seconds),
        };

        let get_metrics_result =
            try_get_metrics(&state_machine, governance_canister_id, payload, true)
                .unwrap()
                .get_metrics_result
                .unwrap();
        let get_metrics_result_1 =
            try_get_metrics(&state_machine, governance_canister_id, payload, false)
                .unwrap()
                .get_metrics_result
                .unwrap();

        assert_eq!(get_metrics_result_1, get_metrics_result);

        let get_metrics_response::GetMetricsResult::Ok(get_metrics_response::Metrics {
            num_recently_submitted_proposals,
            num_recently_executed_proposals,
            last_ledger_block_timestamp,
            treasury_metrics,
            voting_power_metrics,
            genesis_timestamp_seconds,
        }) = get_metrics_result
        else {
            panic!("Expected to get an Ok() from the response, got {get_metrics_result:?}");
        };

        {
            let num_recently_submitted_proposals = num_recently_submitted_proposals.unwrap();

            assert_eq!(
                num_recently_submitted_proposals, 2,
                "Expected 1 proposals to be submitted, got {}",
                num_recently_submitted_proposals
            );
        }

        {
            let num_recently_executed_proposals = num_recently_executed_proposals.unwrap();

            assert_eq!(
                num_recently_executed_proposals, 1,
                "Expected 1 proposals to be executed, got {}",
                num_recently_executed_proposals
            );
        }

        {
            let last_ledger_block_timestamp = last_ledger_block_timestamp.unwrap();

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

        {
            // Redact the timestamps
            let treasury_metrics = treasury_metrics
                .unwrap()
                .into_iter()
                .map(
                    |sns_gov::TreasuryMetrics {
                         treasury,
                         name,
                         ledger_canister_id,
                         account,
                         amount_e8s,
                         original_amount_e8s,
                         timestamp_seconds: _, // We don't care about the timestamp in this test
                     }| sns_gov::TreasuryMetrics {
                        treasury,
                        name,
                        ledger_canister_id,
                        account,
                        amount_e8s,
                        original_amount_e8s,
                        timestamp_seconds: None, // Redact the timestamp
                    },
                )
                .collect::<Vec<_>>();

            assert_eq!(
                treasury_metrics,
                vec![sns_gov::TreasuryMetrics {
                    treasury: 1,
                    name: Some("TOKEN_ICP".to_string()),

                    ledger_canister_id: Some(LEDGER_CANISTER_ID.get()),
                    account: Some(sns_gov::Account {
                        owner: Some(governance_canister_id.get()),
                        subaccount: None,
                    }),

                    amount_e8s: Some(1000000000000),
                    original_amount_e8s: Some(0),

                    timestamp_seconds: None,
                }]
            )
        }

        {
            let voting_power_metrics = voting_power_metrics.unwrap();

            // This is quite a weak assertion. Once we get treasury valuations (and this test) to work
            // deterministically, we should make this assertion stronger.
            assert!(
                voting_power_metrics
                    .governance_total_potential_voting_power
                    .is_some()
            );
        }

        assert_eq!(
            genesis_timestamp_seconds,
            Some(expected_genesis_timestamp_seconds)
        );
    }
}
