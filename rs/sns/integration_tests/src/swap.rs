use candid::{Decode, Encode, Nat, Principal};
use dfn_candid::candid_one;

use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::{InitArgs as LedgerInit, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};

use ic_nervous_system_common::{
    assert_is_ok, ledger::compute_neuron_staking_subaccount, ExplosiveTokens, E8, SECONDS_PER_DAY,
    START_OF_2022_TIMESTAMP_SECONDS,
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL,
};
use ic_nns_common::{pb::v1 as nns_common_pb, types::ProposalId as NnsProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    self as nns_governance_pb,
    manage_neuron::{self, RegisterVote},
    manage_neuron_response::{self, StakeMaturityResponse},
    neuron::DissolveState::DissolveDelaySeconds,
    proposal, ManageNeuron, ManageNeuronResponse, OpenSnsTokenSwap, Proposal, ProposalStatus,
    RewardEvent, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    ids::TEST_NEURON_1_ID,
    sns_wasm::{
        add_real_wasms_to_sns_wasms_and_return_immediately, deploy_new_sns,
        wait_for_proposal_status,
    },
    state_test_helpers::{
        icrc1_balance, icrc1_transfer, ledger_account_balance, nns_governance_get_full_neuron,
        nns_governance_get_proposal_info_as_anonymous, nns_governance_make_proposal,
        nns_join_community_fund, nns_leave_community_fund, nns_stake_maturity, set_controllers,
        set_up_universal_canister, setup_nns_canisters, sns_governance_get_mode, sns_make_proposal,
        update_with_sender,
    },
};
use ic_sns_governance::pb::v1::{
    self as sns_governance_pb, governance::Mode as SnsGovernanceMode, ListNeurons,
    NervousSystemParameters, NeuronPermission, NeuronPermissionType,
};
use ic_sns_init::pb::v1::{
    sns_init_payload::InitialTokenDistribution, AirdropDistribution, DeveloperDistribution,
    FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload, SwapDistribution,
    TreasuryDistribution,
};
use ic_sns_swap::{
    pb::v1::{
        self as swap_pb, error_refund_icp_response, set_mode_call_result, ErrorRefundIcpRequest,
        ErrorRefundIcpResponse, GetOpenTicketResponse, GetStateRequest, GetStateResponse, Init,
        NeuronBasketConstructionParameters, OpenRequest, RefreshBuyerTokensResponse,
    },
    swap::principal_to_subaccount,
};
use ic_sns_test_utils::{
    now_seconds,
    state_test_helpers::{
        canister_status, get_buyer_state, get_open_ticket, get_sns_sale_parameters,
        list_community_fund_participants, new_sale_ticket, participate_in_swap,
        refresh_buyer_tokens, send_participation_funds,
        sns_governance_get_nervous_system_parameters, sns_governance_list_neurons,
        sns_root_register_dapp_canisters, swap_get_state,
    },
};
use ic_sns_wasm::pb::v1::SnsCanisterIds;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::{ingress::WasmResult, Cycles};

use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs as AccountBalanceArgs, BlockIndex,
    DEFAULT_TRANSFER_FEE as DEFAULT_TRANSFER_FEE_TOKENS,
};
use lazy_static::lazy_static;
use maplit::hashmap;
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use rand::{thread_rng, Rng, SeedableRng};
use std::{
    collections::{hash_map, HashMap, HashSet},
    time::{Duration, SystemTime},
};
const ONE_TRILLION: u128 = 1_000_000_000_000;
const EXPECTED_SNS_CREATION_FEE: u128 = 180 * ONE_TRILLION;
const SALE_DURATION_SECONDS: u64 = 13 * SECONDS_PER_DAY;

const DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR: f64 = 0.0;
use ic_nns_constants::LEDGER_CANISTER_ID;

lazy_static! {
    static ref INITIAL_ICP_BALANCE: ExplosiveTokens = ExplosiveTokens::from_e8s(100 * E8);
    static ref DEFAULT_TRANSFER_FEE: ExplosiveTokens =
        ExplosiveTokens::from(DEFAULT_TRANSFER_FEE_TOKENS);
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct SwapPerformanceResults {
    instructions_consumed_base: f64,
    instructions_consumed_swapping: f64,
    instructions_consumed_finalization: f64,
    time_to_finalize_swap: Duration,
}

/// For example, if you were expecting 10, but you observe 9, then, you have a
/// relative difference of -10%. The same relative difference would result if
/// you were expecting 1000, and you see 900, even though the 1000 - 900 = 100
/// is much greater than 10 - 9 = 1.
fn relative_difference(observed: f64, reference: f64) -> f64 {
    assert!(reference > 0.0, "{}", reference);
    (observed - reference) / reference
}

/// Returns a list of randomly generated principal IDs.
///
/// This relies on thread_rng. As a result, this produces consistent results iff
/// thread_rng does.
fn generate_principal_ids(count: u64) -> Vec<ic_base_types::PrincipalId> {
    (0..count)
        .map(|_| PrincipalId::new_user_test_id(thread_rng().gen()))
        .collect()
}

fn generate_community_fund_neurons(neuron_ids: &[u64]) -> Vec<nns_governance_pb::Neuron> {
    neuron_ids
        .iter()
        .map(|neuron_id| {
            let controller = PrincipalId::new_user_test_id(thread_rng().gen());
            let account = AccountIdentifier::new(
                NNS_GOVERNANCE_CANISTER_ID.into(),
                Some(compute_neuron_staking_subaccount(
                    controller, /* nonce = */ 0,
                )),
            )
            .to_address();

            nns_governance_pb::Neuron {
                id: Some(nns_common_pb::NeuronId { id: *neuron_id }),
                account: account.into(),
                controller: Some(controller),
                cached_neuron_stake_e8s: 100 * E8,
                maturity_e8s_equivalent: 100 * E8,
                ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
            }
        })
        .collect()
}

/// Serves as a fixture (factory) for the tests in this file. (The previous
/// stuff is generic to any SNS test; whereas, this is specific to swap.)
///
/// Configures, creates, and inits the following canisters:
///   1. NNS
///   2. SNS
///   3. dapp
///
/// Brings the SNS token swap canister to the Open state. That is, this not only
/// creates the canister, and installs the code, but also does the following:
///
///   1. Funds it with SNS tokens.
///   2. Makes OpenSnsTokenSwap NNS proposal.
///     a. The proposal includes Community Fund. The return value includes a
///        list of the NNS CF neurons (i.e. those that will participate in the
///        Community Fund if/when the proposal passes).
///   3. Makes all NNS neurons vote in favor of the proposal so that it passes
///      and executes.
///
/// At that point, the test can start sending direct participants (as opposed to
/// CF participants) to the swap.
///
/// TEST_USER2 has 100 ICP that they can use to buy into the swap, as well as
/// any principal IDs listed in `direct_participant_principal_ids`.
fn begin_swap_legacy(
    state_machine: &mut StateMachine,
    direct_participant_principal_ids: &[ic_base_types::PrincipalId],
    additional_nns_neurons: &[nns_governance_pb::Neuron],
    planned_participation_amount_per_account: ExplosiveTokens,
    planned_community_fund_participation_amount: ExplosiveTokens,
    neuron_basket_count: u64,
    max_community_fund_relative_error: f64,
    before_proposal_is_adopted: impl FnOnce(&mut StateMachine),
) -> (
    SnsCanisterIds,
    /* community_fund_nns_neurons */ Vec<nns_governance_pb::Neuron>,
    FractionalDeveloperVotingPower,
    /* dapp_canister_id */ CanisterId,
    NnsProposalId,
) {
    let direct_participant_count = direct_participant_principal_ids.len().max(1) as u64;
    // Give TEST_USER2 and everyone in `direct_participant_principal_ids` some ICP so that they can buy into the swap.
    let test_user2_principal_id: PrincipalId = *TEST_USER2_PRINCIPAL;
    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);
    let nns_init_payloads = {
        let mut builder = NnsInitPayloadsBuilder::new();
        builder
            .with_initial_invariant_compliant_mutations()
            .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
            .with_sns_wasm_access_controls(true)
            .with_sns_wasm_allowed_principals(vec![wallet_canister_id.into()])
            .with_ledger_account(
                test_user2_principal_id.into(),
                (*INITIAL_ICP_BALANCE).into(),
            )
            .with_ledger_accounts(
                direct_participant_principal_ids
                    .iter()
                    .map(|principal_id| ((*principal_id).into(), (*INITIAL_ICP_BALANCE).into()))
                    .collect(),
            )
            .with_test_neurons();

        // Enhance the standard neurons so that they all have some maturity, and
        // a couple of them are in the Community Fund.
        if additional_nns_neurons.is_empty() {
            let neurons = &mut builder.governance.proto.neurons;
            assert_eq!(neurons.len(), 3, "{:#?}", neurons);

            // Modify some of the test neurons so that they all have some
            // maturity, and some of them are in the Community Fund. The
            // maturity of the CF neurons can later be used to participate in an
            // SNS token swap/sale.
            let mut n = 1;
            for (i, neuron) in neurons.values_mut().enumerate() {
                neuron.maturity_e8s_equivalent = n * 25 * E8;
                n *= 3;

                if i < 2 {
                    neuron.joined_community_fund_timestamp_seconds = Some(1);
                }
            }
        }

        // Add extra neurons.
        for neuron in additional_nns_neurons {
            // Insert each element into builder.governance.proto.neurons,
            // but only if the ID is unique.
            let neuron_id = neuron.id.as_ref().unwrap().id;
            let entry = builder.governance.proto.neurons.entry(neuron_id);
            match entry {
                hash_map::Entry::Occupied(_) => {
                    panic!("Neuron ID {} is not unique.", neuron_id);
                }
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(neuron.clone());
                }
            }
        }

        let mut result = builder.build();

        // Stop voting rewards from happening by setting last_reward_event to far into the future.
        result.governance.latest_reward_event = Some(RewardEvent {
            day_after_genesis: 999_999_999_999,
            actual_timestamp_seconds: 32503680000,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0),
        });

        result
    };

    let neuron_id_to_principal_id: HashMap<u64, PrincipalId> = nns_init_payloads
        .governance
        .neurons
        .iter()
        .map(|(id, neuron)| (*id, neuron.controller.unwrap()))
        .collect();

    setup_nns_canisters(state_machine, nns_init_payloads.clone());

    {
        fn is_executed(status: i32) -> bool {
            status == ProposalStatus::Executed as i32
        }
        let proposal_timeout = Duration::from_secs(120); // This is probably overly generous.
        for (_, (proposal_id, _)) in
            add_real_wasms_to_sns_wasms_and_return_immediately(state_machine)
        {
            stuff_ballot_box(
                state_machine,
                proposal_id,
                &neuron_id_to_principal_id,
                Vote::Yes,
            );
            wait_for_proposal_status(state_machine, proposal_id, is_executed, proposal_timeout);
        }
    }

    let fund_raising_amount_icp_e8s = (planned_participation_amount_per_account
        * direct_participant_count
        + planned_community_fund_participation_amount)
        .into_e8s();
    // Scale up SNS tokens to ensure that participants get enough SNS tokens to form neurons.
    let sns_token_e8s = fund_raising_amount_icp_e8s * neuron_basket_count;

    // Create, configure, and init SNS canisters.
    let mut sns_init_payload: SnsInitPayload =
        SnsInitPayload::with_valid_legacy_values_for_testing();
    sns_init_payload.fallback_controller_principal_ids = vec![TEST_USER1_PRINCIPAL.to_string()];
    let fractional_developer_voting_power = FractionalDeveloperVotingPower {
        swap_distribution: Some(SwapDistribution {
            total_e8s: sns_token_e8s,
            initial_swap_amount_e8s: sns_token_e8s,
        }),
        airdrop_distribution: Some(AirdropDistribution {
            airdrop_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
        }),
        developer_distribution: Some(DeveloperDistribution {
            developer_neurons: vec![],
        }),
        treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
    };
    sns_init_payload.initial_token_distribution =
        Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            fractional_developer_voting_power.clone(),
        ));
    let cycle_count = EXPECTED_SNS_CREATION_FEE;
    let wallet_canister = set_up_universal_canister(state_machine, Some(Cycles::new(cycle_count)));
    println!(
        "BEGIN sns_init_payload\n{:#?}\nEND sns_init_payload",
        sns_init_payload
    );
    let deploy_new_sns_response = deploy_new_sns(
        state_machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
        cycle_count,
    );
    let canister_ids = deploy_new_sns_response
        .canisters
        .unwrap_or_else(|| panic!("SNS deployment failed: {:#?}", deploy_new_sns_response));
    let sns_governance_canister_id =
        CanisterId::try_from(canister_ids.governance.unwrap()).unwrap();

    let sns_neuron_principal_id = fractional_developer_voting_power
        .airdrop_distribution
        .as_ref()
        .unwrap()
        .airdrop_neurons[0]
        .controller
        .unwrap();
    let sns_neuron_id = sns_governance_pb::NeuronId {
        id: compute_neuron_staking_subaccount(sns_neuron_principal_id, /* memo */ 0)
            .0
            .to_vec(),
    };

    let assert_pre_initialization_swap_mode = |state_machine: &mut StateMachine| {
        assert_eq!(
            sns_governance_get_mode(state_machine, sns_governance_canister_id),
            Ok(SnsGovernanceMode::PreInitializationSwap as i32),
        );

        let err = sns_make_proposal(
            state_machine,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_governance_pb::Proposal {
                title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                        in PreInitializationSwap mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(
                    sns_governance_pb::proposal::Action::ManageNervousSystemParameters(
                        NervousSystemParameters {
                            reject_cost_e8s: Some(20_000), // More strongly discourage spam
                            ..Default::default()
                        },
                    ),
                ),
            },
        )
        .unwrap_err();
        let sns_governance_pb::GovernanceError {
            error_type,
            error_message,
        } = &err;

        use sns_governance_pb::governance_error::ErrorType;
        assert_eq!(
            ErrorType::from_i32(*error_type).unwrap(),
            ErrorType::PreconditionFailed,
            "{:#?}",
            err
        );
        assert!(
            error_message.contains("PreInitializationSwap"),
            "{:#?}",
            err
        );

        // assert that SNS neuron is not allowed to start dissolving yet.
        let start_dissolving_request = sns_governance_pb::ManageNeuron {
            subaccount: sns_neuron_id.id.clone(),
            command: Some(sns_governance_pb::manage_neuron::Command::Configure(
                sns_governance_pb::manage_neuron::Configure {
                    operation: Some(
                        sns_governance_pb::manage_neuron::configure::Operation::StartDissolving(
                            sns_governance_pb::manage_neuron::StartDissolving {},
                        ),
                    ),
                },
            )),
        };
        let start_dissolving_response: sns_governance_pb::ManageNeuronResponse =
            update_with_sender(
                state_machine,
                sns_governance_canister_id,
                "manage_neuron",
                candid_one,
                start_dissolving_request,
                sns_neuron_principal_id,
            )
            .expect("Error calling the manage_neuron API.");
        use sns_governance_pb::manage_neuron_response::Command;
        match start_dissolving_response.command {
            // An error is expected.
            Some(Command::Error(error)) => {
                let sns_governance_pb::GovernanceError {
                    error_type,
                    error_message,
                } = &error;
                // Inspect the error.
                assert_eq!(
                    ErrorType::from_i32(*error_type).unwrap(),
                    ErrorType::PreconditionFailed,
                    "{:#?}",
                    error
                );
                assert!(
                    error_message.contains("PreInitializationSwap"),
                    "{:#?}",
                    error
                );
            }

            response => panic!("{:#?}", response),
        };
    };
    assert_pre_initialization_swap_mode(state_machine);

    // Create dapp canister, and make it controlled by the SNS that was just created.
    let dapp_canister_id = state_machine.create_canister(/* settings = */ None);
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        dapp_canister_id,
        vec![canister_ids.root.unwrap()],
    );
    sns_root_register_dapp_canisters(
        state_machine,
        canister_ids.root.unwrap().try_into().unwrap(),
        canister_ids.governance.unwrap().try_into().unwrap(),
        vec![dapp_canister_id],
    );

    // Make OpenSnsTokenSwap proposal.
    let min_icp_e8s =
        if max_community_fund_relative_error == DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR {
            fund_raising_amount_icp_e8s - 1
        } else {
            ((1.0 - max_community_fund_relative_error) * fund_raising_amount_icp_e8s as f64) as u64
        };
    let proposal = Proposal {
        title: Some("Schedule SNS Token Sale".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(proposal::Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
            target_swap_canister_id: Some(canister_ids.swap.unwrap()),
            params: Some(swap_pb::Params {
                // Succeed as soon as we raise `fund_raising_amount_icp_e8s`. In this case,
                // SNS tokens and ICP trade at a ratio of `neuron_basket` so each
                // created neron reached minimum stake requirements.
                max_icp_e8s: fund_raising_amount_icp_e8s,
                // We want to make sure our test is exactly right, so we set the
                // minimum to be just one e8 less than the maximum.
                min_icp_e8s,

                // We need at least one participant, but they can contribute whatever
                // amount they want (subject to max_icp_e8s for the whole swap).
                min_participants: 1,
                // 1.2 ICP to ensure that all participants are able to form SNS
                // neurons.
                min_participant_icp_e8s: E8 * 5 / 4,
                max_participant_icp_e8s: INITIAL_ICP_BALANCE.get_e8s(),
                swap_due_timestamp_seconds: swap_due_from_now_timestamp_seconds(state_machine),
                sns_token_e8s,
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: neuron_basket_count,
                    dissolve_delay_interval_seconds: 7890000, // 3 months,
                }),
                sale_delay_seconds: None,
            }),
            // This is not sufficient to make the swap an automatic success.
            community_fund_investment_e8s: Some(
                planned_community_fund_participation_amount.into_e8s(),
            ),
        })),
    };
    println!("proposal = {:#?}", proposal);
    let response = match nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL, // sender
        nns_common_pb::NeuronId {
            id: TEST_NEURON_1_ID,
        },
        &proposal,
    )
    .command
    {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        command => panic!("Response was not of type MakeProposal: {:#?}", command),
    };
    let proposal_id = response
        .proposal_id
        .unwrap_or_else(|| panic!("Response did not contain a proposal_id: {:#?}", response));

    before_proposal_is_adopted(state_machine);

    assert_pre_initialization_swap_mode(state_machine);

    // Make all the neurons vote for the OpenSnsTokenSwap proposal.
    stuff_ballot_box(
        state_machine,
        proposal_id.into(),
        &neuron_id_to_principal_id,
        Vote::Yes,
    );

    // Proposal executed successfully.
    let proposal = nns_governance_get_proposal_info_as_anonymous(state_machine, proposal_id.id);
    assert_eq!(proposal.failure_reason, None, "{:#?}", proposal);
    assert!(proposal.executed_timestamp_seconds > 0, "{:#?}", proposal);

    // Make sure that the swap is now open.
    {
        let result = swap_get_state(
            state_machine,
            canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Open,
            "{:#?}",
            result
        );
    }

    assert_pre_initialization_swap_mode(state_machine);

    let community_fund_neurons = nns_init_payloads
        .governance
        .neurons
        .iter()
        .filter_map(|(_id, original_neuron)| {
            // There is at least one test where the membership of the Community
            // Fund changes during the voting of the OpenSnsTokenSwap
            // proposal. Therefore, we query governance to determine the subset
            // of the ORIGINAL neurons that we want to return.
            let refreshed_neuron = nns_governance_get_full_neuron(
                state_machine,
                original_neuron.controller.unwrap(),
                original_neuron.id.as_ref().unwrap().id,
            )
            .unwrap();
            refreshed_neuron.joined_community_fund_timestamp_seconds?;

            Some(original_neuron.clone())
        })
        .collect();

    (
        canister_ids,
        community_fund_neurons,
        fractional_developer_voting_power,
        dapp_canister_id,
        proposal_id.into(),
    )
}

fn stuff_ballot_box(
    state_machine: &mut StateMachine,
    proposal_id: NnsProposalId,
    neuron_id_to_principal_id: &HashMap<u64, PrincipalId>,
    vote: Vote,
) {
    for (neuron_id, principal_id) in neuron_id_to_principal_id {
        // Skip TEST_NEURON_1, since it, being the proposer, automatically voted in favor already.
        if *neuron_id == TEST_NEURON_1_ID {
            continue;
        }

        state_machine
            .execute_ingress_as(
                *principal_id,
                NNS_GOVERNANCE_CANISTER_ID,
                "manage_neuron",
                Encode!(&ManageNeuron {
                    id: Some(nns_common_pb::NeuronId { id: *neuron_id }),
                    command: Some(manage_neuron::Command::RegisterVote(RegisterVote {
                        proposal: Some(proposal_id.into()),
                        vote: vote as i32,
                    })),
                    neuron_id_or_subaccount: None
                })
                .unwrap(),
            )
            .unwrap();
    }

    let proposal = nns_governance_get_proposal_info_as_anonymous(state_machine, proposal_id.0);
    assert!(proposal.decided_timestamp_seconds > 0, "{:#?}", proposal);
}

#[test]
fn swap_lifecycle_happy_one_neuron_legacy() {
    assert_successful_swap_finalizes_correctly_legacy(
        &generate_principal_ids(1),         // direct_participant_principal_ids
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    );
}

#[test]
fn swap_lifecycle_happy_two_neurons_legacy() {
    assert_successful_swap_finalizes_correctly_legacy(
        &generate_principal_ids(2),         // direct_participant_principal_ids
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    );
}

#[test]
fn swap_lifecycle_happy_more_neurons_legacy() {
    assert_successful_swap_finalizes_correctly_legacy(
        &generate_principal_ids(101),       // direct_participant_principal_ids
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(10 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    );
}

lazy_static! {
    static ref COMMUNITY_FUND_NEURON_TEMPLATE: nns_governance_pb::Neuron = nns_governance_pb::Neuron {
        // These fields need to be filled in.
        id: None,
        account: vec![],
        controller: None,
        // Technically, you could just leave this as is, but a CF neuron with no maturity is kinda
        // useless.
        maturity_e8s_equivalent: 0,

        // Fields that we want to have non-default values.
        cached_neuron_stake_e8s: 10 * E8,
        joined_community_fund_timestamp_seconds: Some(START_OF_2022_TIMESTAMP_SECONDS),
        created_timestamp_seconds: START_OF_2022_TIMESTAMP_SECONDS,
        aging_since_timestamp_seconds: START_OF_2022_TIMESTAMP_SECONDS,
        dissolve_state: Some(DissolveDelaySeconds(4 * 365 * SECONDS_PER_DAY)),

        // Fields where we want the default value. (These are filled in explicitly instead of using
        // ..Default::default so that if/when new fields are added to Neuron, the compiler will tell
        // the programmer to update this test.)
        hot_keys: vec![],
        neuron_fees_e8s: 0,
        spawn_at_timestamp_seconds: None,
        followees: hashmap! {},
        recent_ballots: vec![],
        kyc_verified: false,
        transfer: None,
        staked_maturity_e8s_equivalent: None,
        auto_stake_maturity: None,
        not_for_profit: false,
        known_neuron_data: None,
    };
}

fn craft_community_fund_neuron(maturity_e8s_equivalent: u64) -> nns_governance_pb::Neuron {
    let controller = PrincipalId::new_user_test_id(thread_rng().gen());
    let account = AccountIdentifier::new(
        NNS_GOVERNANCE_CANISTER_ID.into(),
        Some(compute_neuron_staking_subaccount(
            controller, /* nonce = */ 0,
        )),
    );
    nns_governance_pb::Neuron {
        id: Some(nns_common_pb::NeuronId {
            id: thread_rng().gen(),
        }),
        account: account.to_address().into(),
        controller: Some(controller),
        maturity_e8s_equivalent,
        ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
    }
}

fn swap_due_from_now_timestamp_seconds(state_machine: &StateMachine) -> u64 {
    state_machine
        .time()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed timestamp computation")
        .as_secs()
        + SALE_DURATION_SECONDS
}

// Swap should succeed when there are many large Community Fund neurons (i.e. CF
// neurons with a large amount of maturity), and few small ones.
#[test]
fn many_large_community_fund_neurons_and_some_small_ones_legacy() {
    let maturities_e8s = [
        // Large neurons.
        100_000 * E8,
        101_000 * E8,
        102_000 * E8,
        103_000 * E8,
        104_000 * E8,
        105_000 * E8,
        106_000 * E8,
        107_000 * E8,
        108_000 * E8,
        109_000 * E8,
        // More large neurons.
        110_000 * E8,
        111_000 * E8,
        112_000 * E8,
        113_000 * E8,
        114_000 * E8,
        115_000 * E8,
        116_000 * E8,
        117_000 * E8,
        118_000 * E8,
        119_000 * E8,
        // Small Neurons.
        E8 + 1,
        E8 + 2,
        E8 + 3,
    ];
    let additional_nns_neurons = maturities_e8s
        .iter()
        .cloned() // "dereference" &u64 en masse.
        .map(craft_community_fund_neuron)
        .collect::<Vec<_>>();

    let direct_participant_principal_ids = generate_principal_ids(20);
    let planned_community_fund_participation_amount =
        ExplosiveTokens::from_e8s((100..121_u64).sum::<u64>() * E8 / 2);
    let max_community_fund_relative_error = 0.025;
    assert_successful_swap_finalizes_correctly_legacy(
        &direct_participant_principal_ids,
        &additional_nns_neurons,
        planned_community_fund_participation_amount,
        max_community_fund_relative_error,
        do_nothing_special_before_proposal_is_adopted,
    );
}

// Similar to the pervious test, swap should succeed when there are many small
// Community Fund neurons (i.e. CF neurons with a large amount of maturity), and
// few large ones.
#[test]
fn many_small_community_fund_neurons_and_some_large_ones() {
    let maturities_e8s = [
        // Large neurons.
        100_000 * E8,
        101_000 * E8,
        102_000 * E8,
        // Small Neurons.
        100 * E8 / 10,
        101 * E8 / 10,
        102 * E8 / 10,
        103 * E8 / 10,
        104 * E8 / 10,
        105 * E8 / 10,
        106 * E8 / 10,
        107 * E8 / 10,
        108 * E8 / 10,
        109 * E8 / 10,
        // More small neurons.
        200 * E8 / 10,
        201 * E8 / 10,
        202 * E8 / 10,
        203 * E8 / 10,
        204 * E8 / 10,
        205 * E8 / 10,
        206 * E8 / 10,
        207 * E8 / 10,
        208 * E8 / 10,
        209 * E8 / 10,
    ];
    let additional_nns_neurons = maturities_e8s
        .iter()
        .cloned() // "dereference" &u64 en masse.
        .map(craft_community_fund_neuron)
        .collect::<Vec<_>>();

    let direct_participant_principal_ids = generate_principal_ids(20);
    let planned_community_fund_participation_amount =
        ExplosiveTokens::from_e8s((100..103_u64).sum::<u64>() * E8 / 2);
    let max_community_fund_relative_error = 0.10;
    assert_successful_swap_finalizes_correctly_legacy(
        &direct_participant_principal_ids,
        &additional_nns_neurons,
        planned_community_fund_participation_amount,
        max_community_fund_relative_error,
        do_nothing_special_before_proposal_is_adopted,
    );
}

#[test]
fn same_principal_can_participate_via_community_fund_and_directly() {
    let double_participant_principal_id = PrincipalId::new_user_test_id(544564);
    println!(
        "double_participant_principal_id={}",
        double_participant_principal_id
    );

    // Craft a CF neuron for participant.
    let neuron_id = 189804;
    let account = AccountIdentifier::new(
        NNS_GOVERNANCE_CANISTER_ID.into(),
        Some(compute_neuron_staking_subaccount(
            double_participant_principal_id,
            /* nonce = */ 0,
        )),
    );
    let double_participant_neuron = nns_governance_pb::Neuron {
        id: Some(nns_common_pb::NeuronId { id: neuron_id }),
        account: account.to_address().into(),
        controller: Some(double_participant_principal_id),
        maturity_e8s_equivalent: 10 * E8,
        ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
    };

    let mut direct_participant_principal_ids = generate_principal_ids(5);
    direct_participant_principal_ids.push(double_participant_principal_id);
    let additional_nns_neurons = [double_participant_neuron];

    assert_successful_swap_finalizes_correctly_legacy(
        &direct_participant_principal_ids,
        &additional_nns_neurons,
        ExplosiveTokens::from_e8s(5 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    );
}

#[test]
fn neurons_only_join_the_community_fund_during_voting() {
    assert_community_fund_can_change_while_proposal_is_being_voted_on(
        10,                   // stay_count
        0,                    // leave_count
        5,                    // join_count
        11288122177468989036, // random_seed
    );
}

#[test]
fn neurons_only_leave_the_community_fund_during_voting() {
    assert_community_fund_can_change_while_proposal_is_being_voted_on(
        10,                  // stay_count
        2,                   // leave_count
        0,                   // join_count
        2612471674910364877, // random_seed
    );
}

#[test]
fn some_neurons_leave_and_join_the_community_fund_during_voting() {
    assert_community_fund_can_change_while_proposal_is_being_voted_on(
        10,                   // stay_count
        7,                    // leave_count
        5,                    // join_count
        11960830403312471140, // random_seed
    );
}

#[test]
fn some_neurons_leave_but_more_join_the_community_fund_during_voting() {
    assert_community_fund_can_change_while_proposal_is_being_voted_on(
        10,                  // stay_count
        6,                   // leave_count
        9,                   // join_count
        7212414449212415636, // random_seed
    );
}

#[test]
fn more_neurons_leave_and_join_the_community_fund_during_voting() {
    assert_community_fund_can_change_while_proposal_is_being_voted_on(
        25,                  // stay_count
        15,                  // leave_count
        17,                  // join_count
        6411684775390932754, // random_seed
    );
}

proptest! {
    // The default number of cases that proptest generates is 256. That would
    // take way too long for us, so tell it to generate fewer cases here.
    #![proptest_config(ProptestConfig::with_cases(10))]

    // This is excluded unless `--test_args=--ignored` is part of the
    // `bazel test` command.
    #[ignore] // Too slow.
    #[test]
    fn test_community_fund_can_change_while_proposal_is_being_voted_on(
        stay_count in 1..25_u64, // TODO: Support testing of full CF turnover.
        leave_count in 0..10_u64,
        join_count in 0..10_u64,
        random_seed in 0..u64::MAX,
    ) {
        assert_community_fund_can_change_while_proposal_is_being_voted_on(
            stay_count,
            leave_count,
            join_count,
            random_seed,
        );
    }
}

/// # Arguments
///   * `stay_count` The number of NNS neurons that stay in the Community Fund.
///   * `leave_count` The number of NNS neurons that are in the CF when the
///     OpenSnsTokenSwap proposal is made, but leave before the proposal is adopted.
///   * `join_count` The oppoiste of leave_count: the number of NNS neurons that are
///     NOT in the CF when the proposal is made, but join before before it is adopted.
///   * `random_seed` How a suitable value can be chosen:
///     python3 -c 'import random as r; print(r.SystemRandom().randint(0, 2 ** 64))'
///
/// Additionally, there is a third category of NNS neurons: Those that join
/// after the OSTS proposal is made, but before it is adopted.
fn assert_community_fund_can_change_while_proposal_is_being_voted_on(
    stay_count: u64,
    leave_count: u64,
    join_count: u64,
    random_seed: u64,
) {
    // Define some helpers.

    let mut rng = rand::rngs::SmallRng::seed_from_u64(random_seed);
    let mut randomize_maturities =
        |mut neurons: Vec<nns_governance_pb::Neuron>| -> Vec<nns_governance_pb::Neuron> {
            const LOW: u64 = 10 * E8;
            const HIGH: u64 = 250 * E8;
            for neuron in neurons.iter_mut() {
                neuron.maturity_e8s_equivalent = rng.gen_range(LOW..HIGH);
            }
            neurons
        };

    let mut next_start: u64 = 1;
    let mut craft_range = |len: u64| {
        let result = (next_start..(next_start + len)).collect::<Vec<_>>();
        next_start += len;
        result
    };

    // Prepare the world. This mostly entails crafting a bunch of neurons. There
    // are three categories of such neurons, as described in the comments
    // directly before this function.

    let stay_neuron_ids = craft_range(stay_count);
    let leave_neuron_ids = craft_range(leave_count);
    let join_neuron_ids = craft_range(join_count);

    let stay_neurons = randomize_maturities(generate_community_fund_neurons(&stay_neuron_ids));
    let leave_neurons = randomize_maturities(generate_community_fund_neurons(&leave_neuron_ids));
    let join_neurons = {
        let mut result = generate_community_fund_neurons(&join_neuron_ids);
        // Pull join_neurons from the CF so that they can join later (after the
        // proposal has proferred, but before the proposal is adopted).
        result
            .iter_mut()
            .for_each(|n| n.joined_community_fund_timestamp_seconds = None);
        randomize_maturities(result)
    };

    assert_community_fund_can_change_while_proposal_is_being_voted_on_with_specific_neurons(
        &stay_neurons,
        &leave_neurons,
        &join_neurons,
    );
}

#[test]
fn small_community_fund_neuron_gets_dropped_due_to_cf_growth_during_voting() {
    let mut next_start: u64 = 1;
    let mut craft_range = |len: u64| {
        let result = (next_start..(next_start + len)).collect::<Vec<_>>();
        next_start += len;
        result
    };

    // Prepare the world. This mostly entails crafting a bunch of neurons. There
    // are three categories of such neurons, as described in the comments
    // directly before this function.

    let stay_neuron_ids = craft_range(11);
    let leave_neuron_ids = craft_range(0);
    // Make almost 2x more neurons, causing the the original/stay neurons to
    // participate in the decentralization sale by (almost) half as much.
    // Whereas, before, they were going to spend 10%, but because of these join
    // neurons, neurons will participate at only (roughly) 5%.
    let join_neuron_ids = craft_range(10);

    let stay_neurons = {
        let mut result = generate_community_fund_neurons(&stay_neuron_ids);

        // This causes the first neuron to be slightly above the the per
        // participant minimum in the original set of CF neurons. However, once
        // more neurons join, this neuron will be too small to participate. It
        // gets "crowded out".
        result.get_mut(0).unwrap().maturity_e8s_equivalent = 15 * E8;

        result
    };
    let leave_neurons = generate_community_fund_neurons(&leave_neuron_ids);
    let join_neurons = {
        let mut result = generate_community_fund_neurons(&join_neuron_ids);
        // Pull join_neurons from the CF so that they can join later (after the
        // proposal has proferred, but before the proposal is adopted).
        result
            .iter_mut()
            .for_each(|n| n.joined_community_fund_timestamp_seconds = None);
        result
    };

    assert_community_fund_can_change_while_proposal_is_being_voted_on_with_specific_neurons(
        &stay_neurons,
        &leave_neurons,
        &join_neurons,
    );
}

/// A lower level version of
/// assert_community_fund_can_change_while_proposal_is_being_voted_on.
///
/// Whereas, as that simply requires a few neuron count arguments, and generates
/// some neurons (albeit with randomized maturities), this takes lists of fully
/// formed neurons as arguments.
///
/// Therefore, this version is less convenient, but allows greater control
/// (classic design tradeoff). The other is implemented in terms of
/// this. Therefore, we sort of get the "best of both worlds" while also
/// re-using as much code as possible. Of course, this makes things more
/// complicated, because now we have two very similar functions, but that is
/// balanced by the fact that this is "just test code".
fn assert_community_fund_can_change_while_proposal_is_being_voted_on_with_specific_neurons(
    stay_neurons: &Vec<nns_governance_pb::Neuron>,
    leave_neurons: &Vec<nns_governance_pb::Neuron>,
    join_neurons: &Vec<nns_governance_pb::Neuron>,
) {
    // Concatenate the three Vec<Neuron> that were built in the previous block
    // of code.
    let additional_nns_neurons = {
        let mut result = vec![];
        for neurons in [stay_neurons, leave_neurons, join_neurons] {
            result.append(&mut neurons.clone());
        }
        result
    };
    assert_eq!(
        additional_nns_neurons.len(),
        stay_neurons.len() + leave_neurons.len() + join_neurons.len(),
    );

    // Done crafting neurons described earlier. Now, we do some accounting of
    // maturities. We need this, because the total CF participation amount might
    // end up differing significantly from the planned amount, due to neurons
    // joining and leaving the CF while the proposal is being voted on.

    fn total_maturity_e8s(neurons: &[nns_governance_pb::Neuron]) -> u64 {
        neurons.iter().map(|n| n.maturity_e8s_equivalent).sum()
    }
    let stay_amount_e8s = total_maturity_e8s(stay_neurons);
    let leave_amount_e8s = total_maturity_e8s(leave_neurons);
    let join_amount_e8s = total_maturity_e8s(join_neurons);

    let before_amount_e8s = stay_amount_e8s + leave_amount_e8s;
    assert!(before_amount_e8s > 0, "{}", before_amount_e8s);
    let after_amount_e8s = stay_amount_e8s + join_amount_e8s;

    let relative_error = -relative_difference(after_amount_e8s as f64, before_amount_e8s as f64);
    let max_community_fund_relative_error = (relative_error
            // This additional fudge factor is needed because maturity
            // randomization can result in shortfalls due to individual
            // participant limits.
            * 1.1)
        // See the previous comment, which describes another related fudge factor.
        .max(0.03);
    println!(
        "maturity (e8s) before={} vs. after={} (relative_error={}",
        before_amount_e8s, after_amount_e8s, relative_error,
    );

    // Done with maturity accounting.

    // Propose that 10% of the (original) CF amount be used to participate in
    // the decentralization sale.
    let target_participation_proportion = 0.10;
    let planned_community_fund_participation_amount = ExplosiveTokens::from_e8s(
        (target_participation_proportion * before_amount_e8s as f64) as u64,
    );

    // The following call inspects CF neurons to make sure the right amount is
    // deducted from their maturities after the decentralization sale/swap is
    // finalized (this is part of asserting that the decentralization sale/swap
    // "finalizes correctly"). It does this by dynamically calculating the
    // expected values. Because of all this dynamic calculation, you might
    // consider it to be "too smart" for test code. That is a fair criticism. As
    // you can imagine, this situation came about due to organic
    // growth/development of this code by multiple engineers.
    //
    // TODO: Figure out how to make asserts more transparent, but also somehow
    // balance that with the desire to avoid massive amounts of copy n' paste
    // code :/
    assert_successful_swap_finalizes_correctly_legacy(
        &generate_principal_ids(5), // Some direct participants
        &additional_nns_neurons,
        planned_community_fund_participation_amount,
        max_community_fund_relative_error,
        // before_proposal_is_adopted
        |state_machine| {
            // This is where we make CF membership dynamic.

            // Make some neurons leave the CF.
            for neuron in leave_neurons {
                nns_leave_community_fund(
                    state_machine,
                    neuron.controller.unwrap(), // sender
                    neuron.id.unwrap(),
                );
            }

            // Make other neurons join the CF.
            for neuron in join_neurons {
                nns_join_community_fund(
                    state_machine,
                    neuron.controller.unwrap(), // sender
                    neuron.id.unwrap(),
                );
            }
        },
    );
}

#[test]
fn stake_maturity_does_not_interfere_with_community_fund_legacy() {
    let maturity_staking_principal_id = PrincipalId::new_user_test_id(807614);

    // Craft a CF neuron for the maturity staking principal ID.
    let neuron_id = 833627;
    let account = AccountIdentifier::new(
        NNS_GOVERNANCE_CANISTER_ID.into(),
        Some(compute_neuron_staking_subaccount(
            maturity_staking_principal_id,
            /* nonce = */ 0,
        )),
    );
    let original_maturity_e8s_equivalent = 25 * E8;
    let maturity_staking_neuron = nns_governance_pb::Neuron {
        id: Some(nns_common_pb::NeuronId { id: neuron_id }),
        account: account.to_address().into(),
        controller: Some(maturity_staking_principal_id),
        maturity_e8s_equivalent: original_maturity_e8s_equivalent,
        ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
    };

    let percentage_to_stake: u64 = 5;
    // Staking maturity causes a (greater) shortfall. If we just went with the
    // standard limit, this test would fail.
    let max_community_fund_relative_error = 0.06;

    assert_successful_swap_finalizes_correctly_legacy(
        &generate_principal_ids(5),        // direct participants
        &[maturity_staking_neuron],        // additional_nns_neurons
        ExplosiveTokens::from_e8s(5 * E8), // planned_community_fund_participation_amount
        max_community_fund_relative_error,
        // before_proposal_is_adopted
        |state_machine| {
            let result = nns_stake_maturity(
                state_machine,
                maturity_staking_principal_id,
                nns_common_pb::NeuronId { id: neuron_id },
                Some(percentage_to_stake as u32),
            );
            match result {
                ManageNeuronResponse {
                    command: Some(manage_neuron_response::Command::StakeMaturity(response)),
                    ..
                } => {
                    let StakeMaturityResponse {
                        maturity_e8s,
                        staked_maturity_e8s,
                    } = response;
                    assert_eq!(
                        maturity_e8s,
                        original_maturity_e8s_equivalent * (100 - percentage_to_stake) / 100,
                    );
                    assert_eq!(
                        staked_maturity_e8s,
                        original_maturity_e8s_equivalent * percentage_to_stake / 100,
                    );
                    assert_eq!(
                        maturity_e8s + staked_maturity_e8s,
                        original_maturity_e8s_equivalent
                    );
                }

                _ => panic!("Result was not StakeMaturityResponse?! {:#?}", result),
            }
        },
    );
}

fn do_nothing_special_before_proposal_is_adopted(_state_machine: &mut StateMachine) {
    // This function intentionally left blank.
}

#[test]
fn sns_governance_starts_life_in_pre_initialization_swap_mode_but_transitions_to_normal_mode_after_sale_legacy(
) {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();

    let direct_participant_principal_ids = generate_principal_ids(5);
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(70 * E8);
    let neuron_basket_count = 3;

    let sns_canister_ids = begin_swap_legacy(
        &mut state_machine,
        &direct_participant_principal_ids,
        &[], // additional_nns_neurons
        planned_participation_amount_per_account,
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    )
    .0;
    let sns_governance_canister_id =
        CanisterId::try_from(*sns_canister_ids.governance.as_ref().unwrap()).unwrap();

    // Get a principal and id of an SNS neuron who can make a proposal.
    let sns_governance_pb::Neuron {
        id: sns_neuron_id,
        mut permissions,
        ..
    } = sns_governance_list_neurons(
        &mut state_machine,
        sns_governance_canister_id,
        &sns_governance_pb::ListNeurons::default(),
    )
    .neurons
    .into_iter()
    .find(|neuron| {
        neuron.dissolve_delay_seconds(neuron.created_timestamp_seconds) >= 6 * 30 * SECONDS_PER_DAY
    })
    .unwrap();
    let sns_neuron_id = sns_neuron_id.unwrap();
    let sns_neuron_principal_id = permissions.pop().unwrap().principal.unwrap();

    // Step 1.1: Make sure we are in PreInitializationSwap mode, and that this
    // restricts what we're allowed to do. (There are asserts for these things
    // within begin_swap, but that's not evident here -> let's do those asserts
    // again explicitly.)
    assert_eq!(
        sns_governance_get_mode(&mut state_machine, sns_governance_canister_id),
        Ok(SnsGovernanceMode::PreInitializationSwap as i32),
    );

    // Step 1.1.1: Not allowed to make ManageNervousSystemParameter proposals.
    let err = sns_make_proposal(
        &state_machine,
        sns_governance_canister_id,
        sns_neuron_principal_id,
        sns_neuron_id.clone(),
        sns_governance_pb::Proposal {
            title: "Try to smuggle in a ManageNervousSystemParameters proposal while \
                    in PreInitializationSwap mode."
                .to_string(),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(
                sns_governance_pb::proposal::Action::ManageNervousSystemParameters(
                    NervousSystemParameters {
                        reject_cost_e8s: Some(20_000), // More strongly discourage spam
                        ..Default::default()
                    },
                ),
            ),
        },
    )
    .unwrap_err();
    {
        let sns_governance_pb::GovernanceError {
            error_type,
            error_message,
        } = &err;
        use sns_governance_pb::governance_error::ErrorType;
        assert_eq!(
            ErrorType::from_i32(*error_type).unwrap(),
            ErrorType::PreconditionFailed,
            "{:#?}",
            err
        );
        assert!(
            error_message.contains("PreInitializationSwap"),
            "{:#?}",
            err
        );
    }

    // assert that SNS neuron is not allowed to start dissolving yet.
    let start_dissolving_request = sns_governance_pb::ManageNeuron {
        subaccount: sns_neuron_id.id.clone(),
        command: Some(sns_governance_pb::manage_neuron::Command::Configure(
            sns_governance_pb::manage_neuron::Configure {
                operation: Some(
                    sns_governance_pb::manage_neuron::configure::Operation::StartDissolving(
                        sns_governance_pb::manage_neuron::StartDissolving {},
                    ),
                ),
            },
        )),
    };
    let start_dissolving_response: sns_governance_pb::ManageNeuronResponse = update_with_sender(
        &state_machine,
        sns_governance_canister_id,
        "manage_neuron",
        candid_one,
        start_dissolving_request,
        sns_neuron_principal_id,
    )
    .expect("Error calling the manage_neuron API.");
    use sns_governance_pb::manage_neuron_response::Command;
    match start_dissolving_response.command {
        // An error is expected.
        Some(Command::Error(error)) => {
            let sns_governance_pb::GovernanceError {
                error_type,
                error_message,
            } = &error;
            use sns_governance_pb::governance_error::ErrorType;
            // Inspect the error.
            assert_eq!(
                ErrorType::from_i32(*error_type).unwrap(),
                ErrorType::PreconditionFailed,
                "{:#?}",
                error
            );
            assert!(
                error_message.contains("PreInitializationSwap"),
                "{:#?}",
                error
            );
        }

        response => panic!("{:#?}", response),
    };

    // Step 2: Make the swap succeed (and finalize).

    // Have all the accounts we created participate in the swap
    for principal_id in &direct_participant_principal_ids {
        participate_in_swap(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            *principal_id,
            planned_participation_amount_per_account,
        );
    }

    // Make sure the swap reached the Committed state.
    {
        let result = swap_get_state(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Committed,
            "{:#?}",
            result
        );
    }

    // Execute the swap.
    let _finalize_swap_response = {
        let result = state_machine
            .execute_ingress(
                sns_canister_ids.swap.unwrap().try_into().unwrap(),
                "finalize_swap",
                Encode!(&swap_pb::FinalizeSwapRequest {}).unwrap(),
            )
            .unwrap();
        let result: Vec<u8> = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => panic!(
                "finalize_swap call was rejected by swap canister: {:#?}",
                reject
            ),
        };
        Decode!(&result, swap_pb::FinalizeSwapResponse).unwrap()
    };

    // Step 3: Verify that we are no in normal mode, and can do things that were
    // disallowed prior to the swapgoing through.
    {
        use sns_governance_pb::governance::Mode;
        let sns_governance_canister_id =
            CanisterId::try_from(sns_canister_ids.governance.unwrap()).unwrap();
        assert_eq!(
            sns_governance_get_mode(&mut state_machine, sns_governance_canister_id)
                .map(|mode| Mode::from_i32(mode).unwrap()),
            Ok(Mode::Normal),
        );

        // Now that we are in Normal mode, we should be able to make this
        // proposal; whereas, we wouldn't have been able to do that prior to the
        // successful execution of the decentralization sale.
        assert_is_ok!(sns_make_proposal(
            &state_machine,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id.clone(),
            sns_governance_pb::Proposal {
                title: "If this proposal is put up for a vote, then we are in normal mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(
                    sns_governance_pb::proposal::Action::ManageNervousSystemParameters(
                        NervousSystemParameters {
                            reject_cost_e8s: Some(20_000), // More strongly discourage spam
                            ..Default::default()
                        },
                    ),
                ),
            },
        ));

        // Similarly, neurons can start dissolving now, if they want to.
        let start_dissolving_request = sns_governance_pb::ManageNeuron {
            subaccount: sns_neuron_id.id,
            command: Some(sns_governance_pb::manage_neuron::Command::Configure(
                sns_governance_pb::manage_neuron::Configure {
                    operation: Some(
                        sns_governance_pb::manage_neuron::configure::Operation::StartDissolving(
                            sns_governance_pb::manage_neuron::StartDissolving {},
                        ),
                    ),
                },
            )),
        };
        let start_dissolving_response: sns_governance_pb::ManageNeuronResponse =
            update_with_sender(
                &state_machine,
                sns_governance_canister_id,
                "manage_neuron",
                candid_one,
                start_dissolving_request,
                sns_neuron_principal_id,
            )
            .expect("Error calling the manage_neuron API.");
        use sns_governance_pb::manage_neuron_response::Command;
        match start_dissolving_response.command {
            Some(Command::Configure(_)) => (),
            _ => panic!("{:#?}", start_dissolving_response),
        };
    }
}

fn assert_successful_swap_finalizes_correctly_legacy(
    direct_participant_principal_ids: &[ic_base_types::PrincipalId],
    additional_nns_neurons: &[nns_governance_pb::Neuron],
    planned_community_fund_participation_amount: ExplosiveTokens,
    max_community_fund_relative_error: f64,
    before_proposal_is_adopted: impl FnOnce(&mut StateMachine),
) -> SwapPerformanceResults {
    // Just for convenience.
    let direct_participant_count = direct_participant_principal_ids.len() as u64;
    assert!(
        direct_participant_count > 0,
        "Testing the swap lifecycle requires > 0 direct participant"
    );
    // For quick and easy detection of direct participants.
    let direct_participant_principal_id_set = direct_participant_principal_ids
        .iter()
        .collect::<HashSet<_>>();

    // Step 0: Constants
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(70 * E8);
    let neuron_basket_count = 3;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();
    let (
        sns_canister_ids,
        community_fund_neurons,
        _fractional_developer_voting_power,
        _dapp_canister_id,
        sns_proposal_id,
    ) = begin_swap_legacy(
        &mut state_machine,
        direct_participant_principal_ids,
        additional_nns_neurons,
        planned_participation_amount_per_account,
        planned_community_fund_participation_amount,
        neuron_basket_count,
        max_community_fund_relative_error,
        before_proposal_is_adopted,
    );
    // For quick and convenient detection of principals with a CF neuron.
    let community_fund_principal_ids = community_fund_neurons
        .iter()
        .map(|neuron| neuron.controller.unwrap())
        .collect::<HashSet<_>>();

    let original_total_community_fund_maturity = {
        let mut result = ExplosiveTokens::from_e8s(0);
        for neuron in &community_fund_neurons {
            result += ExplosiveTokens::from_e8s(neuron.maturity_e8s_equivalent);
        }
        result
    };
    let original_id_to_community_fund_neuron = community_fund_neurons
        .iter()
        .map(|neuron| {
            let id = neuron.id.as_ref().unwrap().id;
            (id, neuron)
        })
        .collect::<HashMap<_, _>>();
    let community_fund_spent = |state_machine: &mut StateMachine| -> ExplosiveTokens {
        let mut current_community_fund_total = ExplosiveTokens::from_e8s(0);
        for original_neuron in &community_fund_neurons {
            let refreshed_neuron = nns_governance_get_full_neuron(
                state_machine,
                original_neuron.controller.unwrap(),
                original_neuron.id.as_ref().unwrap().id,
            )
            .unwrap();
            assert!(
                refreshed_neuron
                    .joined_community_fund_timestamp_seconds
                    .is_some(),
                "{:#?}",
                refreshed_neuron
            );

            current_community_fund_total += ExplosiveTokens::from_e8s(refreshed_neuron.maturity_e8s_equivalent)
                // WARNING: The following line assumes that staked maturity
                // happened after the OpenSnsTokenSale proposal was made, but
                // before it was approved. As of now, the only time this field
                // is populated is in during
                // stake_maturity_does_not_interfere_with_community_fund.
                + ExplosiveTokens::from_e8s(refreshed_neuron.staked_maturity_e8s_equivalent.unwrap_or(0));
        }

        original_total_community_fund_maturity - current_community_fund_total
    };

    // Step 1.5: initialize variables for the benchmark
    let instructions_consumed_base = state_machine.instructions_consumed();
    let mut instructions_consumed_swapping = None;
    let mut time_finalization_started = None;

    let assert_community_fund_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawal_amounts: &[ExplosiveTokens]| {
            assert_eq!(community_fund_neurons.len(), withdrawal_amounts.len());

            for (original_neuron, withdrawal_amount) in
                community_fund_neurons.iter().zip(withdrawal_amounts.iter())
            {
                let refreshed_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                assert_eq!(
                    refreshed_neuron.maturity_e8s_equivalent,
                    original_neuron.maturity_e8s_equivalent - withdrawal_amount.into_e8s(),
                );
            }
        };

    // Inspect the amount of participation by Community Fund neurons. We'll do this again after
    // finalizing the swap to make sure settlement happened correctly (currently, the funds are
    // still in escrow).
    let community_fund_in_escrow = community_fund_spent(&mut state_machine);
    if additional_nns_neurons.is_empty() {
        assert_community_fund_neuron_maturities(
            &mut state_machine,
            &[
                planned_community_fund_participation_amount.mul_div_or_die(1, 4),
                planned_community_fund_participation_amount.mul_div_or_die(3, 4),
            ],
        );
    } else {
        let relative_error = -relative_difference(
            community_fund_in_escrow.get_e8s() as f64,
            planned_community_fund_participation_amount.get_e8s() as f64,
        );
        assert!(
            (0.0..=max_community_fund_relative_error).contains(&relative_error),
            "{} vs. {} ({}% error)",
            community_fund_in_escrow,
            planned_community_fund_participation_amount,
            100.0 * relative_error,
        );
    }

    let community_fund_neuron_id_to_participation_amount_e8s = original_id_to_community_fund_neuron
        .iter()
        .map(|(id, original_neuron)| {
            let refreshed_neuron = nns_governance_get_full_neuron(
                &mut state_machine,
                original_neuron.controller.unwrap(),
                original_neuron.id.as_ref().unwrap().id,
            )
            .unwrap();
            (
                *id,
                original_neuron.maturity_e8s_equivalent - refreshed_neuron.maturity_e8s_equivalent,
            )
        })
        .collect::<HashMap<u64, u64>>();

    // Step 2: Run code under test.

    // Have all the accounts we created participate in the swap
    for (index, principal_id) in direct_participant_principal_ids.iter().enumerate() {
        println!(
            "Direct participant {}/{}",
            index + 1,
            direct_participant_count
        );
        if index == direct_participant_count as usize - 1 {
            time_finalization_started = Some(SystemTime::now());
            instructions_consumed_swapping =
                Some(state_machine.instructions_consumed() - instructions_consumed_base);
        }
        participate_in_swap(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            *principal_id,
            planned_participation_amount_per_account,
        );
    }

    // If caller asked for a larger Community Fund fudge factor, swap probably won't reach Committed
    // early via "short circuit". Instead, we probably need to wait until it is due. In that case,
    // we fast forward to some time after the due date.
    if max_community_fund_relative_error > DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR {
        state_machine.advance_time(Duration::from_secs(15 * SECONDS_PER_DAY));
    }

    // Make sure the swap reached the Committed state.
    {
        let result = swap_get_state(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Committed,
            "{:#?}",
            result
        );
    }

    // Execute the swap.
    // TODO(NNS1-2359): We should also verify the FinalizeSwapResponse from
    // automatic finalization is correct.
    let finalize_swap_response = {
        let result = state_machine
            .execute_ingress(
                sns_canister_ids.swap.unwrap().try_into().unwrap(),
                "finalize_swap",
                Encode!(&swap_pb::FinalizeSwapRequest {}).unwrap(),
            )
            .unwrap();
        let result: Vec<u8> = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => panic!(
                "finalize_swap call was rejected by swap canister: {:#?}",
                reject
            ),
        };
        Decode!(&result, swap_pb::FinalizeSwapResponse).unwrap()
    };

    let instructions_consumed_finalization =
        state_machine.instructions_consumed() - instructions_consumed_swapping.unwrap();
    let time_to_finalize_swap = time_finalization_started.unwrap().elapsed().unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect finalize_swap_response.
    {
        let participating_community_fund_neuron_count =
            community_fund_neuron_id_to_participation_amount_e8s
                .iter()
                .filter(|(_, e8s): &(_, &u64)| **e8s > 0)
                .count() as u64;
        use swap_pb::settle_community_fund_participation_result::{Possibility, Response};
        let expected_neuron_count = ((direct_participant_count
            + participating_community_fund_neuron_count)
            * neuron_basket_count) as u32;
        assert_eq!(
            finalize_swap_response,
            swap_pb::FinalizeSwapResponse {
                sweep_icp_result: Some(swap_pb::SweepResult {
                    success: direct_participant_count as u32,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                sweep_sns_result: Some(swap_pb::SweepResult {
                    success: expected_neuron_count,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                claim_neuron_result: Some(swap_pb::SweepResult {
                    success: expected_neuron_count,
                    failure: 0,
                    skipped: 0,
                    invalid: 0,
                    global_failures: 0,
                }),
                set_mode_call_result: Some(swap_pb::SetModeCallResult {
                    possibility: Some(set_mode_call_result::Possibility::Ok(
                        set_mode_call_result::SetModeResult {}
                    ))
                }),
                set_dapp_controllers_call_result: None,
                settle_community_fund_participation_result: Some(
                    swap_pb::SettleCommunityFundParticipationResult {
                        possibility: Some(Possibility::Ok(Response {
                            governance_error: None,
                        })),
                    }
                ),
                error_message: None,
            }
        );
    }

    // Step 3.2.1: Inspect ICP balances.

    // SNS governance should get the ICP.

    let total_icp_transferred = planned_participation_amount_per_account * direct_participant_count
        + community_fund_in_escrow;
    {
        let observed_sns_governance_icp_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(sns_canister_ids.governance.unwrap(), None)
                    .to_address(),
            },
        );
        let total_paid_in_transfer_fee = *DEFAULT_TRANSFER_FEE * direct_participant_count;
        let expected_balance = total_icp_transferred - total_paid_in_transfer_fee;
        assert_eq!(
            observed_sns_governance_icp_balance,
            expected_balance.into(),
            "planned_participation_amount_per_account={} \
             direct_participant_count={} \
             community_fund_in_escrow={} \
             transfer_fee={}",
            planned_participation_amount_per_account,
            direct_participant_count,
            community_fund_in_escrow,
            DEFAULT_TRANSFER_FEE.into_e8s(),
        );
    }
    // All the users still has the change left over from their participation in the swap/sale.
    for principal_id in direct_participant_principal_ids.iter() {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(*principal_id, None).to_address(),
            },
        );
        let expected_balance =
            *INITIAL_ICP_BALANCE - planned_participation_amount_per_account - *DEFAULT_TRANSFER_FEE;
        assert_eq!(observed_balance, expected_balance.into());
    }

    let sns_tokens_being_offered_e8s =
        match &nns_governance_get_proposal_info_as_anonymous(&mut state_machine, sns_proposal_id.0)
            .proposal
            .as_ref()
            .unwrap()
            .action
        {
            Some(proposal::Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
                params: Some(swap_pb::Params { sns_token_e8s, .. }),
                ..
            })) => *sns_token_e8s,
            action => panic!("{:#?}", action),
        };

    // Step 3.2.2: Inspect SNS token balances.
    // Expected reward amount = participation amount (ICP) * sns_tokens_per_icp.
    let mut assert_sns_neuron_balances =
        |expected_principal_id_to_gross_sns_token_participation_amount_e8s: Vec<(
            PrincipalId,
            u64,
        )>,
         is_community_fund: bool| {
            for (principal_id, expected_sns_tokens_e8s) in
                &expected_principal_id_to_gross_sns_token_participation_amount_e8s
            {
                let distributed_neurons = sns_governance_list_neurons(
                    &mut state_machine,
                    sns_canister_ids.governance.unwrap().try_into().unwrap(),
                    &ListNeurons {
                        limit: 100,
                        start_page_at: None,
                        of_principal: Some(*principal_id),
                    },
                )
                .neurons
                .into_iter()
                .filter(|n| n.source_nns_neuron_id.is_some() == is_community_fund)
                .collect::<Vec<_>>();

                let mut actual_total_sns_tokens_e8s = 0;

                // Make sure cached stake in reward SNS neurons match their respective balances.
                // Also, add up stakes.
                for neuron in &distributed_neurons {
                    let subaccount = neuron.id.as_ref().unwrap().subaccount().unwrap();

                    let observed_balance_e8s = icrc1_balance(
                        &state_machine,
                        sns_canister_ids.ledger.unwrap().try_into().unwrap(),
                        Account {
                            owner: sns_canister_ids.governance.unwrap().0,
                            subaccount: Some(subaccount),
                        },
                    )
                    .get_e8s();

                    // Check that the cached balance of the neuron is equal to the neuron's account in the ledger
                    assert_eq!(neuron.cached_neuron_stake_e8s, observed_balance_e8s);

                    // Add to the actual total including the default transfer fee which was deducted
                    // during swap committal
                    actual_total_sns_tokens_e8s +=
                        observed_balance_e8s + DEFAULT_TRANSFER_FEE.get_e8s();
                }

                assert_eq!(
                    actual_total_sns_tokens_e8s,
                    *expected_sns_tokens_e8s,
                    "principal_id: {}\n\
                     planned_participation_amount_per_account.into_e8s(): {}\n\
                     distributed_neurons:\n{:#?}",
                    principal_id,
                    planned_participation_amount_per_account.into_e8s(),
                    distributed_neurons,
                );
            }
        };

    assert_sns_neuron_balances(
        community_fund_neurons
            .iter()
            .filter_map(|nns_neuron| {
                let principal_id = nns_neuron.controller.unwrap();
                let original_maturity_e8s = original_id_to_community_fund_neuron
                    .get(&nns_neuron.id.as_ref().unwrap().id)
                    .unwrap()
                    .maturity_e8s_equivalent;
                let icp_participation_e8s =
                    original_maturity_e8s - nns_neuron.maturity_e8s_equivalent;
                // Skip Community Fund neurons that were too small to participate.
                if icp_participation_e8s == 0 {
                    return None;
                }

                let expected_sns_tokens_e8s =
                    (icp_participation_e8s as u128 * sns_tokens_being_offered_e8s as u128
                        / total_icp_transferred.get_e8s() as u128) as u64;
                Some((principal_id, expected_sns_tokens_e8s))
            })
            .collect(),
        true, // is_community_fund
    );

    assert_sns_neuron_balances(
        direct_participant_principal_ids
            .iter()
            .map(|principal_id| {
                let expected_sns_tokens_e8s =
                    (planned_participation_amount_per_account.into_e8s() as u128
                        * sns_tokens_being_offered_e8s as u128
                        / total_icp_transferred.get_e8s() as u128) as u64;
                (*principal_id, expected_sns_tokens_e8s)
            })
            .collect(),
        false, // is_community_fund
    );

    // Step 3.3: Inspect SNS neurons.
    let mut assert_sns_neurons_are_configured_correctly =
        |principal_ids: &[PrincipalId], is_community_fund: bool| {
            let nervous_system_parameters = sns_governance_get_nervous_system_parameters(
                &mut state_machine,
                sns_canister_ids.governance.unwrap().try_into().unwrap(),
            );

            for principal_id in principal_ids {
                // List all neurons that have the principal_id with some permission in it
                let observed_sns_neurons = sns_governance_list_neurons(
                    &mut state_machine,
                    sns_canister_ids.governance.unwrap().try_into().unwrap(),
                    &ListNeurons {
                        limit: 100,
                        start_page_at: None,
                        of_principal: Some(*principal_id),
                    },
                )
                .neurons
                .into_iter()
                .filter(|n| n.source_nns_neuron_id.is_some() == is_community_fund)
                .collect::<Vec<_>>();

                let claimer_permissions = nervous_system_parameters
                    .neuron_claimer_permissions
                    .as_ref()
                    .expect("Expected neuron_claimer_permissions to be set");

                assert_eq!(
                    observed_sns_neurons.len(),
                    neuron_basket_count as usize,
                    "{:#?}",
                    observed_sns_neurons
                );

                let longest_dissolve_delay_neuron_id = observed_sns_neurons
                    .iter()
                    .max_by(|x, y| {
                        x.dissolve_delay_seconds(now_seconds(None))
                            .cmp(&y.dissolve_delay_seconds(now_seconds(None)))
                    })
                    .map(|neuron| neuron.id.as_ref().unwrap())
                    .unwrap()
                    .clone();

                for mut observed_sns_neuron in observed_sns_neurons {
                    if is_community_fund {
                        assert_eq!(
                            observed_sns_neuron.auto_stake_maturity,
                            Some(true),
                            "{:#?}",
                            observed_sns_neuron,
                        );

                        observed_sns_neuron
                            .permissions
                            .sort_by(|x, y| x.principal.unwrap().cmp(&y.principal.unwrap()));
                        assert_eq!(
                            observed_sns_neuron.permissions,
                            vec![
                                NeuronPermission {
                                    principal: Some(*principal_id),
                                    permission_type: vec![
                                        NeuronPermissionType::ManageVotingPermission as i32,
                                        NeuronPermissionType::SubmitProposal as i32,
                                        NeuronPermissionType::Vote as i32,
                                    ],
                                },
                                NeuronPermission {
                                    principal: Some(NNS_GOVERNANCE_CANISTER_ID.get()),
                                    permission_type: claimer_permissions.permissions.clone(),
                                },
                            ],
                            "{:#?}",
                            observed_sns_neuron,
                        );

                        assert_eq!(
                            observed_sns_neuron
                                .permissions
                                .iter()
                                .find(|permission| permission.principal == Some(*principal_id))
                                .expect("Expected a cf principal to have permissions"),
                            &NeuronPermission {
                                principal: Some(*principal_id),
                                permission_type: vec![
                                    NeuronPermissionType::ManageVotingPermission as i32,
                                    NeuronPermissionType::SubmitProposal as i32,
                                    NeuronPermissionType::Vote as i32,
                                ],
                            },
                            "{:#?}",
                            observed_sns_neuron,
                        );

                        assert_eq!(
                            observed_sns_neuron
                                .permissions
                                .iter()
                                .find(|permission| permission.principal
                                    == Some(NNS_GOVERNANCE_CANISTER_ID.get()))
                                .expect("Expected a cf principal to have permissions"),
                            &NeuronPermission {
                                principal: Some(NNS_GOVERNANCE_CANISTER_ID.get()),
                                permission_type: claimer_permissions.permissions.clone(),
                            },
                            "{:#?}",
                            observed_sns_neuron,
                        )
                    } else {
                        assert_eq!(
                            observed_sns_neuron.auto_stake_maturity, None,
                            "{:#?}",
                            observed_sns_neuron,
                        );

                        assert_eq!(
                            observed_sns_neuron.permissions,
                            vec![NeuronPermission {
                                principal: Some(*principal_id),
                                permission_type: claimer_permissions.permissions.clone(),
                            }],
                            "{:#?}",
                            observed_sns_neuron,
                        )
                    }
                    if observed_sns_neuron.id.as_ref().unwrap() != &longest_dissolve_delay_neuron_id
                    {
                        for followees in observed_sns_neuron.followees.values() {
                            assert_eq!(
                                followees.followees,
                                vec![longest_dissolve_delay_neuron_id.clone()],
                                "{:#?}",
                                observed_sns_neuron,
                            )
                        }
                    } else {
                        for followees in observed_sns_neuron.followees.values() {
                            assert!(followees.followees.is_empty(), "{:#?}", observed_sns_neuron,)
                        }
                    }

                    assert_eq!(
                        observed_sns_neuron.maturity_e8s_equivalent, 0,
                        "{:#?}",
                        observed_sns_neuron,
                    );
                    assert_eq!(
                        observed_sns_neuron.neuron_fees_e8s, 0,
                        "{:#?}",
                        observed_sns_neuron
                    );
                }
            }
        };

    assert_sns_neurons_are_configured_correctly(
        &community_fund_neurons
            .iter()
            .filter_map(|nns_neuron| {
                let principal_id = nns_neuron.controller.unwrap();
                let original_maturity_e8s = original_id_to_community_fund_neuron
                    .get(&nns_neuron.id.as_ref().unwrap().id)
                    .unwrap()
                    .maturity_e8s_equivalent;
                let icp_participation_e8s =
                    original_maturity_e8s - nns_neuron.maturity_e8s_equivalent;
                // Skip Community Fund neurons that were too small to participate.
                if icp_participation_e8s == 0 {
                    return None;
                }
                Some(principal_id)
            })
            .collect::<Vec<_>>(),
        true, // is_community_fund
    );

    assert_sns_neurons_are_configured_correctly(
        direct_participant_principal_ids,
        false, // is_community_fund
    );

    // Inspect the source_nns_neuron_id field in Community Fund neurons.
    for community_fund_neuron in &community_fund_neurons {
        let controller = community_fund_neuron.controller.unwrap();

        let mut sns_neurons = sns_governance_list_neurons(
            &mut state_machine,
            CanisterId::try_from(*sns_canister_ids.governance.as_ref().unwrap()).unwrap(),
            &ListNeurons {
                limit: 100,
                start_page_at: None,
                of_principal: Some(controller),
            },
        )
        .neurons;

        if direct_participant_principal_id_set.contains(&controller) {
            // Filter out neurons from direct participation.
            sns_neurons.retain(|neuron| neuron.source_nns_neuron_id.is_some());
        }

        let expected_source_neuron_id = community_fund_neuron.id.as_ref().unwrap().id;
        let participation_amount_e8s = *community_fund_neuron_id_to_participation_amount_e8s
            .get(&expected_source_neuron_id)
            .unwrap();

        let expected_count = if participation_amount_e8s > 0 {
            neuron_basket_count
        } else {
            0
        };
        assert_eq!(sns_neurons.len() as u64, expected_count, "{}", controller);

        for sns_neuron in sns_neurons {
            assert_eq!(
                sns_neuron.source_nns_neuron_id,
                Some(expected_source_neuron_id)
            );
        }
    }

    // Analogous to the previous loop, insepct the source_nns_neuron_id field,
    // but this time, in non-Community Fund neurons.
    for principal_id in direct_participant_principal_ids {
        let mut sns_neurons = sns_governance_list_neurons(
            &mut state_machine,
            sns_canister_ids.governance.unwrap().try_into().unwrap(),
            &ListNeurons {
                limit: 100,
                start_page_at: None,
                of_principal: Some(*principal_id),
            },
        )
        .neurons;

        if community_fund_principal_ids.contains(principal_id) {
            // Filter out SNS neurons from CF participation.
            sns_neurons.retain(|neuron| neuron.source_nns_neuron_id.is_none());
        }

        assert_eq!(
            sns_neurons.len() as u64,
            neuron_basket_count,
            "{}",
            principal_id
        );
        for sns_neuron in sns_neurons {
            assert_eq!(sns_neuron.source_nns_neuron_id, None);
        }
    }

    // Step 3.4: NNS governance is responsible for "settling" CF participation.
    //
    // We already noticed the ICP being added to the SNS governance
    // canister's (default) account in step 3.2.1. Therefore, all that remains
    // for us to verify is that the maturity of the CF neurons have been
    // decreased by the right amounts.
    if additional_nns_neurons.is_empty() {
        assert_community_fund_neuron_maturities(
            &mut state_machine,
            &[
                planned_community_fund_participation_amount.mul_div_or_die(1, 4),
                planned_community_fund_participation_amount.mul_div_or_die(3, 4),
            ],
        );
    } else {
        let spent = community_fund_spent(&mut state_machine);
        let relative_error = -relative_difference(
            spent.get_e8s() as f64,
            planned_community_fund_participation_amount.get_e8s() as f64,
        );
        assert!(
            (0.0..=max_community_fund_relative_error).contains(&relative_error),
            "{} vs. {} ({}% error)",
            spent,
            planned_community_fund_participation_amount,
            100.0 * relative_error,
        );
    }

    // Step 3.5: SNS governance is now in Normal mode, not PreInitializationSwap mode.

    // From step 3.1, it looks like SNS governance is in normal mode, but we
    // verify this in a different way here.
    {
        use sns_governance_pb::governance::Mode;
        let sns_governance_canister_id =
            CanisterId::try_from(sns_canister_ids.governance.unwrap()).unwrap();
        assert_eq!(
            sns_governance_get_mode(&mut state_machine, sns_governance_canister_id)
                .map(|mode| Mode::from_i32(mode).unwrap()),
            Ok(Mode::Normal),
        );

        // Get a principal and id of an SNS neuron who can make a proposal.
        let sns_governance_pb::Neuron {
            id: sns_neuron_id,
            mut permissions,
            ..
        } = sns_governance_list_neurons(
            &mut state_machine,
            sns_governance_canister_id,
            &sns_governance_pb::ListNeurons::default(),
        )
        .neurons
        .into_iter()
        .find(|neuron| {
            neuron.dissolve_delay_seconds(neuron.created_timestamp_seconds)
                >= 6 * 30 * SECONDS_PER_DAY
        })
        .unwrap();
        let sns_neuron_id = sns_neuron_id.unwrap();
        let sns_neuron_principal_id = permissions.pop().unwrap().principal.unwrap();

        // Now that we are in Normal mode, we should be able to make this
        // proposal; whereas, we wouldn't have been able to do that prior to the
        // successful execution of the decentralization sale.
        assert_is_ok!(sns_make_proposal(
            &state_machine,
            sns_governance_canister_id,
            sns_neuron_principal_id,
            sns_neuron_id,
            sns_governance_pb::Proposal {
                title: "If this proposal is put up for a vote, then we are in normal mode."
                    .to_string(),
                summary: "".to_string(),
                url: "".to_string(),
                action: Some(
                    sns_governance_pb::proposal::Action::ManageNervousSystemParameters(
                        NervousSystemParameters {
                            reject_cost_e8s: Some(20_000), // More strongly discourage spam
                            ..Default::default()
                        },
                    ),
                ),
            },
        ));
    }

    SwapPerformanceResults {
        instructions_consumed_base,
        instructions_consumed_swapping: instructions_consumed_swapping.unwrap(),
        instructions_consumed_finalization,
        time_to_finalize_swap,
    }
}

#[test]
fn swap_lifecycle_sad() {
    // Step 0: Constants
    let planned_contribution_per_account = ExplosiveTokens::from_e8s(70 * E8);
    let planned_community_fund_participation_amount = ExplosiveTokens::from_e8s(30 * E8);
    let neuron_basket_count = 3;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();
    let (
        sns_canister_ids,
        community_fund_neurons,
        fractional_developer_voting_power,
        dapp_canister_id,
        _sns_proposal_id,
    ) = begin_swap_legacy(
        &mut state_machine,
        &[], // direct_participant_principal_ids
        &[], // additional_nns_neurons
        planned_contribution_per_account,
        planned_community_fund_participation_amount,
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    );

    let assert_community_fund_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawal_amounts: &[ExplosiveTokens]| {
            assert_eq!(community_fund_neurons.len(), withdrawal_amounts.len());

            for (original_neuron, withdrawal_amount) in
                community_fund_neurons.iter().zip(withdrawal_amounts.iter())
            {
                let refreshed_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                let expected_e8s =
                    original_neuron.maturity_e8s_equivalent - withdrawal_amount.into_e8s();
                assert!(refreshed_neuron.maturity_e8s_equivalent >= expected_e8s);
                // This can occur if neurons are given their voting rewards.
                let extra =
                    (refreshed_neuron.maturity_e8s_equivalent as f64) / (expected_e8s as f64) - 1.0;
                assert!(
                    (0.0..0.03).contains(&extra),
                    "observed = {} expected = {} extra = {}",
                    refreshed_neuron.maturity_e8s_equivalent,
                    expected_e8s,
                    extra,
                );
            }
        };

    // We'll do something like this again after finalizing the swap, except
    // we'll pass all zero withdrawal amounts instead, because finalization ins
    // supposed to include restoring maturities after a failed swap.
    assert_community_fund_neuron_maturities(
        &mut state_machine,
        &[
            planned_community_fund_participation_amount.mul_div_or_die(1, 4),
            planned_community_fund_participation_amount.mul_div_or_die(3, 4),
        ],
    );

    // Step 2: Run code under test.

    // TEST_USER2 participates, but not enough for the swap to succeed, even
    // after the open time window has passed.
    participate_in_swap(
        &mut state_machine,
        sns_canister_ids.swap.unwrap().try_into().unwrap(),
        *TEST_USER2_PRINCIPAL,
        ExplosiveTokens::from_e8s(E8 * 5 / 4),
    );

    // Make sure the swap is still in the Open state.
    {
        let result = swap_get_state(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Open,
            "{:#?}",
            result
        );
    }

    // TEST_USER2_PRINCIPAL sends this to the swap, but does not tell the swap
    // canister about it. After calling the swap canister's finalize_swap Candid
    // method, this user is then eligible to request a refund for this
    // "half-baked" participation.
    let half_baked_participation_amount = ExplosiveTokens::from_e8s(E8);
    send_participation_funds(
        &mut state_machine,
        sns_canister_ids.swap.unwrap().try_into().unwrap(),
        *TEST_USER2_PRINCIPAL,
        half_baked_participation_amount,
    );
    // refresh_buyer_tokens is intentionally NOT called here.

    // Advance time well into the future so that the swap fails due to no participants.
    let after_swap_due = swap_due_from_now_timestamp_seconds(&state_machine) + 10;
    state_machine.set_time(std::time::UNIX_EPOCH + std::time::Duration::from_secs(after_swap_due));

    state_machine.tick();

    // Make sure the swap reached the Aborted state.
    {
        let result = swap_get_state(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        )
        .swap
        .unwrap();

        assert_eq!(
            result.lifecycle(),
            swap_pb::Lifecycle::Aborted,
            "{:#?}",
            result
        );
    }

    // Ticking will cause the swap to auto-finalize
    state_machine.tick();
    // Make sure that governance is still in PreInitializationSwap mode
    {
        use sns_governance_pb::governance::Mode;
        let sns_governance_canister_id =
            CanisterId::try_from(sns_canister_ids.governance.unwrap()).unwrap();
        let mode = sns_governance_get_mode(&mut state_machine, sns_governance_canister_id)
            .map(|mode| Mode::from_i32(mode).unwrap())
            .unwrap();
        assert_eq!(mode, Mode::PreInitializationSwap);
    }

    // Step 3.1: TODO(NNS1-2359): Verify the FinalizeSwapResponse from automatic finalization is correct.

    // Step 3.2.1: Inspect ICP balance(s).
    // TEST_USER2 (the participant) should get their ICP back (less two transfer fees).
    {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(*TEST_USER2_PRINCIPAL, None).to_address(),
            },
        );

        let expected_balance = *INITIAL_ICP_BALANCE
            - half_baked_participation_amount
            // Two fees are from transfers from TEST_USER2 to swap, and the
            // third is for the transfer from swap back to TEST_USER2.
            - *DEFAULT_TRANSFER_FEE * 3;

        assert_eq!(observed_balance, expected_balance.into());
    }

    // Anonymously, request a refund on behalf of TEST_USER2.
    {
        let response = state_machine
            .execute_ingress(
                sns_canister_ids.swap.unwrap().try_into().unwrap(),
                "error_refund_icp",
                Encode!(&ErrorRefundIcpRequest {
                    source_principal_id: Some(*TEST_USER2_PRINCIPAL),
                })
                .unwrap(),
            )
            .unwrap();
        // Assert refund was ok.
        match response {
            WasmResult::Reject(reject) => panic!("Refund request rejected: {:?}", reject),
            WasmResult::Reply(reply) => {
                use error_refund_icp_response::Result;
                match Decode!(&reply, ErrorRefundIcpResponse).unwrap().result {
                    Some(Result::Ok(_)) => (),
                    fail => panic!("Unable to get refund: {:?}", fail),
                }
            }
        }

        // After refund, TEST_USER2's balance is what it was at the beginning, minute a few fees.
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(*TEST_USER2_PRINCIPAL, None).to_address(),
            },
        );
        let expected_balance = *INITIAL_ICP_BALANCE
            // Fees paid:
            //   1. Participation.
            //   2. Half-baked pariticipation.
            //   3. Finalize Aborted swap.
            //   4. error_refund_icp.
            - *DEFAULT_TRANSFER_FEE * 4;
        assert_eq!(observed_balance, expected_balance.into());
    }

    // Step 3.2.2: Inspect SNS token balance(s).
    {
        // Assert that the swap/sale canister's SNS token balance is unchanged.
        // Since this is the entire supply, we can be sure that nobody else has
        // any SNS tokens.
        let observed_balance_e8s = icrc1_balance(
            &state_machine,
            sns_canister_ids.ledger.unwrap().try_into().unwrap(),
            icrc_ledger_types::icrc1::account::Account {
                owner: sns_canister_ids.swap.unwrap().0,
                subaccount: None,
            },
        )
        .get_e8s();
        assert_eq!(observed_balance_e8s, 100 * neuron_basket_count * E8);
    }

    // Step 3.3: No additional SNS neurons are created.
    {
        let observed_neurons = sns_governance_list_neurons(
            &mut state_machine,
            sns_canister_ids.governance.unwrap().try_into().unwrap(),
            &ListNeurons::default(),
        )
        .neurons;
        let expected_neurons = fractional_developer_voting_power
            .airdrop_distribution
            .unwrap()
            .airdrop_neurons
            .iter()
            .chain(
                fractional_developer_voting_power
                    .developer_distribution
                    .unwrap()
                    .developer_neurons
                    .iter(),
            )
            .map(|neuron_distribution| neuron_distribution.id())
            .collect::<HashSet<_>>();
        assert_eq!(
            observed_neurons
                .iter()
                .map(|neuron| neuron.id.as_ref().unwrap().clone())
                .collect::<HashSet<_>>(),
            expected_neurons,
        );
    }

    // Step 3.4: Dapp should once again return to the (exclusive) control of TEST_USER1.
    {
        let dapp_canister_status = canister_status(
            &state_machine,
            *TEST_USER1_PRINCIPAL,
            &dapp_canister_id.into(),
        );
        assert_eq!(
            dapp_canister_status.controllers(),
            vec![*TEST_USER1_PRINCIPAL],
        );
    }

    // Step 3.5: Maturity of CF neurons should be restored.
    let zero = ExplosiveTokens::from_e8s(0);
    assert_community_fund_neuron_maturities(&mut state_machine, &[zero, zero]);
}

/// Results get printed to stderr, and such lines are prefixed with
/// "swap_load_test result:". Thus, if out.txt contains output sent to stderr,
/// then results can be obtained by running the following command:
///
///   grep 'swap_load_test result: ' out.txt | \
///     sed 's/swap_load_test result: //'
///
/// To obtain such a out.txt file using bazel, the following command could be
/// run:
///
///   bazel run \
///     //rs/sns/integration_test:long_bench \
///     --test_output=streamed \
///     --test_arg=--nocapture \
///     > out.txt
///
/// Aside: Of course, such results could alternatively be obtained using cargo.
/// Constructing a suitable command is left as an exercise to the reader,
/// because bazel is our Glorious Future (TM) ;).
///
/// A visualization of results from a past run can be found here:
/// https://observablehq.com/d/104149cffee41a66
#[cfg(feature = "long_bench")]
#[test]
fn swap_load_test() {
    use std::env::var as get_env_var;

    // By default, this is 6_400, but can be overridden using MAX_DIRECT_PARTICIPANT_COUNT
    // environment variable. Hint: to set this in bazel, use the --test_env
    // flag.
    let max_direct_participant_count = get_env_var("MAX_DIRECT_PARTICIPANT_COUNT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(6_400);
    let mut direct_participant_count = get_env_var("MIN_DIRECT_PARTICIPANT_COUNT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(100);

    fn print_result_record(record: &str) {
        println!("swap_load_test result: {}", record);
    }

    print_result_record(
        "direct_participant_count,\
         instructions_consumed_base,\
         instructions_consumed_swapping,\
         instructions_consumed_finalization,\
         time_ms",
    );

    while direct_participant_count <= max_direct_participant_count {
        println!();
        println!("-----");
        println!(
            "Measuring swap performance when {} participants are involved.",
            direct_participant_count,
        );
        println!();

        let direct_participant_principal_ids = generate_principal_ids(direct_participant_count);
        // We want the number of NNS neurons in the test scenario to scale with
        // the number of direct participants (i.e. direct_participant_count).
        let additional_nns_neurons =
            generate_community_fund_neurons(&(1..=direct_participant_count).collect::<Vec<_>>());
        let SwapPerformanceResults {
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap,
        } = assert_successful_swap_finalizes_correctly_legacy(
            &direct_participant_principal_ids,
            &additional_nns_neurons,
            ExplosiveTokens::from_e8s(20 * E8 * additional_nns_neurons.len() as u64),
            DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
            do_nothing_special_before_proposal_is_adopted,
        );

        print_result_record(&format!(
            "{},{},{},{},{}",
            direct_participant_count,
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap.as_millis()
        ));
        println!();

        // Prepare for the next iteration of this loop.
        direct_participant_count *= 2;
    }
}

#[test]
fn test_upgrade() {
    let state_machine = StateMachine::new();

    // install the swap canister
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&Init {
        nns_governance_canister_id: Principal::anonymous().to_string(),
        sns_governance_canister_id: Principal::anonymous().to_string(),
        sns_ledger_canister_id: Principal::anonymous().to_string(),
        icp_ledger_canister_id: Principal::anonymous().to_string(),
        sns_root_canister_id: Principal::anonymous().to_string(),
        fallback_controller_principal_ids: vec![Principal::anonymous().to_string()],
        transaction_fee_e8s: Some(10_000),
        neuron_minimum_stake_e8s: Some(1_000_000),
        confirmation_text: None,
        restricted_countries: None,
        min_participants: None,                      // TODO[NNS1-2339]
        min_icp_e8s: None,                           // TODO[NNS1-2339]
        max_icp_e8s: None,                           // TODO[NNS1-2339]
        min_participant_icp_e8s: None,               // TODO[NNS1-2339]
        max_participant_icp_e8s: None,               // TODO[NNS1-2339]
        swap_start_timestamp_seconds: None,          // TODO[NNS1-2339]
        swap_due_timestamp_seconds: None,            // TODO[NNS1-2339]
        sns_token_e8s: None,                         // TODO[NNS1-2339]
        neuron_basket_construction_parameters: None, // TODO[NNS1-2339]
        nns_proposal_id: None,                       // TODO[NNS1-2339]
        neurons_fund_participants: None,             // TODO[NNS1-2339]
        should_auto_finalize: Some(true),
    })
    .unwrap();
    let canister_id = state_machine
        .install_canister(wasm.clone(), args, None)
        .unwrap();

    // get the state before upgrading
    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_before_upgrade = state_machine
        .execute_ingress(canister_id, "get_state", args)
        .expect("Unable to call get_state on the Swap canister");
    let state_before_upgrade = Decode!(&state_before_upgrade.bytes(), GetStateResponse).unwrap();

    // upgrade the canister
    state_machine
        .upgrade_canister(canister_id, wasm, Encode!(&()).unwrap())
        .expect("Swap pre_upgrade or post_upgrade failed");

    // get the state after upgrading and verify it
    let args = Encode!(&GetStateRequest {}).unwrap();
    let state_after_upgrade = state_machine
        .execute_ingress(canister_id, "get_state", args)
        .expect("Unable to call get_state on the Swap canister");
    let state_after_upgrade = Decode!(&state_after_upgrade.bytes(), GetStateResponse).unwrap();
    assert_eq!(state_before_upgrade, state_after_upgrade);
}

#[test]
fn test_deletion_of_sale_ticket_legacy() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();

    let direct_participant_principal_ids = vec![*TEST_USER1_PRINCIPAL];
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(70 * E8);
    let neuron_basket_count = 3;
    let sns_canister_ids = begin_swap_legacy(
        &mut state_machine,
        &direct_participant_principal_ids,
        &[], // additional_nns_neurons
        planned_participation_amount_per_account,
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    )
    .0;

    // Create a ticket for TEST_USER1_PRINCIPAL as a prerequisite to be able to call refresh_buyer_tokens with a valid ticket
    let ticket = new_sale_ticket(
        &state_machine,
        sns_canister_ids.swap(),
        *TEST_USER1_PRINCIPAL,
        E8 * 5 / 4,
        None,
    )
    .unwrap();

    // Make sure the ticket can be retrieved
    assert_eq!(
        get_open_ticket(
            &state_machine,
            sns_canister_ids.swap(),
            *TEST_USER1_PRINCIPAL
        ),
        GetOpenTicketResponse::ok(Some(ticket.clone()))
    );

    //Transfer ICP to the SNS Sale canister. The balance of USER2 on the corresponding subaccount of the SNS sale canister has now been topped up
    assert!(icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: sns_canister_ids.swap().into(),
                subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(E8 * 5 / 4)
        },
    )
    .is_ok());

    //Check the balance on the icp ledger to make sure the balance on the subaccount of TEST_USER1_PRINCIPAL shows up on the icp ledger
    assert_eq!(
        &ticket.amount_icp_e8s,
        &icrc1_balance(
            &state_machine,
            LEDGER_CANISTER_ID,
            Account {
                owner: PrincipalId::from(sns_canister_ids.swap()).0,
                subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
            }
        )
        .get_e8s()
    );

    //Call refresh buyer tokens. There exists a valid ticket and the refresh call is expected to be successfull --> the ticket should no longer exist afterwards
    let refresh_response = refresh_buyer_tokens(
        &state_machine,
        &sns_canister_ids.swap(),
        &TEST_USER1_PRINCIPAL,
        None,
    );
    assert_eq!(
        refresh_response.unwrap(),
        RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: ticket.amount_icp_e8s,
            icp_ledger_account_balance_e8s: ticket.amount_icp_e8s
        }
    );

    //Ticket should be deleted as transfer was successful
    assert_eq!(
        get_open_ticket(
            &state_machine,
            sns_canister_ids.swap(),
            *TEST_USER1_PRINCIPAL
        ),
        GetOpenTicketResponse::ok(None)
    );

    // Make sure a new ticket can be created after the prior ticket was deleted
    let ticket_new = new_sale_ticket(
        &state_machine,
        sns_canister_ids.swap(),
        *TEST_USER1_PRINCIPAL,
        E8 * 5 / 4 + 1,
        None,
    )
    .unwrap();

    // Make sure that the ticket ids are unique, i.e. the tickets created by TEST_USER1_PRINCIPAL have different ticket ids.
    assert_ne!(ticket_new.ticket_id, ticket.ticket_id);

    //Transfer less ICP than what is stated on the new ticket
    assert!(icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: sns_canister_ids.swap().into(),
                subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(ticket_new.amount_icp_e8s - 1)
        },
    )
    .is_ok());

    //Call refresh buyer tokens --> Should fail as the balance on the icp ledger used to make new sns token purchases is lower than specified by the ticket.
    let refresh_response = refresh_buyer_tokens(
        &state_machine,
        &sns_canister_ids.swap(),
        &TEST_USER1_PRINCIPAL,
        None,
    );
    assert!(refresh_response.unwrap_err().contains("smaller"));

    //Ticket should still be available since the refresh buyer token call was unsuccessful
    assert_eq!(
        get_open_ticket(
            &state_machine,
            sns_canister_ids.swap(),
            *TEST_USER1_PRINCIPAL
        ),
        GetOpenTicketResponse::ok(Some(ticket_new.clone()))
    );

    // Send the missing ICP tokens so that the balance matches the amount on the ticket: Missing amount is 1 since that is the previous ticket amount was E8 * 5 / 4 - 1
    assert!(icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: sns_canister_ids.swap().into(),
                subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(ticket_new.amount_icp_e8s - (ticket_new.amount_icp_e8s - 1))
        },
    )
    .is_ok());

    // Refresh tokens so ticket is deleted: Call is successfull and the existing ticket is deleted.
    let refresh_response = refresh_buyer_tokens(
        &state_machine,
        &sns_canister_ids.swap(),
        &TEST_USER1_PRINCIPAL,
        None,
    );
    assert_eq!(
        refresh_response.unwrap(),
        RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: ticket.amount_icp_e8s + ticket_new.amount_icp_e8s,
            icp_ledger_account_balance_e8s: ticket.amount_icp_e8s + ticket_new.amount_icp_e8s
        }
    );

    // There should be no open ticket right now.
    assert_eq!(
        get_open_ticket(
            &state_machine,
            sns_canister_ids.swap(),
            *TEST_USER1_PRINCIPAL
        ),
        GetOpenTicketResponse::ok(None)
    );

    // Make another transfer so refresh token can be called again
    assert!(icrc1_transfer(
        &state_machine,
        LEDGER_CANISTER_ID,
        *TEST_USER1_PRINCIPAL,
        TransferArg {
            from_subaccount: None,
            to: Account {
                owner: sns_canister_ids.swap().into(),
                subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(E8 * 5 / 4)
        },
    )
    .is_ok());

    // If no ticket was provided make sure the payment flow works as before ticket system was introduced
    let refresh_response = refresh_buyer_tokens(
        &state_machine,
        &sns_canister_ids.swap(),
        &TEST_USER1_PRINCIPAL,
        None,
    );
    assert_eq!(
        refresh_response.unwrap(),
        RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: ticket.amount_icp_e8s - 1
                + ticket_new.amount_icp_e8s * 2,
            icp_ledger_account_balance_e8s: ticket.amount_icp_e8s - 1
                + ticket_new.amount_icp_e8s * 2
        }
    );
}

#[test]
fn test_get_sale_parameters_legacy() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();

    let direct_participant_principal_ids = vec![*TEST_USER1_PRINCIPAL];
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(100 * E8);
    let neuron_basket_count = 3;
    let sns_canister_ids = begin_swap_legacy(
        &mut state_machine,
        &direct_participant_principal_ids,
        &[], // additional_nns_neurons
        planned_participation_amount_per_account,
        ExplosiveTokens::from_e8s(0), // planned_community_fund_participation_amount
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    )
    .0;

    assert!(
        get_sns_sale_parameters(&state_machine, &sns_canister_ids.swap(),)
            .params
            .is_some()
    );
}

#[test]
fn test_list_community_fund_participants_legacy() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();

    let direct_participant_principal_ids = vec![*TEST_USER1_PRINCIPAL];
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(100 * E8);
    let neuron_basket_count = 3;
    let sns_canister_ids = begin_swap_legacy(
        &mut state_machine,
        &direct_participant_principal_ids,
        &[], // additional_nns_neurons
        planned_participation_amount_per_account,
        ExplosiveTokens::from_e8s(0), // planned_community_fund_participation_amount
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    )
    .0;

    assert_eq!(
        list_community_fund_participants(
            &state_machine,
            &sns_canister_ids.swap(),
            &TEST_USER1_PRINCIPAL,
            &0,
            &0
        )
        .cf_participants,
        vec![]
    );
}

#[test]
fn test_last_man_less_than_min() {
    let state_machine = StateMachine::new();
    let icp_ledger_id = state_machine.create_canister(None);
    let sns_ledger_id = state_machine.create_canister(None);
    let swap_id = state_machine.create_canister(None);
    let minting_account = Account {
        owner: PrincipalId::new_user_test_id(42).0,
        subaccount: None,
    };

    // install the icp ledger
    let wasm = ic_test_utilities_load_wasm::load_wasm(
        "../../rosetta-api/icp_ledger/ledger",
        "ledger-canister",
        &[],
    );
    let args = icp_ledger::LedgerCanisterInitPayload::builder()
        .minting_account(minting_account.into())
        .build()
        .unwrap();
    let args = Encode!(&args).unwrap();
    state_machine
        .install_existing_canister(icp_ledger_id, wasm, args)
        .unwrap();

    // install the sns ledger
    let wasm = ic_test_utilities_load_wasm::load_wasm(
        "../../rosetta-api/icrc1/ledger",
        "ic-icrc1-ledger",
        &[],
    );
    let args = Encode!(&LedgerArgument::Init(LedgerInit {
        minting_account,
        fee_collector_account: None,
        initial_balances: vec![(
            Account {
                owner: swap_id.into(),
                subaccount: None
            },
            Nat::from(10_000_000),
        )],
        transfer_fee: Nat::from(10_000),
        token_name: "SNS Token".to_string(),
        token_symbol: "STK".to_string(),
        decimals: None,
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 1,
            num_blocks_to_archive: 1,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: Principal::anonymous().into(),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None
        },
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }))
    .unwrap();
    state_machine
        .install_existing_canister(sns_ledger_id, wasm, args)
        .unwrap();

    // install the sale canister
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&Init {
        nns_governance_canister_id: Principal::anonymous().to_string(),
        sns_governance_canister_id: Principal::anonymous().to_string(),
        sns_ledger_canister_id: sns_ledger_id.to_string(),
        icp_ledger_canister_id: icp_ledger_id.to_string(),
        sns_root_canister_id: Principal::anonymous().to_string(),
        fallback_controller_principal_ids: vec![Principal::anonymous().to_string()],
        transaction_fee_e8s: Some(10_000),
        neuron_minimum_stake_e8s: Some(400_000),
        confirmation_text: None,
        restricted_countries: None,
        min_participants: None,                      // TODO[NNS1-2339]
        min_icp_e8s: None,                           // TODO[NNS1-2339]
        max_icp_e8s: None,                           // TODO[NNS1-2339]
        min_participant_icp_e8s: None,               // TODO[NNS1-2339]
        max_participant_icp_e8s: None,               // TODO[NNS1-2339]
        swap_start_timestamp_seconds: None,          // TODO[NNS1-2339]
        swap_due_timestamp_seconds: None,            // TODO[NNS1-2339]
        sns_token_e8s: None,                         // TODO[NNS1-2339]
        neuron_basket_construction_parameters: None, // TODO[NNS1-2339]
        nns_proposal_id: None,                       // TODO[NNS1-2339]
        neurons_fund_participants: None,             // TODO[NNS1-2339]
        should_auto_finalize: Some(true),
    })
    .unwrap();
    state_machine
        .install_existing_canister(swap_id, wasm, args)
        .unwrap();

    // open the sale
    // min_participant_icp_e8s >= neuron_basket_count * (neuron_minimum_stake_e8s + transaction_fee_e8s) * max_icp_e8s / sns_token_e8s
    // 1 >= 1 * (+ 10_000) * 10_000_000 / 10_000_000
    let min_participant_icp_e8s = 1_010_000;
    let max_participant_icp_e8s = 2_000_000;
    let max_icp_e8s = 10_000_000;
    let args = OpenRequest {
        params: Some(swap_pb::Params {
            min_participants: 1,
            min_icp_e8s: 1,
            max_icp_e8s,
            min_participant_icp_e8s,
            max_participant_icp_e8s,
            swap_due_timestamp_seconds: swap_due_from_now_timestamp_seconds(&state_machine),
            sns_token_e8s: 10_000_000,
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 2,
                dissolve_delay_interval_seconds: 1,
            }),
            sale_delay_seconds: None,
        }),
        cf_participants: vec![],
        open_sns_token_swap_proposal_id: Some(0),
    };
    let args = Encode!(&args).unwrap();
    let _res = state_machine
        .execute_ingress(swap_id, "open", args)
        .unwrap();

    // utilities
    let mint_min_participant_icp_e8s = |user: u64| -> BlockIndex {
        let to = Account {
            owner: swap_id.into(),
            subaccount: Some(principal_to_subaccount(&PrincipalId::new_user_test_id(
                user,
            ))),
        };
        icrc1_transfer(
            &state_machine,
            icp_ledger_id,
            PrincipalId::new_user_test_id(42),
            TransferArg {
                from_subaccount: None,
                to,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(min_participant_icp_e8s),
            },
        )
        .unwrap_or_else(|_| panic!("Unable to mint to user {}", user))
    };
    let refresh_buyer_icp_e8s = |user: u64| -> Result<RefreshBuyerTokensResponse, String> {
        refresh_buyer_tokens(
            &state_machine,
            &swap_id,
            &PrincipalId::new_user_test_id(user),
            None,
        )
    };
    // /utilities

    // The test starts here

    // num_good_users can commit min_participant_icp_e8s icps
    let num_good_users = max_icp_e8s / min_participant_icp_e8s;
    for i in 1..num_good_users + 1 {
        mint_min_participant_icp_e8s(i);
        let res = refresh_buyer_icp_e8s(i)
            .unwrap_or_else(|_| panic!("Unable to refresh_buyer_tokens for user {}", i));
        assert_eq!(res.icp_accepted_participation_e8s, min_participant_icp_e8s);
        assert_eq!(res.icp_ledger_account_balance_e8s, min_participant_icp_e8s);
    }

    // there aren't enough tokens for the last users so
    // refresh_buyer_tokens_fails
    mint_min_participant_icp_e8s(num_good_users + 1);
    let res = refresh_buyer_icp_e8s(num_good_users + 1);
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(err.contains("minimum required to participate"), "{}", err);
}

#[test]
fn test_refresh_buyer_token_legacy() {
    // Step 1: Prepare the world.
    let mut state_machine = StateMachineBuilder::new().with_current_time().build();

    let direct_participant_principal_ids = vec![
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        *TEST_USER3_PRINCIPAL,
    ];
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(100 * E8);
    let neuron_basket_count = 3;
    let sns_canister_ids = begin_swap_legacy(
        &mut state_machine,
        &direct_participant_principal_ids,
        &[], // additional_nns_neurons
        planned_participation_amount_per_account,
        ExplosiveTokens::from_e8s(0), // planned_community_fund_participation_amount
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        do_nothing_special_before_proposal_is_adopted,
    )
    .0;

    let sns_params = get_sns_sale_parameters(&state_machine, &sns_canister_ids.swap())
        .params
        .unwrap();

    //Happy Case
    {
        // Create a ticket for user1, amount is the minimum that has to be transferred for a purchase
        let ticket = new_sale_ticket(
            &state_machine,
            sns_canister_ids.swap(),
            *TEST_USER1_PRINCIPAL,
            sns_params.min_participant_icp_e8s,
            None,
        )
        .unwrap();

        //Transfer ICP to the SNS Sale canister. The balance of user1 on the corresponding subaccount of the SNS sale canister has now been topped up
        assert!(icrc1_transfer(
            &state_machine,
            LEDGER_CANISTER_ID,
            *TEST_USER1_PRINCIPAL,
            TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: sns_canister_ids.swap().into(),
                    subaccount: Some(principal_to_subaccount(&TEST_USER1_PRINCIPAL))
                },
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(ticket.amount_icp_e8s)
            },
        )
        .is_ok());

        //Check the balance on the sns sale canister buyer state to make sure the balance of user1 is 0 (or not existing since no purchase has been made yet) before committing to the purchase
        assert!(get_buyer_state(
            &state_machine,
            &sns_canister_ids.swap(),
            &TEST_USER1_PRINCIPAL
        )
        .buyer_state
        .is_none());

        let refresh_response = refresh_buyer_tokens(
            &state_machine,
            &sns_canister_ids.swap(),
            &TEST_USER1_PRINCIPAL,
            None,
        );

        assert_eq!(
            refresh_response.unwrap(),
            RefreshBuyerTokensResponse {
                icp_accepted_participation_e8s: ticket.amount_icp_e8s,
                icp_ledger_account_balance_e8s: ticket.amount_icp_e8s
            }
        );

        //Check the balance on the sns sale canister buyer state to make sure the balance of user1 is the same as specified on the ticket
        assert!(
            get_buyer_state(
                &state_machine,
                &sns_canister_ids.swap(),
                &TEST_USER1_PRINCIPAL
            )
            .buyer_state
            .unwrap()
            .amount_icp_e8s()
                == ticket.amount_icp_e8s
        );
    }
}
