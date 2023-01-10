use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Account;
use ic_nervous_system_common::{
    ledger::compute_neuron_staking_subaccount, ExplosiveTokens, E8, SECONDS_PER_DAY,
    START_OF_2022_TIMESTAMP_SECONDS,
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
};
use ic_nns_common::{pb::v1 as nns_common_pb, types::ProposalId as NnsProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    self as nns_governance_pb,
    manage_neuron::{self, RegisterVote},
    manage_neuron_response,
    neuron::DissolveState::DissolveDelaySeconds,
    proposal, ManageNeuron, OpenSnsTokenSwap, Proposal, ProposalStatus, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    ids::TEST_NEURON_1_ID,
    sns_wasm::{
        add_real_wasms_to_sns_wasms_and_return_immediately, deploy_new_sns,
        wait_for_proposal_status,
    },
    state_test_helpers::{
        icrc1_balance, ledger_account_balance, nns_governance_get_full_neuron,
        nns_governance_get_proposal_info, nns_governance_make_proposal, set_controllers,
        set_up_universal_canister, setup_nns_canisters,
    },
};
use ic_sns_governance::pb::v1::ListNeurons;
use ic_sns_init::pb::v1::{
    sns_init_payload::InitialTokenDistribution, AirdropDistribution, DeveloperDistribution,
    FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload, SwapDistribution,
    TreasuryDistribution,
};
use ic_sns_root::{pb::v1::RegisterDappCanisterRequest, CanisterIdRecord, CanisterStatusResultV2};
use ic_sns_swap::pb::v1::{
    self as swap_pb, error_refund_icp_response, params::NeuronBasketConstructionParameters,
    set_dapp_controllers_call_result, ErrorRefundIcpRequest, ErrorRefundIcpResponse,
    SetDappControllersCallResult, SetDappControllersResponse,
};
use ic_sns_test_utils::state_test_helpers::{
    participate_in_swap, send_participation_funds, sns_governance_list_neurons,
    sns_root_register_dapp_canister, swap_get_state,
};
use ic_sns_wasm::pb::v1::SnsCanisterIds;
use ic_state_machine_tests::StateMachine;
use ic_types::{
    crypto::{AlgorithmId, UserPublicKey},
    ingress::WasmResult,
    Cycles,
};
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs as AccountBalanceArgs,
    DEFAULT_TRANSFER_FEE as DEFAULT_TRANSFER_FEE_TOKENS,
};
use lazy_static::lazy_static;
use maplit::hashmap;
use pretty_assertions::assert_eq;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{
    collections::{hash_map, HashMap, HashSet},
    time::{Duration, SystemTime},
};

const ONE_TRILLION: u128 = 1_000_000_000_000;
const EXPECTED_SNS_CREATION_FEE: u128 = 180 * ONE_TRILLION;

const DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR: f64 = 0.01;

lazy_static! {
    static ref INITIAL_ICP_BALANCE: ExplosiveTokens = ExplosiveTokens::from_e8s(100 * E8);
    static ref SWAP_DUE_TIMESTAMP_SECONDS: u64 = StateMachine::new()
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 13 * SECONDS_PER_DAY;
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

// TODO: Move this to one of the state_test_helpers.rs files.
fn canister_status(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    request: &CanisterIdRecord,
) -> CanisterStatusResultV2 {
    let request = Encode!(&request).unwrap();
    let result = state_machine
        .execute_ingress_as(sender, CanisterId::ic_00(), "canister_status", request)
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, CanisterStatusResultV2).unwrap()
}

fn make_account(seed: u64) -> ic_base_types::PrincipalId {
    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    let pubkey: UserPublicKey = UserPublicKey {
        key: keypair.public_key.to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };
    let principal_id: PrincipalId = PrincipalId::new_self_authenticating(
        &ic_canister_client_sender::ed25519_public_key_to_der(pubkey.key),
    );
    principal_id
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
/// any accounts listed in `accounts`.
fn begin_swap(
    state_machine: &mut StateMachine,
    accounts: &[ic_base_types::PrincipalId],
    additional_nns_neurons: &[nns_governance_pb::Neuron],
    planned_participation_amount_per_account: ExplosiveTokens,
    planned_community_fund_participation_amount: ExplosiveTokens,
    neuron_basket_count: u64,
    max_community_fund_relative_error: f64,
) -> (
    SnsCanisterIds,
    /* community_fund_nns_neurons */ Vec<nns_governance_pb::Neuron>,
    FractionalDeveloperVotingPower,
    /* dapp_canister_id */ CanisterId,
    NnsProposalId,
) {
    let num_accounts = accounts.len().max(1) as u64;
    // Give TEST_USER2 and everyone in `accounts` some ICP so that they can buy into the swap.
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
                accounts
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

        builder.build()
    };

    let neurons = &nns_init_payloads.governance.neurons;
    let community_fund_neurons = neurons
        .iter()
        .filter(|(_id, neuron)| neuron.joined_community_fund_timestamp_seconds.is_some())
        .map(|(_id, neuron)| neuron.clone())
        .collect();
    let neuron_id_to_principal_id: HashMap<u64, PrincipalId> = neurons
        .iter()
        .map(|(id, neuron)| (*id, neuron.controller.unwrap()))
        .collect();

    setup_nns_canisters(state_machine, nns_init_payloads);

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

    let fund_raising_amount_icp_e8s = (planned_participation_amount_per_account * num_accounts
        + planned_community_fund_participation_amount)
        .into_e8s();
    // Scale up SNS tokens to ensure that participants get enough SNS tokens to form neurons.
    let sns_token_e8s = fund_raising_amount_icp_e8s * neuron_basket_count;

    // Create, configure, and init SNS canisters.
    let mut sns_init_payload: SnsInitPayload = SnsInitPayload::with_valid_values_for_testing();
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

    // Create dapp canister, and make it controlled by the SNS that was just created.
    let dapp_canister_id = state_machine.create_canister(/* settings = */ None);
    set_controllers(
        state_machine,
        PrincipalId::new_anonymous(),
        dapp_canister_id,
        vec![canister_ids.root.unwrap()],
    );
    sns_root_register_dapp_canister(
        state_machine,
        canister_ids.root.unwrap().try_into().unwrap(),
        &RegisterDappCanisterRequest {
            canister_id: Some(dapp_canister_id.into()),
        },
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

                swap_due_timestamp_seconds: *SWAP_DUE_TIMESTAMP_SECONDS,

                sns_token_e8s,
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: neuron_basket_count,
                    dissolve_delay_interval_seconds: 7890000, // 3 months,
                }),
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

    // Make all the neurons vote for the OpenSnsTokenSwap proposal.
    stuff_ballot_box(
        state_machine,
        proposal_id.into(),
        &neuron_id_to_principal_id,
        Vote::Yes,
    );

    // Proposal executed successfully.
    let proposal = nns_governance_get_proposal_info(state_machine, proposal_id.id);
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

    let proposal = nns_governance_get_proposal_info(state_machine, proposal_id.0);
    assert!(proposal.decided_timestamp_seconds > 0, "{:#?}", proposal);
}

#[test]
fn swap_lifecycle_happy_one_neuron() {
    swap_n_accounts(
        1,                                  // num_accounts
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
    );
}

#[test]
fn swap_lifecycle_happy_two_neurons() {
    swap_n_accounts(
        2,                                  // num_accounts
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(30 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
    );
}

#[test]
fn swap_lifecycle_happy_more_neurons() {
    swap_n_accounts(
        101,                                // num_accounts
        &[],                                // additional_nns_neurons
        ExplosiveTokens::from_e8s(10 * E8), // planned_community_fund_participation_amount
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
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
    )
    .to_address();

    nns_governance_pb::Neuron {
        id: Some(nns_common_pb::NeuronId {
            id: thread_rng().gen(),
        }),
        account: account.into(),
        controller: Some(controller),
        maturity_e8s_equivalent,
        ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
    }
}

// Swap should succeed when there are many large Community Fund neurons (i.e. CF
// neurons with a large amount of maturity), and few small ones.
#[test]
fn many_large_community_fund_neurons_and_some_small_ones() {
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

    let num_accounts = 20;
    let planned_community_fund_participation_amount =
        ExplosiveTokens::from_e8s((100..121_u64).sum::<u64>() * E8 / 2);
    let max_community_fund_relative_error = 0.025;
    swap_n_accounts(
        num_accounts,
        &additional_nns_neurons,
        planned_community_fund_participation_amount,
        max_community_fund_relative_error,
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

    let num_accounts = 20;
    let planned_community_fund_participation_amount =
        ExplosiveTokens::from_e8s((100..103_u64).sum::<u64>() * E8 / 2);
    let max_community_fund_relative_error = 0.10;
    swap_n_accounts(
        num_accounts,
        &additional_nns_neurons,
        planned_community_fund_participation_amount,
        max_community_fund_relative_error,
    );
}

fn swap_n_accounts(
    num_accounts: u64,
    additional_nns_neurons: &[nns_governance_pb::Neuron],
    planned_community_fund_participation_amount: ExplosiveTokens,
    max_community_fund_relative_error: f64,
) -> SwapPerformanceResults {
    assert!(
        num_accounts > 0,
        "Testing the swap lifecycle requires num_accounts > 0"
    );

    // Step 0: Constants
    let planned_participation_amount_per_account = ExplosiveTokens::from_e8s(70 * E8);
    let neuron_basket_count = 3;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let accounts = (0..num_accounts).map(make_account).collect::<Vec<_>>();
    let (
        sns_canister_ids,
        community_fund_neurons,
        _fractional_developer_voting_power,
        _dapp_canister_id,
        sns_proposal_id,
    ) = begin_swap(
        &mut state_machine,
        &accounts,
        additional_nns_neurons,
        planned_participation_amount_per_account,
        planned_community_fund_participation_amount,
        neuron_basket_count,
        max_community_fund_relative_error,
    );

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
            let new_neuron = nns_governance_get_full_neuron(
                state_machine,
                original_neuron.controller.unwrap(),
                original_neuron.id.as_ref().unwrap().id,
            )
            .unwrap();

            current_community_fund_total +=
                ExplosiveTokens::from_e8s(new_neuron.maturity_e8s_equivalent);
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
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                assert_eq!(
                    new_neuron.maturity_e8s_equivalent,
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
        let relative_error = (planned_community_fund_participation_amount
            - community_fund_in_escrow)
            .into_e8s() as f64
            / planned_community_fund_participation_amount.get_e8s() as f64;
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
            let new_neuron = nns_governance_get_full_neuron(
                &mut state_machine,
                original_neuron.controller.unwrap(),
                original_neuron.id.as_ref().unwrap().id,
            )
            .unwrap();
            (
                *id,
                original_neuron.maturity_e8s_equivalent - new_neuron.maturity_e8s_equivalent,
            )
        })
        .collect::<HashMap<u64, u64>>();

    // Step 2: Run code under test.

    // Have all the accounts we created participate in the swap
    for (index, principal_id) in accounts.iter().enumerate() {
        println!("Direct participant {}/{}", index + 1, num_accounts);
        if index == num_accounts as usize - 1 {
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
        let expected_neuron_count = ((num_accounts + participating_community_fund_neuron_count)
            * neuron_basket_count) as u32;
        assert_eq!(
            finalize_swap_response,
            swap_pb::FinalizeSwapResponse {
                sweep_icp: Some(swap_pb::SweepResult {
                    success: num_accounts as u32,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: Some(swap_pb::SweepResult {
                    success: expected_neuron_count,
                    failure: 0,
                    skipped: 0,
                }),
                create_neuron: Some(swap_pb::SweepResult {
                    success: expected_neuron_count,
                    failure: 0,
                    skipped: 0,
                }),
                sns_governance_normal_mode_enabled: Some(swap_pb::SetModeCallResult {
                    possibility: None
                }),
                set_dapp_controllers_result: None,
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

    let total_icp_transferred =
        planned_participation_amount_per_account * num_accounts + community_fund_in_escrow;
    {
        let observed_sns_governance_icp_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(sns_canister_ids.governance.unwrap(), None)
                    .to_address(),
            },
        );
        let total_paid_in_transfer_fee = *DEFAULT_TRANSFER_FEE * num_accounts;
        let expected_balance = total_icp_transferred - total_paid_in_transfer_fee;
        assert_eq!(
            observed_sns_governance_icp_balance,
            expected_balance.into(),
            "planned_participation_amount_per_account={} \
             num_accounts={} \
             community_fund_in_escrow={} \
             transfer_fee={}",
            planned_participation_amount_per_account,
            num_accounts,
            community_fund_in_escrow,
            DEFAULT_TRANSFER_FEE.into_e8s(),
        );
    }
    // All the users still has the change left over from their participation in the swap/sale.
    for principal_id in accounts.iter() {
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
        match &nns_governance_get_proposal_info(&mut state_machine, sns_proposal_id.0)
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
    let expected_principal_id_to_gross_sns_token_participation_amount_e8s = community_fund_neurons
        .iter()
        .filter_map(|nns_neuron| {
            let principal_id = nns_neuron.controller.unwrap();
            let original_maturity_e8s = original_id_to_community_fund_neuron
                .get(&nns_neuron.id.as_ref().unwrap().id)
                .unwrap()
                .maturity_e8s_equivalent;
            let icp_participation_e8s = original_maturity_e8s - nns_neuron.maturity_e8s_equivalent;
            // Skip Community Fund neurons that were too small to participate.
            if icp_participation_e8s == 0 {
                return None;
            }

            let expected_sns_tokens_e8s =
                (icp_participation_e8s as u128 * sns_tokens_being_offered_e8s as u128
                    / total_icp_transferred.get_e8s() as u128) as u64;
            Some((principal_id, expected_sns_tokens_e8s))
        })
        .chain(accounts.iter().map(|principal_id| {
            let expected_sns_tokens_e8s =
                (planned_participation_amount_per_account.into_e8s() as u128
                    * sns_tokens_being_offered_e8s as u128
                    / total_icp_transferred.get_e8s() as u128) as u64;
            (*principal_id, expected_sns_tokens_e8s)
        }))
        .collect::<Vec<(
            /* principal_id: */ PrincipalId,
            /* gross_participation_amount_e8s: */ u64,
        )>>();

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
        .neurons;

        let mut actual_total_sns_tokens_e8s = 0;

        // Make sure cached stake in reward SNS neurons match their respective balances.
        // Also, add up stakes.
        for neuron in &distributed_neurons {
            let subaccount = neuron.id.as_ref().unwrap().subaccount().unwrap();

            let observed_balance_e8s = icrc1_balance(
                &state_machine,
                sns_canister_ids.ledger.unwrap().try_into().unwrap(),
                Account {
                    owner: sns_canister_ids.governance.unwrap(),
                    subaccount: Some(subaccount),
                },
            )
            .get_e8s();

            // Check that the cached balance of the neuron is equal to the neuron's account in the ledger
            assert_eq!(neuron.cached_neuron_stake_e8s, observed_balance_e8s);

            // Add to the actual total including the default transfer fee which was deducted
            // during swap committal
            actual_total_sns_tokens_e8s += observed_balance_e8s + DEFAULT_TRANSFER_FEE.get_e8s();
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

    // Step 3.3: Inspect SNS neurons.
    for (principal_id, _) in &expected_principal_id_to_gross_sns_token_participation_amount_e8s {
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
        .neurons;

        assert_eq!(
            observed_sns_neurons.len(),
            neuron_basket_count as usize,
            "{:#?}",
            observed_sns_neurons
        );

        for observed_sns_neuron in &observed_sns_neurons {
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

    // Inspect the source_nns_neuron_id field in Community Fund neurons.
    for community_fund_neuron in &community_fund_neurons {
        let controller = community_fund_neuron.controller.unwrap();

        let sns_neurons = sns_governance_list_neurons(
            &mut state_machine,
            sns_canister_ids.governance.unwrap().try_into().unwrap(),
            &ListNeurons {
                limit: 100,
                start_page_at: None,
                of_principal: Some(controller),
            },
        )
        .neurons;

        let expected_source_neuron_id = community_fund_neuron.id.as_ref().unwrap().id;
        let participation_amount_e8s = *community_fund_neuron_id_to_participation_amount_e8s
            .get(&expected_source_neuron_id)
            .unwrap();
        if participation_amount_e8s > 0 {
            assert!(!sns_neurons.is_empty(), "{}", controller);
        }
        for sns_neuron in sns_neurons {
            assert_eq!(
                sns_neuron.source_nns_neuron_id,
                Some(expected_source_neuron_id)
            );
        }
    }

    // Analogous to the previous loop, insepct the source_nns_neuron_id field,
    // but this time, in non-Community Fund neurons.
    for principal_id in accounts {
        let sns_neurons = sns_governance_list_neurons(
            &mut state_machine,
            sns_canister_ids.governance.unwrap().try_into().unwrap(),
            &ListNeurons {
                limit: 100,
                start_page_at: None,
                of_principal: Some(principal_id),
            },
        )
        .neurons;

        assert!(!sns_neurons.is_empty(), "{}", principal_id);
        for sns_neuron in sns_neurons {
            assert_eq!(sns_neuron.source_nns_neuron_id, None);
        }
    }

    // STEP 3.4: NNS governance is responsible for "settling" CF participation.
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
        let relative_error = (planned_community_fund_participation_amount - spent).into_e8s()
            as f64
            / planned_community_fund_participation_amount.get_e8s() as f64;
        assert!(
            (0.0..=max_community_fund_relative_error).contains(&relative_error),
            "{} vs. {} ({}% error)",
            spent,
            planned_community_fund_participation_amount,
            100.0 * relative_error,
        );
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
    let mut state_machine = StateMachine::new();
    let (
        sns_canister_ids,
        community_fund_neurons,
        fractional_developer_voting_power,
        dapp_canister_id,
        _sns_proposal_id,
    ) = begin_swap(
        &mut state_machine,
        &[], // accounts
        &[], // additional_nns_neurons
        planned_contribution_per_account,
        planned_community_fund_participation_amount,
        neuron_basket_count,
        DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
    );

    let assert_community_fund_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawal_amounts: &[ExplosiveTokens]| {
            assert_eq!(community_fund_neurons.len(), withdrawal_amounts.len());

            for (original_neuron, withdrawal_amount) in
                community_fund_neurons.iter().zip(withdrawal_amounts.iter())
            {
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                let expected_e8s =
                    original_neuron.maturity_e8s_equivalent - withdrawal_amount.into_e8s();
                assert!(new_neuron.maturity_e8s_equivalent >= expected_e8s);
                // This can occur if neurons are given their voting rewards.
                let extra =
                    (new_neuron.maturity_e8s_equivalent as f64) / (expected_e8s as f64) - 1.0;
                assert!(
                    (0.0..0.03).contains(&extra),
                    "observed = {} expected = {} extra = {}",
                    new_neuron.maturity_e8s_equivalent,
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
    state_machine.set_time(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(*SWAP_DUE_TIMESTAMP_SECONDS + 1),
    );

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

    // Execute the swap.
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

    // Step 3: Inspect results.

    // Step 3.1: Inspect finalize_swap_response.
    {
        use swap_pb::settle_community_fund_participation_result::{Possibility, Response};
        assert_eq!(
            finalize_swap_response,
            swap_pb::FinalizeSwapResponse {
                sweep_icp: Some(swap_pb::SweepResult {
                    success: 1,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: None,
                create_neuron: None,
                sns_governance_normal_mode_enabled: None,
                set_dapp_controllers_result: Some(SetDappControllersCallResult {
                    possibility: Some(set_dapp_controllers_call_result::Possibility::Ok(
                        SetDappControllersResponse {
                            failed_updates: vec![],
                        }
                    )),
                }),
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
            ic_icrc1::Account {
                owner: sns_canister_ids.swap.unwrap(),
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
            &mut state_machine,
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

    // By default, this is 6_400, but can be overridden using MAX_ACCOUNTS
    // environment varaible. Hint: to set this in bazel, use the --test_env
    // flag.
    let max_accounts = get_env_var("MAX_ACCOUNTS")
        .map(|s| s.parse().unwrap())
        .unwrap_or(6_400);
    let mut num_accounts = get_env_var("MIN_ACCOUNTS")
        .map(|s| s.parse().unwrap())
        .unwrap_or(100);

    fn print_result_record(record: &str) {
        println!("swap_load_test result: {}", record);
    }

    print_result_record(
        "num_accounts,\
         instructions_consumed_base,\
         instructions_consumed_swapping,\
         instructions_consumed_finalization,\
         time_ms",
    );

    // Neurons will have maturity, and be in the Community fund.
    fn generate_some_neurons(count: u64) -> Vec<nns_governance_pb::Neuron> {
        let mut rng = thread_rng();
        let neuron_ids = 1..=count;

        neuron_ids
            .map(|id| {
                let controller = PrincipalId::new_user_test_id(rng.gen());
                let account = AccountIdentifier::new(
                    NNS_GOVERNANCE_CANISTER_ID.into(),
                    Some(compute_neuron_staking_subaccount(
                        controller, /* nonce = */ 0,
                    )),
                )
                .to_address();

                nns_governance_pb::Neuron {
                    id: Some(nns_common_pb::NeuronId { id }),
                    account: account.into(),
                    controller: Some(controller),
                    cached_neuron_stake_e8s: 100 * E8,
                    maturity_e8s_equivalent: 100 * E8,
                    ..COMMUNITY_FUND_NEURON_TEMPLATE.clone()
                }
            })
            .collect()
    }

    while num_accounts <= max_accounts {
        println!();
        println!("-----");
        println!(
            "Measuring swap performance when {} participants are involved.",
            num_accounts,
        );
        println!();

        // We want the number of NNS neurons in the test scenario to scale with
        // the number of direct participants (i.e. num_accounts).
        let additional_nns_neurons = generate_some_neurons(num_accounts);
        let SwapPerformanceResults {
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap,
        } = swap_n_accounts(
            num_accounts,
            &additional_nns_neurons,
            ExplosiveTokens::from_e8s(20 * E8 * additional_nns_neurons.len() as u64),
            DEFAULT_MAX_COMMUNITY_FUND_RELATIVE_ERROR,
        );

        print_result_record(&format!(
            "{},{},{},{},{}",
            num_accounts,
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap.as_millis()
        ));
        println!();

        // Prepare for the next iteration of this loop.
        num_accounts = ((num_accounts as f64) * 2.0) as u64;
    }
}
