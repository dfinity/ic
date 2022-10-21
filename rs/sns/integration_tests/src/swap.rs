use candid::{types::number::Nat, Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterSettingsArgs, UpdateSettingsArgs};
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL,
};
use ic_nns_common::pb::v1 as nns_common_pb;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{
    self as nns_governance_pb,
    manage_neuron::{self, RegisterVote},
    manage_neuron_response, proposal, ManageNeuron, OpenSnsTokenSwap, Proposal, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    ids::TEST_NEURON_1_ID,
    sns_wasm::{add_real_wasms_to_sns_wasms, deploy_new_sns},
    state_test_helpers::{self, set_up_universal_canister, setup_nns_canisters},
};
use ic_sns_governance::pb::v1::{ListNeurons, ListNeuronsResponse};
use ic_sns_init::pb::v1::{
    sns_init_payload::InitialTokenDistribution, AirdropDistribution, DeveloperDistribution,
    FractionalDeveloperVotingPower, NeuronDistribution, SnsInitPayload, SwapDistribution,
    TreasuryDistribution,
};
use ic_sns_root::{
    pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse},
    CanisterIdRecord, CanisterStatusResultV2,
};
use ic_sns_swap::pb::v1::{
    self as swap_pb, params::NeuronBasketConstructionParameters, set_dapp_controllers_call_result,
    SetDappControllersCallResult, SetDappControllersResponse,
};
use ic_sns_wasm::pb::v1::SnsCanisterIds;
use ic_state_machine_tests::StateMachine;
use ic_types::{
    crypto::{AlgorithmId, UserPublicKey},
    ingress::WasmResult,
    Cycles,
};
use lazy_static::lazy_static;
use ledger_canister::{
    AccountIdentifier, BinaryAccountBalanceArgs as AccountBalanceArgs, Memo, TransferArgs,
    DEFAULT_TRANSFER_FEE,
};
use num_traits::ToPrimitive;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::HashSet;
use std::time::{Duration, SystemTime};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

const COMMUNITY_FUND_INVESTMENT_E8S: u64 = 30 * E8;

lazy_static! {
    static ref TEST_USER2_ORIGINAL_BALANCE_ICP: Tokens = Tokens::from_tokens(100).unwrap();
    static ref SWAP_DUE_TIMESTAMP_SECONDS: u64 = StateMachine::new()
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 13 * SECONDS_PER_DAY;
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct SwapPerformanceResults {
    instructions_consumed_base: f64,
    instructions_consumed_swapping: f64,
    instructions_consumed_finalization: f64,
    time_to_finalize_swap: Duration,
}

fn set_controllers(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    target: CanisterId,
    controllers: Vec<PrincipalId>,
) {
    let request = Encode!(&UpdateSettingsArgs {
        canister_id: target.into(),
        settings: CanisterSettingsArgs::new(None, Some(controllers), None, None, None,),
    })
    .unwrap();

    state_machine
        .execute_ingress_as(sender, CanisterId::ic_00(), "update_settings", request)
        .unwrap();
}

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
    /// This is copied from ic_canister_client::agent::ed25519_public_key_to_der to
    /// avoid having to import that crate.
    fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
        let mut encoded: Vec<u8> = vec![
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        encoded.append(&mut key);
        encoded
    }

    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    let pubkey: UserPublicKey = UserPublicKey {
        key: keypair.public_key.to_vec(),
        algorithm_id: AlgorithmId::Ed25519,
    };
    let principal_id: PrincipalId =
        PrincipalId::new_self_authenticating(&ed25519_public_key_to_der(pubkey.key));
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
    planned_contribution_per_account: u64,
    planned_cf_contribution: u64,
    neuron_basket_count: u64,
) -> (
    SnsCanisterIds,
    /* community_fund_nns_neurons */ Vec<nns_governance_pb::Neuron>,
    FractionalDeveloperVotingPower,
    /* dapp_canister_id */ CanisterId,
) {
    let num_accounts = accounts.len().max(1) as u64;
    // Give TEST_USER2 and everyone in `accounts` some ICP so that they can buy into the swap.
    let test_user2_principal_id: PrincipalId = *TEST_USER2_PRINCIPAL;
    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);
    let mut nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .with_sns_wasm_allowed_principals(vec![wallet_canister_id.into()])
        .with_ledger_account(
            test_user2_principal_id.into(),
            *TEST_USER2_ORIGINAL_BALANCE_ICP,
        )
        .with_ledger_accounts(
            accounts
                .iter()
                .map(|principal_id| ((*principal_id).into(), *TEST_USER2_ORIGINAL_BALANCE_ICP))
                .collect(),
        )
        .with_test_neurons()
        .build();
    // Give neurons maturity and make the first two join the community fund.
    let mut community_fund_neurons = vec![];
    {
        for (i, neuron) in nns_init_payloads
            .governance
            .neurons
            .values_mut()
            .enumerate()
        {
            let n = (i + 1) as u64;
            neuron.maturity_e8s_equivalent = n * 25 * E8;

            if i < 2 {
                neuron.joined_community_fund_timestamp_seconds = Some(1);
                community_fund_neurons.push(neuron.clone());
            }
        }
    }
    let neuron_id_to_principal_id: Vec<(u64, PrincipalId)> = nns_init_payloads
        .governance
        .neurons
        .iter()
        .map(|(id, neuron)| (*id, neuron.controller.unwrap()))
        .collect();
    assert_eq!(
        neuron_id_to_principal_id.len(),
        3,
        "{:#?}",
        neuron_id_to_principal_id
    );
    setup_nns_canisters(state_machine, nns_init_payloads);
    add_real_wasms_to_sns_wasms(state_machine);

    // Create, configure, and init SNS canisters.
    let mut sns_init_payload: SnsInitPayload = SnsInitPayload::with_valid_values_for_testing();
    sns_init_payload.fallback_controller_principal_ids = vec![TEST_USER1_PRINCIPAL.to_string()];
    let fractional_developer_voting_power = FractionalDeveloperVotingPower {
        swap_distribution: Some(SwapDistribution {
            total_e8s: 100 * num_accounts * neuron_basket_count * E8,
            initial_swap_amount_e8s: 100 * num_accounts * neuron_basket_count * E8,
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
    let cycle_count = 50_000_000_000_000;
    let wallet_canister = set_up_universal_canister(state_machine, Some(Cycles::new(cycle_count)));
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

    // Propose that a swap be scheduled to start 3 days from now, and last for
    // 10 days.
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_1_ID,
    };
    let goal_tokens_raised = Tokens::from_tokens(
        planned_contribution_per_account * num_accounts + planned_cf_contribution,
    )
    .unwrap()
    .get_e8s();
    let response = nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL, // sender
        neuron_id,
        &Proposal {
            title: Some("Schedule SNS Token Sale".to_string()),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
                target_swap_canister_id: Some(canister_ids.swap.unwrap()),
                params: Some(swap_pb::Params {
                    // Succeed as soon as we raise `goal_tokens_raised`. In this case,
                    // SNS tokens and ICP trade at a ratio of `neuron_basket` so each
                    // created neron reached minimum stake requirements.
                    max_icp_e8s: goal_tokens_raised,
                    // We want to make sure our test is exactly right, so we set the
                    // minimum to be just one e8 less than the maximum.
                    min_icp_e8s: goal_tokens_raised - 1,

                    // We need at least one participant, but they can contribute whatever
                    // amount they want (subject to max_icp_e8s for the whole swap).
                    min_participants: 1,
                    min_participant_icp_e8s: 1,
                    max_participant_icp_e8s: TEST_USER2_ORIGINAL_BALANCE_ICP.get_e8s(),

                    swap_due_timestamp_seconds: *SWAP_DUE_TIMESTAMP_SECONDS,

                    // With setting the sns_tokens_e8s to goal_tokens_raised * neuron_basket_count,
                    // max_icp_e8s goal_tokens_raised, the neurons that are created within the neuron basket
                    // should reach the minimum staking requirement of governance
                    sns_token_e8s: goal_tokens_raised * neuron_basket_count,
                    neuron_basket_construction_parameters: Some(
                        NeuronBasketConstructionParameters {
                            count: neuron_basket_count,
                            dissolve_delay_interval_seconds: 7890000, // 3 months,
                        },
                    ),
                }),
                // This is not sufficient to make the swap an automatic success.
                community_fund_investment_e8s: Some(COMMUNITY_FUND_INVESTMENT_E8S),
            })),
        },
    );
    let proposal_id = response
        .proposal_id
        .unwrap_or_else(|| panic!("Response did not contain a proposal_id: {:#?}", response));

    // Vote for the proposal.
    for (neuron_id, principal_id) in neuron_id_to_principal_id {
        // Skip TEST_NEURON_1, since it, being the proposer, automatically voted in favor already.
        if neuron_id == TEST_NEURON_1_ID {
            continue;
        }

        state_machine
            .execute_ingress_as(
                principal_id,
                NNS_GOVERNANCE_CANISTER_ID,
                "manage_neuron",
                Encode!(&ManageNeuron {
                    id: Some(nns_common_pb::NeuronId { id: neuron_id }),
                    command: Some(manage_neuron::Command::RegisterVote(RegisterVote {
                        proposal: Some(proposal_id),
                        vote: Vote::Yes as i32,
                    })),
                    neuron_id_or_subaccount: None
                })
                .unwrap(),
            )
            .unwrap();
    }

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
    )
}

#[test]
fn swap_lifecycle_happy_one_neuron() {
    swap_n_accounts(1);
}

#[test]
fn swap_lifecycle_happy_two_neurons() {
    swap_n_accounts(2);
}

#[test]
fn swap_lifecycle_happy_more_neurons() {
    swap_n_accounts(101);
}

fn swap_n_accounts(num_accounts: u64) -> SwapPerformanceResults {
    assert!(
        num_accounts > 0,
        "Testing the swap lifecycle requires num_accounts > 0"
    );
    // Step 0: Constants
    let planned_contribution_per_account = 70;
    let planned_cf_contribution = 30;
    let neuron_basket_count = 3;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let accounts = (0..num_accounts).map(make_account).collect::<Vec<_>>();
    let (
        sns_canister_ids,
        community_fund_neurons,
        _fractional_developer_voting_power,
        _dapp_canister_id,
    ) = begin_swap(
        &mut state_machine,
        &accounts,
        planned_contribution_per_account,
        planned_cf_contribution,
        neuron_basket_count,
    );

    // Step 1.5: initialize variables for the benchmark
    let instructions_consumed_base = state_machine.instructions_consumed();
    let mut instructions_consumed_swapping = None;
    let mut time_finalization_started = None;

    let assert_cf_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawal_amounts_e8s: &[u64]| {
            assert_eq!(community_fund_neurons.len(), withdrawal_amounts_e8s.len());

            for (original_neuron, withdrawal_amount_e8s) in community_fund_neurons
                .iter()
                .zip(withdrawal_amounts_e8s.iter())
            {
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                assert_eq!(
                    new_neuron.maturity_e8s_equivalent,
                    original_neuron.maturity_e8s_equivalent - withdrawal_amount_e8s,
                );
            }
        };

    // We'll do this again after finalizing the swap.
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

    // Step 2: Run code under test.

    // Have all the accounts we created participate in the swap
    for (index, principal_id) in accounts.iter().enumerate() {
        println!("Swapping user {index}/{num_accounts}");
        if index == num_accounts as usize - 1 {
            time_finalization_started = Some(SystemTime::now());
            instructions_consumed_swapping =
                Some(state_machine.instructions_consumed() - instructions_consumed_base);
        }
        participate_in_swap(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            *principal_id,
            Tokens::from_tokens(planned_contribution_per_account).unwrap(),
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
        use swap_pb::settle_community_fund_participation_result::{Possibility, Response};
        assert_eq!(
            finalize_swap_response,
            swap_pb::FinalizeSwapResponse {
                sweep_icp: Some(swap_pb::SweepResult {
                    success: num_accounts as u32,
                    failure: 0,
                    skipped: 0,
                }),
                sweep_sns: Some(swap_pb::SweepResult {
                    success: ((num_accounts + 2) * neuron_basket_count) as u32,
                    failure: 0,
                    skipped: 0,
                }),
                create_neuron: Some(swap_pb::SweepResult {
                    success: ((num_accounts + 2) * neuron_basket_count) as u32,
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
                )
            }
        );
    }

    // Step 3.2.1: Inspect ICP balances.

    // SNS governance should get the ICP.
    {
        let observed_balance = ledger_account_balance(
            &mut state_machine,
            ICP_LEDGER_CANISTER_ID,
            &AccountBalanceArgs {
                account: AccountIdentifier::new(sns_canister_ids.governance.unwrap(), None)
                    .to_address(),
            },
        );
        let total_transferred = Tokens::from_tokens(
            planned_contribution_per_account * num_accounts + planned_cf_contribution,
        )
        .unwrap();
        let total_paid_in_transfer_fee =
            Tokens::from_e8s(DEFAULT_TRANSFER_FEE.get_e8s() * num_accounts);
        let expected_balance = (total_transferred - total_paid_in_transfer_fee).unwrap();
        assert_eq!(observed_balance, expected_balance);
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
            (Tokens::from_tokens(planned_cf_contribution).unwrap() - DEFAULT_TRANSFER_FEE).unwrap();
        assert_eq!(observed_balance, expected_balance);
    }

    // Step 3.2.2: Inspect SNS token balances.
    let community_fund_total_maturity: u64 = community_fund_neurons
        .iter()
        .map(|neuron| neuron.maturity_e8s_equivalent)
        .sum();

    let sns_tokens_per_icp_e8s = {
        let swap_state = swap_get_state(
            &mut state_machine,
            sns_canister_ids.swap.unwrap().try_into().unwrap(),
            &swap_pb::GetStateRequest {},
        );
        swap_state.derived.unwrap().sns_tokens_per_icp as f64
    };

    let expected_principal_id_to_gross_sns_token_participation_amount_e8s = community_fund_neurons
        .iter()
        .map(|nns_neuron| {
            let principal_id = nns_neuron.controller.unwrap();
            let icp_participation_e8s = COMMUNITY_FUND_INVESTMENT_E8S
                * nns_neuron.maturity_e8s_equivalent
                / community_fund_total_maturity;

            let expected_sns_tokens_e8s =
                (icp_participation_e8s as f64 * sns_tokens_per_icp_e8s) as u64;

            (principal_id, expected_sns_tokens_e8s)
        })
        .chain(accounts.iter().map(|principal_id| {
            let icp_participation_e8s = (planned_contribution_per_account * E8) as f64;
            let expected_sns_tokens_e8s = (icp_participation_e8s * sns_tokens_per_icp_e8s) as u64;
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

        for neuron in distributed_neurons {
            let subaccount = neuron.id.unwrap().subaccount().unwrap();

            let observed_balance = icrc1_balance_of(
                &mut state_machine,
                sns_canister_ids.ledger.unwrap().try_into().unwrap(),
                &Account {
                    owner: sns_canister_ids.governance.unwrap(),
                    subaccount: Some(subaccount),
                },
            )
            .0
            .to_u64()
            .unwrap();

            // Check that the cached balance of the neuron is equal to the neuron's account in the ledger
            assert_eq!(neuron.cached_neuron_stake_e8s, observed_balance);

            // Add to the actual total including the default transfer fee which was deducted
            // during swap committal
            actual_total_sns_tokens_e8s += observed_balance + DEFAULT_TRANSFER_FEE.get_e8s();
        }
        assert_eq!(actual_total_sns_tokens_e8s, *expected_sns_tokens_e8s);
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

        assert!(!sns_neurons.is_empty(), "{}", controller);
        let expected_source_neuron_id = community_fund_neuron.id.as_ref().map(|id| id.id);
        for sns_neuron in sns_neurons {
            assert_eq!(sns_neuron.source_nns_neuron_id, expected_source_neuron_id);
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

    // STEP 3.4: NNS governance is responsible for "settling" CF
    // contributions. In this case, that means that a total of 30 ICP was minted
    // and sent to the the default account of the SNS governance canister, 10
    // ICP coming from NNS neuron 1 and 20 ICP from neuron 2 (more accurately,
    // from their maturity).
    //
    // We already noticed the 30 ICP being added to the SNS governance
    // canister's (default) account in step 3.2.1. Therefore, all that remains
    // for us to verify is that the maturity of the two CF neurons have been
    // decreased by the right amounts.
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

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
    let planned_contribution_per_account = 70;
    let planned_cf_contribution = 30;
    let neuron_basket_count = 3;

    // Step 1: Prepare the world.
    let mut state_machine = StateMachine::new();
    let (
        sns_canister_ids,
        community_fund_neurons,
        fractional_developer_voting_power,
        dapp_canister_id,
    ) = begin_swap(
        &mut state_machine,
        &[],
        planned_contribution_per_account,
        planned_cf_contribution,
        neuron_basket_count,
    );

    let assert_cf_neuron_maturities =
        |state_machine: &mut StateMachine, withdrawal_amounts_e8s: &[u64]| {
            assert_eq!(community_fund_neurons.len(), withdrawal_amounts_e8s.len());

            for (original_neuron, withdrawal_amount_e8s) in community_fund_neurons
                .iter()
                .zip(withdrawal_amounts_e8s.iter())
            {
                let new_neuron = nns_governance_get_full_neuron(
                    state_machine,
                    original_neuron.controller.unwrap(),
                    original_neuron.id.as_ref().unwrap().id,
                )
                .unwrap();
                let expected_e8s = original_neuron.maturity_e8s_equivalent - withdrawal_amount_e8s;
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
    assert_cf_neuron_maturities(&mut state_machine, &[10 * E8, 20 * E8]);

    // Step 2: Run code under test.

    // TEST_USER2 participates, but not enough for the swap to succeed, even
    // after the open time window has passed.
    participate_in_swap(
        &mut state_machine,
        sns_canister_ids.swap.unwrap().try_into().unwrap(),
        *TEST_USER2_PRINCIPAL,
        Tokens::from_e8s(E8 - 1),
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
                )
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
        let expected_balance = ((*TEST_USER2_ORIGINAL_BALANCE_ICP - DEFAULT_TRANSFER_FEE).unwrap()
            - DEFAULT_TRANSFER_FEE)
            .unwrap();
        assert_eq!(observed_balance, expected_balance);
    }

    // Step 3.2.2: Inspect SNS token balance(s).
    {
        // Assert that the swap/sale canister's SNS token balance is unchanged.
        // Since this is the entire supply, we can be sure that nobody else has
        // any SNS tokens.
        let observed_balance = icrc1_balance_of(
            &mut state_machine,
            sns_canister_ids.ledger.unwrap().try_into().unwrap(),
            &ic_icrc1::Account {
                owner: sns_canister_ids.swap.unwrap(),
                subaccount: None,
            },
        )
        .0
        .to_u64()
        .unwrap();
        assert_eq!(observed_balance, 100 * neuron_basket_count * E8);
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
    assert_cf_neuron_maturities(&mut state_machine, &[0, 0]);
}

fn participate_in_swap(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    participant_principal_id: PrincipalId,
    amount: Tokens,
) {
    // First, transfer ICP to swap. Needs to go into a special subaccount...
    let subaccount = ledger_canister::Subaccount(ic_sns_swap::swap::principal_to_subaccount(
        &participant_principal_id,
    ));
    let request = Encode!(&TransferArgs {
        memo: Memo(0),
        amount,
        fee: DEFAULT_TRANSFER_FEE,
        from_subaccount: None,
        to: AccountIdentifier::new(swap_canister_id.into(), Some(subaccount)).to_address(),
        created_at_time: None,
    })
    .unwrap();
    state_machine
        .execute_ingress_as(
            participant_principal_id,
            ICP_LEDGER_CANISTER_ID,
            "transfer",
            request,
        )
        .unwrap();
    // ... then, swap must be notified about that transfer.
    state_machine
        .execute_ingress(
            swap_canister_id,
            "refresh_buyer_tokens",
            Encode!(&swap_pb::RefreshBuyerTokensRequest {
                buyer: participant_principal_id.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
}

fn nns_governance_make_proposal(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: nns_common_pb::NeuronId,
    proposal: &Proposal,
) -> manage_neuron_response::MakeProposalResponse {
    let result = state_test_helpers::nns_governance_make_proposal(
        state_machine,
        sender,
        neuron_id,
        proposal,
    );

    match result.command {
        Some(manage_neuron_response::Command::MakeProposal(response)) => response,
        _ => panic!("Response was not of type MakeProposal: {:#?}", result),
    }
}

fn nns_governance_get_full_neuron(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
    neuron_id: u64,
) -> Result<nns_governance_pb::Neuron, nns_governance_pb::GovernanceError> {
    let result = state_machine
        .execute_ingress_as(
            sender,
            NNS_GOVERNANCE_CANISTER_ID,
            "get_full_neuron",
            Encode!(&neuron_id).unwrap(),
        )
        .unwrap();

    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_full_neuron was rejected by the NNS governance canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, Result<nns_governance_pb::Neuron, nns_governance_pb::GovernanceError>).unwrap()
}

fn sns_root_register_dapp_canister(
    state_machine: &mut StateMachine,
    target_canister_id: CanisterId,
    request: &RegisterDappCanisterRequest,
) -> RegisterDappCanisterResponse {
    let result = state_machine
        .execute_ingress(
            target_canister_id,
            "register_dapp_canister",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "register_dapp_canister was rejected by the swap canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, RegisterDappCanisterResponse).unwrap()
}

fn sns_governance_list_neurons(
    state_machine: &mut StateMachine,
    sns_governance_canister_id: CanisterId,
    request: &ListNeurons,
) -> ListNeuronsResponse {
    let result = state_machine
        .execute_ingress(
            sns_governance_canister_id,
            "list_neurons",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, ListNeuronsResponse).unwrap()
}

fn icrc1_balance_of(
    state_machine: &mut StateMachine,
    target_canister_id: CanisterId,
    request: &ic_icrc1::Account,
) -> Nat {
    let result = state_machine
        .execute_ingress(
            target_canister_id,
            "icrc1_balance_of",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, Nat).unwrap()
}

fn ledger_account_balance(
    state_machine: &mut StateMachine,
    ledger_canister_id: CanisterId,
    request: &AccountBalanceArgs,
) -> Tokens {
    let result = state_machine
        .execute_ingress(
            ledger_canister_id,
            "account_balance",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, Tokens).unwrap()
}

fn swap_get_state(
    state_machine: &mut StateMachine,
    swap_canister_id: CanisterId,
    request: &swap_pb::GetStateRequest,
) -> swap_pb::GetStateResponse {
    let result = state_machine
        .execute_ingress(swap_canister_id, "get_state", Encode!(request).unwrap())
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!("get_state was rejected by the swap canister: {:#?}", reject)
        }
    };
    Decode!(&result, swap_pb::GetStateResponse).unwrap()
}

#[cfg(feature = "long_bench")]
#[test]
fn swap_load_test() {
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    let filename = "swap_load_test_results.csv";

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // Fail if the file already exists
        .open(filename)
        .unwrap();

    if let Err(e) = writeln!(file, "num_accounts,instructions_consumed_base,instructions_consumed_swapping,instructions_consumed_finalization,time_ms") {
        eprintln!("Couldn't write to file: {}", e);
    }

    let max_accounts = 100_000;
    let mut num_accounts = 10;
    loop {
        if num_accounts > max_accounts {
            break;
        }
        let SwapPerformanceResults {
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap,
        } = swap_n_accounts(num_accounts);

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(filename)
            .unwrap();

        if let Err(e) = writeln!(
            file,
            "{},{},{},{},{}",
            num_accounts,
            instructions_consumed_base,
            instructions_consumed_swapping,
            instructions_consumed_finalization,
            time_to_finalize_swap.as_millis()
        ) {
            eprintln!("Couldn't write to file: {}", e);
        }
        num_accounts = ((num_accounts as f64) * 2.0) as u64;
    }
}
