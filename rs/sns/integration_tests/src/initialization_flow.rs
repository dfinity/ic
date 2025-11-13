use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{E8, ExplosiveTokens, ONE_DAY_SECONDS, ONE_TRILLION};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_proto::pb::v1::{
    Canister, Duration, GlobalTimeOfDay, Image, Percentage, Tokens,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance_api::{
    CreateServiceNervousSystem, MakeProposalRequest, ProposalActionRequest,
    create_service_nervous_system::{
        GovernanceParameters, InitialTokenDistribution, LedgerParameters, SwapParameters,
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            DeveloperDistribution, SwapDistribution, TreasuryDistribution,
            developer_distribution::NeuronDistribution,
        },
        swap_parameters::NeuronBasketConstructionParameters,
    },
    manage_neuron_response,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::{get_neuron_1, get_test_neurons_maturity_snapshot},
    sns_wasm::add_real_wasms_to_sns_wasms,
    state_test_helpers::{
        get_canister_status_from_root, get_controllers, list_deployed_snses,
        nns_governance_make_proposal, nns_wait_for_proposal_execution,
        nns_wait_for_proposal_failure, set_controllers, set_up_universal_canister,
        setup_nns_canisters, sns_get_icp_treasury_account_balance, sns_governance_get_mode,
        sns_swap_get_auto_finalization_status,
    },
};
use ic_sns_governance::pb::v1::{
    ListNeurons,
    governance::Mode::{Normal, PreInitializationSwap},
};
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_test_utils::state_test_helpers::{
    get_lifecycle, get_sns_canisters_summary, list_community_fund_participants,
    participate_in_swap, sns_governance_list_neurons, state_machine_builder_for_sns_tests,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::DEFAULT_TRANSFER_FEE;
use lazy_static::lazy_static;
use maplit::hashmap;
use std::{
    collections::{BTreeSet, HashMap},
    time::UNIX_EPOCH,
};

// Valid images to be used in the CreateServiceNervousSystem proposal.
pub const IMAGE_1: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAD/DwIRAQ8HgT3GAAAAAElFTkSuQmCC";
pub const IMAGE_2: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAAD0lEQVQIHQEEAPv/AAAAAAAEAAEvUrSNAAAAAElFTkSuQmCC";

// TODO move this to a common lib and have SNS-W depend on it as well
pub const EXPECTED_SNS_CREATION_FEE: u128 = 180 * ONE_TRILLION as u128;

fn canister_id_or_panic(maybe_pid: Option<PrincipalId>) -> CanisterId {
    CanisterId::try_from(maybe_pid.unwrap()).unwrap()
}

lazy_static! {
    pub static ref CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL: CreateServiceNervousSystem =
        CreateServiceNervousSystem {
            name: Some("SNS-2".to_string()),
            description: Some("This is the second generic SNS to be created".to_string()),
            url: Some("https://sqbzf-5aaaa-aaaam-aavya-cai.ic0.app/".to_string()),
            logo: Some(Image {
                base64_encoding: Some(IMAGE_1.to_string()),
            }),
            // This will be filled in at test execution time
            dapp_canisters: vec![],
            fallback_controller_principal_ids: vec![*TEST_NEURON_1_OWNER_PRINCIPAL],
            initial_token_distribution: Some(InitialTokenDistribution {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: vec![NeuronDistribution {
                        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                        stake: Some(Tokens::from_e8s(230_000_000_000_000)), // 23%
                        memo: Some(0),
                        dissolve_delay: Some(Duration::from_secs(2_629_800)),
                        vesting_period: Some(Duration::from_secs(0)),
                    }],
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total: Some(Tokens::from_e8s(5_200_000_000_000_000)), // 52%
                }),
                swap_distribution: Some(SwapDistribution {
                    total: Some(Tokens::from_e8s(2_500_000_000_000_000)), // 25%
                }),
            }),
            ledger_parameters: Some(LedgerParameters {
            transaction_fee: Some(Tokens::from_e8s(100_000)),
                token_name: Some("SNS-2".to_string()),
                token_symbol: Some("SNS2".to_string()),
                token_logo: Some(Image {
                    base64_encoding: Some(IMAGE_2.to_string()),
                }),
            }),
            swap_parameters: Some(SwapParameters {
                minimum_participants: Some(4),
                minimum_direct_participation_icp: Some(Tokens::from_tokens(499_900)),
                maximum_direct_participation_icp: Some(Tokens::from_tokens(549_900)),
                minimum_participant_icp: Some(Tokens::from_tokens(20)),
                maximum_participant_icp: Some(Tokens::from_tokens(500_000)),
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: Some(3),
                    dissolve_delay_interval: Some(Duration::from_secs(7_890_000)), // 3 months
                }),
                confirmation_text: None,
                restricted_countries: None,
                start_time: GlobalTimeOfDay::from_hh_mm(12, 0).ok(),
                duration: Some(Duration::from_secs(60 * 60 * 24 * 7)),
                neurons_fund_participation: Some(true),

                // Deprecated fields must not be set.
                neurons_fund_investment_icp: None,
                minimum_icp: None,
                maximum_icp: None,
            }),
            governance_parameters: Some(GovernanceParameters {
                proposal_rejection_fee: Some(Tokens::from_e8s(1_000_000_000)),
                proposal_initial_voting_period: Some(Duration::from_secs(345_600)),
                proposal_wait_for_quiet_deadline_increase: Some(Duration::from_secs(86_400)),
                neuron_minimum_stake: Some(Tokens::from_tokens(1)),
                neuron_minimum_dissolve_delay_to_vote: Some(Duration::from_secs(2_629_800)), // 1 month
                neuron_maximum_dissolve_delay: Some(Duration::from_secs(252_288_000)), // 8 years
                neuron_maximum_dissolve_delay_bonus: Some(Percentage::from_percentage(100.0)),
                neuron_maximum_age_for_age_bonus: Some(Duration::from_secs(15_778_800)),
                neuron_maximum_age_bonus: Some(Percentage::from_percentage(25.0)),
                voting_reward_parameters: Some(VotingRewardParameters {
                    initial_reward_rate: Some(Percentage::from_percentage(2.5)),
                    final_reward_rate: Some(Percentage::from_percentage(2.5)),
                    reward_rate_transition_duration: Some(Duration::from_secs(0)),
                }),
            }),
        };
}

pub struct SnsInitializationFlowTestSetup {
    /// The StateMachine the test is being executed on.
    pub state_machine: StateMachine,

    /// The dapp canisters being decentralized with the SNS.
    pub dapp_canisters: Vec<CanisterId>,

    /// Principals that have ICP in their main ledger account and can be used in the test, most
    /// likely used to participate in the swap.
    pub funded_principals: Vec<PrincipalId>,
}

impl SnsInitializationFlowTestSetup {
    /// The default test setup for exercising the 1-proposal SNS Initialization flow
    pub fn default_setup() -> Self {
        let state_machine = state_machine_builder_for_sns_tests().build();

        let funded_principals: Vec<_> = (0..10).map(PrincipalId::new_user_test_id).collect();
        let developer_principal_id = *TEST_NEURON_1_OWNER_PRINCIPAL;

        let nns_init_payloads = {
            let mut builder = NnsInitPayloadsBuilder::new();
            builder
                .with_initial_invariant_compliant_mutations()
                .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
                .with_sns_wasm_access_controls(true)
                .with_ledger_accounts(
                    funded_principals
                        .iter()
                        .map(|principal_id| {
                            (
                                (*principal_id).into(),
                                ic_ledger_core::Tokens::from_e8s(1_000_000 * E8),
                            )
                        })
                        .collect(),
                )
                .with_test_neurons();

            // Enhance the standard neurons so that they all have some maturity, and
            // a couple of them are in the Neurons' Fund.
            let neurons = &mut builder.governance.proto.neurons;

            // Modify some of the test neurons so that they all have some
            // maturity, and some of them are in the Neurons' Fund. The
            // maturity of the NF neurons can later be used to participate in an
            // SNS token swap.
            let mut n = 1;
            for (i, neuron) in neurons.values_mut().enumerate() {
                neuron.maturity_e8s_equivalent = n * 250_000 * E8;
                n *= 3;

                if i < 2 {
                    neuron.joined_community_fund_timestamp_seconds = Some(1);
                }
            }
            builder.build()
        };

        // Setup the NNS canisters
        setup_nns_canisters(&state_machine, nns_init_payloads.clone());

        // Populate the SNS-W canister with SNS canister WASMs
        add_real_wasms_to_sns_wasms(&state_machine);

        // Add cycles to the SNS-W canister to deploy the SNS
        state_machine.add_cycles(SNS_WASM_CANISTER_ID, 2_000 * ONE_TRILLION as u128);

        // Create a dapp_canister and add NNS Root as a controller of it
        {
            // but first let's set up some phony canisters just to make sure the dapp canister's canister ID doesn't collide with a "real" canister
            set_up_universal_canister(&state_machine, None);
            set_up_universal_canister(&state_machine, None);
            set_up_universal_canister(&state_machine, None);
        }
        let dapp_canister = set_up_universal_canister(&state_machine, None);
        set_controllers(
            &state_machine,
            PrincipalId::new_anonymous(),
            dapp_canister,
            vec![ROOT_CANISTER_ID.get(), developer_principal_id],
        );

        Self {
            state_machine,
            dapp_canisters: vec![dapp_canister],
            funded_principals,
        }
    }

    pub fn propose_create_service_nervous_system(
        &mut self,
        sender: PrincipalId,
        neuron_id: NeuronId,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> ProposalId {
        let proposal = MakeProposalRequest {
            title: Some("Proposal to create the SNS-2 ServiceNervousSystem".to_string()),
            summary: "Please do this, if anything just so that the test can pass.".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::CreateServiceNervousSystem(
                create_service_nervous_system.clone(),
            )),
        };

        let response =
            nns_governance_make_proposal(&self.state_machine, sender, neuron_id, &proposal);

        match response.command {
            Some(manage_neuron_response::Command::MakeProposal(make_proposal_response)) => {
                match make_proposal_response.proposal_id {
                    Some(proposal_id) => proposal_id,
                    None => panic!("Unable to find proposal ID!"),
                }
            }
            _ => panic!("Unable to submit the proposal: {response:?}"),
        }
    }

    /// Return the time since unix epoch in seconds of the StateMachine
    pub fn now_seconds(&self) -> u64 {
        self.state_machine
            .time()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn advance_time_to_open_swap(&mut self, swap_canister_id: PrincipalId) {
        // Assert the lifecycle of the Swap canister is adopted
        let get_lifecycle_response = get_lifecycle(
            &self.state_machine,
            &canister_id_or_panic(Some(swap_canister_id)),
        );

        let time_until_swap_opens = core::time::Duration::from_secs(
            get_lifecycle_response
                .decentralization_sale_open_timestamp_seconds
                .unwrap()
                - self.now_seconds(),
        );
        self.state_machine.advance_time(time_until_swap_opens);
    }

    pub fn await_for_swap_auto_finalization_to_complete(&mut self, swap_canister_id: PrincipalId) {
        for _ in 0..100 {
            self.state_machine.tick();
            let auto_finalization_response = sns_swap_get_auto_finalization_status(
                &self.state_machine,
                canister_id_or_panic(Some(swap_canister_id)),
            );

            if auto_finalization_response
                .auto_finalize_swap_response
                .is_some()
            {
                return;
            }
        }
        panic!(
            "SNS Swap({swap_canister_id}) never had its finalization status set during automatic swap finalization"
        );
    }
}

#[test]
fn test_one_proposal_sns_initialization_success_with_neurons_fund_participation() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    let initial_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let initial_sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&sns_initialization_flow_test.state_machine).instances,
        vec![]
    );

    // Step 1: Submit and execute the proposal in the NNS

    // Create the proposal and splice in the dapp canisters
    let proposal = CreateServiceNervousSystem {
        dapp_canisters: sns_initialization_flow_test
            .dapp_canisters
            .iter()
            .map(|cid| Canister::new(cid.get()))
            .collect(),
        ..CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone()
    };

    // Submit the proposal! :)
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to be executed, and therefore the SNS to be deployed
    nns_wait_for_proposal_execution(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 2: Inspect the newly created SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 1);
    let test_sns = snses.first().unwrap();

    // Get the cycle balance of the SNS-W canister and verify it has been decremented
    let sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;
    assert_eq!(
        initial_sns_wasm_cycles_balance,
        sns_wasm_cycles_balance + Nat::from(EXPECTED_SNS_CREATION_FEE)
    );

    // Assert that the initial SNS ICP Treasury balance is 0
    let initial_icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );
    assert_eq!(initial_icp_treasury_balance.get_e8s(), 0);

    // Assert the dapp canister is now fully controlled by the SNS
    let root_summary = get_sns_canisters_summary(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.root_canister_id),
    );
    for (dapp_canister_summary, test_canister_id) in root_summary
        .dapps
        .iter()
        .zip(sns_initialization_flow_test.dapp_canisters.iter())
    {
        assert_eq!(
            dapp_canister_summary.canister_id.unwrap(),
            test_canister_id.get()
        );
        assert_eq!(
            dapp_canister_summary
                .status
                .as_ref()
                .unwrap()
                .settings
                .controllers
                .clone()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            vec![test_sns.root_canister_id.unwrap(), ROOT_CANISTER_ID.get()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    // Assert the lifecycle of the Swap canister is adopted
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Adopted);

    // Assert that the timestamp of the Swap is at least 24 hours in the future
    let now = sns_initialization_flow_test.now_seconds();
    assert!(
        get_lifecycle_response
            .decentralization_sale_open_timestamp_seconds
            .unwrap()
            >= now + ONE_DAY_SECONDS
    );

    // Assert the sns governance canister should be in PreInitializationSwap mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, PreInitializationSwap as i32);

    // Assert that the maturity was decremented from the NNS Neurons and properly recorded
    // in the swap canister.
    let current_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let cf_participants = list_community_fund_participants(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
        &PrincipalId::new_anonymous(),
        &100, // Limit
        &0,   // offset
    )
    .cf_participants;
    // With Matched Funding, this field remains unset set until the swap finalization phase.
    assert!(
        cf_participants.is_empty(),
        "Unexpected Neurons' Fund participants: {cf_participants:#?}"
    );

    // Step 3: Advance time to open the swap for participation, and then finish it
    sns_initialization_flow_test.advance_time_to_open_swap(test_sns.swap_canister_id.unwrap());

    // Make sure the opening can occur in the heartbeat
    sns_initialization_flow_test
        .state_machine
        .advance_time(std::time::Duration::from_secs(100));
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Open);

    // Participate in the swap so that it reaches success conditions. This means
    // reaching minimum_participants and max_icp.
    let min_participants = *proposal
        .swap_parameters
        .as_ref()
        .unwrap()
        .minimum_participants
        .as_ref()
        .unwrap();

    let direct_participant_amount_e8s = 150_000 * E8;
    let mut direct_participant_amounts = hashmap! {};
    for i in 0..min_participants as usize {
        let participant = sns_initialization_flow_test.funded_principals[i];

        let response = participate_in_swap(
            &sns_initialization_flow_test.state_machine,
            canister_id_or_panic(test_sns.swap_canister_id),
            participant,
            ExplosiveTokens::from_e8s(direct_participant_amount_e8s),
        );

        direct_participant_amounts.insert(participant, response.icp_accepted_participation_e8s);
    }

    // Assert the Swap lifecycle transitions to Committed after the next periodic task ran.
    sns_initialization_flow_test
        .state_machine
        .advance_time(std::time::Duration::from_secs(100));
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Committed);
    assert!(
        get_lifecycle_response
            .decentralization_swap_termination_timestamp_seconds
            .is_some()
    );

    // Step 4: Verify the Swap auto-finalizes and the SNS is in the correct state
    sns_initialization_flow_test
        .await_for_swap_auto_finalization_to_complete(test_sns.swap_canister_id.unwrap());

    // SNS Governance should now be in normal mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, Normal as i32);

    // Assert that the the SNS Treasury has had the correct amount of ICP deposited.
    let icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );

    let icp_transfer_fee_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
    // Each participant's ICP is transferred to the treasury account encountering the transfer
    // fee for each transaction
    let expected_direct_participation_amount_e8s: u64 = direct_participant_amounts
        .values()
        .map(|amount_icp_e8| amount_icp_e8 - icp_transfer_fee_e8s)
        .sum::<u64>();

    // The Neurons' Fund participants should be known by now.
    let cf_participants = list_community_fund_participants(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
        &PrincipalId::new_anonymous(),
        &100, // Limit
        &0,   // offset
    )
    .cf_participants;
    assert!(!cf_participants.is_empty());

    // Unlike the direct participants, since NNS Governance is sending minted ICP, there is no
    // transfer fee.
    let expected_cf_participation_amount_e8s: u64 = cf_participants
        .iter()
        .flat_map(|cf_participants| &cf_participants.cf_neurons)
        .map(|cf_neuron| cf_neuron.amount_icp_e8s)
        .sum::<u64>();

    assert_eq!(
        icp_treasury_balance.get_e8s(),
        expected_direct_participation_amount_e8s + expected_cf_participation_amount_e8s,
    );

    // Check that the Neurons' Fund maturity is conserved, i.e., the amount of maturity in each
    // Neurons' Fund neuron has decreased by how much that neuron participated in the swap (as
    // per the rules of Matched Funding).
    for cf_participant in &cf_participants {
        for cf_neuron in &cf_participant.cf_neurons {
            let pledged_icp = cf_neuron.amount_icp_e8s;
            let cf_neuron_nns_id = NeuronId {
                id: cf_neuron.nns_neuron_id,
            };

            let initial_maturity = initial_nns_neurons_maturity_snapshot
                .get(&cf_neuron_nns_id)
                .unwrap();

            let current_maturity = current_nns_neurons_maturity_snapshot
                .get(&cf_neuron_nns_id)
                .unwrap();

            assert_eq!(*current_maturity + pledged_icp, *initial_maturity);
        }
    }

    let cf_participants_principals = cf_participants
        .iter()
        .map(|cf_participant| cf_participant.try_get_controller().unwrap())
        .collect::<Vec<_>>();
    let neurons = sns_governance_list_neurons(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
        &ListNeurons::default(),
    )
    .neurons;
    let mut at_least_one_sns_neuron_is_nf_controlled = false;
    for neuron in neurons {
        if neuron.is_neurons_fund_controlled() {
            at_least_one_sns_neuron_is_nf_controlled = true;
            let from_neurons_fund = neuron.permissions.iter().any(|permission| {
                cf_participants_principals.contains(&permission.principal.unwrap())
            });
            assert!(
                from_neurons_fund,
                "Neuron permissions: {:?}",
                neuron.permissions
            );
        }
    }
    assert!(at_least_one_sns_neuron_is_nf_controlled);
}

#[test]
fn test_one_proposal_sns_initialization_success_without_neurons_fund_participation() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    let initial_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let initial_sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&sns_initialization_flow_test.state_machine).instances,
        vec![]
    );

    // Step 1: Submit and execute the proposal in the NNS

    let mut swap_parameters = CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL
        .swap_parameters
        .clone();

    // Disable Neurons' Fund participation
    if let Some(s) = &mut swap_parameters {
        s.neurons_fund_participation = Some(false);
        if s.minimum_icp.is_some() {
            s.minimum_direct_participation_icp = s.minimum_icp;
        }
        if s.maximum_icp.is_some() {
            s.maximum_direct_participation_icp = s.maximum_icp;
        }
    }

    // Create the proposal and splice in the dapp canisters and swap_parameters
    let proposal = CreateServiceNervousSystem {
        dapp_canisters: sns_initialization_flow_test
            .dapp_canisters
            .iter()
            .map(|cid| Canister::new(cid.get()))
            .collect(),
        swap_parameters,
        ..CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone()
    };

    // Submit the proposal! :)
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to be executed, and therefore the SNS to be deployed
    nns_wait_for_proposal_execution(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 2: Inspect the newly created SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 1);
    let test_sns = snses.first().unwrap();

    // Get the cycle balance of the SNS-W canister and verify it has been decremented
    let sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;
    assert_eq!(
        initial_sns_wasm_cycles_balance,
        sns_wasm_cycles_balance + Nat::from(EXPECTED_SNS_CREATION_FEE)
    );

    // Assert that the cf neurons have not had their maturity decremented.
    let post_execution_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);
    assert_eq!(
        initial_nns_neurons_maturity_snapshot,
        post_execution_nns_neurons_maturity_snapshot
    );

    // Assert that the initial SNS ICP Treasury balance is 0
    let initial_icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );
    assert_eq!(initial_icp_treasury_balance.get_e8s(), 0);

    // Assert the dapp canister is now fully controlled by the SNS
    let root_summary = get_sns_canisters_summary(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.root_canister_id),
    );
    for (dapp_canister_summary, test_canister_id) in root_summary
        .dapps
        .iter()
        .zip(sns_initialization_flow_test.dapp_canisters.iter())
    {
        assert_eq!(
            dapp_canister_summary.canister_id.unwrap(),
            test_canister_id.get()
        );
        assert_eq!(
            dapp_canister_summary
                .status
                .as_ref()
                .unwrap()
                .settings
                .controllers
                .clone()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            vec![test_sns.root_canister_id.unwrap(), ROOT_CANISTER_ID.get()]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    // Assert the lifecycle of the Swap canister is adopted
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Adopted);

    // Assert that the timestamp of the Swap is at least 24 hours in the future
    let now = sns_initialization_flow_test.now_seconds();
    assert!(
        get_lifecycle_response
            .decentralization_sale_open_timestamp_seconds
            .unwrap()
            >= now + ONE_DAY_SECONDS
    );

    // Assert the sns governance canister should be in PreInitializationSwap mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, PreInitializationSwap as i32);

    // There should be no cf_participants recorded in the Swap Canister
    let cf_participants = list_community_fund_participants(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
        &PrincipalId::new_anonymous(),
        &100, // Limit
        &0,   // offset
    )
    .cf_participants;
    assert_eq!(cf_participants, vec![]);

    // Step 3: Advance time to open the swap for participation, and then finish it
    sns_initialization_flow_test.advance_time_to_open_swap(test_sns.swap_canister_id.unwrap());

    // Make sure the opening can occur in the heartbeat
    sns_initialization_flow_test
        .state_machine
        .advance_time(std::time::Duration::from_secs(100));
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Open);

    // Participate in the swap so that it reaches success conditions. This means
    // reaching minimum_participants and max_icp.
    let min_participants = *proposal
        .swap_parameters
        .as_ref()
        .unwrap()
        .minimum_participants
        .as_ref()
        .unwrap();

    let direct_participant_amount_e8s = 150_000 * E8;
    let mut direct_participant_amounts = hashmap! {};
    for i in 0..min_participants as usize {
        let participant = sns_initialization_flow_test.funded_principals[i];

        let response = participate_in_swap(
            &sns_initialization_flow_test.state_machine,
            canister_id_or_panic(test_sns.swap_canister_id),
            participant,
            ExplosiveTokens::from_e8s(direct_participant_amount_e8s),
        );

        direct_participant_amounts.insert(participant, response.icp_accepted_participation_e8s);
    }

    // Assert the Swap lifecycle transitions to Committed after the next periodic task ran.
    sns_initialization_flow_test
        .state_machine
        .advance_time(std::time::Duration::from_secs(100));
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Committed);
    assert!(
        get_lifecycle_response
            .decentralization_swap_termination_timestamp_seconds
            .is_some()
    );

    // Step 4: Verify the Swap auto-finalizes and the SNS is in the correct state
    sns_initialization_flow_test
        .await_for_swap_auto_finalization_to_complete(test_sns.swap_canister_id.unwrap());

    // SNS Governance should now be in normal mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, Normal as i32);

    // Assert that the the SNS Treasury has had the correct amount of ICP deposited.
    let icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );

    let icp_transfer_fee_e8s = DEFAULT_TRANSFER_FEE.get_e8s();
    // Each participant's ICP is transferred to the treasury account encountering the transfer
    // fee for each transaction
    let expected_direct_participation_amount_e8s: u64 = direct_participant_amounts
        .values()
        .map(|amount_icp_e8| amount_icp_e8 - icp_transfer_fee_e8s)
        .sum::<u64>();

    assert_eq!(
        icp_treasury_balance.get_e8s(),
        expected_direct_participation_amount_e8s,
    );
}

#[test]
fn test_one_proposal_sns_initialization_fails_to_initialize_and_returns_dapps_and_neurons_fund() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    let initial_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let initial_sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&sns_initialization_flow_test.state_machine).instances,
        vec![]
    );

    let initial_dapp_canisters_control = sns_initialization_flow_test
        .dapp_canisters
        .iter()
        .map(|dapp_canister_id| {
            (
                *dapp_canister_id,
                get_canister_status_from_root(
                    &sns_initialization_flow_test.state_machine,
                    *dapp_canister_id,
                ),
            )
        })
        .collect::<HashMap<_, _>>();

    // Step 1: Submit and execute the proposal in the NNS

    // This dapp_canister_id will be included in the proposal but is not-controlled by the
    // NNS Root canister. This is how we will induce a deployment error without any
    // special privileges.
    let uncontrolled_dapp_canister_id = CanisterId::from_u64(9999);
    let mut dapp_canisters = sns_initialization_flow_test
        .dapp_canisters
        .iter()
        .map(|canister_id| Canister::new(canister_id.get()))
        .collect::<Vec<_>>();
    dapp_canisters.extend(vec![Canister::new(uncontrolled_dapp_canister_id.get())]);

    // Create the proposal and splice in the dapp canisters
    let proposal = CreateServiceNervousSystem {
        dapp_canisters,
        ..CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone()
    };

    // Submit the proposal! :)
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to fail due to SNS deployment failure
    nns_wait_for_proposal_failure(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 2: Inspect the system

    // Assert that no SNS was created
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 0);

    // Assert that the cf neurons have not had their maturity refunded.
    let post_execution_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);
    assert_eq!(
        initial_nns_neurons_maturity_snapshot,
        post_execution_nns_neurons_maturity_snapshot
    );

    // Get the cycle balance of the SNS-W canister and verify it has not been decremented
    let sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;
    assert_eq!(initial_sns_wasm_cycles_balance, sns_wasm_cycles_balance);

    // Assert that the dapps have been returned to the original controllers
    let post_execution_dapp_canisters_control = sns_initialization_flow_test
        .dapp_canisters
        .iter()
        .map(|dapp_canister_id| {
            (
                *dapp_canister_id,
                get_canister_status_from_root(
                    &sns_initialization_flow_test.state_machine,
                    *dapp_canister_id,
                ),
            )
        })
        .collect::<HashMap<_, _>>();

    assert_eq!(
        initial_dapp_canisters_control,
        post_execution_dapp_canisters_control
    );
}

#[test]
fn test_one_proposal_sns_initialization_failed_swap_returns_neurons_fund_and_dapps() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    let initial_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let initial_sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&sns_initialization_flow_test.state_machine).instances,
        vec![]
    );

    // Step 1: Submit and execute the proposal in the NNS

    // Create the proposal and splice in the dapp canisters
    let proposal = CreateServiceNervousSystem {
        dapp_canisters: sns_initialization_flow_test
            .dapp_canisters
            .iter()
            .map(|cid| Canister::new(cid.get()))
            .collect(),
        ..CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone()
    };

    // Submit the proposal! :)
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to be executed, and therefore the SNS to be deployed
    nns_wait_for_proposal_execution(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 2: Inspect the newly created SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 1);
    let test_sns = snses.first().unwrap();

    // Get the cycle balance of the SNS-W canister and verify it has been decremented
    let sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;
    assert_eq!(
        initial_sns_wasm_cycles_balance,
        sns_wasm_cycles_balance + Nat::from(EXPECTED_SNS_CREATION_FEE)
    );

    // Assert that the initial SNS ICP Treasury balance is 0
    let initial_icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );
    assert_eq!(initial_icp_treasury_balance.get_e8s(), 0);

    // Assert the dapp canister is now fully controlled by the SNS
    let root_summary = get_sns_canisters_summary(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.root_canister_id),
    );
    for (dapp_canister_summary, test_canister_id) in root_summary
        .dapps
        .iter()
        .zip(sns_initialization_flow_test.dapp_canisters.iter())
    {
        assert_eq!(
            dapp_canister_summary.canister_id.unwrap(),
            test_canister_id.get()
        );
        assert_eq!(
            dapp_canister_summary
                .status
                .as_ref()
                .unwrap()
                .settings
                .controllers
                .clone()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            vec![test_sns.root_canister_id.unwrap(), ROOT_CANISTER_ID.get()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
    }

    // Assert the lifecycle of the Swap canister is adopted
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Adopted);

    // Assert that the timestamp of the Swap is at least 24 hours in the future
    let now = sns_initialization_flow_test.now_seconds();
    assert!(
        get_lifecycle_response
            .decentralization_sale_open_timestamp_seconds
            .unwrap()
            >= now + ONE_DAY_SECONDS
    );

    // Assert the sns governance canister should be in PreInitializationSwap mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, PreInitializationSwap as i32);

    // Assert that the maturity was decremented from the NNS Neurons and properly recorded
    // in the swap canister.
    let current_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    let cf_participants = list_community_fund_participants(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
        &PrincipalId::new_anonymous(),
        &100, // Limit
        &0,   // offset
    )
    .cf_participants;

    for cf_participant in &cf_participants {
        for cf_neuron in &cf_participant.cf_neurons {
            let pledged_icp = cf_neuron.amount_icp_e8s;
            let cf_neuron_nns_id = NeuronId {
                id: cf_neuron.nns_neuron_id,
            };

            let initial_maturity = initial_nns_neurons_maturity_snapshot
                .get(&cf_neuron_nns_id)
                .unwrap();

            let current_maturity = current_nns_neurons_maturity_snapshot
                .get(&cf_neuron_nns_id)
                .unwrap();

            assert_eq!(*current_maturity + pledged_icp, *initial_maturity);
        }
    }

    // Step 3: Advance time to open the swap for participation, and then finish it
    sns_initialization_flow_test.advance_time_to_open_swap(test_sns.swap_canister_id.unwrap());

    // Make sure the opening can occur in the heartbeat
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns.swap_canister_id.unwrap()).unwrap(),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Open);

    // Fail the swap by contributing the max_icp without reaching the min_participants requirement
    let min_participants = 2;
    let direct_participant_amount_e8s = 500_000 * E8;
    let mut direct_participant_amounts = hashmap! {};
    for i in 0..min_participants as usize {
        let participant = sns_initialization_flow_test.funded_principals[i];

        let response = participate_in_swap(
            &sns_initialization_flow_test.state_machine,
            canister_id_or_panic(test_sns.swap_canister_id),
            participant,
            ExplosiveTokens::from_e8s(direct_participant_amount_e8s),
        );

        direct_participant_amounts.insert(participant, response.icp_accepted_participation_e8s);
    }

    // Assert the Swap lifecycle transitions to Committed after the next periodic task ran.
    sns_initialization_flow_test
        .state_machine
        .advance_time(std::time::Duration::from_secs(100));
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Aborted);

    // Step 4: Verify the Swap auto-finalizes and the SNS is in the correct state
    sns_initialization_flow_test
        .await_for_swap_auto_finalization_to_complete(test_sns.swap_canister_id.unwrap());

    // SNS Governance should now be in normal mode
    let sns_governance_mode = sns_governance_get_mode(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, PreInitializationSwap as i32);

    // Assert that the the SNS Treasury is still 0.
    let icp_treasury_balance = sns_get_icp_treasury_account_balance(
        &sns_initialization_flow_test.state_machine,
        test_sns.governance_canister_id.unwrap(),
    );
    assert_eq!(icp_treasury_balance.get_e8s(), 0);

    // Assert that the maturity was refunded to the NNS Neurons.
    let current_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&sns_initialization_flow_test.state_machine);

    assert_eq!(
        initial_nns_neurons_maturity_snapshot,
        current_nns_neurons_maturity_snapshot
    );

    // Assert that all dapps have been returned to the fallback_controllers
    let fallback_controller = CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL
        .fallback_controller_principal_ids
        .clone();

    for dapp_canister_id in sns_initialization_flow_test.dapp_canisters {
        let controllers = get_controllers(
            &sns_initialization_flow_test.state_machine,
            fallback_controller[0],
            dapp_canister_id,
        );

        assert_eq!(controllers, fallback_controller);
    }
}

#[test]
fn test_one_proposal_sns_initialization_supports_multiple_open_swaps() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&sns_initialization_flow_test.state_machine).instances,
        vec![]
    );

    // Step 1: Submit and execute the proposal in the NNS
    let proposal = CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL.clone();

    // Submit the proposal!
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to be executed, and therefore the SNS to be deployed
    nns_wait_for_proposal_execution(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 2: Inspect the newly created SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 1);
    let test_sns_1 = snses.first().unwrap();

    // Assert the lifecycle of the Swap canister is adopted
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns_1.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Adopted);

    // Assert that the timestamp of the Swap is at least 24 hours in the future
    let now = sns_initialization_flow_test.now_seconds();
    assert!(
        get_lifecycle_response
            .decentralization_sale_open_timestamp_seconds
            .unwrap()
            >= now + ONE_DAY_SECONDS
    );

    // Step 3: Advance time to open the swap for participation
    sns_initialization_flow_test.advance_time_to_open_swap(test_sns_1.swap_canister_id.unwrap());

    // Make sure the opening can occur after the next periodic task ran.
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns_1.swap_canister_id.unwrap()).unwrap(),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Open);

    // Assert that you can participate in the first Swap, but do not let it commit
    let participant = sns_initialization_flow_test.funded_principals[0];
    let response = participate_in_swap(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns_1.swap_canister_id),
        participant,
        ExplosiveTokens::from_e8s(20 * E8),
    );

    assert_eq!(response.icp_accepted_participation_e8s, 20 * E8);

    // Submit a copy of the same proposal. This should succeed since there is no deduping mechanism
    // for SNS content
    let proposal_id = sns_initialization_flow_test.propose_create_service_nervous_system(
        get_neuron_1().principal_id,
        get_neuron_1().neuron_id,
        &proposal,
    );

    // Wait for the proposal to be executed, and therefore the SNS to be deployed
    nns_wait_for_proposal_execution(&sns_initialization_flow_test.state_machine, proposal_id.id);

    // Step 4: Inspect the second SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 2);
    let test_sns_2 = snses.last().unwrap();

    // Assert the lifecycle of the Swap canister is adopted
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns_2.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Adopted);

    // Assert that the timestamp of the Swap is at least 24 hours in the future
    let now = sns_initialization_flow_test.now_seconds();
    assert!(
        get_lifecycle_response
            .decentralization_sale_open_timestamp_seconds
            .unwrap()
            >= now + ONE_DAY_SECONDS
    );

    // Step 5: Advance time to open the swap for participation, and then finish it
    sns_initialization_flow_test.advance_time_to_open_swap(test_sns_2.swap_canister_id.unwrap());

    // Make sure the opening can occur in the heartbeat
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &CanisterId::try_from(test_sns_2.swap_canister_id.unwrap()).unwrap(),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Open);

    // Assert that you can participate in the second Swap
    let participant = sns_initialization_flow_test.funded_principals[0];
    let response = participate_in_swap(
        &sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns_2.swap_canister_id),
        participant,
        ExplosiveTokens::from_e8s(20 * E8),
    );

    assert_eq!(response.icp_accepted_participation_e8s, 20 * E8);
}
