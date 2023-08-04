use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{ExplosiveTokens, E8, ONE_TRILLION};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nervous_system_proto::pb::v1::{
    Canister, Duration, GlobalTimeOfDay, Image, Percentage, Tokens,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::pb::v1::{
    create_service_nervous_system::{
        governance_parameters::VotingRewardParameters,
        initial_token_distribution::{
            developer_distribution::NeuronDistribution, DeveloperDistribution, SwapDistribution,
            TreasuryDistribution,
        },
        swap_parameters::NeuronBasketConstructionParameters,
        GovernanceParameters, InitialTokenDistribution, LedgerParameters, SwapParameters,
    },
    manage_neuron_response,
    proposal::Action,
    CreateServiceNervousSystem, Proposal,
};
use ic_nns_test_utils::neuron_helpers::get_test_neurons_maturity_snapshot;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    sns_wasm::add_real_wasms_to_sns_wasms,
    state_test_helpers::{
        get_canister_status_from_root, list_deployed_snses, nns_governance_make_proposal,
        nns_wait_for_proposal_execution, set_controllers, set_up_universal_canister,
        setup_nns_canisters, sns_get_icp_treasury_account_balance, sns_governance_get_mode,
    },
};
use ic_sns_governance::pb::v1::governance::Mode::{Normal, PreInitializationSwap};
use ic_sns_governance::types::ONE_DAY_SECONDS;
use ic_sns_swap::pb::v1::Lifecycle;
use ic_sns_test_utils::state_test_helpers::{
    get_lifecycle, get_sns_canisters_summary, list_community_fund_participants, participate_in_swap,
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::DEFAULT_TRANSFER_FEE;
use lazy_static::lazy_static;
use maplit::hashmap;
use std::time::UNIX_EPOCH;

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
                minimum_participants: Some(5),
                minimum_icp: Some(Tokens::from_tokens(500_000)),
                maximum_icp: Some(Tokens::from_tokens(750_000)),
                minimum_participant_icp: Some(Tokens::from_tokens(1)),
                maximum_participant_icp: Some(Tokens::from_tokens(150_000)),
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: Some(5),
                    dissolve_delay_interval: Some(Duration::from_secs(7_890_000)), // 3 months
                }),
                confirmation_text: None,
                restricted_countries: None,
                start_time: GlobalTimeOfDay::from_hh_mm(12, 0).ok(),
                duration: Some(Duration::from_secs(60 * 60 * 24 * 7)),
                neurons_fund_investment_icp: Some(Tokens::from_tokens(100)),
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

    /// The developer principal used to propose and own the dapp being decentralized.
    pub developer_principal_id: PrincipalId,

    /// Principals that have ICP in their main ledger account and can be used in the test, most
    /// likely used to participate in the swap.
    pub funded_principals: Vec<PrincipalId>,
}

impl SnsInitializationFlowTestSetup {
    /// The default test setup for exercising the 1-proposal SNS Initialization flow
    pub fn default_setup() -> Self {
        let state_machine = StateMachine::new();

        let funded_principals: Vec<_> = (0..10).map(|i| PrincipalId::new_user_test_id(i)).collect();
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
                                ic_ledger_core::Tokens::from_e8s(200_000 * E8),
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
                neuron.maturity_e8s_equivalent = n * 25 * E8;
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
        state_machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION as u128);

        // Create a dapp_canister and add NNS Root as a controller of it
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
            developer_principal_id,
            funded_principals,
        }
    }

    pub fn propose_create_service_nervous_system(
        &mut self,
        sender: PrincipalId,
        neuron_id: NeuronId,
        create_service_nervous_system: &CreateServiceNervousSystem,
    ) -> ProposalId {
        let proposal = Proposal {
            title: Some("Proposal to create the SNS-2 ServiceNervousSystem".to_string()),
            summary: "Please do this, if anything just so that the test can pass.".to_string(),
            url: "".to_string(),
            action: Some(Action::CreateServiceNervousSystem(
                create_service_nervous_system.clone(),
            )),
        };

        let response =
            nns_governance_make_proposal(&mut self.state_machine, sender, neuron_id, &proposal);

        match response.command {
            Some(manage_neuron_response::Command::MakeProposal(make_proposal_response)) => {
                match make_proposal_response.proposal_id {
                    Some(proposal_id) => proposal_id,
                    None => panic!("Unable to find proposal ID!"),
                }
            }
            _ => panic!("Unable to submit the proposal: {:?}", response),
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

    pub fn await_for_finalize_swap_to_complete(&mut self, governance_canister_id: PrincipalId) {
        for _ in 0..100 {
            self.state_machine.tick();
            let sns_governance_mode = sns_governance_get_mode(
                &mut self.state_machine,
                canister_id_or_panic(Some(governance_canister_id)),
            )
            .unwrap();

            if sns_governance_mode == Normal as i32 {
                return;
            }
        }
        panic!(
            "SNS governance({}) never reached Normal mode during automatic swap finalization",
            governance_canister_id
        );
    }
}

#[test]
fn test_one_proposal_sns_initialization() {
    // Step 0: Setup the world and record its state
    let mut sns_initialization_flow_test = SnsInitializationFlowTestSetup::default_setup();

    let initial_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&mut sns_initialization_flow_test.state_machine);

    let initial_sns_wasm_cycles_balance = get_canister_status_from_root(
        &sns_initialization_flow_test.state_machine,
        SNS_WASM_CANISTER_ID,
    )
    .cycles;

    // There should be no SNSes deployed.
    assert_eq!(
        list_deployed_snses(&mut sns_initialization_flow_test.state_machine).instances,
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
    nns_wait_for_proposal_execution(
        &mut sns_initialization_flow_test.state_machine,
        proposal_id.id,
    );

    // Step 2: Inspect the newly created SNS

    // Assert the SNS was created and get its info
    let snses = list_deployed_snses(&mut sns_initialization_flow_test.state_machine).instances;
    assert_eq!(snses.len(), 1);
    let test_sns = snses.get(0).unwrap();

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
                .controllers,
            vec![test_sns.root_canister_id.unwrap()]
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
        &mut sns_initialization_flow_test.state_machine,
        canister_id_or_panic(test_sns.governance_canister_id),
    )
    .unwrap();
    assert_eq!(sns_governance_mode, PreInitializationSwap as i32);

    // Assert that the maturity was decremented from the NNS Neurons and properly recorded
    // in the swap canister.
    let current_nns_neurons_maturity_snapshot =
        get_test_neurons_maturity_snapshot(&mut sns_initialization_flow_test.state_machine);

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
            &mut sns_initialization_flow_test.state_machine,
            canister_id_or_panic(test_sns.swap_canister_id),
            participant,
            ExplosiveTokens::from_e8s(direct_participant_amount_e8s),
        );

        direct_participant_amounts.insert(participant, response.icp_accepted_participation_e8s);
    }

    // Assert the Swap lifecycle transitions to Committed in a heartbeat message
    sns_initialization_flow_test.state_machine.tick();
    let get_lifecycle_response = get_lifecycle(
        &sns_initialization_flow_test.state_machine,
        &canister_id_or_panic(test_sns.swap_canister_id),
    );
    assert_eq!(get_lifecycle_response.lifecycle(), Lifecycle::Committed);

    // Step 4: Verify the Swap auto-finalizes and the SNS is in the correct state
    sns_initialization_flow_test
        .await_for_finalize_swap_to_complete(test_sns.governance_canister_id.unwrap());

    // SNS Governance should now be in normal mode
    let sns_governance_mode = sns_governance_get_mode(
        &mut sns_initialization_flow_test.state_machine,
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
}
