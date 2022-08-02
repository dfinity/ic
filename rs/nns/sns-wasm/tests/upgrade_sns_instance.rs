use candid::{Decode, Encode};
use canister_test::Wasm;
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_ledger_sns_wasm, build_root_sns_wasm,
};
use ic_nns_test_utils::state_test_helpers::{
    query, setup_nns_canisters, update, update_with_sender,
};
use ic_nns_test_utils::{sns_wasm, state_test_helpers};
use ic_sns_governance::pb::v1::manage_neuron::claim_or_refresh::{By, MemoAndController};
use ic_sns_governance::pb::v1::manage_neuron::configure::Operation;
use ic_sns_governance::pb::v1::manage_neuron::{
    ClaimOrRefresh, Command, Configure, IncreaseDissolveDelay,
};

use ic_sns_governance::pb::v1::get_proposal_response;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    GetProposal, GetProposalResponse, GovernanceError, ManageNeuron, ManageNeuronResponse,
    NeuronId, Proposal, ProposalData, ProposalId, UpgradeSnsToNextVersion,
};
use ic_sns_governance::types::{DEFAULT_TRANSFER_FEE, E8S_PER_TOKEN};
use ic_sns_init::distributions::DEFAULT_NEURON_STAKING_NONCE;
use ic_sns_init::pb::v1::sns_init_payload::InitialTokenDistribution;
use ic_sns_init::pb::v1::{
    AirdropDistribution, DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution,
    SnsInitPayload, SwapDistribution, TreasuryDistribution,
};
use ic_sns_root::{
    CanisterStatusType, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
};
use ic_sns_wasm::pb::v1::{SnsCanisterIds, SnsCanisterType, SnsWasm};
use ic_sns_wasm::sns_wasm::vec_to_hash;
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;
use walrus::{Module, RawCustomSection};

#[test]
fn upgrade_root_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Root);
}

#[test]
fn upgrade_ledger_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Ledger);
}

#[test]
fn upgrade_governance_sns_canister_via_sns_wasms() {
    run_upgrade_test(SnsCanisterType::Governance);
}

fn run_upgrade_test(canister_type: SnsCanisterType) {
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .build();

    setup_nns_canisters(&machine, nns_init_payload);

    // Enough cycles for one SNS deploy. 50T
    let wallet_canister = state_test_helpers::set_up_universal_canister(
        &machine,
        Some(Cycles::new(50_000_000_000_000)),
    );

    sns_wasm::add_real_wasms_to_sns_wasms(&machine);

    // To get an SNS neuron, we airdrop our new tokens to this user.
    let user = PrincipalId::new_user_test_id(0);

    let payload = SnsInitPayload {
        transaction_fee_e8s: Some(DEFAULT_TRANSFER_FEE.get_e8s()),
        token_name: Some("An SNS Token".to_string()),
        token_symbol: Some("AST".to_string()),
        proposal_reject_cost_e8s: Some(E8S_PER_TOKEN),
        neuron_minimum_stake_e8s: Some(E8S_PER_TOKEN),
        min_participant_icp_e8s: Some(100),
        max_icp_e8s: Some(1_000_000_000),
        min_participants: Some(1),
        min_icp_e8s: Some(100),
        max_participant_icp_e8s: Some(1_000_000_000),
        fallback_controller_principal_ids: vec![user.to_string()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: Default::default(),
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 1_000_000_000,
                    initial_swap_amount_e8s: 1_000_000_000,
                }),
                airdrop_distribution: Some(AirdropDistribution {
                    airdrop_neurons: vec![NeuronDistribution {
                        controller: Some(user),
                        stake_e8s: 2_000_000_000,
                    }],
                }),
            },
        )),
        ..SnsInitPayload::with_valid_values_for_testing()
    };

    let response = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        payload,
        50_000_000_000_000,
    );

    let SnsCanisterIds {
        root,
        ledger: _,
        governance,
        swap: _,
    } = response.canisters.unwrap();

    let root = CanisterId::new(root.unwrap()).unwrap();
    let governance = CanisterId::new(governance.unwrap()).unwrap();

    // We want to get the original hash of the canister being upgraded.
    let status_summary = update(
        &machine,
        root,
        "get_sns_canisters_summary",
        Encode!(&GetSnsCanistersSummaryRequest {}).unwrap(),
    )
    .unwrap();
    let status_summary = Decode!(&status_summary, GetSnsCanistersSummaryResponse).unwrap();

    let original_hash = match canister_type {
        SnsCanisterType::Unspecified => panic!("Cannot be unspecified"),
        SnsCanisterType::Root => status_summary.root.unwrap().status.unwrap().module_hash(),
        SnsCanisterType::Governance => status_summary
            .governance
            .unwrap()
            .status
            .unwrap()
            .module_hash(),
        SnsCanisterType::Ledger => status_summary.ledger.unwrap().status.unwrap().module_hash(),
        SnsCanisterType::Swap => panic!("Swap can't be upgraded by SNS"),
    };

    let original_hash = vec_to_hash(original_hash.unwrap()).unwrap();

    // We add a new WASM to the SNS-WASMs (for whatever canister we want to test)
    let wasm_to_add = match canister_type {
        SnsCanisterType::Unspecified => panic!("Cannot be unspecified"),
        SnsCanisterType::Root => build_root_sns_wasm().wasm,
        SnsCanisterType::Governance => build_governance_sns_wasm().wasm,
        SnsCanisterType::Ledger => build_ledger_sns_wasm().wasm,
        SnsCanisterType::Swap => panic!("swap not supported via SNS-WASMs upgrade"),
    };
    let mut wasm_to_add = Module::from_buffer(&wasm_to_add).unwrap();
    let custom_section = RawCustomSection {
        name: "no op".into(),
        data: vec![1u8, 2u8, 3u8],
    };
    wasm_to_add.customs.add(custom_section);

    // We get our new WASM, which is functionally the same.
    let wasm_to_add = Wasm::from_bytes(wasm_to_add.emit_wasm());
    let sns_wasm_to_add = SnsWasm {
        wasm: wasm_to_add.bytes(),
        canister_type: canister_type.into(),
    };
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();

    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm::add_wasm(
        &machine,
        SNS_WASM_CANISTER_ID,
        sns_wasm_to_add,
        &new_wasm_hash,
    );

    // Make a proposal to upgrade (that is auto-executed) with the neuron for our user.
    let neuron_id = claim_staked_neuron(&machine, governance, user, Some(1_000_000));
    let sub_account = neuron_id.subaccount().unwrap();
    let proposal_id = make_proposal(
        &machine,
        governance,
        user,
        sub_account.as_slice(),
        Proposal {
            title: "Upgrade Canister.".into(),
            action: Some(Action::UpgradeSnsToNextVersion(UpgradeSnsToNextVersion {})),
            ..Default::default()
        },
    )
    .unwrap();

    // We create some blocks until the proposal has finished executing (machine.tick())
    let mut attempt_count = 0;
    let mut proposal_executed = false;
    while !proposal_executed {
        attempt_count += 1;
        machine.tick();

        let proposal = get_proposal(&machine, governance, proposal_id);
        proposal_executed = proposal.executed_timestamp_seconds != 0;
        assert!(attempt_count < 25, "proposal: {:?}", proposal);
    }

    // Now we attempt to get the status for the canister (but the canister may be updating or stopped)
    // which will cause the GetSnsCanistersSummaryRequest to fail.
    let mut attempt_count = 0;
    let status = loop {
        attempt_count += 1;
        machine.tick();
        // We have to wait for the canisters to restart....
        let status_summary = match update(
            &machine,
            root,
            "get_sns_canisters_summary",
            Encode!(&GetSnsCanistersSummaryRequest {}).unwrap(),
        ) {
            Ok(summary) => summary,
            Err(_) => continue,
        };

        let status_summary = Decode!(&status_summary, GetSnsCanistersSummaryResponse).unwrap();

        let status = match canister_type {
            SnsCanisterType::Unspecified => panic!("Cannot be unspecified"),
            SnsCanisterType::Root => status_summary.root.unwrap().status.unwrap(),
            SnsCanisterType::Governance => status_summary.governance.unwrap().status.unwrap(),
            SnsCanisterType::Ledger => status_summary.ledger.unwrap().status.unwrap(),
            SnsCanisterType::Swap => panic!("Swap can't be upgraded by SNS"),
        };

        // Stop waiting once it dapp has reached the Running state.
        if status.status() == CanisterStatusType::Running {
            break status;
        }

        assert!(attempt_count < 250, "status: {:?}", status);
    };

    // Our selected module has the new hash.
    assert_eq!(status.module_hash().unwrap(), new_wasm_hash.to_vec());
}

pub fn claim_staked_neuron(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    sender: PrincipalId,
    dissolve_delay: Option<u32>,
) -> NeuronId {
    // Find the neuron staked
    let to_subaccount = compute_neuron_staking_subaccount(sender, DEFAULT_NEURON_STAKING_NONCE);

    // Claim the neuron on the governance canister.
    let claim_response: ManageNeuronResponse = update_with_sender(
        machine,
        governance_canister_id,
        "manage_neuron",
        candid_one,
        ManageNeuron {
            subaccount: to_subaccount.to_vec(),
            command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                by: Some(By::MemoAndController(MemoAndController {
                    memo: DEFAULT_NEURON_STAKING_NONCE,
                    controller: None,
                })),
            })),
        },
        sender,
    )
    .expect("Error calling the manage_neuron API.");

    let neuron_id = match claim_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => {
            println!("User {} successfully claimed neuron", sender);

            response.refreshed_neuron_id.unwrap()
        }
        CommandResponse::Error(error) => panic!(
            "Unexpected error when claiming neuron for user {}: {}",
            sender, error
        ),
        _ => panic!(
            "Unexpected command response when claiming neuron for user {}.",
            sender
        ),
    };

    // Increase dissolve delay
    if let Some(dissolve_delay) = dissolve_delay {
        increase_dissolve_delay(
            machine,
            governance_canister_id,
            sender,
            &to_subaccount.0,
            dissolve_delay,
        );
    }

    neuron_id
}

fn increase_dissolve_delay(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    sender: PrincipalId,
    subaccount: &[u8],
    dissolve_delay: u32,
) {
    let payload = ManageNeuron {
        subaccount: subaccount.to_vec(),
        command: Some(Command::Configure(Configure {
            operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                additional_dissolve_delay_seconds: dissolve_delay,
            })),
        })),
    };
    let increase_response: ManageNeuronResponse = update_with_sender(
        machine,
        governance_canister_id,
        "manage_neuron",
        candid_one,
        payload,
        sender,
    )
    .expect("Error calling the manage_neuron API.");

    match increase_response.command.unwrap() {
        CommandResponse::Configure(_) => (),
        CommandResponse::Error(error) => panic!(
            "Unexpected error when increasing dissolve delay for user {}: {}",
            sender, error
        ),
        _ => panic!(
            "Unexpected command response when increasing dissolve delay for user {}.",
            sender
        ),
    };
}
/// Make a Governance proposal
pub fn make_proposal(
    machine: &StateMachine,
    sns_governance_canister_id: CanisterId,
    sender: PrincipalId,
    subaccount: &[u8],
    proposal: Proposal,
) -> Result<ProposalId, GovernanceError> {
    let manage_neuron_response: ManageNeuronResponse = update_with_sender(
        machine,
        sns_governance_canister_id,
        "manage_neuron",
        candid_one,
        ManageNeuron {
            subaccount: subaccount.to_vec(),
            command: Some(Command::MakeProposal(proposal)),
        },
        sender,
    )
    .expect("Error calling manage_neuron");

    match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(e) => Err(e),
        CommandResponse::MakeProposal(make_proposal_response) => {
            Ok(make_proposal_response.proposal_id.unwrap())
        }
        _ => panic!("Unexpected MakeProposal response"),
    }
}

/// Get a proposal
pub fn get_proposal(
    machine: &StateMachine,
    governance_canister_id: CanisterId,
    proposal_id: ProposalId,
) -> ProposalData {
    let get_proposal_response = query(
        machine,
        governance_canister_id,
        "get_proposal",
        Encode!(&GetProposal {
            proposal_id: Some(proposal_id),
        })
        .unwrap(),
    )
    .expect("Error calling get_proposal");

    let get_proposal_response = Decode!(&get_proposal_response, GetProposalResponse).unwrap();
    match get_proposal_response
        .result
        .expect("Empty get_proposal_response")
    {
        get_proposal_response::Result::Error(e) => {
            panic!("get_proposal error: {}", e);
        }
        get_proposal_response::Result::Proposal(proposal) => proposal,
    }
}
