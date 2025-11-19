use crate::{
    governance::{
        EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX, Governance,
        test_data::CREATE_SERVICE_NERVOUS_SYSTEM,
    },
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{
        ExecuteNnsFunction, Followees, ManageNeuron, Motion, NetworkEconomics, NnsFunction,
        Proposal, ProposalRewardStatus, ProposalStatus, Topic, WaitForQuietState,
        manage_neuron::{Command, NeuronIdOrSubaccount, RegisterVote},
        proposal::Action,
    },
    test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger},
};

use assert_matches::assert_matches;
use core::panic;
use futures::FutureExt;
use ic_nervous_system_common::{E8, ONE_YEAR_SECONDS};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance_api::{
    Governance as ApiGovernance, ListProposalInfoRequest, ListProposalInfoResponse,
    NetworkEconomics as ApiNetworkEconomics, ProposalInfo, Vote, proposal::Action as ApiAction,
};
use ic_types::PrincipalId;
use lazy_static::lazy_static;
use maplit::hashmap;
use std::{collections::HashMap, sync::Arc};

lazy_static! {
    static ref PROPOSER: NeuronId = NeuronId::from_u64(1);
    static ref PROPOSER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(b"proposer");
    static ref NOW: u64 = 1_000;
    static ref PROPOSAL_VOTING_PERIOD_SECONDS: u64 = 100;
}

fn new_governance() -> Governance {
    Governance::new(
        ApiGovernance {
            economics: Some(ApiNetworkEconomics::with_default_values()),
            wait_for_quiet_threshold_seconds: *PROPOSAL_VOTING_PERIOD_SECONDS,
            ..Default::default()
        },
        Arc::new(MockEnvironment::new(Default::default(), *NOW)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    )
}

fn prepare_voting_eligible_neurons(governance: &mut Governance) {
    let proposer = NeuronBuilder::new_for_test(
        PROPOSER.id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: ONE_YEAR_SECONDS,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_controller(*PROPOSER_PRINCIPAL)
    .with_cached_neuron_stake_e8s(10_000 * E8)
    .build();

    governance.add_neuron(PROPOSER.id, proposer).unwrap();

    // Another neuron with a greater stake is added so that proposals don't get executed
    // immediately.
    let another_neuron_id = 2;
    assert!(another_neuron_id != PROPOSER.id);
    let another_neuron = NeuronBuilder::new_for_test(
        another_neuron_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: ONE_YEAR_SECONDS,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_cached_neuron_stake_e8s(20_000 * E8)
    .build();
    governance
        .add_neuron(another_neuron_id, another_neuron)
        .unwrap();
}

fn make_proposal(governance: &mut Governance, action: Action) {
    governance
        .make_proposal(
            &PROPOSER,
            &PROPOSER_PRINCIPAL,
            &Proposal {
                title: Some("Title".to_string()),
                summary: "Summary".to_string(),
                url: "".to_string(),
                action: Some(action),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();
}

fn governance_with_proposals(proposal_actions: Vec<Action>) -> Governance {
    let mut governance = new_governance();
    prepare_voting_eligible_neurons(&mut governance);

    for action in proposal_actions {
        make_proposal(&mut governance, action);
    }

    governance
}

#[test]
fn test_list_proposals_removes_execute_nns_function_payload() {
    let governance =
        governance_with_proposals(vec![Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::UninstallCode as i32,
            payload: vec![42; EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX + 1],
        })]);

    let response =
        governance.list_proposals(&PROPOSER_PRINCIPAL, ListProposalInfoRequest::default());

    let action = response.proposal_info[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        ApiAction::ExecuteNnsFunction(execute_nns_function) if execute_nns_function.payload.is_empty()
    );
}

#[test]
fn test_list_proposals_retains_execute_nns_function_payload() {
    let governance =
        governance_with_proposals(vec![Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::UninstallCode as i32,
            payload: vec![42; EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX],
        })]);

    let response =
        governance.list_proposals(&PROPOSER_PRINCIPAL, ListProposalInfoRequest::default());

    let action = response.proposal_info[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        ApiAction::ExecuteNnsFunction(execute_nns_function) if execute_nns_function.payload.len() == EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX
    );
}

#[test]
fn test_get_pending_proposals_removes_execute_nns_function_payload() {
    let governance =
        governance_with_proposals(vec![Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::UninstallCode as i32,
            payload: vec![42; EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX + 1],
        })]);

    let response = governance.get_pending_proposals(&PROPOSER_PRINCIPAL);

    let action = response[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        ApiAction::ExecuteNnsFunction(execute_nns_function) if execute_nns_function.payload.is_empty()
    );
}

fn proposal_ids(response: &ListProposalInfoResponse) -> Vec<u64> {
    response
        .proposal_info
        .iter()
        .map(|x| x.id.unwrap().id)
        .collect()
}

#[test]
fn test_list_proposals_paging() {
    let proposal_actions = (1..=100)
        .map(|_i| {
            Action::Motion(Motion {
                motion_text: "Motion text".to_string(),
            })
        })
        .collect::<Vec<_>>();
    let governance = governance_with_proposals(proposal_actions);

    // Listing proposals without a limit should return all 100 proposals.
    let response =
        governance.list_proposals(&PROPOSER_PRINCIPAL, ListProposalInfoRequest::default());
    assert_eq!(proposal_ids(&response), (1..=100).rev().collect::<Vec<_>>());

    // First page should return the last 50 proposals.
    let first_page = governance.list_proposals(
        &PROPOSER_PRINCIPAL,
        ListProposalInfoRequest {
            limit: 50,
            ..Default::default()
        },
    );
    assert_eq!(
        proposal_ids(&first_page),
        (51..=100).rev().collect::<Vec<_>>()
    );

    // Second page should return the first 50 proposals.
    let second_page = governance.list_proposals(
        &PROPOSER_PRINCIPAL,
        ListProposalInfoRequest {
            limit: 50,
            before_proposal: first_page.proposal_info.last().and_then(|x| x.id),
            ..Default::default()
        },
    );
    assert_eq!(
        proposal_ids(&second_page),
        (1..=50).rev().collect::<Vec<_>>()
    );

    // Third page should return an empty list.
    let third_page = governance.list_proposals(
        &PROPOSER_PRINCIPAL,
        ListProposalInfoRequest {
            limit: 50,
            before_proposal: second_page.proposal_info.last().and_then(|x| x.id),
            ..Default::default()
        },
    );
    assert_eq!(third_page.proposal_info, vec![]);
}

#[test]
fn test_filter_proposals_manage_neuron_proposal_visibility() {
    let mut governance = new_governance();
    let hot_key_of_manager = PrincipalId::new_self_authenticating(b"hot_key");
    let neuron_manager = NeuronBuilder::new_for_test(
        1,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: ONE_YEAR_SECONDS,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_controller(*PROPOSER_PRINCIPAL)
    .with_hot_keys(vec![hot_key_of_manager])
    .with_cached_neuron_stake_e8s(10_000 * E8)
    .build();
    governance.add_neuron(1, neuron_manager.clone()).unwrap();
    let managed_neuron = NeuronBuilder::new_for_test(
        2,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 0,
        },
    )
    .with_followees(hashmap! {
        Topic::NeuronManagement as i32 => Followees {
            // 2 followees are set so that the proposal is not instantly executed.
            followees: vec![neuron_manager.id(), NeuronId::from_u64(1000)],
        }
    })
    .build();
    governance.add_neuron(2, managed_neuron.clone()).unwrap();
    let some_other_neuron = NeuronBuilder::new_for_test(
        3,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: 0,
        },
    )
    .build();
    governance.add_neuron(3, some_other_neuron.clone()).unwrap();

    make_proposal(
        &mut governance,
        Action::ManageNeuron(Box::new(ManageNeuron {
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(managed_neuron.id())),
            id: None,
            command: Some(Command::RegisterVote(RegisterVote {
                proposal: Some(ProposalId { id: 1 }),
                vote: Vote::Yes as i32,
            })),
        })),
    );

    // The controller of the manager can see the proposal.
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &neuron_manager.controller(),
            ListProposalInfoRequest::default()
        )),
        vec![1]
    );

    // The hot key of the manager can see the proposal.
    assert_eq!(
        proposal_ids(
            &governance.list_proposals(&hot_key_of_manager, ListProposalInfoRequest::default())
        ),
        vec![1]
    );

    // The controller of the managed neuron cannot see the proposal.
    assert_eq!(
        governance
            .list_proposals(
                &managed_neuron.controller(),
                ListProposalInfoRequest::default()
            )
            .proposal_info,
        vec![]
    );

    // Some other neuron cannot see the proposal.
    assert_eq!(
        governance
            .list_proposals(
                &some_other_neuron.controller(),
                ListProposalInfoRequest::default()
            )
            .proposal_info,
        vec![]
    );

    // Some arbitrary principal cannot see the proposal.
    assert_eq!(
        governance
            .list_proposals(
                &PrincipalId::new_self_authenticating(b"some_principal"),
                ListProposalInfoRequest::default()
            )
            .proposal_info,
        vec![]
    );

    // With the `include_all_manage_neuron_proposals` flag, the proposal is visible to any principal.
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_self_authenticating(b"some_principal"),
            ListProposalInfoRequest {
                include_all_manage_neuron_proposals: Some(true),
                ..Default::default()
            }
        )),
        vec![1]
    );

    // The proposal can still be excluded through `exclude_topic`.
    assert_eq!(
        governance
            .list_proposals(
                &PrincipalId::new_self_authenticating(b"some_principal"),
                ListProposalInfoRequest {
                    exclude_topic: vec![Topic::NeuronManagement as i32],
                    include_all_manage_neuron_proposals: Some(true),
                    ..Default::default()
                }
            )
            .proposal_info,
        vec![]
    );
}

#[test]
fn test_filter_proposals_by_status() {
    let proposal_actions = (0..3)
        .map(|_i| {
            Action::Motion(Motion {
                motion_text: "Motion text".to_string(),
            })
        })
        .collect::<Vec<_>>();
    let mut governance = governance_with_proposals(proposal_actions);
    // Make sure the proposal ids are expected before using them to modifty the status.
    assert_eq!(
        proposal_ids(
            &governance.list_proposals(&PROPOSER_PRINCIPAL, ListProposalInfoRequest::default(),)
        ),
        vec![3, 2, 1]
    );

    let executed_proposal = governance.heap_data.proposals.get_mut(&2).unwrap();
    executed_proposal.decided_timestamp_seconds = 1;
    executed_proposal.executed_timestamp_seconds = 1;
    let failed_proposal = governance.heap_data.proposals.get_mut(&3).unwrap();
    failed_proposal.decided_timestamp_seconds = 1;
    failed_proposal.failed_timestamp_seconds = 1;

    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_status: vec![ProposalStatus::Open as i32],
                ..Default::default()
            },
        )),
        vec![1]
    );
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_status: vec![ProposalStatus::Executed as i32],
                ..Default::default()
            },
        )),
        vec![2]
    );
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_status: vec![ProposalStatus::Failed as i32],
                ..Default::default()
            },
        )),
        vec![3]
    );
}

#[test]
fn test_filter_proposals_by_reward_status() {
    let proposal_actions = (0..3)
        .map(|_i| {
            Action::Motion(Motion {
                motion_text: "Motion text".to_string(),
            })
        })
        .collect::<Vec<_>>();
    let mut governance = governance_with_proposals(proposal_actions);
    // Make sure the proposal ids are expected before using them to modifty the status.
    assert_eq!(
        proposal_ids(
            &governance.list_proposals(&PROPOSER_PRINCIPAL, ListProposalInfoRequest::default(),)
        ),
        vec![3, 2, 1]
    );

    let settled_proposal = governance.heap_data.proposals.get_mut(&1).unwrap();
    settled_proposal.decided_timestamp_seconds = *NOW - 1;
    settled_proposal.executed_timestamp_seconds = *NOW - 1;
    settled_proposal.reward_event_round = 1;
    let accept_votes_proposal = governance.heap_data.proposals.get_mut(&2).unwrap();
    accept_votes_proposal.decided_timestamp_seconds = *NOW - 1;
    accept_votes_proposal.executed_timestamp_seconds = *NOW - 1;
    let ready_to_settle_proposal = governance.heap_data.proposals.get_mut(&3).unwrap();
    ready_to_settle_proposal.wait_for_quiet_state = Some(WaitForQuietState {
        current_deadline_timestamp_seconds: *NOW - 1,
    });
    ready_to_settle_proposal.decided_timestamp_seconds = *NOW - 1;
    ready_to_settle_proposal.executed_timestamp_seconds = *NOW - 1;

    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_reward_status: vec![ProposalRewardStatus::Settled as i32],
                ..Default::default()
            },
        )),
        vec![1]
    );
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_reward_status: vec![ProposalRewardStatus::AcceptVotes as i32],
                ..Default::default()
            },
        )),
        vec![2]
    );
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                include_reward_status: vec![ProposalRewardStatus::ReadyToSettle as i32],
                ..Default::default()
            },
        )),
        vec![3]
    );
}

#[test]
fn test_filter_proposals_excluding_topics() {
    let governance = governance_with_proposals(vec![
        Action::Motion(Motion {
            motion_text: "Motion text".to_string(),
        }),
        Action::ManageNetworkEconomics(NetworkEconomics::default()),
        Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::HardResetNnsRootToVersion as i32,
            payload: Vec::new(),
        }),
    ]);

    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                exclude_topic: vec![Topic::Governance as i32],
                ..Default::default()
            },
        )),
        vec![3, 2]
    );
    assert_eq!(
        proposal_ids(&governance.list_proposals(
            &PrincipalId::new_anonymous(),
            ListProposalInfoRequest {
                exclude_topic: vec![
                    Topic::ProtocolCanisterManagement as i32,
                    Topic::NetworkEconomics as i32
                ],
                ..Default::default()
            },
        )),
        vec![1]
    );
}

fn proposal_ballot_votes(proposal_info: &ProposalInfo) -> HashMap<u64 /*neuron_id*/, i32 /*vote*/> {
    proposal_info
        .ballots
        .iter()
        .map(|(neuron_id, ballot)| (*neuron_id, ballot.vote))
        .collect()
}

#[test]
fn test_filter_proposal_ballots() {
    // Set up 2 neurons with different controllers and hot keys.
    let neuron_1_controller = *PROPOSER_PRINCIPAL;
    let neuron_2_controller = PrincipalId::new_self_authenticating(b"neuron_2_controller");
    let neuron_2_hot_key = PrincipalId::new_self_authenticating(b"neuron_2_hot_key");
    let mut governance = new_governance();
    let neuron_1 = NeuronBuilder::new_for_test(
        PROPOSER.id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: ONE_YEAR_SECONDS,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_controller(neuron_1_controller)
    .with_cached_neuron_stake_e8s(10_000 * E8)
    .build();
    governance
        .add_neuron(PROPOSER.id, neuron_1.clone())
        .unwrap();
    let neuron_2 = NeuronBuilder::new_for_test(
        2,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: ONE_YEAR_SECONDS,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_controller(neuron_2_controller)
    .with_hot_keys(vec![neuron_2_hot_key])
    .with_cached_neuron_stake_e8s(10_000 * E8)
    .build();
    governance.add_neuron(2, neuron_2.clone()).unwrap();

    // Create a proposal with votes from both neurons.
    make_proposal(
        &mut governance,
        Action::Motion(Motion {
            motion_text: "Motion text".to_string(),
        }),
    );

    assert_eq!(
        proposal_ballot_votes(
            &governance
                .list_proposals(&neuron_1_controller, ListProposalInfoRequest::default())
                .proposal_info[0]
        ),
        hashmap! {
                1 => Vote::Yes as i32,
        }
    );
    assert_eq!(
        proposal_ballot_votes(
            &governance
                .list_proposals(&neuron_2_controller, ListProposalInfoRequest::default())
                .proposal_info[0]
        ),
        hashmap! {
                2 => Vote::Unspecified as i32,
        }
    );
    assert_eq!(
        proposal_ballot_votes(
            &governance
                .list_proposals(&neuron_2_hot_key, ListProposalInfoRequest::default())
                .proposal_info[0]
        ),
        hashmap! {
                2 => Vote::Unspecified as i32,
        }
    );
}

fn create_service_nervous_system_has_logo(proposal_info: &ProposalInfo) -> bool {
    let action = proposal_info
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    if let ApiAction::CreateServiceNervousSystem(create_service_nervous_system) = action {
        create_service_nervous_system.logo.is_some()
    } else {
        panic!("Expected CreateServiceNervousSystem action")
    }
}

#[test]
fn test_omit_large_fields() {
    let governance = governance_with_proposals(vec![Action::CreateServiceNervousSystem(
        CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
    )]);

    let response = governance.list_proposals(
        &PrincipalId::new_anonymous(),
        ListProposalInfoRequest {
            omit_large_fields: Some(false),
            ..ListProposalInfoRequest::default()
        },
    );
    assert!(
        create_service_nervous_system_has_logo(&response.proposal_info[0]),
        "{response:?}"
    );

    let response = governance.list_proposals(
        &PrincipalId::new_anonymous(),
        ListProposalInfoRequest {
            omit_large_fields: None,
            ..ListProposalInfoRequest::default()
        },
    );
    assert!(
        create_service_nervous_system_has_logo(&response.proposal_info[0]),
        "{response:?}"
    );

    let response = governance.list_proposals(
        &PrincipalId::new_anonymous(),
        ListProposalInfoRequest {
            omit_large_fields: Some(true),
            ..ListProposalInfoRequest::default()
        },
    );
    assert!(
        !create_service_nervous_system_has_logo(&response.proposal_info[0]),
        "{response:?}"
    );
}
