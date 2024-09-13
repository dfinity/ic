use crate::state_test_helpers::{list_neurons_by_principal, nns_governance_make_proposal};
use ic_base_types::PrincipalId;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_PRINCIPAL, TEST_NEURON_3_ID, TEST_NEURON_3_OWNER_PRINCIPAL,
};
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response::Command, ExecuteNnsFunction, MakeProposalRequest, Neuron, NnsFunction,
    ProposalActionRequest,
};
use ic_state_machine_tests::StateMachine;
use std::collections::HashMap;

const INVALID_NEURON_ID: u64 = 0;

#[derive(Clone, Debug)]
pub struct TestNeuronOwner {
    pub principal_id: PrincipalId,
    pub neuron_id: NeuronId,
}

pub fn get_unauthorized_neuron() -> TestNeuronOwner {
    TestNeuronOwner {
        neuron_id: NeuronId {
            id: TEST_NEURON_2_ID,
        },
        principal_id: *TEST_NEURON_3_OWNER_PRINCIPAL,
    }
}

pub fn get_nonexistent_neuron() -> TestNeuronOwner {
    TestNeuronOwner {
        neuron_id: NeuronId {
            id: INVALID_NEURON_ID,
        },
        principal_id: *TEST_NEURON_2_OWNER_PRINCIPAL,
    }
}

pub fn get_neuron_1() -> TestNeuronOwner {
    TestNeuronOwner {
        neuron_id: NeuronId {
            id: TEST_NEURON_1_ID,
        },
        principal_id: *TEST_NEURON_1_OWNER_PRINCIPAL,
    }
}

pub fn get_neuron_2() -> TestNeuronOwner {
    TestNeuronOwner {
        neuron_id: NeuronId {
            id: TEST_NEURON_2_ID,
        },
        principal_id: *TEST_NEURON_2_OWNER_PRINCIPAL,
    }
}

pub fn get_neuron_3() -> TestNeuronOwner {
    TestNeuronOwner {
        neuron_id: NeuronId {
            id: TEST_NEURON_3_ID,
        },
        principal_id: *TEST_NEURON_3_OWNER_PRINCIPAL,
    }
}

pub fn get_some_proposal() -> MakeProposalRequest {
    MakeProposalRequest {
        title: Some("<proposal created from initialization>".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ExecuteNnsFunction(
            ExecuteNnsFunction {
                nns_function: NnsFunction::NnsRootUpgrade as i32,
                payload: Vec::new(),
            },
        )),
    }
}

pub fn submit_proposal(state_machine: &StateMachine, neuron: &TestNeuronOwner) -> ProposalId {
    let proposal = get_some_proposal();
    let response = nns_governance_make_proposal(
        state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &proposal,
    )
    .command
    .expect("Making NNS proposal failed");

    if let Command::MakeProposal(resp) = response {
        ProposalId::from(resp.proposal_id.unwrap())
    } else {
        panic!("funny ManageNeuronResponse")
    }
}

pub fn get_all_test_neurons(state_machine: &StateMachine) -> Vec<Neuron> {
    let mut neurons = vec![];

    // Get Test Neuron 1
    neurons
        .extend(list_neurons_by_principal(state_machine, get_neuron_1().principal_id).full_neurons);

    // Get Test Neuron 2
    neurons
        .extend(list_neurons_by_principal(state_machine, get_neuron_2().principal_id).full_neurons);

    // Get Test Neuron 3
    neurons
        .extend(list_neurons_by_principal(state_machine, get_neuron_3().principal_id).full_neurons);

    neurons
}

pub fn get_test_neurons_maturity_snapshot(state_machine: &StateMachine) -> HashMap<NeuronId, u64> {
    get_all_test_neurons(state_machine)
        .iter()
        .map(|neuron| (neuron.id.unwrap(), neuron.maturity_e8s_equivalent))
        .collect()
}
