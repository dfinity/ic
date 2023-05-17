use async_trait::async_trait;

use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;

use crate::governance::manage_neuron_request::neuron_mutation::{
    GovernanceMutationProxy, GovernanceNeuronMutation,
};
use crate::governance::Governance;
use crate::pb::v1::{GovernanceError, ManageNeuronResponse};

mod merge_neuron;
mod neuron_mutation;

pub async fn execute_manage_neuron<T>(
    gov: &mut Governance,
    manage_neuron_action: impl ManageNeuronRequestHandler<T>,
) -> Result<ManageNeuronResponse, GovernanceError> {
    manage_neuron_action.validate_request(gov)?;

    manage_neuron_action.pre_commit_validate(gov)?;

    let mut gov_proxy = GovernanceMutationProxy::new_committing(gov);
    for t in manage_neuron_action.get_mutations() {
        t.apply_all_mutations(&mut gov_proxy).await?;
    }

    manage_neuron_action.build_response(&gov_proxy)
}

pub async fn simulate_manage_neuron<T>(
    gov: &Governance,
    manage_neuron_action: impl ManageNeuronRequestHandler<T>,
) -> Result<ManageNeuronResponse, GovernanceError> {
    manage_neuron_action.validate_request(gov)?;

    let mut gov_proxy = GovernanceMutationProxy::new_simulating(gov);
    for t in manage_neuron_action.get_mutations() {
        t.apply_internal_mutations(&mut gov_proxy)?;
    }

    manage_neuron_action.build_response(&gov_proxy)
}

/// The logic for handling a ManageNeuronRequest
#[async_trait]
pub trait ManageNeuronRequestHandler<T> {
    /// Perform request validation, including authentication and authorization
    fn validate_request(&self, gov: &Governance) -> Result<(), GovernanceError>;

    /// Validation that is not needed for simulating a request but is required when executing.
    /// This is usually not needed.
    fn pre_commit_validate(&self, _: &Governance) -> Result<(), GovernanceError> {
        // Not normally needed, but can be overridden.
        Ok(())
    }

    /// Return the list of mutations to apply when executing or simulating the manage_neuron request
    fn get_mutations(&self) -> Vec<Box<dyn GovernanceNeuronMutation>>;

    /// Build a response for the request with the updated data
    fn build_response(
        &self,
        gov_proxy: &GovernanceMutationProxy,
    ) -> Result<ManageNeuronResponse, GovernanceError>;
}

/// An object representing a valid request about an existing neuron.
pub struct ManageNeuronRequest<T> {
    manage_neuron_command_data: T,
    target_neuron_id: NeuronId,
    caller: PrincipalId,
}

impl<T> ManageNeuronRequest<T> {
    pub fn new(command_data: T, id: NeuronId, caller: PrincipalId) -> Self {
        Self {
            manage_neuron_command_data: command_data,
            target_neuron_id: id,
            caller,
        }
    }
}
