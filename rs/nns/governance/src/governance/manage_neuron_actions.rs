use crate::governance::Governance;
use crate::pb::v1::governance_error::ErrorType;
use crate::pb::v1::{manage_neuron, GovernanceError, ManageNeuronResponse, Neuron, NeuronState};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;

/// The action to take for a ManageNeuron request
pub trait ManageNeuronAction {
    /// Perform request validation, including authentication and authorization
    fn validate_request(
        &self,
        gov: &Governance,
        caller: PrincipalId,
    ) -> Result<(), GovernanceError>;

    /// Calculate the changes that will happen
    fn calculate(&self) -> Result<Neuron, GovernanceError>;
    /// Commit the changes to Governance
    fn commit(&self, neuron: Neuron) -> Result<Neuron, GovernanceError>;

    /// Build the response from the committed changes to return to the caller
    fn build_response(&self, neuron: Neuron) -> Result<ManageNeuronResponse, GovernanceError>;

    /// Calculate the results and return a response without committing
    fn preview(
        &self,
        gov: &Governance,
        caller: PrincipalId,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        self.validate_request(gov, caller)
            .and_then(|_| self.calculate())
            .and_then(|neuron| self.build_response(neuron))
    }

    /// Calculate the results, commit them, and return the response.
    fn execute(
        &self,
        gov: &mut Governance,
        caller: PrincipalId,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        self.validate_request(gov, caller)
            .and_then(|_| self.calculate())
            .and_then(|neuron| self.commit(neuron))
            .and_then(|neuron| self.build_response(neuron))
    }
}

/// A Handler for our ManageNeuronAction for Merge neurons
pub struct MergeNeuronAction {
    merge_neuron: manage_neuron::Merge,
    target_neuron_id: NeuronId,
}

impl MergeNeuronAction {
    pub fn new(merge_neuron: manage_neuron::Merge, id: NeuronId) -> Self {
        Self {
            merge_neuron,
            target_neuron_id: id,
        }
    }
}

impl ManageNeuronAction for MergeNeuronAction {
    fn validate_request(
        &self,
        gov: &Governance,
        caller: PrincipalId,
    ) -> Result<(), GovernanceError> {
        // Auth check
        let source_id = self.merge_neuron.source_neuron_id.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "There was no source neuron id",
            )
        })?;

        let target_neuron = gov.get_neuron(&self.target_neuron_id)?;
        if !target_neuron.is_controlled_by(&caller) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Target neuron must be owned by the caller",
            ));
        }

        let source_neuron = gov.get_neuron(source_id)?;
        if !source_neuron.is_controlled_by(&caller) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Source neuron must be owned by the caller",
            ));
        }
        // Other validations

        // Assert neurons not same neuron
        if self.target_neuron_id.id == source_id.id {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Cannot merge a neuron into itself",
            ));
        }

        let now = gov.env.now();
        // Ensure both neurons are not spawning
        if source_neuron.state(now) == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Source neuron is spawning.",
            ));
        }

        if target_neuron.state(now) == NeuronState::Spawning {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Can't perform operation on neuron: Target neuron is spawning.",
            ));
        }

        // Check that fields match to avoid surprising behaviors
        if source_neuron.neuron_managers() != target_neuron.neuron_managers() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "ManageNeuron following of source and target does not match",
            ));
        }

        if source_neuron.kyc_verified != target_neuron.kyc_verified {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's kyc_verified field does not match target",
            ));
        }

        if source_neuron.not_for_profit != target_neuron.not_for_profit {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's not_for_profit field does not match target",
            ));
        }

        if source_neuron.is_community_fund_neuron() || target_neuron.is_community_fund_neuron() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that have been dedicated to the community fund",
            ));
        }

        Ok(())
    }

    fn calculate(&self) -> Result<Neuron, GovernanceError> {
        unimplemented!()
    }

    fn commit(&self, _neuron: Neuron) -> Result<Neuron, GovernanceError> {
        unimplemented!()
    }

    fn build_response(&self, _neuron: Neuron) -> Result<ManageNeuronResponse, GovernanceError> {
        unimplemented!()
    }
}
