use crate::{
    governance::{
        manage_neuron_request::{
            neuron_mutation::{
                burn_fees_mutation::BurnFeesMutation, merge_neuron_mutation::MergeNeuronMutation,
                GovernanceMutationProxy, GovernanceNeuronMutation,
            },
            ManageNeuronRequest, ManageNeuronRequestHandler,
        },
        Governance, HeapGovernanceData, LOG_PREFIX,
    },
    pb::v1::{
        governance_error::ErrorType, manage_neuron, manage_neuron::NeuronIdOrSubaccount,
        manage_neuron_response::MergeResponse, GovernanceError, ManageNeuronResponse, NeuronState,
        ProposalStatus,
    },
};
use async_trait::async_trait;
use ic_nns_common::pb::v1::NeuronId;

impl ManageNeuronRequest<manage_neuron::Merge> {
    fn source_neuron_id(&self) -> Result<NeuronId, GovernanceError> {
        self.manage_neuron_command_data
            .source_neuron_id
            .as_ref()
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "There was no source neuron id",
                )
            })
            .cloned()
    }

    fn target_neuron_id(&self) -> NeuronId {
        self.neuron_id
    }
}

#[async_trait]
impl ManageNeuronRequestHandler<manage_neuron::Merge>
    for ManageNeuronRequest<manage_neuron::Merge>
{
    fn validate_request(&self, gov: &Governance) -> Result<(), GovernanceError> {
        // Auth check
        let caller = self.caller;
        let source_id = self.source_neuron_id()?;
        let target_id = self.target_neuron_id();

        let target_neuron = gov.neuron_store.with_neuron(&target_id, |n| n.clone())?;
        if !target_neuron.is_authorized_to_simulate_manage_neuron(&caller) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Caller must be hotkey or controller of the target neuron",
            ));
        }

        let source_neuron = gov.neuron_store.with_neuron(&source_id, |n| n.clone())?;
        if !source_neuron.is_authorized_to_simulate_manage_neuron(&caller) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Caller must be hotkey or controller of the source neuron",
            ));
        }
        // Other validations

        // Assert neurons not same neuron
        if target_id.id == source_id.id {
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

        if source_neuron.is_a_neurons_fund_member() || target_neuron.is_a_neurons_fund_member() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that have been dedicated to the Neurons' Fund",
            ));
        }

        if source_neuron.state(now) != NeuronState::NotDissolving
            || target_neuron.state(now) != NeuronState::NotDissolving
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::RequiresNotDissolving,
                "Only two non-dissolving neurons with a dissolve \
                    delay greater than 0 can be merged.",
            ));
        }

        if source_neuron.neuron_type != target_neuron.neuron_type {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Source neuron's neuron_type field does not match target",
            ));
        }

        Ok(())
    }

    fn pre_commit_validate(&self, gov: &Governance) -> Result<(), GovernanceError> {
        // NOTE: We do not do the validations in this method during validate_request because we want
        // to be able to simulate the process even for neurons that are in the middle of proposals.

        // Do not allow this command to be called for any neuron that is the
        // involved in an open proposal.
        fn involved_with_proposal(proto: &HeapGovernanceData, id: &NeuronId) -> bool {
            proto.proposals.values().any(|p| {
                p.status() == ProposalStatus::Open
                    && (p.proposer.as_ref() == Some(id)
                        || (p.is_manage_neuron()
                            && p.proposal.as_ref().map_or(false, |pr| {
                                pr.managed_neuron() == Some(NeuronIdOrSubaccount::NeuronId(*id))
                            })))
            })
        }

        let caller = self.caller;
        let source_id = self.source_neuron_id()?;
        let target_id = self.target_neuron_id();

        let target_controlled_by_caller = gov
            .neuron_store
            .with_neuron(&target_id, |target| target.is_controlled_by(&caller))?;

        if !target_controlled_by_caller {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Target neuron must be owned by the caller",
            ));
        }

        let source_controlled_by_caller = gov
            .neuron_store
            .with_neuron(&source_id, |source| source.is_controlled_by(&caller))?;

        if !source_controlled_by_caller {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Source neuron must be owned by the caller",
            ));
        }

        if involved_with_proposal(&gov.heap_data, &target_id)
            || involved_with_proposal(&gov.heap_data, &source_id)
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that are involved in open proposals",
            ));
        }

        Ok(())
    }

    fn get_mutations(&self) -> Result<Vec<Box<dyn GovernanceNeuronMutation>>, GovernanceError> {
        let source_neuron_id = self.source_neuron_id()?;
        let target_neuron_id = self.target_neuron_id();
        Ok(vec![
            Box::new(BurnFeesMutation::new(source_neuron_id)),
            Box::new(MergeNeuronMutation::new(source_neuron_id, target_neuron_id)),
        ])
    }

    fn build_response(
        &self,
        gov_proxy: &GovernanceMutationProxy,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        let source_neuron_id = self.source_neuron_id()?;
        let target_neuron_id = self.target_neuron_id();

        match gov_proxy {
            GovernanceMutationProxy::Committing(_) => {
                println!(
                    "{}Merged neuron {} into {} at {:?}",
                    LOG_PREFIX,
                    source_neuron_id.id,
                    target_neuron_id.id,
                    gov_proxy.now()
                );
            }
            GovernanceMutationProxy::Simulating(_) => {
                println!(
                    "{}Simulated merging neuron {} into {} at {:?}",
                    LOG_PREFIX,
                    source_neuron_id.id,
                    target_neuron_id.id,
                    gov_proxy.now()
                );
            }
        };

        let source_neuron = gov_proxy.with_neuron(&source_neuron_id, |n| n.clone())?;
        let target_neuron = gov_proxy.with_neuron(&target_neuron_id, |n| n.clone())?;

        let now = gov_proxy.now();
        let source_neuron_info = source_neuron.get_neuron_info(now);
        let target_neuron_info = target_neuron.get_neuron_info(now);

        Ok(ManageNeuronResponse::merge_response(MergeResponse {
            source_neuron: Some(source_neuron.into()),
            target_neuron: Some(target_neuron.into()),
            source_neuron_info: Some(source_neuron_info),
            target_neuron_info: Some(target_neuron_info),
        }))
    }
}
