use async_trait::async_trait;

use ic_nns_common::pb::v1::NeuronId;

use crate::governance::manage_neuron_request::neuron_mutation::burn_fees_mutation::BurnFeesMutation;
use crate::governance::manage_neuron_request::neuron_mutation::merge_neuron_mutation::MergeNeuronMutation;
use crate::governance::manage_neuron_request::neuron_mutation::{
    GovernanceMutationProxy, GovernanceNeuronMutation,
};
use crate::governance::manage_neuron_request::{ManageNeuronRequest, ManageNeuronRequestHandler};
use crate::governance::{Governance, LOG_PREFIX};
use crate::pb::v1::governance_error::ErrorType;
use crate::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use crate::pb::v1::manage_neuron_response::MergeResponse;
use crate::pb::v1::{
    manage_neuron, Governance as GovernanceProto, GovernanceError, ManageNeuronResponse,
    NeuronState, ProposalStatus,
};

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
}

#[async_trait]
impl ManageNeuronRequestHandler<manage_neuron::Merge>
    for ManageNeuronRequest<manage_neuron::Merge>
{
    fn validate_request(&self, gov: &Governance) -> Result<(), GovernanceError> {
        // Auth check
        let caller = self.caller;
        let source_id = self.source_neuron_id()?;

        let target_neuron = gov.get_neuron(&self.target_neuron_id)?;
        if !target_neuron.is_controlled_by(&caller) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                "Target neuron must be owned by the caller",
            ));
        }

        let source_neuron = gov.get_neuron(&source_id)?;
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

    fn pre_commit_validate(&self, gov: &Governance) -> Result<(), GovernanceError> {
        // NOTE: We do not do the validations in this method during validate_request because we want
        // to be able to simulate the process even for neurons that are in the middle of proposals.

        // Do not allow this command to be called for any neuron that is the
        // involved in an open proposal.
        fn involved_with_proposal(proto: &GovernanceProto, id: &NeuronId) -> bool {
            proto.proposals.values().any(|p| {
                p.status() == ProposalStatus::Open
                    && (p.proposer.as_ref() == Some(id)
                        || (p.is_manage_neuron()
                            && p.proposal.as_ref().map_or(false, |pr| {
                                pr.managed_neuron()
                                    == Some(NeuronIdOrSubaccount::NeuronId(id.clone()))
                            })))
            })
        }
        if involved_with_proposal(&gov.proto, &self.target_neuron_id)
            || involved_with_proposal(
                &gov.proto,
                self.manage_neuron_command_data
                    .source_neuron_id
                    .as_ref()
                    .unwrap(),
            )
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Cannot merge neurons that are involved in open proposals",
            ));
        }

        Ok(())
    }

    fn get_mutations(&self) -> Vec<Box<dyn GovernanceNeuronMutation>> {
        vec![
            Box::new(BurnFeesMutation::new(
                self.manage_neuron_command_data
                    .source_neuron_id
                    .clone()
                    .unwrap(),
            )),
            Box::new(MergeNeuronMutation::new(
                self.manage_neuron_command_data
                    .source_neuron_id
                    .clone()
                    .unwrap(),
                self.target_neuron_id.clone(),
            )),
        ]
    }

    fn build_response(
        &self,
        gov_proxy: &GovernanceMutationProxy,
    ) -> Result<ManageNeuronResponse, GovernanceError> {
        match gov_proxy {
            GovernanceMutationProxy::Committing(_) => {
                println!(
                    "{}Merged neuron {} into {} at {:?}",
                    LOG_PREFIX,
                    self.manage_neuron_command_data
                        .source_neuron_id
                        .as_ref()
                        .unwrap()
                        .id,
                    self.target_neuron_id.id,
                    gov_proxy.now()
                );
            }
            GovernanceMutationProxy::Simulating(_) => {
                println!(
                    "{}Simulated merging neuron {} into {} at {:?}",
                    LOG_PREFIX,
                    self.manage_neuron_command_data
                        .source_neuron_id
                        .as_ref()
                        .unwrap()
                        .id,
                    self.target_neuron_id.id,
                    gov_proxy.now()
                );
            }
        };

        let source_neuron = gov_proxy
            .get_neuron(
                self.manage_neuron_command_data
                    .source_neuron_id
                    .as_ref()
                    .unwrap(),
            )?
            .clone();
        let target_neuron = gov_proxy.get_neuron(&self.target_neuron_id)?.clone();

        let now = gov_proxy.now();
        let source_neuron_info = source_neuron.get_neuron_info(now);
        let target_neuron_info = target_neuron.get_neuron_info(now);

        Ok(ManageNeuronResponse::merge_response(MergeResponse {
            source_neuron: Some(source_neuron),
            target_neuron: Some(target_neuron),
            source_neuron_info: Some(source_neuron_info),
            target_neuron_info: Some(target_neuron_info),
        }))
    }
}
