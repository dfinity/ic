use crate::{
    governance::{Environment, LOG_PREFIX},
    pb::v1::{
        AddOrRemoveNodeProvider, ApproveGenesisKyc, CreateServiceNervousSystem,
        DeregisterKnownNeuron, FulfillSubnetRentalRequest, GovernanceError, InstallCode,
        KnownNeuron, ManageNeuron, Motion, NetworkEconomics, ProposalData, RewardNodeProvider,
        RewardNodeProviders, SelfDescribingProposalAction, StopOrStartCanister, Topic,
        UpdateCanisterSettings, Vote, governance_error::ErrorType, proposal::Action,
    },
    proposals::{
        execute_nns_function::ValidExecuteNnsFunction,
        self_describing::LocallyDescribableProposalAction,
    },
};
use ic_base_types::CanisterId;
use ic_cdk::println;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{PROTOCOL_CANISTER_IDS, SNS_AGGREGATOR_CANISTER_ID, SNS_WASM_CANISTER_ID};
use std::{collections::HashMap, sync::Arc};

pub mod call_canister;
pub mod create_service_nervous_system;
pub mod deregister_known_neuron;
pub mod execute_nns_function;
pub mod fulfill_subnet_rental_request;
pub mod install_code;
pub mod register_known_neuron;
pub mod self_describing;
pub mod stop_or_start_canister;
pub mod update_canister_settings;

/// Represents a valid proposal action that has passed initial validation.
/// Unlike the protobuf Action enum, this enum only includes non-obsolete actions.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum ValidProposalAction {
    ManageNeuron(Box<ManageNeuron>),
    ManageNetworkEconomics(NetworkEconomics),
    Motion(Motion),
    ExecuteNnsFunction(ValidExecuteNnsFunction),
    ApproveGenesisKyc(ApproveGenesisKyc),
    AddOrRemoveNodeProvider(AddOrRemoveNodeProvider),
    RewardNodeProvider(RewardNodeProvider),
    RewardNodeProviders(RewardNodeProviders),
    RegisterKnownNeuron(KnownNeuron),
    DeregisterKnownNeuron(DeregisterKnownNeuron),
    CreateServiceNervousSystem(CreateServiceNervousSystem),
    InstallCode(InstallCode),
    StopOrStartCanister(StopOrStartCanister),
    UpdateCanisterSettings(UpdateCanisterSettings),
    FulfillSubnetRentalRequest(FulfillSubnetRentalRequest),
}

impl TryFrom<Option<Action>> for ValidProposalAction {
    type Error = GovernanceError;

    fn try_from(action: Option<Action>) -> Result<Self, Self::Error> {
        let action = action.ok_or(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "Action is required",
        ))?;
        match action {
            Action::ManageNeuron(manage_neuron) => {
                Ok(ValidProposalAction::ManageNeuron(manage_neuron))
            }
            Action::ManageNetworkEconomics(network_economics) => Ok(
                ValidProposalAction::ManageNetworkEconomics(network_economics),
            ),
            Action::Motion(motion) => Ok(ValidProposalAction::Motion(motion)),
            Action::ExecuteNnsFunction(execute_nns_function) => {
                ValidExecuteNnsFunction::try_from(execute_nns_function)
                    .map(ValidProposalAction::ExecuteNnsFunction)
            }
            Action::ApproveGenesisKyc(approve_genesis_kyc) => {
                Ok(ValidProposalAction::ApproveGenesisKyc(approve_genesis_kyc))
            }
            Action::AddOrRemoveNodeProvider(add_or_remove_node_provider) => Ok(
                ValidProposalAction::AddOrRemoveNodeProvider(add_or_remove_node_provider),
            ),
            Action::RewardNodeProvider(reward_node_provider) => Ok(
                ValidProposalAction::RewardNodeProvider(reward_node_provider),
            ),
            Action::RewardNodeProviders(reward_node_providers) => Ok(
                ValidProposalAction::RewardNodeProviders(reward_node_providers),
            ),
            Action::RegisterKnownNeuron(register_known_neuron) => Ok(
                ValidProposalAction::RegisterKnownNeuron(register_known_neuron),
            ),
            Action::DeregisterKnownNeuron(deregister_known_neuron) => Ok(
                ValidProposalAction::DeregisterKnownNeuron(deregister_known_neuron),
            ),
            Action::CreateServiceNervousSystem(create_service_nervous_system) => Ok(
                ValidProposalAction::CreateServiceNervousSystem(create_service_nervous_system),
            ),
            Action::InstallCode(install_code) => Ok(ValidProposalAction::InstallCode(install_code)),
            Action::StopOrStartCanister(stop_or_start_canister) => Ok(
                ValidProposalAction::StopOrStartCanister(stop_or_start_canister),
            ),
            Action::UpdateCanisterSettings(update_canister_settings) => Ok(
                ValidProposalAction::UpdateCanisterSettings(update_canister_settings),
            ),
            Action::FulfillSubnetRentalRequest(fulfill_subnet_rental_request) => Ok(
                ValidProposalAction::FulfillSubnetRentalRequest(fulfill_subnet_rental_request),
            ),

            // Obsolete actions
            Action::SetDefaultFollowees(_) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Se tDefaultFollowees is obsolete",
            )),
            Action::OpenSnsTokenSwap(_) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "OpenSnsTokenSwap is obsolete",
            )),
            Action::SetSnsTokenSwapOpenTimeWindow(_) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "SetSnsTokenSwapOpenTimeWindow is obsolete",
            )),
        }
    }
}

impl ValidProposalAction {
    /// Computes a topic to a given proposal action at the creation time.
    pub fn topic(&self) -> Result<Topic, GovernanceError> {
        let topic = match self {
            ValidProposalAction::ManageNeuron(_) => Topic::NeuronManagement,
            ValidProposalAction::ManageNetworkEconomics(_) => Topic::NetworkEconomics,
            ValidProposalAction::Motion(_)
            | ValidProposalAction::RegisterKnownNeuron(_)
            | ValidProposalAction::DeregisterKnownNeuron(_) => Topic::Governance,
            ValidProposalAction::ExecuteNnsFunction(execute_nns_function) => {
                execute_nns_function.topic()
            }
            ValidProposalAction::ApproveGenesisKyc(_) => Topic::Kyc,
            ValidProposalAction::AddOrRemoveNodeProvider(_) => Topic::ParticipantManagement,
            ValidProposalAction::RewardNodeProvider(_)
            | ValidProposalAction::RewardNodeProviders(_) => Topic::NodeProviderRewards,
            ValidProposalAction::CreateServiceNervousSystem(_) => Topic::SnsAndCommunityFund,
            ValidProposalAction::InstallCode(install_code) => install_code.valid_topic()?,
            ValidProposalAction::StopOrStartCanister(stop_or_start) => {
                stop_or_start.valid_topic()?
            }
            ValidProposalAction::UpdateCanisterSettings(update_settings) => {
                update_settings.valid_topic()?
            }
            ValidProposalAction::FulfillSubnetRentalRequest(_) => Topic::SubnetRental,
        };
        Ok(topic)
    }

    /// Returns whether proposals with such an action should be allowed to
    /// be submitted when the heap growth potential is low.
    pub fn allowed_when_resources_are_low(&self) -> bool {
        match self {
            ValidProposalAction::ExecuteNnsFunction(execute_nns_function) => {
                execute_nns_function.allowed_when_resources_are_low()
            }
            ValidProposalAction::InstallCode(install_code) => {
                install_code.allowed_when_resources_are_low()
            }
            ValidProposalAction::UpdateCanisterSettings(update_settings) => {
                update_settings.allowed_when_resources_are_low()
            }
            _ => false,
        }
    }

    /// Returns the ManageNeuron action if this is a ManageNeuron proposal.
    pub fn manage_neuron(&self) -> Option<&ManageNeuron> {
        if let ValidProposalAction::ManageNeuron(manage_neuron) = self {
            Some(manage_neuron)
        } else {
            None
        }
    }

    /// Converts the proposal action to a self describing representation of itself. Note that it is
    /// async because we need to call `ic0.canister_metadata` to get the candid file of an external
    /// canister.
    pub async fn to_self_describing(
        &self,
        _env: Arc<dyn Environment>,
    ) -> Result<SelfDescribingProposalAction, GovernanceError> {
        match self {
            ValidProposalAction::Motion(motion) => Ok(motion.to_self_describing_action()),
            _ => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Self describing proposal actions are not supported for this proposal action yet.",
            )),
        }
    }
}

const SNS_RELATED_CANISTER_IDS: [&CanisterId; 2] =
    [&SNS_WASM_CANISTER_ID, &SNS_AGGREGATOR_CANISTER_ID];

pub(crate) fn topic_to_manage_canister(canister_id: &CanisterId) -> Topic {
    if PROTOCOL_CANISTER_IDS.contains(&canister_id) {
        Topic::ProtocolCanisterManagement
    } else if SNS_RELATED_CANISTER_IDS.contains(&canister_id) {
        Topic::ServiceNervousSystemManagement
    } else {
        Topic::ApplicationCanisterManagement
    }
}

pub(crate) fn invalid_proposal_error(reason: &str) -> GovernanceError {
    GovernanceError::new_with_message(
        ErrorType::InvalidProposal,
        format!("Proposal invalid because of {reason}"),
    )
}

/// Weighted voting power is just voting power * the proposal's (topic's) weight.
///
/// For example, suppose this returns ({42 => 3.14}, 99.9). This means that
/// neuron 42 should get 3.14/99.9 of today's reward purse.
///
/// Non-essential fact: Typically, result.1 is strictly greater than the sum of
/// the values in result.0. The main reason they are usually not equal is that
/// some neurons didn't vote. Another reason is that some neurons did not
/// "refresh" their voting power recently enough. Probably the former has more
/// of an impact on the sum of values in result.1.
pub fn sum_weighted_voting_power<'a>(
    proposals: impl Iterator<Item = &'a ProposalData>,
) -> (
    HashMap<
        NeuronId,
        f64, // exercised
    >,
    f64, // total
) {
    // Results.
    let mut neuron_id_to_exercised_weighted_voting_power: HashMap<NeuronId, f64> = HashMap::new();
    let mut total_weighted_voting_power = 0.0;

    for proposal in proposals {
        let reward_weight = proposal.topic().reward_weight();

        // This is used in lieu of total_potential_voting_power. That is, this
        // gets used if proposal does not have total_potential_voting_power.
        // This fall back will only be used during a short transition period
        // when there is a backlog of "old" proposals that were created without
        // total_potential_voting_power, but all new proposals have it. In the
        // case of such legacy proposals, their total potential voting power
        // would have been equal to this anyway, so this is a sound substitute
        // for total_potential_voting_power.
        let mut total_ballots_voting_power = 0;

        for (neuron_id, ballot) in &proposal.ballots {
            total_ballots_voting_power += ballot.voting_power;

            // Don't reward neurons that did not actually vote. (Whereas, ALL
            // eligible neurons get an "empty" ballot when the proposal is first
            // created. An "empty" ballot is one where the vote field is set to
            // Unspecified.)
            let vote = Vote::try_from(ballot.vote).unwrap_or_else(|err| {
                println!(
                    "{}ERROR: Unrecognized Vote {} in ballot by neuron {} \
                     on proposal {:?}: {:?}",
                    LOG_PREFIX, ballot.vote, neuron_id, proposal.id, err,
                );
                Vote::Unspecified
            });
            if !vote.eligible_for_rewards() {
                continue;
            }

            // Increment neuron.
            *neuron_id_to_exercised_weighted_voting_power
                .entry(NeuronId { id: *neuron_id })
                .or_insert(0.0) += (ballot.voting_power as f64) * reward_weight;
        }

        // Increment global total.
        total_weighted_voting_power += reward_weight
            * proposal
                .total_potential_voting_power
                .unwrap_or(total_ballots_voting_power) as f64;
    }

    (
        neuron_id_to_exercised_weighted_voting_power,
        total_weighted_voting_power,
    )
}
