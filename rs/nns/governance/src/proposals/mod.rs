use crate::{
    governance::{Environment, LOG_PREFIX},
    pb::v1::{
        ApproveGenesisKyc, BlessAlternativeGuestOsVersion, CreateServiceNervousSystem,
        DeregisterKnownNeuron, GovernanceError, InstallCode, KnownNeuron, LoadCanisterSnapshot,
        ManageNeuron, Motion, NetworkEconomics, ProposalData, RewardNodeProvider,
        RewardNodeProviders, SelfDescribingProposalAction, SelfDescribingValue,
        StopOrStartCanister, TakeCanisterSnapshot, Topic, UpdateCanisterSettings, Vote,
        governance_error::ErrorType, proposal::Action,
    },
    proposals::{
        add_or_remove_node_provider::ValidAddOrRemoveNodeProvider,
        execute_nns_function::ValidExecuteNnsFunction,
        fulfill_subnet_rental_request::ValidFulfillSubnetRentalRequest,
    },
};
use ic_base_types::CanisterId;
use ic_cdk::println;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{PROTOCOL_CANISTER_IDS, SNS_AGGREGATOR_CANISTER_ID, SNS_WASM_CANISTER_ID};
use std::{collections::HashMap, sync::Arc};

pub mod add_or_remove_node_provider;
pub mod bless_alternative_guest_os_version;
pub mod call_canister;
pub mod create_service_nervous_system;
pub mod deregister_known_neuron;
pub mod execute_nns_function;
pub mod fulfill_subnet_rental_request;
pub mod install_code;
pub mod load_canister_snapshot;
pub mod manage_neuron;
pub mod register_known_neuron;
pub mod self_describing;
pub mod stop_or_start_canister;
pub mod take_canister_snapshot;
pub mod update_canister_settings;

mod decode_candid_args_to_self_describing_value;

/// Represents a valid proposal action that has passed initial validation.
/// Unlike the protobuf Action enum, this enum only includes non-obsolete actions.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ValidProposalAction {
    ManageNeuron(Box<ManageNeuron>),
    ManageNetworkEconomics(NetworkEconomics),
    Motion(Motion),
    ExecuteNnsFunction(ValidExecuteNnsFunction),
    ApproveGenesisKyc(ApproveGenesisKyc),
    AddOrRemoveNodeProvider(ValidAddOrRemoveNodeProvider),
    RewardNodeProvider(RewardNodeProvider),
    RewardNodeProviders(RewardNodeProviders),
    RegisterKnownNeuron(KnownNeuron),
    DeregisterKnownNeuron(DeregisterKnownNeuron),
    CreateServiceNervousSystem(CreateServiceNervousSystem),
    InstallCode(InstallCode),
    StopOrStartCanister(StopOrStartCanister),
    UpdateCanisterSettings(UpdateCanisterSettings),
    FulfillSubnetRentalRequest(ValidFulfillSubnetRentalRequest),
    BlessAlternativeGuestOsVersion(BlessAlternativeGuestOsVersion),
    TakeCanisterSnapshot(TakeCanisterSnapshot),
    LoadCanisterSnapshot(LoadCanisterSnapshot),
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
            Action::AddOrRemoveNodeProvider(add_or_remove_node_provider) => {
                ValidAddOrRemoveNodeProvider::try_from(add_or_remove_node_provider)
                    .map(ValidProposalAction::AddOrRemoveNodeProvider)
            }
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
            Action::FulfillSubnetRentalRequest(fulfill_subnet_rental_request) => {
                ValidFulfillSubnetRentalRequest::try_from(fulfill_subnet_rental_request)
                    .map(ValidProposalAction::FulfillSubnetRentalRequest)
            }
            Action::BlessAlternativeGuestOsVersion(bless_alternative_guest_os_version) => {
                Ok(ValidProposalAction::BlessAlternativeGuestOsVersion(
                    bless_alternative_guest_os_version,
                ))
            }
            Action::TakeCanisterSnapshot(take_canister_snapshot) => Ok(
                ValidProposalAction::TakeCanisterSnapshot(take_canister_snapshot),
            ),
            Action::LoadCanisterSnapshot(load_canister_snapshot) => Ok(
                ValidProposalAction::LoadCanisterSnapshot(load_canister_snapshot),
            ),

            // Obsolete actions
            Action::SetDefaultFollowees(_) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "SetDefaultFollowees is obsolete",
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
            ValidProposalAction::BlessAlternativeGuestOsVersion(_) => Topic::NodeAdmin,
            ValidProposalAction::TakeCanisterSnapshot(take_canister_snapshot) => {
                take_canister_snapshot.valid_topic()?
            }
            ValidProposalAction::LoadCanisterSnapshot(load_canister_snapshot) => {
                load_canister_snapshot.valid_topic()?
            }
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
        env: Arc<dyn Environment>,
    ) -> Result<SelfDescribingProposalAction, GovernanceError> {
        let to_self_describing_action =
            |type_name: &str,
             type_description: &str,
             value: SelfDescribingValue|
             -> Result<SelfDescribingProposalAction, GovernanceError> {
                Ok(SelfDescribingProposalAction {
                    type_name: type_name.to_string(),
                    type_description: type_description.to_string(),
                    value: Some(value),
                })
            };

        match self {
            // ExecuteNnsFunction is the only case where we need to call `canister_metadata` to get
            // the candid file of an external canister, and hence it's the only one with `await`.
            ValidProposalAction::ExecuteNnsFunction(execute_nns_function) => {
                execute_nns_function.to_self_describing_action(env).await
            }

            ValidProposalAction::Motion(motion) => to_self_describing_action(
                "Motion",
                "Propose a text that can be adopted or rejected. \
                    No code is executed when a motion is adopted. An adopted motion should guide the future \
                    strategy of the Internet Computer ecosystem.",
                SelfDescribingValue::from(motion.clone()),
            ),
            ValidProposalAction::ApproveGenesisKyc(approve_genesis_kyc) => {
                to_self_describing_action(
                    "Approve Genesis KYC",
                    "Set GenesisKYC=true for batches of principals.\n\n\
                    When new neurons are created at Genesis, they have GenesisKYC=false. This restricts what \
                    actions they can perform. Specifically, they cannot spawn new neurons, and once their \
                    dissolve delays are zero, they cannot be disbursed and their balances unlocked to new \
                    accounts.\n\n\
                    (Special note: The Genesis event disburses all ICP in the form of neurons, \
                    whose principals must be KYCed. Consequently, all neurons created after Genesis have \
                    GenesisKYC=true set automatically since they must have been derived from balances that \
                    have already been KYCed.)",
                    SelfDescribingValue::from(approve_genesis_kyc.clone()),
                )
            }
            ValidProposalAction::AddOrRemoveNodeProvider(add_or_remove_node_provider) => {
                to_self_describing_action(
                    "Add or Remove Node Provider",
                    "Assign (or revoke) an identity to a node provider, \
                        associating key information regarding the legal person associated that should provide a \
                        way to uniquely identify it.",
                    SelfDescribingValue::from(add_or_remove_node_provider.clone()),
                )
            }
            ValidProposalAction::RegisterKnownNeuron(register_known_neuron) => {
                to_self_describing_action(
                    "Register Known Neuron",
                    "Register an existing neuron as a \"known neuron,\" \
                    giving it a name and an optional description, and adding it to the list of known neurons.",
                    SelfDescribingValue::from(register_known_neuron.clone()),
                )
            }
            ValidProposalAction::DeregisterKnownNeuron(deregister_known_neuron) => {
                to_self_describing_action(
                    "Deregister Known Neuron",
                    "Deregister an existing neuron as a \"known neuron\" \
                        and remove it from the list of known neurons.",
                    SelfDescribingValue::from(*deregister_known_neuron),
                )
            }
            ValidProposalAction::InstallCode(install_code) => to_self_describing_action(
                "Install Code",
                "Install, reinstall or upgrade code of a canister controlled by the NNS.",
                SelfDescribingValue::from(install_code.clone()),
            ),
            ValidProposalAction::StopOrStartCanister(stop_or_start_canister) => {
                to_self_describing_action(
                    "Stop or Start Canister",
                    "Stop or start a canister controlled by the NNS.",
                    SelfDescribingValue::from(stop_or_start_canister.clone()),
                )
            }
            ValidProposalAction::UpdateCanisterSettings(update_canister_settings) => {
                to_self_describing_action(
                    "Update Canister Settings",
                    "Update the settings of an NNS-controlled canister.",
                    SelfDescribingValue::from(update_canister_settings.clone()),
                )
            }
            ValidProposalAction::ManageNeuron(manage_neuron) => to_self_describing_action(
                "Manage Neuron",
                "Call a major function on a specified target neuron. \
                    Only the followees of the target neuron may vote on these proposals, which effectively \
                    provides the followees with control over the target neuron. This can provide a convenient \
                    and highly secure means for a team of individuals to manage an important neuron. For \
                    example, a neuron might hold a large balance, or belong to an organization of high \
                    repute, and be publicized so that many other neurons can follow its vote. In both cases, \
                    managing the private key of the principal securely could be problematic. (Either a single \
                    copy is held, which is very insecure and provides for a single party to take control, or \
                    a group of individuals must divide responsibility — for example, using threshold \
                    cryptography, which is complex and time consuming). To address this using this proposal \
                    type, the important neuron can be configured to follow the neurons controlled by \
                    individual members of a team. Now they can submit proposals to make the important neuron \
                    perform actions, which are adopted if and only if a majority of them vote to adopt. \
                    (Submitting such a proposal costs a small fee, to prevent denial-of-service attacks.) \
                    Nearly any command on the target neuron can be executed, including commands that change \
                    the follow rules, allowing the set of team members to be dynamic. Only the final step of \
                    dissolving the neuron once its dissolve delay reaches zero cannot be performed using this \
                    type of proposal, since this would allow control/\"ownership\" over the locked balances \
                    to be transferred. (The only exception to this rule applies to not-for-profit \
                    organizations, which may be allowed to dissolve their neurons without using the initial \
                    private key.) To prevent a neuron falling under the malign control of the principal's \
                    private key by accident, the private key can be destroyed so that the neuron can only be \
                    controlled by its followees, although this makes it impossible to subsequently unlock the \
                    balance.",
                SelfDescribingValue::from(manage_neuron.as_ref().clone()),
            ),
            ValidProposalAction::ManageNetworkEconomics(manage_network_economics) => {
                to_self_describing_action(
                    "Manage Network Economics",
                    "Update the network economics parameters that control \
                        various costs, rewards, and thresholds in the Network Nervous System, including proposal \
                        costs, neuron staking requirements, transaction fees, and voting power economics.",
                    SelfDescribingValue::from(manage_network_economics.clone()),
                )
            }
            ValidProposalAction::FulfillSubnetRentalRequest(fulfill_subnet_rental_request) => {
                to_self_describing_action(
                    "Subnet Rental Agreement",
                    "Create a rented subnet with a subnet rental \
                        agreement, based on a previously executed Subnet Rental Request proposal. The resulting \
                        subnet allows only the user of the rental agreement to create canisters, and canisters \
                        are not charged cycles for computation and storage.",
                    SelfDescribingValue::from(fulfill_subnet_rental_request.clone()),
                )
            }
            ValidProposalAction::CreateServiceNervousSystem(create_service_nervous_system) => {
                to_self_describing_action(
                    "Create Service Nervous System (SNS)",
                    "Create a new Service Nervous System (SNS).",
                    SelfDescribingValue::from(create_service_nervous_system.clone()),
                )
            }
            ValidProposalAction::BlessAlternativeGuestOsVersion(
                bless_alternative_guest_os_version,
            ) => to_self_describing_action(
                "Bless Alternative GuestOS Version",
                "Bless an alternative GuestOS version that can be \
                    used to recover the specified set of replicas that are in a non-functional state. This \
                    is a last resort recovery mechanism to be used when the replica cannot be upgraded \
                    through the regular mechanisms.",
                SelfDescribingValue::from(bless_alternative_guest_os_version.clone()),
            ),
            ValidProposalAction::TakeCanisterSnapshot(take_canister_snapshot) => {
                to_self_describing_action(
                    "Take Canister Snapshot",
                    "Create a snapshot of a canister controlled by the \
                    NNS. The snapshot saves the canister's current stable memory, heap memory, data, and \
                    Wasm module. The snapshot can be loaded later using a Load Canister Snapshot proposal, \
                    rolling the canister back to the state saved within the snapshot.",
                    SelfDescribingValue::from(take_canister_snapshot.clone()),
                )
            }
            ValidProposalAction::LoadCanisterSnapshot(load_canister_snapshot) => {
                to_self_describing_action(
                    "Load Canister Snapshot",
                    "Load a snapshot created by a Take Canister Snapshot \
                    proposal into a canister controlled by the NNS. Loading a snapshot replaces the \
                    canister's current stable memory, heap memory, data, and Wasm module with what was saved \
                    in the snapshot, rolling the canister back to that earlier state.",
                    SelfDescribingValue::from(load_canister_snapshot.clone()),
                )
            }
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
