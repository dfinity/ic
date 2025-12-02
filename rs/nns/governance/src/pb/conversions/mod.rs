use crate::pb::proposal_conversions::{ProposalDisplayOptions, convert_proposal};
use crate::pb::v1 as pb;

use candid::{Int, Nat};
use ic_crypto_sha2::Sha256;
use ic_nns_governance_api as pb_api;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

impl From<pb::NodeProvider> for pb_api::NodeProvider {
    fn from(item: pb::NodeProvider) -> Self {
        let reward_account = item.reward_account.map(|account| {
            match icp_ledger::AccountIdentifier::try_from(&account) {
                // If it's valid, we make sure it has the checksum.
                Ok(account) => account.into_proto_with_checksum(),
                Err(_) => {
                    // If it fails, we return what is there, since this is going from internal
                    // to API, and there's no good way to recover at this point
                    account
                }
            }
        });
        Self {
            id: item.id,
            reward_account,
        }
    }
}
impl From<pb_api::NodeProvider> for pb::NodeProvider {
    fn from(item: pb_api::NodeProvider) -> Self {
        Self {
            id: item.id,
            reward_account: item.reward_account,
        }
    }
}

impl From<pb::UpdateNodeProvider> for pb_api::UpdateNodeProvider {
    fn from(item: pb::UpdateNodeProvider) -> Self {
        Self {
            reward_account: item.reward_account,
        }
    }
}
impl From<pb_api::UpdateNodeProvider> for pb::UpdateNodeProvider {
    fn from(item: pb_api::UpdateNodeProvider) -> Self {
        Self {
            reward_account: item.reward_account,
        }
    }
}

impl From<pb_api::DeregisterKnownNeuron> for pb::DeregisterKnownNeuron {
    fn from(item: pb_api::DeregisterKnownNeuron) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::DeregisterKnownNeuron> for pb_api::DeregisterKnownNeuron {
    fn from(item: pb::DeregisterKnownNeuron) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::BallotInfo> for pb_api::BallotInfo {
    fn from(item: pb::BallotInfo) -> Self {
        Self {
            proposal_id: item.proposal_id,
            vote: item.vote,
        }
    }
}
impl From<pb_api::BallotInfo> for pb::BallotInfo {
    fn from(item: pb_api::BallotInfo) -> Self {
        Self {
            proposal_id: item.proposal_id,
            vote: item.vote,
        }
    }
}

impl From<pb::NeuronStakeTransfer> for pb_api::NeuronStakeTransfer {
    fn from(item: pb::NeuronStakeTransfer) -> Self {
        Self {
            transfer_timestamp: item.transfer_timestamp,
            from: item.from,
            from_subaccount: item.from_subaccount,
            to_subaccount: item.to_subaccount,
            neuron_stake_e8s: item.neuron_stake_e8s,
            block_height: item.block_height,
            memo: item.memo,
        }
    }
}
impl From<pb_api::NeuronStakeTransfer> for pb::NeuronStakeTransfer {
    fn from(item: pb_api::NeuronStakeTransfer) -> Self {
        Self {
            transfer_timestamp: item.transfer_timestamp,
            from: item.from,
            from_subaccount: item.from_subaccount,
            to_subaccount: item.to_subaccount,
            neuron_stake_e8s: item.neuron_stake_e8s,
            block_height: item.block_height,
            memo: item.memo,
        }
    }
}

impl From<pb::Followees> for pb_api::neuron::Followees {
    fn from(item: pb::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}
impl From<pb_api::neuron::Followees> for pb::Followees {
    fn from(item: pb_api::neuron::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}

impl From<pb::Visibility> for pb_api::Visibility {
    fn from(item: pb::Visibility) -> Self {
        match item {
            pb::Visibility::Unspecified => pb_api::Visibility::Unspecified,
            pb::Visibility::Private => pb_api::Visibility::Private,
            pb::Visibility::Public => pb_api::Visibility::Public,
        }
    }
}

impl From<pb_api::Visibility> for pb::Visibility {
    fn from(item: pb_api::Visibility) -> Self {
        match item {
            pb_api::Visibility::Unspecified => pb::Visibility::Unspecified,
            pb_api::Visibility::Private => pb::Visibility::Private,
            pb_api::Visibility::Public => pb::Visibility::Public,
        }
    }
}

impl From<pb::ExecuteNnsFunction> for pb_api::ExecuteNnsFunction {
    fn from(item: pb::ExecuteNnsFunction) -> Self {
        Self {
            nns_function: item.nns_function,
            payload: item.payload,
        }
    }
}
impl From<pb_api::ExecuteNnsFunction> for pb::ExecuteNnsFunction {
    fn from(item: pb_api::ExecuteNnsFunction) -> Self {
        Self {
            nns_function: item.nns_function,
            payload: item.payload,
        }
    }
}

impl From<pb::Motion> for pb_api::Motion {
    fn from(item: pb::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}
impl From<pb_api::Motion> for pb::Motion {
    fn from(item: pb_api::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}

impl From<pb::ApproveGenesisKyc> for pb_api::ApproveGenesisKyc {
    fn from(item: pb::ApproveGenesisKyc) -> Self {
        Self {
            principals: item.principals,
        }
    }
}
impl From<pb_api::ApproveGenesisKyc> for pb::ApproveGenesisKyc {
    fn from(item: pb_api::ApproveGenesisKyc) -> Self {
        Self {
            principals: item.principals,
        }
    }
}

impl From<pb::AddOrRemoveNodeProvider> for pb_api::AddOrRemoveNodeProvider {
    fn from(item: pb::AddOrRemoveNodeProvider) -> Self {
        Self {
            change: item.change.map(|x| x.into()),
        }
    }
}
impl From<pb_api::AddOrRemoveNodeProvider> for pb::AddOrRemoveNodeProvider {
    fn from(item: pb_api::AddOrRemoveNodeProvider) -> Self {
        Self {
            change: item.change.map(|x| x.into()),
        }
    }
}

impl From<pb::add_or_remove_node_provider::Change> for pb_api::add_or_remove_node_provider::Change {
    fn from(item: pb::add_or_remove_node_provider::Change) -> Self {
        match item {
            pb::add_or_remove_node_provider::Change::ToAdd(v) => {
                pb_api::add_or_remove_node_provider::Change::ToAdd(v.into())
            }
            pb::add_or_remove_node_provider::Change::ToRemove(v) => {
                pb_api::add_or_remove_node_provider::Change::ToRemove(v.into())
            }
        }
    }
}
impl From<pb_api::add_or_remove_node_provider::Change> for pb::add_or_remove_node_provider::Change {
    fn from(item: pb_api::add_or_remove_node_provider::Change) -> Self {
        match item {
            pb_api::add_or_remove_node_provider::Change::ToAdd(v) => {
                pb::add_or_remove_node_provider::Change::ToAdd(v.into())
            }
            pb_api::add_or_remove_node_provider::Change::ToRemove(v) => {
                pb::add_or_remove_node_provider::Change::ToRemove(v.into())
            }
        }
    }
}

impl From<pb::RewardNodeProvider> for pb_api::RewardNodeProvider {
    fn from(item: pb::RewardNodeProvider) -> Self {
        Self {
            node_provider: item.node_provider.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
            reward_mode: item.reward_mode.map(|x| x.into()),
        }
    }
}
impl From<pb_api::RewardNodeProvider> for pb::RewardNodeProvider {
    fn from(item: pb_api::RewardNodeProvider) -> Self {
        Self {
            node_provider: item.node_provider.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
            reward_mode: item.reward_mode.map(|x| x.into()),
        }
    }
}

impl From<pb::reward_node_provider::RewardToNeuron>
    for pb_api::reward_node_provider::RewardToNeuron
{
    fn from(item: pb::reward_node_provider::RewardToNeuron) -> Self {
        Self {
            dissolve_delay_seconds: item.dissolve_delay_seconds,
        }
    }
}
impl From<pb_api::reward_node_provider::RewardToNeuron>
    for pb::reward_node_provider::RewardToNeuron
{
    fn from(item: pb_api::reward_node_provider::RewardToNeuron) -> Self {
        Self {
            dissolve_delay_seconds: item.dissolve_delay_seconds,
        }
    }
}

impl From<pb::reward_node_provider::RewardToAccount>
    for pb_api::reward_node_provider::RewardToAccount
{
    fn from(item: pb::reward_node_provider::RewardToAccount) -> Self {
        let to_account = item.to_account.map(|account| {
            match icp_ledger::AccountIdentifier::try_from(&account) {
                // If it's valid, we make sure it has the checksum.
                Ok(account) => account.into_proto_with_checksum(),
                Err(_) => {
                    // If it fails, we return what is there, since this is going from internal
                    // to API, and there's no good way to recover at this point
                    account
                }
            }
        });
        Self { to_account }
    }
}

impl From<pb_api::reward_node_provider::RewardToAccount>
    for pb::reward_node_provider::RewardToAccount
{
    fn from(item: pb_api::reward_node_provider::RewardToAccount) -> Self {
        Self {
            to_account: item.to_account,
        }
    }
}

impl From<pb::reward_node_provider::RewardMode> for pb_api::reward_node_provider::RewardMode {
    fn from(item: pb::reward_node_provider::RewardMode) -> Self {
        match item {
            pb::reward_node_provider::RewardMode::RewardToNeuron(v) => {
                pb_api::reward_node_provider::RewardMode::RewardToNeuron(v.into())
            }
            pb::reward_node_provider::RewardMode::RewardToAccount(v) => {
                pb_api::reward_node_provider::RewardMode::RewardToAccount(v.into())
            }
        }
    }
}
impl From<pb_api::reward_node_provider::RewardMode> for pb::reward_node_provider::RewardMode {
    fn from(item: pb_api::reward_node_provider::RewardMode) -> Self {
        match item {
            pb_api::reward_node_provider::RewardMode::RewardToNeuron(v) => {
                pb::reward_node_provider::RewardMode::RewardToNeuron(v.into())
            }
            pb_api::reward_node_provider::RewardMode::RewardToAccount(v) => {
                pb::reward_node_provider::RewardMode::RewardToAccount(v.into())
            }
        }
    }
}

impl From<pb::RewardNodeProviders> for pb_api::RewardNodeProviders {
    fn from(item: pb::RewardNodeProviders) -> Self {
        Self {
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            use_registry_derived_rewards: item.use_registry_derived_rewards,
        }
    }
}
impl From<pb_api::RewardNodeProviders> for pb::RewardNodeProviders {
    fn from(item: pb_api::RewardNodeProviders) -> Self {
        Self {
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            use_registry_derived_rewards: item.use_registry_derived_rewards,
        }
    }
}

impl From<pb::SetDefaultFollowees> for pb_api::SetDefaultFollowees {
    fn from(item: pb::SetDefaultFollowees) -> Self {
        Self {
            default_followees: item
                .default_followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}
impl From<pb_api::SetDefaultFollowees> for pb::SetDefaultFollowees {
    fn from(item: pb_api::SetDefaultFollowees) -> Self {
        Self {
            default_followees: item
                .default_followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<pb::SetSnsTokenSwapOpenTimeWindow> for pb_api::SetSnsTokenSwapOpenTimeWindow {
    fn from(item: pb::SetSnsTokenSwapOpenTimeWindow) -> Self {
        Self {
            swap_canister_id: item.swap_canister_id,
            request: item.request,
        }
    }
}
impl From<pb_api::SetSnsTokenSwapOpenTimeWindow> for pb::SetSnsTokenSwapOpenTimeWindow {
    fn from(item: pb_api::SetSnsTokenSwapOpenTimeWindow) -> Self {
        Self {
            swap_canister_id: item.swap_canister_id,
            request: item.request,
        }
    }
}

impl From<pb_api::Proposal> for pb::Proposal {
    fn from(item: pb_api::Proposal) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
            self_describing_action: None,
        }
    }
}
impl From<pb_api::MakeProposalRequest> for pb::Proposal {
    fn from(item: pb_api::MakeProposalRequest) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
            self_describing_action: None,
        }
    }
}

impl From<pb_api::proposal::Action> for pb::proposal::Action {
    fn from(item: pb_api::proposal::Action) -> Self {
        match item {
            pb_api::proposal::Action::ManageNeuron(v) => {
                pb::proposal::Action::ManageNeuron(Box::new((*v).into()))
            }
            pb_api::proposal::Action::ManageNetworkEconomics(v) => {
                pb::proposal::Action::ManageNetworkEconomics(v.into())
            }
            pb_api::proposal::Action::Motion(v) => pb::proposal::Action::Motion(v.into()),
            pb_api::proposal::Action::ExecuteNnsFunction(v) => {
                pb::proposal::Action::ExecuteNnsFunction(v.into())
            }
            pb_api::proposal::Action::ApproveGenesisKyc(v) => {
                pb::proposal::Action::ApproveGenesisKyc(v.into())
            }
            pb_api::proposal::Action::AddOrRemoveNodeProvider(v) => {
                pb::proposal::Action::AddOrRemoveNodeProvider(v.into())
            }
            pb_api::proposal::Action::RewardNodeProvider(v) => {
                pb::proposal::Action::RewardNodeProvider(v.into())
            }
            pb_api::proposal::Action::SetDefaultFollowees(v) => {
                pb::proposal::Action::SetDefaultFollowees(v.into())
            }
            pb_api::proposal::Action::RewardNodeProviders(v) => {
                pb::proposal::Action::RewardNodeProviders(v.into())
            }
            pb_api::proposal::Action::RegisterKnownNeuron(v) => {
                pb::proposal::Action::RegisterKnownNeuron(v.into())
            }
            pb_api::proposal::Action::DeregisterKnownNeuron(v) => {
                pb::proposal::Action::DeregisterKnownNeuron(v.into())
            }
            pb_api::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v) => {
                pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.into())
            }
            pb_api::proposal::Action::OpenSnsTokenSwap(v) => {
                pb::proposal::Action::OpenSnsTokenSwap(v.into())
            }
            pb_api::proposal::Action::CreateServiceNervousSystem(v) => {
                pb::proposal::Action::CreateServiceNervousSystem(v.into())
            }
            pb_api::proposal::Action::InstallCode(v) => pb::proposal::Action::InstallCode(v.into()),
            pb_api::proposal::Action::StopOrStartCanister(v) => {
                pb::proposal::Action::StopOrStartCanister(v.into())
            }
            pb_api::proposal::Action::UpdateCanisterSettings(v) => {
                pb::proposal::Action::UpdateCanisterSettings(v.into())
            }
            pb_api::proposal::Action::FulfillSubnetRentalRequest(v) => {
                pb::proposal::Action::FulfillSubnetRentalRequest(v.into())
            }
            pb_api::proposal::Action::DeclareAlternativeReplicaVirtualMachineSoftwareSet(v) => {
                pb::proposal::Action::DeclareAlternativeReplicaVirtualMachineSoftwareSet(v.into())
            }
        }
    }
}
impl From<pb_api::ProposalActionRequest> for pb::proposal::Action {
    fn from(item: pb_api::ProposalActionRequest) -> Self {
        match item {
            pb_api::ProposalActionRequest::ManageNeuron(v) => {
                pb::proposal::Action::ManageNeuron(Box::new((*v).into()))
            }
            pb_api::ProposalActionRequest::ManageNetworkEconomics(v) => {
                pb::proposal::Action::ManageNetworkEconomics(v.into())
            }
            pb_api::ProposalActionRequest::Motion(v) => pb::proposal::Action::Motion(v.into()),
            pb_api::ProposalActionRequest::ExecuteNnsFunction(v) => {
                pb::proposal::Action::ExecuteNnsFunction(v.into())
            }
            pb_api::ProposalActionRequest::ApproveGenesisKyc(v) => {
                pb::proposal::Action::ApproveGenesisKyc(v.into())
            }
            pb_api::ProposalActionRequest::AddOrRemoveNodeProvider(v) => {
                pb::proposal::Action::AddOrRemoveNodeProvider(v.into())
            }
            pb_api::ProposalActionRequest::RewardNodeProvider(v) => {
                pb::proposal::Action::RewardNodeProvider(v.into())
            }
            pb_api::ProposalActionRequest::RewardNodeProviders(v) => {
                pb::proposal::Action::RewardNodeProviders(v.into())
            }
            pb_api::ProposalActionRequest::RegisterKnownNeuron(v) => {
                pb::proposal::Action::RegisterKnownNeuron(v.into())
            }
            pb_api::ProposalActionRequest::DeregisterKnownNeuron(v) => {
                pb::proposal::Action::DeregisterKnownNeuron(v.into())
            }
            pb_api::ProposalActionRequest::CreateServiceNervousSystem(v) => {
                pb::proposal::Action::CreateServiceNervousSystem(v.into())
            }
            pb_api::ProposalActionRequest::InstallCode(v) => {
                pb::proposal::Action::InstallCode(v.into())
            }
            pb_api::ProposalActionRequest::StopOrStartCanister(v) => {
                pb::proposal::Action::StopOrStartCanister(v.into())
            }
            pb_api::ProposalActionRequest::UpdateCanisterSettings(v) => {
                pb::proposal::Action::UpdateCanisterSettings(v.into())
            }
            pb_api::ProposalActionRequest::FulfillSubnetRentalRequest(v) => {
                pb::proposal::Action::FulfillSubnetRentalRequest(v.into())
            }
        }
    }
}

impl From<pb::Empty> for pb_api::Empty {
    fn from(_: pb::Empty) -> Self {
        Self {}
    }
}
impl From<pb_api::Empty> for pb::Empty {
    fn from(_: pb_api::Empty) -> Self {
        Self {}
    }
}

impl From<pb::ManageNeuron> for pb_api::ManageNeuronProposal {
    fn from(item: pb::ManageNeuron) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuronProposal> for pb::ManageNeuron {
    fn from(item: pb_api::ManageNeuronProposal) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuronRequest> for pb::ManageNeuron {
    fn from(item: pb_api::ManageNeuronRequest) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::IncreaseDissolveDelay>
    for pb_api::manage_neuron::IncreaseDissolveDelay
{
    fn from(item: pb::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}
impl From<pb_api::manage_neuron::IncreaseDissolveDelay>
    for pb::manage_neuron::IncreaseDissolveDelay
{
    fn from(item: pb_api::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}

impl From<pb::manage_neuron::StartDissolving> for pb_api::manage_neuron::StartDissolving {
    fn from(_: pb::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::StartDissolving> for pb::manage_neuron::StartDissolving {
    fn from(_: pb_api::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::StopDissolving> for pb_api::manage_neuron::StopDissolving {
    fn from(_: pb::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::StopDissolving> for pb::manage_neuron::StopDissolving {
    fn from(_: pb_api::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::AddHotKey> for pb_api::manage_neuron::AddHotKey {
    fn from(item: pb::manage_neuron::AddHotKey) -> Self {
        Self {
            new_hot_key: item.new_hot_key,
        }
    }
}
impl From<pb_api::manage_neuron::AddHotKey> for pb::manage_neuron::AddHotKey {
    fn from(item: pb_api::manage_neuron::AddHotKey) -> Self {
        Self {
            new_hot_key: item.new_hot_key,
        }
    }
}

impl From<pb::manage_neuron::RemoveHotKey> for pb_api::manage_neuron::RemoveHotKey {
    fn from(item: pb::manage_neuron::RemoveHotKey) -> Self {
        Self {
            hot_key_to_remove: item.hot_key_to_remove,
        }
    }
}
impl From<pb_api::manage_neuron::RemoveHotKey> for pb::manage_neuron::RemoveHotKey {
    fn from(item: pb_api::manage_neuron::RemoveHotKey) -> Self {
        Self {
            hot_key_to_remove: item.hot_key_to_remove,
        }
    }
}

impl From<pb::manage_neuron::SetDissolveTimestamp> for pb_api::manage_neuron::SetDissolveTimestamp {
    fn from(item: pb::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}
impl From<pb_api::manage_neuron::SetDissolveTimestamp> for pb::manage_neuron::SetDissolveTimestamp {
    fn from(item: pb_api::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}

impl From<pb::manage_neuron::JoinCommunityFund> for pb_api::manage_neuron::JoinCommunityFund {
    fn from(_: pb::manage_neuron::JoinCommunityFund) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::JoinCommunityFund> for pb::manage_neuron::JoinCommunityFund {
    fn from(_: pb_api::manage_neuron::JoinCommunityFund) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::LeaveCommunityFund> for pb_api::manage_neuron::LeaveCommunityFund {
    fn from(_: pb::manage_neuron::LeaveCommunityFund) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::LeaveCommunityFund> for pb::manage_neuron::LeaveCommunityFund {
    fn from(_: pb_api::manage_neuron::LeaveCommunityFund) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::ChangeAutoStakeMaturity>
    for pb_api::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: pb::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}
impl From<pb_api::manage_neuron::ChangeAutoStakeMaturity>
    for pb::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: pb_api::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}

impl From<pb::manage_neuron::SetVisibility> for pb_api::manage_neuron::SetVisibility {
    fn from(item: pb::manage_neuron::SetVisibility) -> Self {
        Self {
            visibility: item.visibility,
        }
    }
}
impl From<pb_api::manage_neuron::SetVisibility> for pb::manage_neuron::SetVisibility {
    fn from(item: pb_api::manage_neuron::SetVisibility) -> Self {
        Self {
            visibility: item.visibility,
        }
    }
}

impl From<pb::manage_neuron::Configure> for pb_api::manage_neuron::Configure {
    fn from(item: pb::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::Configure> for pb::manage_neuron::Configure {
    fn from(item: pb_api::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::configure::Operation> for pb_api::manage_neuron::configure::Operation {
    fn from(item: pb::manage_neuron::configure::Operation) -> Self {
        match item {
            pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                pb_api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            pb::manage_neuron::configure::Operation::StartDissolving(v) => {
                pb_api::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::StopDissolving(v) => {
                pb_api::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::AddHotKey(v) => {
                pb_api::manage_neuron::configure::Operation::AddHotKey(v.into())
            }
            pb::manage_neuron::configure::Operation::RemoveHotKey(v) => {
                pb_api::manage_neuron::configure::Operation::RemoveHotKey(v.into())
            }
            pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                pb_api::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            pb::manage_neuron::configure::Operation::JoinCommunityFund(v) => {
                pb_api::manage_neuron::configure::Operation::JoinCommunityFund(v.into())
            }
            pb::manage_neuron::configure::Operation::LeaveCommunityFund(v) => {
                pb_api::manage_neuron::configure::Operation::LeaveCommunityFund(v.into())
            }
            pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                pb_api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
            pb::manage_neuron::configure::Operation::SetVisibility(v) => {
                pb_api::manage_neuron::configure::Operation::SetVisibility(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::configure::Operation> for pb::manage_neuron::configure::Operation {
    fn from(item: pb_api::manage_neuron::configure::Operation) -> Self {
        match item {
            pb_api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            pb_api::manage_neuron::configure::Operation::StartDissolving(v) => {
                pb::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            pb_api::manage_neuron::configure::Operation::StopDissolving(v) => {
                pb::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            pb_api::manage_neuron::configure::Operation::AddHotKey(v) => {
                pb::manage_neuron::configure::Operation::AddHotKey(v.into())
            }
            pb_api::manage_neuron::configure::Operation::RemoveHotKey(v) => {
                pb::manage_neuron::configure::Operation::RemoveHotKey(v.into())
            }
            pb_api::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            pb_api::manage_neuron::configure::Operation::JoinCommunityFund(v) => {
                pb::manage_neuron::configure::Operation::JoinCommunityFund(v.into())
            }
            pb_api::manage_neuron::configure::Operation::LeaveCommunityFund(v) => {
                pb::manage_neuron::configure::Operation::LeaveCommunityFund(v.into())
            }
            pb_api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
            pb_api::manage_neuron::configure::Operation::SetVisibility(v) => {
                pb::manage_neuron::configure::Operation::SetVisibility(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::Disburse> for pb_api::manage_neuron::Disburse {
    fn from(item: pb::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account,
        }
    }
}
impl From<pb_api::manage_neuron::Disburse> for pb::manage_neuron::Disburse {
    fn from(item: pb_api::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account,
        }
    }
}

impl From<pb::manage_neuron::disburse::Amount> for pb_api::manage_neuron::disburse::Amount {
    fn from(item: pb::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}
impl From<pb_api::manage_neuron::disburse::Amount> for pb::manage_neuron::disburse::Amount {
    fn from(item: pb_api::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}

impl From<pb::manage_neuron::Split> for pb_api::manage_neuron::Split {
    fn from(item: pb::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}
impl From<pb_api::manage_neuron::Split> for pb::manage_neuron::Split {
    fn from(item: pb_api::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}

impl From<pb::manage_neuron::Merge> for pb_api::manage_neuron::Merge {
    fn from(item: pb::manage_neuron::Merge) -> Self {
        Self {
            source_neuron_id: item.source_neuron_id,
        }
    }
}
impl From<pb_api::manage_neuron::Merge> for pb::manage_neuron::Merge {
    fn from(item: pb_api::manage_neuron::Merge) -> Self {
        Self {
            source_neuron_id: item.source_neuron_id,
        }
    }
}

impl From<pb::manage_neuron::Spawn> for pb_api::manage_neuron::Spawn {
    fn from(item: pb::manage_neuron::Spawn) -> Self {
        Self {
            new_controller: item.new_controller,
            nonce: item.nonce,
            percentage_to_spawn: item.percentage_to_spawn,
        }
    }
}
impl From<pb_api::manage_neuron::Spawn> for pb::manage_neuron::Spawn {
    fn from(item: pb_api::manage_neuron::Spawn) -> Self {
        Self {
            new_controller: item.new_controller,
            nonce: item.nonce,
            percentage_to_spawn: item.percentage_to_spawn,
        }
    }
}

impl From<pb::manage_neuron::MergeMaturity> for pb_api::manage_neuron::MergeMaturity {
    fn from(item: pb::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}
impl From<pb_api::manage_neuron::MergeMaturity> for pb::manage_neuron::MergeMaturity {
    fn from(item: pb_api::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}

impl From<pb::manage_neuron::StakeMaturity> for pb_api::manage_neuron::StakeMaturity {
    fn from(item: pb::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}
impl From<pb_api::manage_neuron::StakeMaturity> for pb::manage_neuron::StakeMaturity {
    fn from(item: pb_api::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}

impl From<pb::manage_neuron::RefreshVotingPower> for pb_api::manage_neuron::RefreshVotingPower {
    fn from(_item: pb::manage_neuron::RefreshVotingPower) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron::RefreshVotingPower> for pb::manage_neuron::RefreshVotingPower {
    fn from(_item: pb_api::manage_neuron::RefreshVotingPower) -> Self {
        Self {}
    }
}
impl From<pb::manage_neuron::DisburseToNeuron> for pb_api::manage_neuron::DisburseToNeuron {
    fn from(item: pb::manage_neuron::DisburseToNeuron) -> Self {
        Self {
            new_controller: item.new_controller,
            amount_e8s: item.amount_e8s,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            kyc_verified: item.kyc_verified,
            nonce: item.nonce,
        }
    }
}
impl From<pb_api::manage_neuron::DisburseToNeuron> for pb::manage_neuron::DisburseToNeuron {
    fn from(item: pb_api::manage_neuron::DisburseToNeuron) -> Self {
        Self {
            new_controller: item.new_controller,
            amount_e8s: item.amount_e8s,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            kyc_verified: item.kyc_verified,
            nonce: item.nonce,
        }
    }
}

impl From<pb::manage_neuron::Follow> for pb_api::manage_neuron::Follow {
    fn from(item: pb::manage_neuron::Follow) -> Self {
        Self {
            topic: item.topic,
            followees: item.followees,
        }
    }
}
impl From<pb_api::manage_neuron::Follow> for pb::manage_neuron::Follow {
    fn from(item: pb_api::manage_neuron::Follow) -> Self {
        Self {
            topic: item.topic,
            followees: item.followees,
        }
    }
}

impl From<pb::manage_neuron::RegisterVote> for pb_api::manage_neuron::RegisterVote {
    fn from(item: pb::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal,
            vote: item.vote,
        }
    }
}
impl From<pb_api::manage_neuron::RegisterVote> for pb::manage_neuron::RegisterVote {
    fn from(item: pb_api::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal,
            vote: item.vote,
        }
    }
}

impl From<pb::manage_neuron::ClaimOrRefresh> for pb_api::manage_neuron::ClaimOrRefresh {
    fn from(item: pb::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron::ClaimOrRefresh> for pb::manage_neuron::ClaimOrRefresh {
    fn from(item: pb_api::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::DisburseMaturity> for pb_api::manage_neuron::DisburseMaturity {
    fn from(item: pb::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
            to_account_identifier: item.to_account_identifier,
        }
    }
}
impl From<pb_api::manage_neuron::DisburseMaturity> for pb::manage_neuron::DisburseMaturity {
    fn from(item: pb_api::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
            to_account_identifier: item.to_account_identifier,
        }
    }
}

impl From<pb::manage_neuron::SetFollowing> for pb_api::manage_neuron::SetFollowing {
    fn from(item: pb::manage_neuron::SetFollowing) -> Self {
        Self {
            topic_following: Some(item.topic_following.into_iter().map(|x| x.into()).collect()),
        }
    }
}
impl From<pb_api::manage_neuron::SetFollowing> for pb::manage_neuron::SetFollowing {
    fn from(item: pb_api::manage_neuron::SetFollowing) -> Self {
        Self {
            topic_following: item
                .topic_following
                .unwrap_or_default()
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<pb::manage_neuron::set_following::FolloweesForTopic>
    for pb_api::manage_neuron::set_following::FolloweesForTopic
{
    fn from(item: pb::manage_neuron::set_following::FolloweesForTopic) -> Self {
        Self {
            followees: Some(item.followees),
            topic: item.topic,
        }
    }
}
impl From<pb_api::manage_neuron::set_following::FolloweesForTopic>
    for pb::manage_neuron::set_following::FolloweesForTopic
{
    fn from(item: pb_api::manage_neuron::set_following::FolloweesForTopic) -> Self {
        Self {
            followees: item.followees.unwrap_or_default(),
            topic: item.topic,
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::MemoAndController>
    for pb_api::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: pb::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}
impl From<pb_api::manage_neuron::claim_or_refresh::MemoAndController>
    for pb::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: pb_api::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::By> for pb_api::manage_neuron::claim_or_refresh::By {
    fn from(item: pb::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            pb::manage_neuron::claim_or_refresh::By::Memo(v) => {
                pb_api::manage_neuron::claim_or_refresh::By::Memo(v)
            }
            pb::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                pb_api::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            pb::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v) => {
                pb_api::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::claim_or_refresh::By> for pb::manage_neuron::claim_or_refresh::By {
    fn from(item: pb_api::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            pb_api::manage_neuron::claim_or_refresh::By::Memo(v) => {
                pb::manage_neuron::claim_or_refresh::By::Memo(v)
            }
            pb_api::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                pb::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            pb_api::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v) => {
                pb::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::NeuronIdOrSubaccount> for pb_api::manage_neuron::NeuronIdOrSubaccount {
    fn from(item: pb::manage_neuron::NeuronIdOrSubaccount) -> Self {
        match item {
            pb::manage_neuron::NeuronIdOrSubaccount::Subaccount(v) => {
                pb_api::manage_neuron::NeuronIdOrSubaccount::Subaccount(v)
            }
            pb::manage_neuron::NeuronIdOrSubaccount::NeuronId(v) => {
                pb_api::manage_neuron::NeuronIdOrSubaccount::NeuronId(v)
            }
        }
    }
}
impl From<pb_api::manage_neuron::NeuronIdOrSubaccount> for pb::manage_neuron::NeuronIdOrSubaccount {
    fn from(item: pb_api::manage_neuron::NeuronIdOrSubaccount) -> Self {
        match item {
            pb_api::manage_neuron::NeuronIdOrSubaccount::Subaccount(v) => {
                pb::manage_neuron::NeuronIdOrSubaccount::Subaccount(v)
            }
            pb_api::manage_neuron::NeuronIdOrSubaccount::NeuronId(v) => {
                pb::manage_neuron::NeuronIdOrSubaccount::NeuronId(v)
            }
        }
    }
}

// TODO: Remove this once the proposals exposed by Governance API no longer includes `Action` but
// only the self-describing version.
impl From<pb::manage_neuron::Command> for pb_api::manage_neuron::ManageNeuronProposalCommand {
    fn from(item: pb::manage_neuron::Command) -> Self {
        match item {
            pb::manage_neuron::Command::Configure(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Configure(v.into())
            }
            pb::manage_neuron::Command::Disburse(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Disburse(v.into())
            }
            pb::manage_neuron::Command::Spawn(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Spawn(v.into())
            }
            pb::manage_neuron::Command::Follow(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Follow(v.into())
            }
            pb::manage_neuron::Command::MakeProposal(v) => {
                // Note: this case is actually impossible since we no longer allow creating
                // proposals through another ManageNeuron proposal. However this case cannot be
                // easily removed until the `manage_neuron` canister method no longer uses
                // `pb::manage_neuron::Command`.
                pb_api::manage_neuron::ManageNeuronProposalCommand::MakeProposal(Box::new(
                    convert_proposal(&v, ProposalDisplayOptions::for_get_proposal_info()),
                ))
            }
            pb::manage_neuron::Command::RegisterVote(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::RegisterVote(v.into())
            }
            pb::manage_neuron::Command::Split(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Split(v.into())
            }
            pb::manage_neuron::Command::DisburseToNeuron(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::DisburseToNeuron(v.into())
            }
            pb::manage_neuron::Command::ClaimOrRefresh(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron::Command::MergeMaturity(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::MergeMaturity(v.into())
            }
            pb::manage_neuron::Command::Merge(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::Merge(v.into())
            }
            pb::manage_neuron::Command::StakeMaturity(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::StakeMaturity(v.into())
            }
            pb::manage_neuron::Command::RefreshVotingPower(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::RefreshVotingPower(v.into())
            }
            pb::manage_neuron::Command::DisburseMaturity(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::DisburseMaturity(v.into())
            }
            pb::manage_neuron::Command::SetFollowing(v) => {
                pb_api::manage_neuron::ManageNeuronProposalCommand::SetFollowing(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::ManageNeuronProposalCommand> for pb::manage_neuron::Command {
    fn from(item: pb_api::manage_neuron::ManageNeuronProposalCommand) -> Self {
        match item {
            pb_api::manage_neuron::ManageNeuronProposalCommand::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::Spawn(v) => {
                pb::manage_neuron::Command::Spawn(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::Split(v) => {
                pb::manage_neuron::Command::Split(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::DisburseToNeuron(v) => {
                pb::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::Merge(v) => {
                pb::manage_neuron::Command::Merge(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::RefreshVotingPower(v) => {
                pb::manage_neuron::Command::RefreshVotingPower(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::DisburseMaturity(v) => {
                pb::manage_neuron::Command::DisburseMaturity(v.into())
            }
            pb_api::manage_neuron::ManageNeuronProposalCommand::SetFollowing(v) => {
                pb::manage_neuron::Command::SetFollowing(v.into())
            }
        }
    }
}
impl From<pb_api::ManageNeuronCommandRequest> for pb::manage_neuron::Command {
    fn from(item: pb_api::ManageNeuronCommandRequest) -> Self {
        match item {
            pb_api::ManageNeuronCommandRequest::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            pb_api::ManageNeuronCommandRequest::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            pb_api::ManageNeuronCommandRequest::Spawn(v) => {
                pb::manage_neuron::Command::Spawn(v.into())
            }
            pb_api::ManageNeuronCommandRequest::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            pb_api::ManageNeuronCommandRequest::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            pb_api::ManageNeuronCommandRequest::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            pb_api::ManageNeuronCommandRequest::Split(v) => {
                pb::manage_neuron::Command::Split(v.into())
            }
            pb_api::ManageNeuronCommandRequest::DisburseToNeuron(v) => {
                pb::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            pb_api::ManageNeuronCommandRequest::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb_api::ManageNeuronCommandRequest::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb_api::ManageNeuronCommandRequest::Merge(v) => {
                pb::manage_neuron::Command::Merge(v.into())
            }
            pb_api::ManageNeuronCommandRequest::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
            }
            pb_api::ManageNeuronCommandRequest::RefreshVotingPower(v) => {
                pb::manage_neuron::Command::RefreshVotingPower(v.into())
            }
            pb_api::ManageNeuronCommandRequest::DisburseMaturity(v) => {
                pb::manage_neuron::Command::DisburseMaturity(v.into())
            }
            pb_api::ManageNeuronCommandRequest::SetFollowing(v) => {
                pb::manage_neuron::Command::SetFollowing(v.into())
            }
        }
    }
}

impl From<pb::GovernanceError> for pb_api::GovernanceError {
    fn from(item: pb::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}
impl From<pb_api::GovernanceError> for pb::GovernanceError {
    fn from(item: pb_api::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}

impl From<pb::governance_error::ErrorType> for pb_api::governance_error::ErrorType {
    fn from(item: pb::governance_error::ErrorType) -> Self {
        match item {
            pb::governance_error::ErrorType::Unspecified => {
                pb_api::governance_error::ErrorType::Unspecified
            }
            pb::governance_error::ErrorType::Ok => pb_api::governance_error::ErrorType::Ok,
            pb::governance_error::ErrorType::Unavailable => {
                pb_api::governance_error::ErrorType::Unavailable
            }
            pb::governance_error::ErrorType::NotAuthorized => {
                pb_api::governance_error::ErrorType::NotAuthorized
            }
            pb::governance_error::ErrorType::NotFound => {
                pb_api::governance_error::ErrorType::NotFound
            }
            pb::governance_error::ErrorType::InvalidCommand => {
                pb_api::governance_error::ErrorType::InvalidCommand
            }
            pb::governance_error::ErrorType::RequiresNotDissolving => {
                pb_api::governance_error::ErrorType::RequiresNotDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolving => {
                pb_api::governance_error::ErrorType::RequiresDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolved => {
                pb_api::governance_error::ErrorType::RequiresDissolved
            }
            pb::governance_error::ErrorType::HotKey => pb_api::governance_error::ErrorType::HotKey,
            pb::governance_error::ErrorType::ResourceExhausted => {
                pb_api::governance_error::ErrorType::ResourceExhausted
            }
            pb::governance_error::ErrorType::PreconditionFailed => {
                pb_api::governance_error::ErrorType::PreconditionFailed
            }
            pb::governance_error::ErrorType::External => {
                pb_api::governance_error::ErrorType::External
            }
            pb::governance_error::ErrorType::LedgerUpdateOngoing => {
                pb_api::governance_error::ErrorType::LedgerUpdateOngoing
            }
            pb::governance_error::ErrorType::InsufficientFunds => {
                pb_api::governance_error::ErrorType::InsufficientFunds
            }
            pb::governance_error::ErrorType::InvalidPrincipal => {
                pb_api::governance_error::ErrorType::InvalidPrincipal
            }
            pb::governance_error::ErrorType::InvalidProposal => {
                pb_api::governance_error::ErrorType::InvalidProposal
            }
            pb::governance_error::ErrorType::AlreadyJoinedCommunityFund => {
                pb_api::governance_error::ErrorType::AlreadyJoinedCommunityFund
            }
            pb::governance_error::ErrorType::NotInTheCommunityFund => {
                pb_api::governance_error::ErrorType::NotInTheCommunityFund
            }
            pb::governance_error::ErrorType::NeuronAlreadyVoted => {
                pb_api::governance_error::ErrorType::NeuronAlreadyVoted
            }
        }
    }
}
impl From<pb_api::governance_error::ErrorType> for pb::governance_error::ErrorType {
    fn from(item: pb_api::governance_error::ErrorType) -> Self {
        match item {
            pb_api::governance_error::ErrorType::Unspecified => {
                pb::governance_error::ErrorType::Unspecified
            }
            pb_api::governance_error::ErrorType::Ok => pb::governance_error::ErrorType::Ok,
            pb_api::governance_error::ErrorType::Unavailable => {
                pb::governance_error::ErrorType::Unavailable
            }
            pb_api::governance_error::ErrorType::NotAuthorized => {
                pb::governance_error::ErrorType::NotAuthorized
            }
            pb_api::governance_error::ErrorType::NotFound => {
                pb::governance_error::ErrorType::NotFound
            }
            pb_api::governance_error::ErrorType::InvalidCommand => {
                pb::governance_error::ErrorType::InvalidCommand
            }
            pb_api::governance_error::ErrorType::RequiresNotDissolving => {
                pb::governance_error::ErrorType::RequiresNotDissolving
            }
            pb_api::governance_error::ErrorType::RequiresDissolving => {
                pb::governance_error::ErrorType::RequiresDissolving
            }
            pb_api::governance_error::ErrorType::RequiresDissolved => {
                pb::governance_error::ErrorType::RequiresDissolved
            }
            pb_api::governance_error::ErrorType::HotKey => pb::governance_error::ErrorType::HotKey,
            pb_api::governance_error::ErrorType::ResourceExhausted => {
                pb::governance_error::ErrorType::ResourceExhausted
            }
            pb_api::governance_error::ErrorType::PreconditionFailed => {
                pb::governance_error::ErrorType::PreconditionFailed
            }
            pb_api::governance_error::ErrorType::External => {
                pb::governance_error::ErrorType::External
            }
            pb_api::governance_error::ErrorType::LedgerUpdateOngoing => {
                pb::governance_error::ErrorType::LedgerUpdateOngoing
            }
            pb_api::governance_error::ErrorType::InsufficientFunds => {
                pb::governance_error::ErrorType::InsufficientFunds
            }
            pb_api::governance_error::ErrorType::InvalidPrincipal => {
                pb::governance_error::ErrorType::InvalidPrincipal
            }
            pb_api::governance_error::ErrorType::InvalidProposal => {
                pb::governance_error::ErrorType::InvalidProposal
            }
            pb_api::governance_error::ErrorType::AlreadyJoinedCommunityFund => {
                pb::governance_error::ErrorType::AlreadyJoinedCommunityFund
            }
            pb_api::governance_error::ErrorType::NotInTheCommunityFund => {
                pb::governance_error::ErrorType::NotInTheCommunityFund
            }
            pb_api::governance_error::ErrorType::NeuronAlreadyVoted => {
                pb::governance_error::ErrorType::NeuronAlreadyVoted
            }
        }
    }
}

impl From<pb::Ballot> for pb_api::Ballot {
    fn from(item: pb::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
        }
    }
}
impl From<pb_api::Ballot> for pb::Ballot {
    fn from(item: pb_api::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
        }
    }
}

impl From<pb::Tally> for pb_api::Tally {
    fn from(item: pb::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}
impl From<pb_api::Tally> for pb::Tally {
    fn from(item: pb_api::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}

impl From<pb_api::ProposalData> for pb::ProposalData {
    fn from(item: pb_api::ProposalData) -> Self {
        Self {
            id: item.id,
            proposer: item.proposer,
            reject_cost_e8s: item.reject_cost_e8s,
            proposal: item.proposal.map(|x| x.into()),
            proposal_timestamp_seconds: item.proposal_timestamp_seconds,
            ballots: item
                .ballots
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            latest_tally: item.latest_tally.map(|x| x.into()),
            decided_timestamp_seconds: item.decided_timestamp_seconds,
            executed_timestamp_seconds: item.executed_timestamp_seconds,
            failed_timestamp_seconds: item.failed_timestamp_seconds,
            failure_reason: item.failure_reason.map(|x| x.into()),
            reward_event_round: item.reward_event_round,
            wait_for_quiet_state: item.wait_for_quiet_state.map(|x| x.into()),
            original_total_community_fund_maturity_e8s_equivalent: item
                .original_total_community_fund_maturity_e8s_equivalent,
            sns_token_swap_lifecycle: item.sns_token_swap_lifecycle,
            derived_proposal_information: item.derived_proposal_information.map(|x| x.into()),
            neurons_fund_data: item.neurons_fund_data.map(|x| x.into()),
            total_potential_voting_power: item.total_potential_voting_power,
            topic: item.topic,
            // This is not intended to be initialized from outside of canister.
            previous_ballots_timestamp_seconds: None,
        }
    }
}

impl From<pb::NeuronsFundData> for pb_api::NeuronsFundData {
    fn from(item: pb::NeuronsFundData) -> Self {
        Self {
            initial_neurons_fund_participation: item
                .initial_neurons_fund_participation
                .map(|x| x.into()),
            final_neurons_fund_participation: item
                .final_neurons_fund_participation
                .map(|x| x.into()),
            neurons_fund_refunds: item.neurons_fund_refunds.map(|x| x.into()),
        }
    }
}
impl From<pb_api::NeuronsFundData> for pb::NeuronsFundData {
    fn from(item: pb_api::NeuronsFundData) -> Self {
        Self {
            initial_neurons_fund_participation: item
                .initial_neurons_fund_participation
                .map(|x| x.into()),
            final_neurons_fund_participation: item
                .final_neurons_fund_participation
                .map(|x| x.into()),
            neurons_fund_refunds: item.neurons_fund_refunds.map(|x| x.into()),
        }
    }
}

impl From<pb::NeuronsFundAuditInfo> for pb_api::NeuronsFundAuditInfo {
    fn from(item: pb::NeuronsFundAuditInfo) -> Self {
        Self {
            initial_neurons_fund_participation: item
                .initial_neurons_fund_participation
                .map(|x| x.into()),
            final_neurons_fund_participation: item
                .final_neurons_fund_participation
                .map(|x| x.into()),
            neurons_fund_refunds: item.neurons_fund_refunds.map(|x| x.into()),
        }
    }
}
impl From<pb_api::NeuronsFundAuditInfo> for pb::NeuronsFundAuditInfo {
    fn from(item: pb_api::NeuronsFundAuditInfo) -> Self {
        Self {
            initial_neurons_fund_participation: item
                .initial_neurons_fund_participation
                .map(|x| x.into()),
            final_neurons_fund_participation: item
                .final_neurons_fund_participation
                .map(|x| x.into()),
            neurons_fund_refunds: item.neurons_fund_refunds.map(|x| x.into()),
        }
    }
}

impl From<pb::GetNeuronsFundAuditInfoRequest> for pb_api::GetNeuronsFundAuditInfoRequest {
    fn from(item: pb::GetNeuronsFundAuditInfoRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
        }
    }
}
impl From<pb_api::GetNeuronsFundAuditInfoRequest> for pb::GetNeuronsFundAuditInfoRequest {
    fn from(item: pb_api::GetNeuronsFundAuditInfoRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
        }
    }
}

impl From<pb::GetNeuronsFundAuditInfoResponse> for pb_api::GetNeuronsFundAuditInfoResponse {
    fn from(item: pb::GetNeuronsFundAuditInfoResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::GetNeuronsFundAuditInfoResponse> for pb::GetNeuronsFundAuditInfoResponse {
    fn from(item: pb_api::GetNeuronsFundAuditInfoResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::get_neurons_fund_audit_info_response::Ok>
    for pb_api::get_neurons_fund_audit_info_response::Ok
{
    fn from(item: pb::get_neurons_fund_audit_info_response::Ok) -> Self {
        Self {
            neurons_fund_audit_info: item.neurons_fund_audit_info.map(|x| x.into()),
        }
    }
}
impl From<pb_api::get_neurons_fund_audit_info_response::Ok>
    for pb::get_neurons_fund_audit_info_response::Ok
{
    fn from(item: pb_api::get_neurons_fund_audit_info_response::Ok) -> Self {
        Self {
            neurons_fund_audit_info: item.neurons_fund_audit_info.map(|x| x.into()),
        }
    }
}

impl From<pb::get_neurons_fund_audit_info_response::Result>
    for pb_api::get_neurons_fund_audit_info_response::Result
{
    fn from(item: pb::get_neurons_fund_audit_info_response::Result) -> Self {
        match item {
            pb::get_neurons_fund_audit_info_response::Result::Err(v) => {
                pb_api::get_neurons_fund_audit_info_response::Result::Err(v.into())
            }
            pb::get_neurons_fund_audit_info_response::Result::Ok(v) => {
                pb_api::get_neurons_fund_audit_info_response::Result::Ok(v.into())
            }
        }
    }
}
impl From<pb_api::get_neurons_fund_audit_info_response::Result>
    for pb::get_neurons_fund_audit_info_response::Result
{
    fn from(item: pb_api::get_neurons_fund_audit_info_response::Result) -> Self {
        match item {
            pb_api::get_neurons_fund_audit_info_response::Result::Err(v) => {
                pb::get_neurons_fund_audit_info_response::Result::Err(v.into())
            }
            pb_api::get_neurons_fund_audit_info_response::Result::Ok(v) => {
                pb::get_neurons_fund_audit_info_response::Result::Ok(v.into())
            }
        }
    }
}

impl From<pb::NeuronsFundParticipation> for pb_api::NeuronsFundParticipation {
    fn from(item: pb::NeuronsFundParticipation) -> Self {
        Self {
            ideal_matched_participation_function: item
                .ideal_matched_participation_function
                .map(|x| x.into()),
            neurons_fund_reserves: item.neurons_fund_reserves.map(|x| x.into()),
            swap_participation_limits: item.swap_participation_limits.map(|x| x.into()),
            direct_participation_icp_e8s: item.direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s: item.total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s: item
                .max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s: item
                .intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s: item
                .allocated_neurons_fund_participation_icp_e8s,
        }
    }
}
impl From<pb_api::NeuronsFundParticipation> for pb::NeuronsFundParticipation {
    fn from(item: pb_api::NeuronsFundParticipation) -> Self {
        Self {
            ideal_matched_participation_function: item
                .ideal_matched_participation_function
                .map(|x| x.into()),
            neurons_fund_reserves: item.neurons_fund_reserves.map(|x| x.into()),
            swap_participation_limits: item.swap_participation_limits.map(|x| x.into()),
            direct_participation_icp_e8s: item.direct_participation_icp_e8s,
            total_maturity_equivalent_icp_e8s: item.total_maturity_equivalent_icp_e8s,
            max_neurons_fund_swap_participation_icp_e8s: item
                .max_neurons_fund_swap_participation_icp_e8s,
            intended_neurons_fund_participation_icp_e8s: item
                .intended_neurons_fund_participation_icp_e8s,
            allocated_neurons_fund_participation_icp_e8s: item
                .allocated_neurons_fund_participation_icp_e8s,
        }
    }
}

impl From<pb::IdealMatchedParticipationFunction> for pb_api::IdealMatchedParticipationFunction {
    fn from(item: pb::IdealMatchedParticipationFunction) -> Self {
        Self {
            serialized_representation: item.serialized_representation,
        }
    }
}
impl From<pb_api::IdealMatchedParticipationFunction> for pb::IdealMatchedParticipationFunction {
    fn from(item: pb_api::IdealMatchedParticipationFunction) -> Self {
        Self {
            serialized_representation: item.serialized_representation,
        }
    }
}

impl From<pb::NeuronsFundSnapshot> for pb_api::NeuronsFundSnapshot {
    fn from(item: pb::NeuronsFundSnapshot) -> Self {
        Self {
            neurons_fund_neuron_portions: item
                .neurons_fund_neuron_portions
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}
impl From<pb_api::NeuronsFundSnapshot> for pb::NeuronsFundSnapshot {
    fn from(item: pb_api::NeuronsFundSnapshot) -> Self {
        Self {
            neurons_fund_neuron_portions: item
                .neurons_fund_neuron_portions
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<pb::neurons_fund_snapshot::NeuronsFundNeuronPortion>
    for pb_api::neurons_fund_snapshot::NeuronsFundNeuronPortion
{
    fn from(item: pb::neurons_fund_snapshot::NeuronsFundNeuronPortion) -> Self {
        Self {
            nns_neuron_id: item.nns_neuron_id,
            amount_icp_e8s: item.amount_icp_e8s,
            maturity_equivalent_icp_e8s: item.maturity_equivalent_icp_e8s,
            is_capped: item.is_capped,
            controller: item.controller,
            hotkeys: item.hotkeys,
        }
    }
}
impl From<pb_api::neurons_fund_snapshot::NeuronsFundNeuronPortion>
    for pb::neurons_fund_snapshot::NeuronsFundNeuronPortion
{
    fn from(item: pb_api::neurons_fund_snapshot::NeuronsFundNeuronPortion) -> Self {
        #[allow(deprecated)]
        Self {
            nns_neuron_id: item.nns_neuron_id,
            amount_icp_e8s: item.amount_icp_e8s,
            maturity_equivalent_icp_e8s: item.maturity_equivalent_icp_e8s,
            is_capped: item.is_capped,
            controller: item.controller,
            hotkeys: item.hotkeys,
        }
    }
}

impl From<pb::SwapParticipationLimits> for pb_api::SwapParticipationLimits {
    fn from(item: pb::SwapParticipationLimits) -> Self {
        Self {
            min_direct_participation_icp_e8s: item.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: item.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: item.min_participant_icp_e8s,
            max_participant_icp_e8s: item.max_participant_icp_e8s,
        }
    }
}
impl From<pb_api::SwapParticipationLimits> for pb::SwapParticipationLimits {
    fn from(item: pb_api::SwapParticipationLimits) -> Self {
        Self {
            min_direct_participation_icp_e8s: item.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: item.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: item.min_participant_icp_e8s,
            max_participant_icp_e8s: item.max_participant_icp_e8s,
        }
    }
}

impl From<pb::DerivedProposalInformation> for pb_api::DerivedProposalInformation {
    fn from(item: pb::DerivedProposalInformation) -> Self {
        Self {
            swap_background_information: item.swap_background_information.map(|x| x.into()),
        }
    }
}
impl From<pb_api::DerivedProposalInformation> for pb::DerivedProposalInformation {
    fn from(item: pb_api::DerivedProposalInformation) -> Self {
        Self {
            swap_background_information: item.swap_background_information.map(|x| x.into()),
        }
    }
}

impl From<pb::SwapBackgroundInformation> for pb_api::SwapBackgroundInformation {
    fn from(item: pb::SwapBackgroundInformation) -> Self {
        Self {
            fallback_controller_principal_ids: item.fallback_controller_principal_ids,
            root_canister_summary: item.root_canister_summary.map(|x| x.into()),
            governance_canister_summary: item.governance_canister_summary.map(|x| x.into()),
            ledger_canister_summary: item.ledger_canister_summary.map(|x| x.into()),
            swap_canister_summary: item.swap_canister_summary.map(|x| x.into()),
            ledger_archive_canister_summaries: item
                .ledger_archive_canister_summaries
                .into_iter()
                .map(|x| x.into())
                .collect(),
            ledger_index_canister_summary: item.ledger_index_canister_summary.map(|x| x.into()),
            dapp_canister_summaries: item
                .dapp_canister_summaries
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}
impl From<pb_api::SwapBackgroundInformation> for pb::SwapBackgroundInformation {
    fn from(item: pb_api::SwapBackgroundInformation) -> Self {
        Self {
            fallback_controller_principal_ids: item.fallback_controller_principal_ids,
            root_canister_summary: item.root_canister_summary.map(|x| x.into()),
            governance_canister_summary: item.governance_canister_summary.map(|x| x.into()),
            ledger_canister_summary: item.ledger_canister_summary.map(|x| x.into()),
            swap_canister_summary: item.swap_canister_summary.map(|x| x.into()),
            ledger_archive_canister_summaries: item
                .ledger_archive_canister_summaries
                .into_iter()
                .map(|x| x.into())
                .collect(),
            ledger_index_canister_summary: item.ledger_index_canister_summary.map(|x| x.into()),
            dapp_canister_summaries: item
                .dapp_canister_summaries
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<pb::swap_background_information::CanisterSummary>
    for pb_api::swap_background_information::CanisterSummary
{
    fn from(item: pb::swap_background_information::CanisterSummary) -> Self {
        Self {
            canister_id: item.canister_id,
            status: item.status.map(|x| x.into()),
        }
    }
}
impl From<pb_api::swap_background_information::CanisterSummary>
    for pb::swap_background_information::CanisterSummary
{
    fn from(item: pb_api::swap_background_information::CanisterSummary) -> Self {
        Self {
            canister_id: item.canister_id,
            status: item.status.map(|x| x.into()),
        }
    }
}

impl From<pb::swap_background_information::CanisterStatusResultV2>
    for pb_api::swap_background_information::CanisterStatusResultV2
{
    fn from(item: pb::swap_background_information::CanisterStatusResultV2) -> Self {
        Self {
            status: item.status,
            module_hash: item.module_hash,
            controllers: item.controllers,
            memory_size: item.memory_size,
            cycles: item.cycles,
            freezing_threshold: item.freezing_threshold,
            idle_cycles_burned_per_day: item.idle_cycles_burned_per_day,
        }
    }
}
impl From<pb_api::swap_background_information::CanisterStatusResultV2>
    for pb::swap_background_information::CanisterStatusResultV2
{
    fn from(item: pb_api::swap_background_information::CanisterStatusResultV2) -> Self {
        Self {
            status: item.status,
            module_hash: item.module_hash,
            controllers: item.controllers,
            memory_size: item.memory_size,
            cycles: item.cycles,
            freezing_threshold: item.freezing_threshold,
            idle_cycles_burned_per_day: item.idle_cycles_burned_per_day,
        }
    }
}

impl From<pb::swap_background_information::CanisterStatusType>
    for pb_api::swap_background_information::CanisterStatusType
{
    fn from(item: pb::swap_background_information::CanisterStatusType) -> Self {
        match item {
            pb::swap_background_information::CanisterStatusType::Unspecified => {
                pb_api::swap_background_information::CanisterStatusType::Unspecified
            }
            pb::swap_background_information::CanisterStatusType::Running => {
                pb_api::swap_background_information::CanisterStatusType::Running
            }
            pb::swap_background_information::CanisterStatusType::Stopping => {
                pb_api::swap_background_information::CanisterStatusType::Stopping
            }
            pb::swap_background_information::CanisterStatusType::Stopped => {
                pb_api::swap_background_information::CanisterStatusType::Stopped
            }
        }
    }
}
impl From<pb_api::swap_background_information::CanisterStatusType>
    for pb::swap_background_information::CanisterStatusType
{
    fn from(item: pb_api::swap_background_information::CanisterStatusType) -> Self {
        match item {
            pb_api::swap_background_information::CanisterStatusType::Unspecified => {
                pb::swap_background_information::CanisterStatusType::Unspecified
            }
            pb_api::swap_background_information::CanisterStatusType::Running => {
                pb::swap_background_information::CanisterStatusType::Running
            }
            pb_api::swap_background_information::CanisterStatusType::Stopping => {
                pb::swap_background_information::CanisterStatusType::Stopping
            }
            pb_api::swap_background_information::CanisterStatusType::Stopped => {
                pb::swap_background_information::CanisterStatusType::Stopped
            }
        }
    }
}

impl From<pb::WaitForQuietState> for pb_api::WaitForQuietState {
    fn from(item: pb::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}
impl From<pb_api::WaitForQuietState> for pb::WaitForQuietState {
    fn from(item: pb_api::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}

impl From<pb::NetworkEconomics> for pb_api::NetworkEconomics {
    fn from(item: pb::NetworkEconomics) -> Self {
        Self {
            reject_cost_e8s: item.reject_cost_e8s,
            neuron_minimum_stake_e8s: item.neuron_minimum_stake_e8s,
            neuron_management_fee_per_proposal_e8s: item.neuron_management_fee_per_proposal_e8s,
            minimum_icp_xdr_rate: item.minimum_icp_xdr_rate,
            neuron_spawn_dissolve_delay_seconds: item.neuron_spawn_dissolve_delay_seconds,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            transaction_fee_e8s: item.transaction_fee_e8s,
            max_proposals_to_keep_per_topic: item.max_proposals_to_keep_per_topic,
            neurons_fund_economics: item.neurons_fund_economics.map(|x| x.into()),
            voting_power_economics: item.voting_power_economics.map(|x| x.into()),
        }
    }
}

impl From<pb_api::NetworkEconomics> for pb::NetworkEconomics {
    fn from(item: pb_api::NetworkEconomics) -> Self {
        Self {
            reject_cost_e8s: item.reject_cost_e8s,
            neuron_minimum_stake_e8s: item.neuron_minimum_stake_e8s,
            neuron_management_fee_per_proposal_e8s: item.neuron_management_fee_per_proposal_e8s,
            minimum_icp_xdr_rate: item.minimum_icp_xdr_rate,
            neuron_spawn_dissolve_delay_seconds: item.neuron_spawn_dissolve_delay_seconds,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            transaction_fee_e8s: item.transaction_fee_e8s,
            max_proposals_to_keep_per_topic: item.max_proposals_to_keep_per_topic,
            neurons_fund_economics: item.neurons_fund_economics.map(|x| x.into()),
            voting_power_economics: item.voting_power_economics.map(|x| x.into()),
        }
    }
}

impl From<pb_api::VotingPowerEconomics> for pb::VotingPowerEconomics {
    fn from(item: pb_api::VotingPowerEconomics) -> Self {
        Self {
            start_reducing_voting_power_after_seconds: item
                .start_reducing_voting_power_after_seconds,
            clear_following_after_seconds: item.clear_following_after_seconds,
            neuron_minimum_dissolve_delay_to_vote_seconds: item
                .neuron_minimum_dissolve_delay_to_vote_seconds,
        }
    }
}

impl From<pb::VotingPowerEconomics> for pb_api::VotingPowerEconomics {
    fn from(item: pb::VotingPowerEconomics) -> Self {
        Self {
            start_reducing_voting_power_after_seconds: item
                .start_reducing_voting_power_after_seconds,
            clear_following_after_seconds: item.clear_following_after_seconds,
            neuron_minimum_dissolve_delay_to_vote_seconds: item
                .neuron_minimum_dissolve_delay_to_vote_seconds,
        }
    }
}

impl From<pb::NeuronsFundMatchedFundingCurveCoefficients>
    for pb_api::NeuronsFundMatchedFundingCurveCoefficients
{
    fn from(item: pb::NeuronsFundMatchedFundingCurveCoefficients) -> Self {
        Self {
            contribution_threshold_xdr: item.contribution_threshold_xdr,
            one_third_participation_milestone_xdr: item.one_third_participation_milestone_xdr,
            full_participation_milestone_xdr: item.full_participation_milestone_xdr,
        }
    }
}
impl From<pb_api::NeuronsFundMatchedFundingCurveCoefficients>
    for pb::NeuronsFundMatchedFundingCurveCoefficients
{
    fn from(item: pb_api::NeuronsFundMatchedFundingCurveCoefficients) -> Self {
        Self {
            contribution_threshold_xdr: item.contribution_threshold_xdr,
            one_third_participation_milestone_xdr: item.one_third_participation_milestone_xdr,
            full_participation_milestone_xdr: item.full_participation_milestone_xdr,
        }
    }
}

impl From<pb::NeuronsFundEconomics> for pb_api::NeuronsFundEconomics {
    fn from(item: pb::NeuronsFundEconomics) -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: item
                .max_theoretical_neurons_fund_participation_amount_xdr,
            neurons_fund_matched_funding_curve_coefficients: item
                .neurons_fund_matched_funding_curve_coefficients
                .map(|x| x.into()),
            minimum_icp_xdr_rate: item.minimum_icp_xdr_rate,
            maximum_icp_xdr_rate: item.maximum_icp_xdr_rate,
        }
    }
}
impl From<pb_api::NeuronsFundEconomics> for pb::NeuronsFundEconomics {
    fn from(item: pb_api::NeuronsFundEconomics) -> Self {
        Self {
            max_theoretical_neurons_fund_participation_amount_xdr: item
                .max_theoretical_neurons_fund_participation_amount_xdr,
            neurons_fund_matched_funding_curve_coefficients: item
                .neurons_fund_matched_funding_curve_coefficients
                .map(|x| x.into()),
            minimum_icp_xdr_rate: item.minimum_icp_xdr_rate,
            maximum_icp_xdr_rate: item.maximum_icp_xdr_rate,
        }
    }
}

impl From<pb::RewardEvent> for pb_api::RewardEvent {
    fn from(item: pb::RewardEvent) -> Self {
        Self {
            day_after_genesis: item.day_after_genesis,
            actual_timestamp_seconds: item.actual_timestamp_seconds,
            settled_proposals: item.settled_proposals,
            distributed_e8s_equivalent: item.distributed_e8s_equivalent,
            total_available_e8s_equivalent: item.total_available_e8s_equivalent,
            latest_round_available_e8s_equivalent: item.latest_round_available_e8s_equivalent,
            rounds_since_last_distribution: item.rounds_since_last_distribution,
        }
    }
}
impl From<pb_api::RewardEvent> for pb::RewardEvent {
    fn from(item: pb_api::RewardEvent) -> Self {
        Self {
            day_after_genesis: item.day_after_genesis,
            actual_timestamp_seconds: item.actual_timestamp_seconds,
            settled_proposals: item.settled_proposals,
            distributed_e8s_equivalent: item.distributed_e8s_equivalent,
            total_available_e8s_equivalent: item.total_available_e8s_equivalent,
            latest_round_available_e8s_equivalent: item.latest_round_available_e8s_equivalent,
            rounds_since_last_distribution: item.rounds_since_last_distribution,
        }
    }
}

impl From<pb::KnownNeuron> for pb_api::KnownNeuron {
    fn from(item: pb::KnownNeuron) -> Self {
        Self {
            id: item.id,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
        }
    }
}
impl From<pb_api::KnownNeuron> for pb::KnownNeuron {
    fn from(item: pb_api::KnownNeuron) -> Self {
        Self {
            id: item.id,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
        }
    }
}

impl From<pb::Topic> for pb_api::TopicToFollow {
    fn from(topic: pb::Topic) -> Self {
        match topic {
            pb::Topic::Unspecified => pb_api::TopicToFollow::CatchAll,
            pb::Topic::NeuronManagement => pb_api::TopicToFollow::NeuronManagement,
            pb::Topic::ExchangeRate => pb_api::TopicToFollow::ExchangeRate,
            pb::Topic::NetworkEconomics => pb_api::TopicToFollow::NetworkEconomics,
            pb::Topic::Governance => pb_api::TopicToFollow::Governance,
            pb::Topic::NodeAdmin => pb_api::TopicToFollow::NodeAdmin,
            pb::Topic::ParticipantManagement => pb_api::TopicToFollow::ParticipantManagement,
            pb::Topic::SubnetManagement => pb_api::TopicToFollow::SubnetManagement,
            pb::Topic::ApplicationCanisterManagement => {
                pb_api::TopicToFollow::ApplicationCanisterManagement
            }
            pb::Topic::Kyc => pb_api::TopicToFollow::Kyc,
            pb::Topic::NodeProviderRewards => pb_api::TopicToFollow::NodeProviderRewards,
            pb::Topic::IcOsVersionDeployment => pb_api::TopicToFollow::IcOsVersionDeployment,
            pb::Topic::IcOsVersionElection => pb_api::TopicToFollow::IcOsVersionElection,
            pb::Topic::SnsAndCommunityFund => pb_api::TopicToFollow::SnsAndCommunityFund,
            pb::Topic::ApiBoundaryNodeManagement => {
                pb_api::TopicToFollow::ApiBoundaryNodeManagement
            }
            pb::Topic::SubnetRental => pb_api::TopicToFollow::SubnetRental,
            pb::Topic::ProtocolCanisterManagement => {
                pb_api::TopicToFollow::ProtocolCanisterManagement
            }
            pb::Topic::ServiceNervousSystemManagement => {
                pb_api::TopicToFollow::ServiceNervousSystemManagement
            }
        }
    }
}

impl From<pb_api::TopicToFollow> for pb::Topic {
    fn from(topic: pb_api::TopicToFollow) -> Self {
        match topic {
            pb_api::TopicToFollow::CatchAll => pb::Topic::Unspecified,
            pb_api::TopicToFollow::NeuronManagement => pb::Topic::NeuronManagement,
            pb_api::TopicToFollow::ExchangeRate => pb::Topic::ExchangeRate,
            pb_api::TopicToFollow::NetworkEconomics => pb::Topic::NetworkEconomics,
            pb_api::TopicToFollow::Governance => pb::Topic::Governance,
            pb_api::TopicToFollow::NodeAdmin => pb::Topic::NodeAdmin,
            pb_api::TopicToFollow::ParticipantManagement => pb::Topic::ParticipantManagement,
            pb_api::TopicToFollow::SubnetManagement => pb::Topic::SubnetManagement,
            pb_api::TopicToFollow::Kyc => pb::Topic::Kyc,
            pb_api::TopicToFollow::NodeProviderRewards => pb::Topic::NodeProviderRewards,
            pb_api::TopicToFollow::IcOsVersionDeployment => pb::Topic::IcOsVersionDeployment,
            pb_api::TopicToFollow::IcOsVersionElection => pb::Topic::IcOsVersionElection,
            pb_api::TopicToFollow::SnsAndCommunityFund => pb::Topic::SnsAndCommunityFund,
            pb_api::TopicToFollow::ApiBoundaryNodeManagement => {
                pb::Topic::ApiBoundaryNodeManagement
            }
            pb_api::TopicToFollow::SubnetRental => pb::Topic::SubnetRental,
            pb_api::TopicToFollow::ApplicationCanisterManagement => {
                pb::Topic::ApplicationCanisterManagement
            }
            pb_api::TopicToFollow::ProtocolCanisterManagement => {
                pb::Topic::ProtocolCanisterManagement
            }
            pb_api::TopicToFollow::ServiceNervousSystemManagement => {
                pb::Topic::ServiceNervousSystemManagement
            }
        }
    }
}

impl From<pb::KnownNeuronData> for pb_api::KnownNeuronData {
    fn from(item: pb::KnownNeuronData) -> Self {
        let committed_topics = Some(
            item.committed_topics
                .iter()
                .map(|&topic_i32| {
                    let topic = pb::Topic::try_from(topic_i32).ok();
                    topic.map(pb_api::TopicToFollow::from)
                })
                .collect(),
        );

        Self {
            name: item.name,
            description: item.description,
            links: Some(item.links),
            committed_topics,
        }
    }
}

impl From<pb_api::KnownNeuronData> for pb::KnownNeuronData {
    fn from(item: pb_api::KnownNeuronData) -> Self {
        let committed_topics = item
            .committed_topics
            .unwrap_or_default()
            .into_iter()
            .filter_map(|topic| topic.map(|topic| pb::Topic::from(topic) as i32))
            .collect();

        Self {
            name: item.name,
            description: item.description,
            committed_topics,
            links: item.links.unwrap_or_default(),
        }
    }
}

impl From<pb::OpenSnsTokenSwap> for pb_api::OpenSnsTokenSwap {
    fn from(item: pb::OpenSnsTokenSwap) -> Self {
        Self {
            target_swap_canister_id: item.target_swap_canister_id,
            params: item.params,
            community_fund_investment_e8s: item.community_fund_investment_e8s,
        }
    }
}
impl From<pb_api::OpenSnsTokenSwap> for pb::OpenSnsTokenSwap {
    fn from(item: pb_api::OpenSnsTokenSwap) -> Self {
        Self {
            target_swap_canister_id: item.target_swap_canister_id,
            params: item.params,
            community_fund_investment_e8s: item.community_fund_investment_e8s,
        }
    }
}

impl From<pb::CreateServiceNervousSystem> for pb_api::CreateServiceNervousSystem {
    fn from(item: pb::CreateServiceNervousSystem) -> Self {
        Self {
            name: item.name,
            description: item.description,
            url: item.url,
            logo: item.logo,
            fallback_controller_principal_ids: item.fallback_controller_principal_ids,
            dapp_canisters: item.dapp_canisters,
            initial_token_distribution: item.initial_token_distribution.map(|x| x.into()),
            swap_parameters: item.swap_parameters.map(|x| x.into()),
            ledger_parameters: item.ledger_parameters.map(|x| x.into()),
            governance_parameters: item.governance_parameters.map(|x| x.into()),
        }
    }
}
impl From<pb_api::CreateServiceNervousSystem> for pb::CreateServiceNervousSystem {
    fn from(item: pb_api::CreateServiceNervousSystem) -> Self {
        Self {
            name: item.name,
            description: item.description,
            url: item.url,
            logo: item.logo,
            fallback_controller_principal_ids: item.fallback_controller_principal_ids,
            dapp_canisters: item.dapp_canisters,
            initial_token_distribution: item.initial_token_distribution.map(|x| x.into()),
            swap_parameters: item.swap_parameters.map(|x| x.into()),
            ledger_parameters: item.ledger_parameters.map(|x| x.into()),
            governance_parameters: item.governance_parameters.map(|x| x.into()),
        }
    }
}

impl From<pb::create_service_nervous_system::InitialTokenDistribution>
    for pb_api::create_service_nervous_system::InitialTokenDistribution
{
    fn from(item: pb::create_service_nervous_system::InitialTokenDistribution) -> Self {
        Self {
            developer_distribution: item.developer_distribution.map(|x| x.into()),
            treasury_distribution: item.treasury_distribution.map(|x| x.into()),
            swap_distribution: item.swap_distribution.map(|x| x.into()),
        }
    }
}
impl From<pb_api::create_service_nervous_system::InitialTokenDistribution>
    for pb::create_service_nervous_system::InitialTokenDistribution
{
    fn from(item: pb_api::create_service_nervous_system::InitialTokenDistribution) -> Self {
        Self {
            developer_distribution: item.developer_distribution.map(|x| x.into()),
            treasury_distribution: item.treasury_distribution.map(|x| x.into()),
            swap_distribution: item.swap_distribution.map(|x| x.into()),
        }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::DeveloperDistribution>
    for pb_api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution
{
    fn from(
        item: pb::create_service_nervous_system::initial_token_distribution::DeveloperDistribution,
    ) -> Self {
        Self {
            developer_neurons: item
                .developer_neurons
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}
impl From<pb_api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::DeveloperDistribution
{
    fn from(
        item: pb_api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution,
    ) -> Self {
        Self {
            developer_neurons: item
                .developer_neurons
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution> for pb_api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution {
    fn from(item: pb::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution) -> Self {
        Self {
            controller: item.controller,
            dissolve_delay: item.dissolve_delay,
            memo: item.memo,
            stake: item.stake,
            vesting_period: item.vesting_period
        }
    }
}
impl From<pb_api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution> for pb::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution {
    fn from(item: pb_api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution) -> Self {
        Self {
            controller: item.controller,
            dissolve_delay: item.dissolve_delay,
            memo: item.memo,
            stake: item.stake,
            vesting_period: item.vesting_period
        }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::TreasuryDistribution>
    for pb_api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution
{
    fn from(
        item: pb::create_service_nervous_system::initial_token_distribution::TreasuryDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}
impl From<pb_api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::TreasuryDistribution
{
    fn from(
        item: pb_api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::SwapDistribution>
    for pb_api::create_service_nervous_system::initial_token_distribution::SwapDistribution
{
    fn from(
        item: pb::create_service_nervous_system::initial_token_distribution::SwapDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}
impl From<pb_api::create_service_nervous_system::initial_token_distribution::SwapDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::SwapDistribution
{
    fn from(
        item: pb_api::create_service_nervous_system::initial_token_distribution::SwapDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}

impl From<pb::create_service_nervous_system::SwapParameters>
    for pb_api::create_service_nervous_system::SwapParameters
{
    fn from(item: pb::create_service_nervous_system::SwapParameters) -> Self {
        Self {
            minimum_participants: item.minimum_participants,
            minimum_icp: item.minimum_icp,
            maximum_icp: item.maximum_icp,
            minimum_direct_participation_icp: item.minimum_direct_participation_icp,
            maximum_direct_participation_icp: item.maximum_direct_participation_icp,
            minimum_participant_icp: item.minimum_participant_icp,
            maximum_participant_icp: item.maximum_participant_icp,
            neuron_basket_construction_parameters: item
                .neuron_basket_construction_parameters
                .map(|x| x.into()),
            confirmation_text: item.confirmation_text,
            restricted_countries: item.restricted_countries,
            start_time: item.start_time,
            duration: item.duration,
            neurons_fund_investment_icp: item.neurons_fund_investment_icp,
            neurons_fund_participation: item.neurons_fund_participation,
        }
    }
}
impl From<pb_api::create_service_nervous_system::SwapParameters>
    for pb::create_service_nervous_system::SwapParameters
{
    fn from(item: pb_api::create_service_nervous_system::SwapParameters) -> Self {
        Self {
            minimum_participants: item.minimum_participants,
            minimum_icp: item.minimum_icp,
            maximum_icp: item.maximum_icp,
            minimum_direct_participation_icp: item.minimum_direct_participation_icp,
            maximum_direct_participation_icp: item.maximum_direct_participation_icp,
            minimum_participant_icp: item.minimum_participant_icp,
            maximum_participant_icp: item.maximum_participant_icp,
            neuron_basket_construction_parameters: item
                .neuron_basket_construction_parameters
                .map(|x| x.into()),
            confirmation_text: item.confirmation_text,
            restricted_countries: item.restricted_countries,
            start_time: item.start_time,
            duration: item.duration,
            neurons_fund_investment_icp: item.neurons_fund_investment_icp,
            neurons_fund_participation: item.neurons_fund_participation,
        }
    }
}

impl From<pb::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters>
    for pb_api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters
{
    fn from(
        item: pb::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters,
    ) -> Self {
        Self {
            count: item.count,
            dissolve_delay_interval: item.dissolve_delay_interval,
        }
    }
}
impl
    From<pb_api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters>
    for pb::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters
{
    fn from(
        item: pb_api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters,
    ) -> Self {
        Self {
            count: item.count,
            dissolve_delay_interval: item.dissolve_delay_interval,
        }
    }
}

impl From<pb::create_service_nervous_system::LedgerParameters>
    for pb_api::create_service_nervous_system::LedgerParameters
{
    fn from(item: pb::create_service_nervous_system::LedgerParameters) -> Self {
        Self {
            transaction_fee: item.transaction_fee,
            token_name: item.token_name,
            token_symbol: item.token_symbol,
            token_logo: item.token_logo,
        }
    }
}
impl From<pb_api::create_service_nervous_system::LedgerParameters>
    for pb::create_service_nervous_system::LedgerParameters
{
    fn from(item: pb_api::create_service_nervous_system::LedgerParameters) -> Self {
        Self {
            transaction_fee: item.transaction_fee,
            token_name: item.token_name,
            token_symbol: item.token_symbol,
            token_logo: item.token_logo,
        }
    }
}

impl From<pb::create_service_nervous_system::GovernanceParameters>
    for pb_api::create_service_nervous_system::GovernanceParameters
{
    fn from(item: pb::create_service_nervous_system::GovernanceParameters) -> Self {
        Self {
            proposal_rejection_fee: item.proposal_rejection_fee,
            proposal_initial_voting_period: item.proposal_initial_voting_period,
            proposal_wait_for_quiet_deadline_increase: item
                .proposal_wait_for_quiet_deadline_increase,
            neuron_minimum_stake: item.neuron_minimum_stake,
            neuron_minimum_dissolve_delay_to_vote: item.neuron_minimum_dissolve_delay_to_vote,
            neuron_maximum_dissolve_delay: item.neuron_maximum_dissolve_delay,
            neuron_maximum_dissolve_delay_bonus: item.neuron_maximum_dissolve_delay_bonus,
            neuron_maximum_age_for_age_bonus: item.neuron_maximum_age_for_age_bonus,
            neuron_maximum_age_bonus: item.neuron_maximum_age_bonus,
            voting_reward_parameters: item.voting_reward_parameters.map(|x| x.into()),
        }
    }
}
impl From<pb_api::create_service_nervous_system::GovernanceParameters>
    for pb::create_service_nervous_system::GovernanceParameters
{
    fn from(item: pb_api::create_service_nervous_system::GovernanceParameters) -> Self {
        Self {
            proposal_rejection_fee: item.proposal_rejection_fee,
            proposal_initial_voting_period: item.proposal_initial_voting_period,
            proposal_wait_for_quiet_deadline_increase: item
                .proposal_wait_for_quiet_deadline_increase,
            neuron_minimum_stake: item.neuron_minimum_stake,
            neuron_minimum_dissolve_delay_to_vote: item.neuron_minimum_dissolve_delay_to_vote,
            neuron_maximum_dissolve_delay: item.neuron_maximum_dissolve_delay,
            neuron_maximum_dissolve_delay_bonus: item.neuron_maximum_dissolve_delay_bonus,
            neuron_maximum_age_for_age_bonus: item.neuron_maximum_age_for_age_bonus,
            neuron_maximum_age_bonus: item.neuron_maximum_age_bonus,
            voting_reward_parameters: item.voting_reward_parameters.map(|x| x.into()),
        }
    }
}

impl From<pb::create_service_nervous_system::governance_parameters::VotingRewardParameters>
    for pb_api::create_service_nervous_system::governance_parameters::VotingRewardParameters
{
    fn from(
        item: pb::create_service_nervous_system::governance_parameters::VotingRewardParameters,
    ) -> Self {
        Self {
            initial_reward_rate: item.initial_reward_rate,
            final_reward_rate: item.final_reward_rate,
            reward_rate_transition_duration: item.reward_rate_transition_duration,
        }
    }
}
impl From<pb_api::create_service_nervous_system::governance_parameters::VotingRewardParameters>
    for pb::create_service_nervous_system::governance_parameters::VotingRewardParameters
{
    fn from(
        item: pb_api::create_service_nervous_system::governance_parameters::VotingRewardParameters,
    ) -> Self {
        Self {
            initial_reward_rate: item.initial_reward_rate,
            final_reward_rate: item.final_reward_rate,
            reward_rate_transition_duration: item.reward_rate_transition_duration,
        }
    }
}

impl From<pb::InstallCode> for pb_api::InstallCode {
    fn from(item: pb::InstallCode) -> Self {
        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
            wasm_module_hash: item.wasm_module_hash,
            arg_hash: item.arg_hash,
        }
    }
}
impl From<pb_api::InstallCode> for pb::InstallCode {
    fn from(item: pb_api::InstallCode) -> Self {
        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
            // Note: the api->internal conversion here only happens when decoding from protobuf in
            // canister_init.
            wasm_module: None,
            arg: None,
            wasm_module_hash: item.wasm_module_hash,
            arg_hash: item.arg_hash,
        }
    }
}
impl From<pb_api::InstallCodeRequest> for pb::InstallCode {
    fn from(item: pb_api::InstallCodeRequest) -> Self {
        let wasm_module_hash = item
            .wasm_module
            .as_ref()
            .map(|wasm_module| Sha256::hash(wasm_module).to_vec());
        let arg_hash = match item.arg.as_ref() {
            Some(arg) => {
                // We could calculate the hash of an empty arg, but it would be confusing for the
                // proposal reviewers, since the arg_hash is the only thing they can see, and it would
                // not be obvious that the arg is empty.
                if arg.is_empty() {
                    Some(vec![])
                } else {
                    Some(Sha256::hash(arg).to_vec())
                }
            }
            None => Some(vec![]),
        };

        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            wasm_module: item.wasm_module,
            arg: item.arg,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
            wasm_module_hash,
            arg_hash,
        }
    }
}

impl From<pb::install_code::CanisterInstallMode> for pb_api::install_code::CanisterInstallMode {
    fn from(item: pb::install_code::CanisterInstallMode) -> Self {
        match item {
            pb::install_code::CanisterInstallMode::Unspecified => {
                pb_api::install_code::CanisterInstallMode::Unspecified
            }
            pb::install_code::CanisterInstallMode::Install => {
                pb_api::install_code::CanisterInstallMode::Install
            }
            pb::install_code::CanisterInstallMode::Reinstall => {
                pb_api::install_code::CanisterInstallMode::Reinstall
            }
            pb::install_code::CanisterInstallMode::Upgrade => {
                pb_api::install_code::CanisterInstallMode::Upgrade
            }
        }
    }
}
impl From<pb_api::install_code::CanisterInstallMode> for pb::install_code::CanisterInstallMode {
    fn from(item: pb_api::install_code::CanisterInstallMode) -> Self {
        match item {
            pb_api::install_code::CanisterInstallMode::Unspecified => {
                pb::install_code::CanisterInstallMode::Unspecified
            }
            pb_api::install_code::CanisterInstallMode::Install => {
                pb::install_code::CanisterInstallMode::Install
            }
            pb_api::install_code::CanisterInstallMode::Reinstall => {
                pb::install_code::CanisterInstallMode::Reinstall
            }
            pb_api::install_code::CanisterInstallMode::Upgrade => {
                pb::install_code::CanisterInstallMode::Upgrade
            }
        }
    }
}

impl From<pb::StopOrStartCanister> for pb_api::StopOrStartCanister {
    fn from(item: pb::StopOrStartCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            action: item.action,
        }
    }
}

impl From<pb_api::StopOrStartCanister> for pb::StopOrStartCanister {
    fn from(item: pb_api::StopOrStartCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            action: item.action,
        }
    }
}

impl From<pb::stop_or_start_canister::CanisterAction>
    for pb_api::stop_or_start_canister::CanisterAction
{
    fn from(item: pb::stop_or_start_canister::CanisterAction) -> Self {
        match item {
            pb::stop_or_start_canister::CanisterAction::Unspecified => {
                pb_api::stop_or_start_canister::CanisterAction::Unspecified
            }
            pb::stop_or_start_canister::CanisterAction::Stop => {
                pb_api::stop_or_start_canister::CanisterAction::Stop
            }
            pb::stop_or_start_canister::CanisterAction::Start => {
                pb_api::stop_or_start_canister::CanisterAction::Start
            }
        }
    }
}

impl From<pb_api::stop_or_start_canister::CanisterAction>
    for pb::stop_or_start_canister::CanisterAction
{
    fn from(item: pb_api::stop_or_start_canister::CanisterAction) -> Self {
        match item {
            pb_api::stop_or_start_canister::CanisterAction::Unspecified => {
                pb::stop_or_start_canister::CanisterAction::Unspecified
            }
            pb_api::stop_or_start_canister::CanisterAction::Stop => {
                pb::stop_or_start_canister::CanisterAction::Stop
            }
            pb_api::stop_or_start_canister::CanisterAction::Start => {
                pb::stop_or_start_canister::CanisterAction::Start
            }
        }
    }
}

impl From<pb::UpdateCanisterSettings> for pb_api::UpdateCanisterSettings {
    fn from(item: pb::UpdateCanisterSettings) -> Self {
        Self {
            canister_id: item.canister_id,
            settings: item.settings.map(|x| x.into()),
        }
    }
}

impl From<pb_api::UpdateCanisterSettings> for pb::UpdateCanisterSettings {
    fn from(item: pb_api::UpdateCanisterSettings) -> Self {
        Self {
            canister_id: item.canister_id,
            settings: item.settings.map(|x| x.into()),
        }
    }
}

impl From<pb::FulfillSubnetRentalRequest> for pb_api::FulfillSubnetRentalRequest {
    fn from(item: pb::FulfillSubnetRentalRequest) -> Self {
        Self {
            user: item.user,
            node_ids: Some(item.node_ids),
            replica_version_id: Some(item.replica_version_id),
        }
    }
}

impl From<pb_api::FulfillSubnetRentalRequest> for pb::FulfillSubnetRentalRequest {
    fn from(item: pb_api::FulfillSubnetRentalRequest) -> Self {
        Self {
            user: item.user,
            node_ids: item.node_ids.unwrap_or_default(),
            replica_version_id: item.replica_version_id.unwrap_or_default(),
        }
    }
}

impl From<pb::DeclareAlternativeReplicaVirtualMachineSoftwareSet>
    for pb_api::DeclareAlternativeReplicaVirtualMachineSoftwareSet
{
    fn from(item: pb::DeclareAlternativeReplicaVirtualMachineSoftwareSet) -> Self {
        Self {
            chip_ids: Some(item.chip_ids),
            hexidecimal_recovery_rootfs_fingerprint: Some(
                item.hexidecimal_recovery_rootfs_fingerprint,
            ),
            base_guest_launch_measurements: item
                .base_guest_launch_measurements
                .map(|item| item.into()),
        }
    }
}

impl From<pb_api::DeclareAlternativeReplicaVirtualMachineSoftwareSet>
    for pb::DeclareAlternativeReplicaVirtualMachineSoftwareSet
{
    fn from(item: pb_api::DeclareAlternativeReplicaVirtualMachineSoftwareSet) -> Self {
        Self {
            chip_ids: item.chip_ids.unwrap_or_default(),
            hexidecimal_recovery_rootfs_fingerprint: item
                .hexidecimal_recovery_rootfs_fingerprint
                .unwrap_or_default(),
            base_guest_launch_measurements: item
                .base_guest_launch_measurements
                .map(|item| item.into()),
        }
    }
}

impl From<pb::GuestLaunchMeasurements> for pb_api::GuestLaunchMeasurements {
    fn from(item: pb::GuestLaunchMeasurements) -> Self {
        Self {
            guest_launch_measurements: Some(
                item.guest_launch_measurements
                    .into_iter()
                    .map(|item| item.into())
                    .collect(),
            ),
        }
    }
}

impl From<pb_api::GuestLaunchMeasurements> for pb::GuestLaunchMeasurements {
    fn from(item: pb_api::GuestLaunchMeasurements) -> Self {
        Self {
            guest_launch_measurements: item
                .guest_launch_measurements
                .unwrap_or_default()
                .into_iter()
                .map(|item| item.into())
                .collect(),
        }
    }
}

impl From<pb::GuestLaunchMeasurement> for pb_api::GuestLaunchMeasurement {
    fn from(item: pb::GuestLaunchMeasurement) -> Self {
        Self {
            measurement: Some(item.measurement),
            metadata: item.metadata.map(|item| item.into()),
        }
    }
}

impl From<pb_api::GuestLaunchMeasurement> for pb::GuestLaunchMeasurement {
    fn from(item: pb_api::GuestLaunchMeasurement) -> Self {
        Self {
            measurement: item.measurement.unwrap_or_default(),
            metadata: item.metadata.map(|item| item.into()),
        }
    }
}

impl From<pb::GuestLaunchMeasurementMetadata> for pb_api::GuestLaunchMeasurementMetadata {
    fn from(item: pb::GuestLaunchMeasurementMetadata) -> Self {
        Self {
            kernel_cmdline: Some(item.kernel_cmdline),
        }
    }
}

impl From<pb_api::GuestLaunchMeasurementMetadata> for pb::GuestLaunchMeasurementMetadata {
    fn from(item: pb_api::GuestLaunchMeasurementMetadata) -> Self {
        Self {
            kernel_cmdline: item.kernel_cmdline.unwrap_or_default(),
        }
    }
}

impl From<pb::update_canister_settings::CanisterSettings>
    for pb_api::update_canister_settings::CanisterSettings
{
    fn from(item: pb::update_canister_settings::CanisterSettings) -> Self {
        Self {
            controllers: item.controllers.map(|x| x.into()),
            compute_allocation: item.compute_allocation,
            memory_allocation: item.memory_allocation,
            freezing_threshold: item.freezing_threshold,
            log_visibility: item.log_visibility,
            wasm_memory_limit: item.wasm_memory_limit,
            wasm_memory_threshold: item.wasm_memory_threshold,
        }
    }
}

impl From<pb_api::update_canister_settings::CanisterSettings>
    for pb::update_canister_settings::CanisterSettings
{
    fn from(item: pb_api::update_canister_settings::CanisterSettings) -> Self {
        Self {
            controllers: item.controllers.map(|x| x.into()),
            compute_allocation: item.compute_allocation,
            memory_allocation: item.memory_allocation,
            freezing_threshold: item.freezing_threshold,
            log_visibility: item.log_visibility,
            wasm_memory_limit: item.wasm_memory_limit,
            wasm_memory_threshold: item.wasm_memory_threshold,
        }
    }
}

impl From<pb::update_canister_settings::Controllers>
    for pb_api::update_canister_settings::Controllers
{
    fn from(item: pb::update_canister_settings::Controllers) -> Self {
        Self {
            controllers: item.controllers,
        }
    }
}

impl From<pb_api::update_canister_settings::Controllers>
    for pb::update_canister_settings::Controllers
{
    fn from(item: pb_api::update_canister_settings::Controllers) -> Self {
        Self {
            controllers: item.controllers,
        }
    }
}

impl From<pb::update_canister_settings::LogVisibility>
    for pb_api::update_canister_settings::LogVisibility
{
    fn from(item: pb::update_canister_settings::LogVisibility) -> Self {
        match item {
            pb::update_canister_settings::LogVisibility::Unspecified => {
                pb_api::update_canister_settings::LogVisibility::Unspecified
            }
            pb::update_canister_settings::LogVisibility::Controllers => {
                pb_api::update_canister_settings::LogVisibility::Controllers
            }
            pb::update_canister_settings::LogVisibility::Public => {
                pb_api::update_canister_settings::LogVisibility::Public
            }
        }
    }
}

impl From<pb_api::update_canister_settings::LogVisibility>
    for pb::update_canister_settings::LogVisibility
{
    fn from(item: pb_api::update_canister_settings::LogVisibility) -> Self {
        match item {
            pb_api::update_canister_settings::LogVisibility::Unspecified => {
                pb::update_canister_settings::LogVisibility::Unspecified
            }
            pb_api::update_canister_settings::LogVisibility::Controllers => {
                pb::update_canister_settings::LogVisibility::Controllers
            }
            pb_api::update_canister_settings::LogVisibility::Public => {
                pb::update_canister_settings::LogVisibility::Public
            }
        }
    }
}

impl From<pb_api::governance::NeuronInFlightCommand> for pb::governance::NeuronInFlightCommand {
    fn from(item: pb_api::governance::NeuronInFlightCommand) -> Self {
        Self {
            timestamp: item.timestamp,
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::neuron_in_flight_command::SyncCommand>
    for pb_api::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: pb::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}
impl From<pb_api::governance::neuron_in_flight_command::SyncCommand>
    for pb::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: pb_api::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}

impl From<pb_api::governance::neuron_in_flight_command::Command>
    for pb::governance::neuron_in_flight_command::Command
{
    fn from(item: pb_api::governance::neuron_in_flight_command::Command) -> Self {
        match item {
            pb_api::governance::neuron_in_flight_command::Command::Disburse(v) => {
                pb::governance::neuron_in_flight_command::Command::Disburse(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Split(v) => {
                pb::governance::neuron_in_flight_command::Command::Split(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::DisburseToNeuron(v) => {
                pb::governance::neuron_in_flight_command::Command::DisburseToNeuron(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::MergeMaturity(v) => {
                pb::governance::neuron_in_flight_command::Command::MergeMaturity(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v) => {
                pb::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Configure(v) => {
                pb::governance::neuron_in_flight_command::Command::Configure(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Merge(v) => {
                pb::governance::neuron_in_flight_command::Command::Merge(v.into())
            }
            pb_api::governance::neuron_in_flight_command::Command::Spawn(v) => {
                pb::governance::neuron_in_flight_command::Command::Spawn(v)
            }
            pb_api::governance::neuron_in_flight_command::Command::SyncCommand(v) => {
                pb::governance::neuron_in_flight_command::Command::SyncCommand(v.into())
            }
        }
    }
}

impl From<pb::governance::GovernanceCachedMetrics> for pb_api::governance::GovernanceCachedMetrics {
    fn from(item: pb::governance::GovernanceCachedMetrics) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            total_supply_icp: item.total_supply_icp,
            dissolving_neurons_count: item.dissolving_neurons_count,
            dissolving_neurons_e8s_buckets: item.dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets: item.dissolving_neurons_count_buckets,
            not_dissolving_neurons_count: item.not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets: item.not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets: item.not_dissolving_neurons_count_buckets,
            dissolved_neurons_count: item.dissolved_neurons_count,
            dissolved_neurons_e8s: item.dissolved_neurons_e8s,
            garbage_collectable_neurons_count: item.garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count: item.neurons_with_invalid_stake_count,
            total_staked_e8s: item.total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count: item
                .neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s: item
                .neurons_with_less_than_6_months_dissolve_delay_e8s,
            community_fund_total_staked_e8s: item.community_fund_total_staked_e8s,
            community_fund_total_maturity_e8s_equivalent: item
                .community_fund_total_maturity_e8s_equivalent,
            neurons_fund_total_active_neurons: item.neurons_fund_total_active_neurons,
            total_locked_e8s: item.total_locked_e8s,
            total_maturity_e8s_equivalent: item.total_maturity_e8s_equivalent,
            total_staked_maturity_e8s_equivalent: item.total_staked_maturity_e8s_equivalent,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets: item
                .dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            dissolving_neurons_staked_maturity_e8s_equivalent_sum: item
                .dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: item
                .not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: item
                .not_dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            seed_neuron_count: item.seed_neuron_count,
            ect_neuron_count: item.ect_neuron_count,
            total_staked_e8s_seed: item.total_staked_e8s_seed,
            total_staked_e8s_ect: item.total_staked_e8s_ect,
            total_staked_maturity_e8s_equivalent_seed: item
                .total_staked_maturity_e8s_equivalent_seed,
            total_staked_maturity_e8s_equivalent_ect: item.total_staked_maturity_e8s_equivalent_ect,
            dissolving_neurons_e8s_buckets_seed: item.dissolving_neurons_e8s_buckets_seed,
            dissolving_neurons_e8s_buckets_ect: item.dissolving_neurons_e8s_buckets_ect,
            not_dissolving_neurons_e8s_buckets_seed: item.not_dissolving_neurons_e8s_buckets_seed,
            not_dissolving_neurons_e8s_buckets_ect: item.not_dissolving_neurons_e8s_buckets_ect,
            total_voting_power_non_self_authenticating_controller: item
                .total_voting_power_non_self_authenticating_controller,
            total_staked_e8s_non_self_authenticating_controller: item
                .total_staked_e8s_non_self_authenticating_controller,
            spawning_neurons_count: item.spawning_neurons_count,
            non_self_authenticating_controller_neuron_subset_metrics: item
                .non_self_authenticating_controller_neuron_subset_metrics
                .map(|x| x.into()),
            public_neuron_subset_metrics: item.public_neuron_subset_metrics.map(|x| x.into()),
            declining_voting_power_neuron_subset_metrics: item
                .declining_voting_power_neuron_subset_metrics
                .map(|x| x.into()),
            fully_lost_voting_power_neuron_subset_metrics: item
                .fully_lost_voting_power_neuron_subset_metrics
                .map(|x| x.into()),
        }
    }
}
impl From<pb_api::governance::GovernanceCachedMetrics> for pb::governance::GovernanceCachedMetrics {
    fn from(item: pb_api::governance::GovernanceCachedMetrics) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            total_supply_icp: item.total_supply_icp,
            dissolving_neurons_count: item.dissolving_neurons_count,
            dissolving_neurons_e8s_buckets: item.dissolving_neurons_e8s_buckets,
            dissolving_neurons_count_buckets: item.dissolving_neurons_count_buckets,
            not_dissolving_neurons_count: item.not_dissolving_neurons_count,
            not_dissolving_neurons_e8s_buckets: item.not_dissolving_neurons_e8s_buckets,
            not_dissolving_neurons_count_buckets: item.not_dissolving_neurons_count_buckets,
            dissolved_neurons_count: item.dissolved_neurons_count,
            dissolved_neurons_e8s: item.dissolved_neurons_e8s,
            garbage_collectable_neurons_count: item.garbage_collectable_neurons_count,
            neurons_with_invalid_stake_count: item.neurons_with_invalid_stake_count,
            total_staked_e8s: item.total_staked_e8s,
            neurons_with_less_than_6_months_dissolve_delay_count: item
                .neurons_with_less_than_6_months_dissolve_delay_count,
            neurons_with_less_than_6_months_dissolve_delay_e8s: item
                .neurons_with_less_than_6_months_dissolve_delay_e8s,
            community_fund_total_staked_e8s: item.community_fund_total_staked_e8s,
            community_fund_total_maturity_e8s_equivalent: item
                .community_fund_total_maturity_e8s_equivalent,
            neurons_fund_total_active_neurons: item.neurons_fund_total_active_neurons,
            total_locked_e8s: item.total_locked_e8s,
            total_maturity_e8s_equivalent: item.total_maturity_e8s_equivalent,
            total_staked_maturity_e8s_equivalent: item.total_staked_maturity_e8s_equivalent,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets: item
                .dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            dissolving_neurons_staked_maturity_e8s_equivalent_sum: item
                .dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: item
                .not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: item
                .not_dissolving_neurons_staked_maturity_e8s_equivalent_sum,
            seed_neuron_count: item.seed_neuron_count,
            ect_neuron_count: item.ect_neuron_count,
            total_staked_e8s_seed: item.total_staked_e8s_seed,
            total_staked_e8s_ect: item.total_staked_e8s_ect,
            total_staked_maturity_e8s_equivalent_seed: item
                .total_staked_maturity_e8s_equivalent_seed,
            total_staked_maturity_e8s_equivalent_ect: item.total_staked_maturity_e8s_equivalent_ect,
            dissolving_neurons_e8s_buckets_seed: item.dissolving_neurons_e8s_buckets_seed,
            dissolving_neurons_e8s_buckets_ect: item.dissolving_neurons_e8s_buckets_ect,
            not_dissolving_neurons_e8s_buckets_seed: item.not_dissolving_neurons_e8s_buckets_seed,
            not_dissolving_neurons_e8s_buckets_ect: item.not_dissolving_neurons_e8s_buckets_ect,
            total_voting_power_non_self_authenticating_controller: item
                .total_voting_power_non_self_authenticating_controller,
            total_staked_e8s_non_self_authenticating_controller: item
                .total_staked_e8s_non_self_authenticating_controller,
            spawning_neurons_count: item.spawning_neurons_count,
            non_self_authenticating_controller_neuron_subset_metrics: item
                .non_self_authenticating_controller_neuron_subset_metrics
                .map(|x| x.into()),
            public_neuron_subset_metrics: item.public_neuron_subset_metrics.map(|x| x.into()),
            declining_voting_power_neuron_subset_metrics: item
                .declining_voting_power_neuron_subset_metrics
                .map(|x| x.into()),
            fully_lost_voting_power_neuron_subset_metrics: item
                .fully_lost_voting_power_neuron_subset_metrics
                .map(|x| x.into()),
        }
    }
}

impl From<pb::governance::governance_cached_metrics::NeuronSubsetMetrics>
    for pb_api::governance::governance_cached_metrics::NeuronSubsetMetrics
{
    fn from(item: pb::governance::governance_cached_metrics::NeuronSubsetMetrics) -> Self {
        Self {
            count: item.count,

            total_staked_e8s: item.total_staked_e8s,
            total_staked_maturity_e8s_equivalent: item.total_staked_maturity_e8s_equivalent,
            total_maturity_e8s_equivalent: item.total_maturity_e8s_equivalent,

            total_voting_power: item.total_voting_power,
            total_deciding_voting_power: item.total_deciding_voting_power,
            total_potential_voting_power: item.total_potential_voting_power,

            count_buckets: item.count_buckets,

            staked_e8s_buckets: item.staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets: item.staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets: item.maturity_e8s_equivalent_buckets,

            voting_power_buckets: item.voting_power_buckets,
            deciding_voting_power_buckets: item.deciding_voting_power_buckets,
            potential_voting_power_buckets: item.potential_voting_power_buckets,
        }
    }
}
impl From<pb_api::governance::governance_cached_metrics::NeuronSubsetMetrics>
    for pb::governance::governance_cached_metrics::NeuronSubsetMetrics
{
    fn from(item: pb_api::governance::governance_cached_metrics::NeuronSubsetMetrics) -> Self {
        Self {
            count: item.count,

            total_staked_e8s: item.total_staked_e8s,
            total_staked_maturity_e8s_equivalent: item.total_staked_maturity_e8s_equivalent,
            total_maturity_e8s_equivalent: item.total_maturity_e8s_equivalent,

            total_voting_power: item.total_voting_power,
            total_deciding_voting_power: item.total_deciding_voting_power,
            total_potential_voting_power: item.total_potential_voting_power,

            count_buckets: item.count_buckets,

            staked_e8s_buckets: item.staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets: item.staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets: item.maturity_e8s_equivalent_buckets,

            voting_power_buckets: item.voting_power_buckets,
            deciding_voting_power_buckets: item.deciding_voting_power_buckets,
            potential_voting_power_buckets: item.potential_voting_power_buckets,
        }
    }
}

impl TryFrom<ic_node_rewards_canister_api::DateUtc> for pb::DateUtc {
    type Error = String;

    fn try_from(value: ic_node_rewards_canister_api::DateUtc) -> Result<Self, Self::Error> {
        let year = value.year.ok_or("Missing field: year")?;
        let month = value.month.ok_or("Missing field: month")?;
        let day = value.day.ok_or("Missing field: day")?;

        Ok(Self { year, month, day })
    }
}
impl From<pb::DateUtc> for pb_api::DateUtc {
    fn from(item: pb::DateUtc) -> Self {
        Self {
            year: item.year,
            month: item.month,
            day: item.day,
        }
    }
}
impl From<pb_api::DateUtc> for pb::DateUtc {
    fn from(item: pb_api::DateUtc) -> Self {
        Self {
            year: item.year,
            month: item.month,
            day: item.day,
        }
    }
}
impl From<pb::XdrConversionRate> for pb_api::XdrConversionRate {
    fn from(item: pb::XdrConversionRate) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            xdr_permyriad_per_icp: item.xdr_permyriad_per_icp,
        }
    }
}
impl From<pb_api::XdrConversionRate> for pb::XdrConversionRate {
    fn from(item: pb_api::XdrConversionRate) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            xdr_permyriad_per_icp: item.xdr_permyriad_per_icp,
        }
    }
}

impl From<pb::ListKnownNeuronsResponse> for pb_api::ListKnownNeuronsResponse {
    fn from(item: pb::ListKnownNeuronsResponse) -> Self {
        Self {
            known_neurons: item.known_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::ListKnownNeuronsResponse> for pb::ListKnownNeuronsResponse {
    fn from(item: pb_api::ListKnownNeuronsResponse) -> Self {
        Self {
            known_neurons: item.known_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ListNodeProvidersResponse> for pb_api::ListNodeProvidersResponse {
    fn from(item: pb::ListNodeProvidersResponse) -> Self {
        Self {
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::ListNodeProvidersResponse> for pb::ListNodeProvidersResponse {
    fn from(item: pb_api::ListNodeProvidersResponse) -> Self {
        Self {
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb::MonthlyNodeProviderRewards> for pb_api::MonthlyNodeProviderRewards {
    fn from(item: pb::MonthlyNodeProviderRewards) -> Self {
        Self {
            timestamp: item.timestamp,
            start_date: item.start_date.map(|x| x.into()),
            end_date: item.end_date.map(|x| x.into()),
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            minimum_xdr_permyriad_per_icp: item.minimum_xdr_permyriad_per_icp,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            registry_version: item.registry_version,
            algorithm_version: item.algorithm_version,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::MonthlyNodeProviderRewards> for pb::MonthlyNodeProviderRewards {
    fn from(item: pb_api::MonthlyNodeProviderRewards) -> Self {
        Self {
            timestamp: item.timestamp,
            start_date: item.start_date.map(|x| x.into()),
            end_date: item.end_date.map(|x| x.into()),
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            minimum_xdr_permyriad_per_icp: item.minimum_xdr_permyriad_per_icp,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            registry_version: item.registry_version,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
            algorithm_version: item.algorithm_version,
        }
    }
}

impl From<pb::SettleCommunityFundParticipation> for pb_api::SettleCommunityFundParticipation {
    fn from(item: pb::SettleCommunityFundParticipation) -> Self {
        Self {
            open_sns_token_swap_proposal_id: item.open_sns_token_swap_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::SettleCommunityFundParticipation> for pb::SettleCommunityFundParticipation {
    fn from(item: pb_api::SettleCommunityFundParticipation) -> Self {
        Self {
            open_sns_token_swap_proposal_id: item.open_sns_token_swap_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_community_fund_participation::Committed>
    for pb_api::settle_community_fund_participation::Committed
{
    fn from(item: pb::settle_community_fund_participation::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_contribution_icp_e8s: item.total_direct_contribution_icp_e8s,
            total_neurons_fund_contribution_icp_e8s: item.total_neurons_fund_contribution_icp_e8s,
        }
    }
}
impl From<pb_api::settle_community_fund_participation::Committed>
    for pb::settle_community_fund_participation::Committed
{
    fn from(item: pb_api::settle_community_fund_participation::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_contribution_icp_e8s: item.total_direct_contribution_icp_e8s,
            total_neurons_fund_contribution_icp_e8s: item.total_neurons_fund_contribution_icp_e8s,
        }
    }
}

impl From<pb::settle_community_fund_participation::Aborted>
    for pb_api::settle_community_fund_participation::Aborted
{
    fn from(_: pb::settle_community_fund_participation::Aborted) -> Self {
        Self {}
    }
}
impl From<pb_api::settle_community_fund_participation::Aborted>
    for pb::settle_community_fund_participation::Aborted
{
    fn from(_: pb_api::settle_community_fund_participation::Aborted) -> Self {
        Self {}
    }
}

impl From<pb::settle_community_fund_participation::Result>
    for pb_api::settle_community_fund_participation::Result
{
    fn from(item: pb::settle_community_fund_participation::Result) -> Self {
        match item {
            pb::settle_community_fund_participation::Result::Committed(v) => {
                pb_api::settle_community_fund_participation::Result::Committed(v.into())
            }
            pb::settle_community_fund_participation::Result::Aborted(v) => {
                pb_api::settle_community_fund_participation::Result::Aborted(v.into())
            }
        }
    }
}
impl From<pb_api::settle_community_fund_participation::Result>
    for pb::settle_community_fund_participation::Result
{
    fn from(item: pb_api::settle_community_fund_participation::Result) -> Self {
        match item {
            pb_api::settle_community_fund_participation::Result::Committed(v) => {
                pb::settle_community_fund_participation::Result::Committed(v.into())
            }
            pb_api::settle_community_fund_participation::Result::Aborted(v) => {
                pb::settle_community_fund_participation::Result::Aborted(v.into())
            }
        }
    }
}

impl From<pb::SettleNeuronsFundParticipationRequest>
    for pb_api::SettleNeuronsFundParticipationRequest
{
    fn from(item: pb::SettleNeuronsFundParticipationRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::SettleNeuronsFundParticipationRequest>
    for pb::SettleNeuronsFundParticipationRequest
{
    fn from(item: pb_api::SettleNeuronsFundParticipationRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_neurons_fund_participation_request::Committed>
    for pb_api::settle_neurons_fund_participation_request::Committed
{
    fn from(item: pb::settle_neurons_fund_participation_request::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_participation_icp_e8s: item.total_direct_participation_icp_e8s,
            total_neurons_fund_participation_icp_e8s: item.total_neurons_fund_participation_icp_e8s,
        }
    }
}
impl From<pb_api::settle_neurons_fund_participation_request::Committed>
    for pb::settle_neurons_fund_participation_request::Committed
{
    fn from(item: pb_api::settle_neurons_fund_participation_request::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_participation_icp_e8s: item.total_direct_participation_icp_e8s,
            total_neurons_fund_participation_icp_e8s: item.total_neurons_fund_participation_icp_e8s,
        }
    }
}

impl From<pb::settle_neurons_fund_participation_request::Aborted>
    for pb_api::settle_neurons_fund_participation_request::Aborted
{
    fn from(_: pb::settle_neurons_fund_participation_request::Aborted) -> Self {
        Self {}
    }
}
impl From<pb_api::settle_neurons_fund_participation_request::Aborted>
    for pb::settle_neurons_fund_participation_request::Aborted
{
    fn from(_: pb_api::settle_neurons_fund_participation_request::Aborted) -> Self {
        Self {}
    }
}

impl From<pb::settle_neurons_fund_participation_request::Result>
    for pb_api::settle_neurons_fund_participation_request::Result
{
    fn from(item: pb::settle_neurons_fund_participation_request::Result) -> Self {
        match item {
            pb::settle_neurons_fund_participation_request::Result::Committed(v) => {
                pb_api::settle_neurons_fund_participation_request::Result::Committed(v.into())
            }
            pb::settle_neurons_fund_participation_request::Result::Aborted(v) => {
                pb_api::settle_neurons_fund_participation_request::Result::Aborted(v.into())
            }
        }
    }
}
impl From<pb_api::settle_neurons_fund_participation_request::Result>
    for pb::settle_neurons_fund_participation_request::Result
{
    fn from(item: pb_api::settle_neurons_fund_participation_request::Result) -> Self {
        match item {
            pb_api::settle_neurons_fund_participation_request::Result::Committed(v) => {
                pb::settle_neurons_fund_participation_request::Result::Committed(v.into())
            }
            pb_api::settle_neurons_fund_participation_request::Result::Aborted(v) => {
                pb::settle_neurons_fund_participation_request::Result::Aborted(v.into())
            }
        }
    }
}

impl From<pb::SettleNeuronsFundParticipationResponse>
    for pb_api::SettleNeuronsFundParticipationResponse
{
    fn from(item: pb::SettleNeuronsFundParticipationResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::SettleNeuronsFundParticipationResponse>
    for pb::SettleNeuronsFundParticipationResponse
{
    fn from(item: pb_api::SettleNeuronsFundParticipationResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_neurons_fund_participation_response::NeuronsFundNeuron>
    for pb_api::settle_neurons_fund_participation_response::NeuronsFundNeuron
{
    fn from(item: pb::settle_neurons_fund_participation_response::NeuronsFundNeuron) -> Self {
        #[allow(deprecated)]
        Self {
            nns_neuron_id: item.nns_neuron_id,
            amount_icp_e8s: item.amount_icp_e8s,
            controller: item.controller,
            hotkeys: item.hotkeys,
            is_capped: item.is_capped,
        }
    }
}
impl From<pb_api::settle_neurons_fund_participation_response::NeuronsFundNeuron>
    for pb::settle_neurons_fund_participation_response::NeuronsFundNeuron
{
    fn from(item: pb_api::settle_neurons_fund_participation_response::NeuronsFundNeuron) -> Self {
        #[allow(deprecated)]
        Self {
            nns_neuron_id: item.nns_neuron_id,
            amount_icp_e8s: item.amount_icp_e8s,
            controller: item.controller,
            hotkeys: item.hotkeys,
            is_capped: item.is_capped,
        }
    }
}

impl From<pb::settle_neurons_fund_participation_response::Ok>
    for pb_api::settle_neurons_fund_participation_response::Ok
{
    fn from(item: pb::settle_neurons_fund_participation_response::Ok) -> Self {
        Self {
            neurons_fund_neuron_portions: item
                .neurons_fund_neuron_portions
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}
impl From<pb_api::settle_neurons_fund_participation_response::Ok>
    for pb::settle_neurons_fund_participation_response::Ok
{
    fn from(item: pb_api::settle_neurons_fund_participation_response::Ok) -> Self {
        Self {
            neurons_fund_neuron_portions: item
                .neurons_fund_neuron_portions
                .into_iter()
                .map(|x| x.into())
                .collect(),
        }
    }
}

impl From<pb::settle_neurons_fund_participation_response::Result>
    for pb_api::settle_neurons_fund_participation_response::Result
{
    fn from(item: pb::settle_neurons_fund_participation_response::Result) -> Self {
        match item {
            pb::settle_neurons_fund_participation_response::Result::Err(v) => {
                pb_api::settle_neurons_fund_participation_response::Result::Err(v.into())
            }
            pb::settle_neurons_fund_participation_response::Result::Ok(v) => {
                pb_api::settle_neurons_fund_participation_response::Result::Ok(v.into())
            }
        }
    }
}
impl From<pb_api::settle_neurons_fund_participation_response::Result>
    for pb::settle_neurons_fund_participation_response::Result
{
    fn from(item: pb_api::settle_neurons_fund_participation_response::Result) -> Self {
        match item {
            pb_api::settle_neurons_fund_participation_response::Result::Err(v) => {
                pb::settle_neurons_fund_participation_response::Result::Err(v.into())
            }
            pb_api::settle_neurons_fund_participation_response::Result::Ok(v) => {
                pb::settle_neurons_fund_participation_response::Result::Ok(v.into())
            }
        }
    }
}

impl From<pb::AuditEvent> for pb_api::AuditEvent {
    fn from(item: pb::AuditEvent) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            payload: item.payload.map(|x| x.into()),
        }
    }
}
impl From<pb_api::AuditEvent> for pb::AuditEvent {
    fn from(item: pb_api::AuditEvent) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            payload: item.payload.map(|x| x.into()),
        }
    }
}

impl From<pb::audit_event::ResetAging> for pb_api::audit_event::ResetAging {
    fn from(item: pb::audit_event::ResetAging) -> Self {
        Self {
            neuron_id: item.neuron_id,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
            new_aging_since_timestamp_seconds: item.new_aging_since_timestamp_seconds,
            neuron_stake_e8s: item.neuron_stake_e8s,
            neuron_dissolve_state: item.neuron_dissolve_state.map(|x| x.into()),
        }
    }
}
impl From<pb_api::audit_event::ResetAging> for pb::audit_event::ResetAging {
    fn from(item: pb_api::audit_event::ResetAging) -> Self {
        Self {
            neuron_id: item.neuron_id,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
            new_aging_since_timestamp_seconds: item.new_aging_since_timestamp_seconds,
            neuron_stake_e8s: item.neuron_stake_e8s,
            neuron_dissolve_state: item.neuron_dissolve_state.map(|x| x.into()),
        }
    }
}

impl From<pb::audit_event::reset_aging::NeuronDissolveState>
    for pb_api::audit_event::reset_aging::NeuronDissolveState
{
    fn from(item: pb::audit_event::reset_aging::NeuronDissolveState) -> Self {
        match item {
            pb::audit_event::reset_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb_api::audit_event::reset_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    v,
                )
            }
            pb::audit_event::reset_aging::NeuronDissolveState::DissolveDelaySeconds(v) => {
                pb_api::audit_event::reset_aging::NeuronDissolveState::DissolveDelaySeconds(v)
            }
        }
    }
}
impl From<pb_api::audit_event::reset_aging::NeuronDissolveState>
    for pb::audit_event::reset_aging::NeuronDissolveState
{
    fn from(item: pb_api::audit_event::reset_aging::NeuronDissolveState) -> Self {
        match item {
            pb_api::audit_event::reset_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v) => pb::audit_event::reset_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v),
            pb_api::audit_event::reset_aging::NeuronDissolveState::DissolveDelaySeconds(v) => pb::audit_event::reset_aging::NeuronDissolveState::DissolveDelaySeconds(v)
        }
    }
}

impl From<pb::audit_event::RestoreAging> for pb_api::audit_event::RestoreAging {
    fn from(item: pb::audit_event::RestoreAging) -> Self {
        Self {
            neuron_id: item.neuron_id,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
            new_aging_since_timestamp_seconds: item.new_aging_since_timestamp_seconds,
            neuron_stake_e8s: item.neuron_stake_e8s,
            neuron_dissolve_state: item.neuron_dissolve_state.map(|x| x.into()),
        }
    }
}
impl From<pb_api::audit_event::RestoreAging> for pb::audit_event::RestoreAging {
    fn from(item: pb_api::audit_event::RestoreAging) -> Self {
        Self {
            neuron_id: item.neuron_id,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
            new_aging_since_timestamp_seconds: item.new_aging_since_timestamp_seconds,
            neuron_stake_e8s: item.neuron_stake_e8s,
            neuron_dissolve_state: item.neuron_dissolve_state.map(|x| x.into()),
        }
    }
}

impl From<pb::audit_event::restore_aging::NeuronDissolveState>
    for pb_api::audit_event::restore_aging::NeuronDissolveState
{
    fn from(item: pb::audit_event::restore_aging::NeuronDissolveState) -> Self {
        match item {
            pb::audit_event::restore_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v) => pb_api::audit_event::restore_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v),
            pb::audit_event::restore_aging::NeuronDissolveState::DissolveDelaySeconds(v) => pb_api::audit_event::restore_aging::NeuronDissolveState::DissolveDelaySeconds(v)
        }
    }
}
impl From<pb_api::audit_event::restore_aging::NeuronDissolveState>
    for pb::audit_event::restore_aging::NeuronDissolveState
{
    fn from(item: pb_api::audit_event::restore_aging::NeuronDissolveState) -> Self {
        match item {
            pb_api::audit_event::restore_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v) => pb::audit_event::restore_aging::NeuronDissolveState::WhenDissolvedTimestampSeconds(v),
            pb_api::audit_event::restore_aging::NeuronDissolveState::DissolveDelaySeconds(v) => pb::audit_event::restore_aging::NeuronDissolveState::DissolveDelaySeconds(v)
        }
    }
}

impl From<pb::audit_event::NormalizeDissolveStateAndAge>
    for pb_api::audit_event::NormalizeDissolveStateAndAge
{
    fn from(item: pb::audit_event::NormalizeDissolveStateAndAge) -> Self {
        Self {
            neuron_id: item.neuron_id,
            neuron_legacy_case: item.neuron_legacy_case,
            previous_when_dissolved_timestamp_seconds: item
                .previous_when_dissolved_timestamp_seconds,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
        }
    }
}
impl From<pb_api::audit_event::NormalizeDissolveStateAndAge>
    for pb::audit_event::NormalizeDissolveStateAndAge
{
    fn from(item: pb_api::audit_event::NormalizeDissolveStateAndAge) -> Self {
        Self {
            neuron_id: item.neuron_id,
            neuron_legacy_case: item.neuron_legacy_case,
            previous_when_dissolved_timestamp_seconds: item
                .previous_when_dissolved_timestamp_seconds,
            previous_aging_since_timestamp_seconds: item.previous_aging_since_timestamp_seconds,
        }
    }
}

impl From<pb::audit_event::NeuronLegacyCase> for pb_api::audit_event::NeuronLegacyCase {
    fn from(item: pb::audit_event::NeuronLegacyCase) -> Self {
        match item {
            pb::audit_event::NeuronLegacyCase::Unspecified => {
                pb_api::audit_event::NeuronLegacyCase::Unspecified
            }
            pb::audit_event::NeuronLegacyCase::DissolvingOrDissolved => {
                pb_api::audit_event::NeuronLegacyCase::DissolvingOrDissolved
            }
            pb::audit_event::NeuronLegacyCase::Dissolved => {
                pb_api::audit_event::NeuronLegacyCase::Dissolved
            }
            pb::audit_event::NeuronLegacyCase::NoneDissolveState => {
                pb_api::audit_event::NeuronLegacyCase::NoneDissolveState
            }
        }
    }
}
impl From<pb_api::audit_event::NeuronLegacyCase> for pb::audit_event::NeuronLegacyCase {
    fn from(item: pb_api::audit_event::NeuronLegacyCase) -> Self {
        match item {
            pb_api::audit_event::NeuronLegacyCase::Unspecified => {
                pb::audit_event::NeuronLegacyCase::Unspecified
            }
            pb_api::audit_event::NeuronLegacyCase::DissolvingOrDissolved => {
                pb::audit_event::NeuronLegacyCase::DissolvingOrDissolved
            }
            pb_api::audit_event::NeuronLegacyCase::Dissolved => {
                pb::audit_event::NeuronLegacyCase::Dissolved
            }
            pb_api::audit_event::NeuronLegacyCase::NoneDissolveState => {
                pb::audit_event::NeuronLegacyCase::NoneDissolveState
            }
        }
    }
}

impl From<pb::audit_event::Payload> for pb_api::audit_event::Payload {
    fn from(item: pb::audit_event::Payload) -> Self {
        match item {
            pb::audit_event::Payload::ResetAging(v) => {
                pb_api::audit_event::Payload::ResetAging(v.into())
            }
            pb::audit_event::Payload::RestoreAging(v) => {
                pb_api::audit_event::Payload::RestoreAging(v.into())
            }
            pb::audit_event::Payload::NormalizeDissolveStateAndAge(v) => {
                pb_api::audit_event::Payload::NormalizeDissolveStateAndAge(v.into())
            }
        }
    }
}
impl From<pb_api::audit_event::Payload> for pb::audit_event::Payload {
    fn from(item: pb_api::audit_event::Payload) -> Self {
        match item {
            pb_api::audit_event::Payload::ResetAging(v) => {
                pb::audit_event::Payload::ResetAging(v.into())
            }
            pb_api::audit_event::Payload::RestoreAging(v) => {
                pb::audit_event::Payload::RestoreAging(v.into())
            }
            pb_api::audit_event::Payload::NormalizeDissolveStateAndAge(v) => {
                pb::audit_event::Payload::NormalizeDissolveStateAndAge(v.into())
            }
        }
    }
}

impl From<pb::RestoreAgingSummary> for pb_api::RestoreAgingSummary {
    fn from(item: pb::RestoreAgingSummary) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            groups: item.groups.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::RestoreAgingSummary> for pb::RestoreAgingSummary {
    fn from(item: pb_api::RestoreAgingSummary) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            groups: item.groups.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::restore_aging_summary::RestoreAgingNeuronGroup>
    for pb_api::restore_aging_summary::RestoreAgingNeuronGroup
{
    fn from(item: pb::restore_aging_summary::RestoreAgingNeuronGroup) -> Self {
        Self {
            group_type: item.group_type,
            count: item.count,
            previous_total_stake_e8s: item.previous_total_stake_e8s,
            current_total_stake_e8s: item.current_total_stake_e8s,
        }
    }
}
impl From<pb_api::restore_aging_summary::RestoreAgingNeuronGroup>
    for pb::restore_aging_summary::RestoreAgingNeuronGroup
{
    fn from(item: pb_api::restore_aging_summary::RestoreAgingNeuronGroup) -> Self {
        Self {
            group_type: item.group_type,
            count: item.count,
            previous_total_stake_e8s: item.previous_total_stake_e8s,
            current_total_stake_e8s: item.current_total_stake_e8s,
        }
    }
}

impl From<pb::restore_aging_summary::NeuronGroupType>
    for pb_api::restore_aging_summary::NeuronGroupType
{
    fn from(item: pb::restore_aging_summary::NeuronGroupType) -> Self {
        match item {
            pb::restore_aging_summary::NeuronGroupType::Unspecified => {
                pb_api::restore_aging_summary::NeuronGroupType::Unspecified
            }
            pb::restore_aging_summary::NeuronGroupType::NotPreAging => {
                pb_api::restore_aging_summary::NeuronGroupType::NotPreAging
            }
            pb::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved => {
                pb_api::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved
            }
            pb::restore_aging_summary::NeuronGroupType::StakeChanged => {
                pb_api::restore_aging_summary::NeuronGroupType::StakeChanged
            }
            pb::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged => {
                pb_api::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged
            }
            pb::restore_aging_summary::NeuronGroupType::StakeSameAgingSame => {
                pb_api::restore_aging_summary::NeuronGroupType::StakeSameAgingSame
            }
        }
    }
}
impl From<pb_api::restore_aging_summary::NeuronGroupType>
    for pb::restore_aging_summary::NeuronGroupType
{
    fn from(item: pb_api::restore_aging_summary::NeuronGroupType) -> Self {
        match item {
            pb_api::restore_aging_summary::NeuronGroupType::Unspecified => {
                pb::restore_aging_summary::NeuronGroupType::Unspecified
            }
            pb_api::restore_aging_summary::NeuronGroupType::NotPreAging => {
                pb::restore_aging_summary::NeuronGroupType::NotPreAging
            }
            pb_api::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved => {
                pb::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved
            }
            pb_api::restore_aging_summary::NeuronGroupType::StakeChanged => {
                pb::restore_aging_summary::NeuronGroupType::StakeChanged
            }
            pb_api::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged => {
                pb::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged
            }
            pb_api::restore_aging_summary::NeuronGroupType::StakeSameAgingSame => {
                pb::restore_aging_summary::NeuronGroupType::StakeSameAgingSame
            }
        }
    }
}

impl From<pb::Account> for pb_api::Account {
    fn from(item: pb::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| x.subaccount),
        }
    }
}
impl From<pb_api::Account> for pb::Account {
    fn from(item: pb_api::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| pb::Subaccount { subaccount: x }),
        }
    }
}

impl From<pb::NeuronState> for pb_api::NeuronState {
    fn from(item: pb::NeuronState) -> Self {
        match item {
            pb::NeuronState::Unspecified => pb_api::NeuronState::Unspecified,
            pb::NeuronState::NotDissolving => pb_api::NeuronState::NotDissolving,
            pb::NeuronState::Dissolving => pb_api::NeuronState::Dissolving,
            pb::NeuronState::Dissolved => pb_api::NeuronState::Dissolved,
            pb::NeuronState::Spawning => pb_api::NeuronState::Spawning,
        }
    }
}
impl From<pb_api::NeuronState> for pb::NeuronState {
    fn from(item: pb_api::NeuronState) -> Self {
        match item {
            pb_api::NeuronState::Unspecified => pb::NeuronState::Unspecified,
            pb_api::NeuronState::NotDissolving => pb::NeuronState::NotDissolving,
            pb_api::NeuronState::Dissolving => pb::NeuronState::Dissolving,
            pb_api::NeuronState::Dissolved => pb::NeuronState::Dissolved,
            pb_api::NeuronState::Spawning => pb::NeuronState::Spawning,
        }
    }
}

impl From<pb::NeuronType> for pb_api::NeuronType {
    fn from(item: pb::NeuronType) -> Self {
        match item {
            pb::NeuronType::Unspecified => pb_api::NeuronType::Unspecified,
            pb::NeuronType::Seed => pb_api::NeuronType::Seed,
            pb::NeuronType::Ect => pb_api::NeuronType::Ect,
        }
    }
}
impl From<pb_api::NeuronType> for pb::NeuronType {
    fn from(item: pb_api::NeuronType) -> Self {
        match item {
            pb_api::NeuronType::Unspecified => pb::NeuronType::Unspecified,
            pb_api::NeuronType::Seed => pb::NeuronType::Seed,
            pb_api::NeuronType::Ect => pb::NeuronType::Ect,
        }
    }
}

impl From<pb::Vote> for pb_api::Vote {
    fn from(item: pb::Vote) -> Self {
        match item {
            pb::Vote::Unspecified => pb_api::Vote::Unspecified,
            pb::Vote::Yes => pb_api::Vote::Yes,
            pb::Vote::No => pb_api::Vote::No,
        }
    }
}
impl From<pb_api::Vote> for pb::Vote {
    fn from(item: pb_api::Vote) -> Self {
        match item {
            pb_api::Vote::Unspecified => pb::Vote::Unspecified,
            pb_api::Vote::Yes => pb::Vote::Yes,
            pb_api::Vote::No => pb::Vote::No,
        }
    }
}

impl From<pb::NnsFunction> for pb_api::NnsFunction {
    fn from(item: pb::NnsFunction) -> Self {
        match item {
            pb::NnsFunction::Unspecified => pb_api::NnsFunction::Unspecified,
            pb::NnsFunction::CreateSubnet => pb_api::NnsFunction::CreateSubnet,
            pb::NnsFunction::AddNodeToSubnet => pb_api::NnsFunction::AddNodeToSubnet,
            pb::NnsFunction::NnsCanisterInstall => pb_api::NnsFunction::NnsCanisterInstall,
            pb::NnsFunction::NnsCanisterUpgrade => pb_api::NnsFunction::NnsCanisterUpgrade,
            pb::NnsFunction::BlessReplicaVersion => pb_api::NnsFunction::BlessReplicaVersion,
            pb::NnsFunction::RecoverSubnet => pb_api::NnsFunction::RecoverSubnet,
            pb::NnsFunction::UpdateConfigOfSubnet => pb_api::NnsFunction::UpdateConfigOfSubnet,
            pb::NnsFunction::AssignNoid => pb_api::NnsFunction::AssignNoid,
            pb::NnsFunction::NnsRootUpgrade => pb_api::NnsFunction::NnsRootUpgrade,
            pb::NnsFunction::IcpXdrConversionRate => pb_api::NnsFunction::IcpXdrConversionRate,
            pb::NnsFunction::DeployGuestosToAllSubnetNodes => {
                pb_api::NnsFunction::DeployGuestosToAllSubnetNodes
            }
            pb::NnsFunction::ClearProvisionalWhitelist => {
                pb_api::NnsFunction::ClearProvisionalWhitelist
            }
            pb::NnsFunction::RemoveNodesFromSubnet => pb_api::NnsFunction::RemoveNodesFromSubnet,
            pb::NnsFunction::SetAuthorizedSubnetworks => {
                pb_api::NnsFunction::SetAuthorizedSubnetworks
            }
            pb::NnsFunction::SetFirewallConfig => pb_api::NnsFunction::SetFirewallConfig,
            pb::NnsFunction::UpdateNodeOperatorConfig => {
                pb_api::NnsFunction::UpdateNodeOperatorConfig
            }
            pb::NnsFunction::StopOrStartNnsCanister => pb_api::NnsFunction::StopOrStartNnsCanister,
            pb::NnsFunction::RemoveNodes => pb_api::NnsFunction::RemoveNodes,
            pb::NnsFunction::UninstallCode => pb_api::NnsFunction::UninstallCode,
            pb::NnsFunction::UpdateNodeRewardsTable => pb_api::NnsFunction::UpdateNodeRewardsTable,
            pb::NnsFunction::AddOrRemoveDataCenters => pb_api::NnsFunction::AddOrRemoveDataCenters,
            pb::NnsFunction::UpdateUnassignedNodesConfig => {
                pb_api::NnsFunction::UpdateUnassignedNodesConfig
            }
            pb::NnsFunction::RemoveNodeOperators => pb_api::NnsFunction::RemoveNodeOperators,
            pb::NnsFunction::RerouteCanisterRanges => pb_api::NnsFunction::RerouteCanisterRanges,
            pb::NnsFunction::AddFirewallRules => pb_api::NnsFunction::AddFirewallRules,
            pb::NnsFunction::RemoveFirewallRules => pb_api::NnsFunction::RemoveFirewallRules,
            pb::NnsFunction::UpdateFirewallRules => pb_api::NnsFunction::UpdateFirewallRules,
            pb::NnsFunction::PrepareCanisterMigration => {
                pb_api::NnsFunction::PrepareCanisterMigration
            }
            pb::NnsFunction::CompleteCanisterMigration => {
                pb_api::NnsFunction::CompleteCanisterMigration
            }
            pb::NnsFunction::AddSnsWasm => pb_api::NnsFunction::AddSnsWasm,
            pb::NnsFunction::ChangeSubnetMembership => pb_api::NnsFunction::ChangeSubnetMembership,
            pb::NnsFunction::UpdateSubnetType => pb_api::NnsFunction::UpdateSubnetType,
            pb::NnsFunction::ChangeSubnetTypeAssignment => {
                pb_api::NnsFunction::ChangeSubnetTypeAssignment
            }
            pb::NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                pb_api::NnsFunction::UpdateSnsWasmSnsSubnetIds
            }
            pb::NnsFunction::UpdateAllowedPrincipals => {
                pb_api::NnsFunction::UpdateAllowedPrincipals
            }
            pb::NnsFunction::RetireReplicaVersion => pb_api::NnsFunction::RetireReplicaVersion,
            pb::NnsFunction::InsertSnsWasmUpgradePathEntries => {
                pb_api::NnsFunction::InsertSnsWasmUpgradePathEntries
            }
            pb::NnsFunction::ReviseElectedGuestosVersions => {
                pb_api::NnsFunction::ReviseElectedGuestosVersions
            }
            pb::NnsFunction::BitcoinSetConfig => pb_api::NnsFunction::BitcoinSetConfig,
            pb::NnsFunction::UpdateElectedHostosVersions => {
                pb_api::NnsFunction::UpdateElectedHostosVersions
            }
            pb::NnsFunction::UpdateNodesHostosVersion => {
                pb_api::NnsFunction::UpdateNodesHostosVersion
            }
            pb::NnsFunction::HardResetNnsRootToVersion => {
                pb_api::NnsFunction::HardResetNnsRootToVersion
            }
            pb::NnsFunction::AddApiBoundaryNodes => pb_api::NnsFunction::AddApiBoundaryNodes,
            pb::NnsFunction::RemoveApiBoundaryNodes => pb_api::NnsFunction::RemoveApiBoundaryNodes,
            pb::NnsFunction::UpdateApiBoundaryNodesVersion => {
                pb_api::NnsFunction::UpdateApiBoundaryNodesVersion
            }
            pb::NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                pb_api::NnsFunction::DeployGuestosToSomeApiBoundaryNodes
            }
            pb::NnsFunction::DeployGuestosToAllUnassignedNodes => {
                pb_api::NnsFunction::DeployGuestosToAllUnassignedNodes
            }
            pb::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                pb_api::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes
            }
            pb::NnsFunction::ReviseElectedHostosVersions => {
                pb_api::NnsFunction::ReviseElectedHostosVersions
            }
            pb::NnsFunction::DeployHostosToSomeNodes => {
                pb_api::NnsFunction::DeployHostosToSomeNodes
            }
            pb::NnsFunction::SubnetRentalRequest => pb_api::NnsFunction::SubnetRentalRequest,
            pb::NnsFunction::PauseCanisterMigrations => {
                pb_api::NnsFunction::PauseCanisterMigrations
            }
            pb::NnsFunction::UnpauseCanisterMigrations => {
                pb_api::NnsFunction::UnpauseCanisterMigrations
            }
            pb::NnsFunction::SetSubnetOperationalLevel => {
                pb_api::NnsFunction::SetSubnetOperationalLevel
            }
        }
    }
}
impl From<pb_api::NnsFunction> for pb::NnsFunction {
    fn from(item: pb_api::NnsFunction) -> Self {
        match item {
            pb_api::NnsFunction::Unspecified => pb::NnsFunction::Unspecified,
            pb_api::NnsFunction::CreateSubnet => pb::NnsFunction::CreateSubnet,
            pb_api::NnsFunction::AddNodeToSubnet => pb::NnsFunction::AddNodeToSubnet,
            pb_api::NnsFunction::NnsCanisterInstall => pb::NnsFunction::NnsCanisterInstall,
            pb_api::NnsFunction::NnsCanisterUpgrade => pb::NnsFunction::NnsCanisterUpgrade,
            pb_api::NnsFunction::BlessReplicaVersion => pb::NnsFunction::BlessReplicaVersion,
            pb_api::NnsFunction::RecoverSubnet => pb::NnsFunction::RecoverSubnet,
            pb_api::NnsFunction::UpdateConfigOfSubnet => pb::NnsFunction::UpdateConfigOfSubnet,
            pb_api::NnsFunction::AssignNoid => pb::NnsFunction::AssignNoid,
            pb_api::NnsFunction::NnsRootUpgrade => pb::NnsFunction::NnsRootUpgrade,
            pb_api::NnsFunction::IcpXdrConversionRate => pb::NnsFunction::IcpXdrConversionRate,
            pb_api::NnsFunction::DeployGuestosToAllSubnetNodes => {
                pb::NnsFunction::DeployGuestosToAllSubnetNodes
            }
            pb_api::NnsFunction::ClearProvisionalWhitelist => {
                pb::NnsFunction::ClearProvisionalWhitelist
            }
            pb_api::NnsFunction::RemoveNodesFromSubnet => pb::NnsFunction::RemoveNodesFromSubnet,
            pb_api::NnsFunction::SetAuthorizedSubnetworks => {
                pb::NnsFunction::SetAuthorizedSubnetworks
            }
            pb_api::NnsFunction::SetFirewallConfig => pb::NnsFunction::SetFirewallConfig,
            pb_api::NnsFunction::UpdateNodeOperatorConfig => {
                pb::NnsFunction::UpdateNodeOperatorConfig
            }
            pb_api::NnsFunction::StopOrStartNnsCanister => pb::NnsFunction::StopOrStartNnsCanister,
            pb_api::NnsFunction::RemoveNodes => pb::NnsFunction::RemoveNodes,
            pb_api::NnsFunction::UninstallCode => pb::NnsFunction::UninstallCode,
            pb_api::NnsFunction::UpdateNodeRewardsTable => pb::NnsFunction::UpdateNodeRewardsTable,
            pb_api::NnsFunction::AddOrRemoveDataCenters => pb::NnsFunction::AddOrRemoveDataCenters,
            pb_api::NnsFunction::UpdateUnassignedNodesConfig => {
                pb::NnsFunction::UpdateUnassignedNodesConfig
            }
            pb_api::NnsFunction::RemoveNodeOperators => pb::NnsFunction::RemoveNodeOperators,
            pb_api::NnsFunction::RerouteCanisterRanges => pb::NnsFunction::RerouteCanisterRanges,
            pb_api::NnsFunction::AddFirewallRules => pb::NnsFunction::AddFirewallRules,
            pb_api::NnsFunction::RemoveFirewallRules => pb::NnsFunction::RemoveFirewallRules,
            pb_api::NnsFunction::UpdateFirewallRules => pb::NnsFunction::UpdateFirewallRules,
            pb_api::NnsFunction::PrepareCanisterMigration => {
                pb::NnsFunction::PrepareCanisterMigration
            }
            pb_api::NnsFunction::CompleteCanisterMigration => {
                pb::NnsFunction::CompleteCanisterMigration
            }
            pb_api::NnsFunction::AddSnsWasm => pb::NnsFunction::AddSnsWasm,
            pb_api::NnsFunction::ChangeSubnetMembership => pb::NnsFunction::ChangeSubnetMembership,
            pb_api::NnsFunction::UpdateSubnetType => pb::NnsFunction::UpdateSubnetType,
            pb_api::NnsFunction::ChangeSubnetTypeAssignment => {
                pb::NnsFunction::ChangeSubnetTypeAssignment
            }
            pb_api::NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                pb::NnsFunction::UpdateSnsWasmSnsSubnetIds
            }
            pb_api::NnsFunction::UpdateAllowedPrincipals => {
                pb::NnsFunction::UpdateAllowedPrincipals
            }
            pb_api::NnsFunction::RetireReplicaVersion => pb::NnsFunction::RetireReplicaVersion,
            pb_api::NnsFunction::InsertSnsWasmUpgradePathEntries => {
                pb::NnsFunction::InsertSnsWasmUpgradePathEntries
            }
            pb_api::NnsFunction::ReviseElectedGuestosVersions => {
                pb::NnsFunction::ReviseElectedGuestosVersions
            }
            pb_api::NnsFunction::BitcoinSetConfig => pb::NnsFunction::BitcoinSetConfig,
            pb_api::NnsFunction::UpdateElectedHostosVersions => {
                pb::NnsFunction::UpdateElectedHostosVersions
            }
            pb_api::NnsFunction::UpdateNodesHostosVersion => {
                pb::NnsFunction::UpdateNodesHostosVersion
            }
            pb_api::NnsFunction::HardResetNnsRootToVersion => {
                pb::NnsFunction::HardResetNnsRootToVersion
            }
            pb_api::NnsFunction::AddApiBoundaryNodes => pb::NnsFunction::AddApiBoundaryNodes,
            pb_api::NnsFunction::RemoveApiBoundaryNodes => pb::NnsFunction::RemoveApiBoundaryNodes,
            pb_api::NnsFunction::UpdateApiBoundaryNodesVersion => {
                pb::NnsFunction::UpdateApiBoundaryNodesVersion
            }
            pb_api::NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                pb::NnsFunction::DeployGuestosToSomeApiBoundaryNodes
            }
            pb_api::NnsFunction::DeployGuestosToAllUnassignedNodes => {
                pb::NnsFunction::DeployGuestosToAllUnassignedNodes
            }
            pb_api::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                pb::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes
            }
            pb_api::NnsFunction::ReviseElectedHostosVersions => {
                pb::NnsFunction::ReviseElectedHostosVersions
            }
            pb_api::NnsFunction::DeployHostosToSomeNodes => {
                pb::NnsFunction::DeployHostosToSomeNodes
            }
            pb_api::NnsFunction::SubnetRentalRequest => pb::NnsFunction::SubnetRentalRequest,
            pb_api::NnsFunction::PauseCanisterMigrations => {
                pb::NnsFunction::PauseCanisterMigrations
            }
            pb_api::NnsFunction::UnpauseCanisterMigrations => {
                pb::NnsFunction::UnpauseCanisterMigrations
            }
            pb_api::NnsFunction::SetSubnetOperationalLevel => {
                pb::NnsFunction::SetSubnetOperationalLevel
            }
        }
    }
}

impl From<pb::ProposalStatus> for pb_api::ProposalStatus {
    fn from(item: pb::ProposalStatus) -> Self {
        match item {
            pb::ProposalStatus::Unspecified => pb_api::ProposalStatus::Unspecified,
            pb::ProposalStatus::Open => pb_api::ProposalStatus::Open,
            pb::ProposalStatus::Rejected => pb_api::ProposalStatus::Rejected,
            pb::ProposalStatus::Adopted => pb_api::ProposalStatus::Adopted,
            pb::ProposalStatus::Executed => pb_api::ProposalStatus::Executed,
            pb::ProposalStatus::Failed => pb_api::ProposalStatus::Failed,
        }
    }
}
impl From<pb_api::ProposalStatus> for pb::ProposalStatus {
    fn from(item: pb_api::ProposalStatus) -> Self {
        match item {
            pb_api::ProposalStatus::Unspecified => pb::ProposalStatus::Unspecified,
            pb_api::ProposalStatus::Open => pb::ProposalStatus::Open,
            pb_api::ProposalStatus::Rejected => pb::ProposalStatus::Rejected,
            pb_api::ProposalStatus::Adopted => pb::ProposalStatus::Adopted,
            pb_api::ProposalStatus::Executed => pb::ProposalStatus::Executed,
            pb_api::ProposalStatus::Failed => pb::ProposalStatus::Failed,
        }
    }
}

impl From<pb::ProposalRewardStatus> for pb_api::ProposalRewardStatus {
    fn from(item: pb::ProposalRewardStatus) -> Self {
        match item {
            pb::ProposalRewardStatus::Unspecified => pb_api::ProposalRewardStatus::Unspecified,
            pb::ProposalRewardStatus::AcceptVotes => pb_api::ProposalRewardStatus::AcceptVotes,
            pb::ProposalRewardStatus::ReadyToSettle => pb_api::ProposalRewardStatus::ReadyToSettle,
            pb::ProposalRewardStatus::Settled => pb_api::ProposalRewardStatus::Settled,
            pb::ProposalRewardStatus::Ineligible => pb_api::ProposalRewardStatus::Ineligible,
        }
    }
}
impl From<pb_api::ProposalRewardStatus> for pb::ProposalRewardStatus {
    fn from(item: pb_api::ProposalRewardStatus) -> Self {
        match item {
            pb_api::ProposalRewardStatus::Unspecified => pb::ProposalRewardStatus::Unspecified,
            pb_api::ProposalRewardStatus::AcceptVotes => pb::ProposalRewardStatus::AcceptVotes,
            pb_api::ProposalRewardStatus::ReadyToSettle => pb::ProposalRewardStatus::ReadyToSettle,
            pb_api::ProposalRewardStatus::Settled => pb::ProposalRewardStatus::Settled,
            pb_api::ProposalRewardStatus::Ineligible => pb::ProposalRewardStatus::Ineligible,
        }
    }
}

impl From<ic_nns_governance_api::test_api::TimeWarp> for crate::TimeWarp {
    fn from(value: ic_nns_governance_api::test_api::TimeWarp) -> Self {
        Self {
            delta_s: value.delta_s,
        }
    }
}

impl From<pb::MaturityDisbursement> for pb_api::MaturityDisbursement {
    fn from(item: pb::MaturityDisbursement) -> Self {
        Self {
            amount_e8s: Some(item.amount_e8s),
            account_to_disburse_to: item
                .destination
                .as_ref()
                .and_then(|x| x.into_account())
                .map(|x| x.into()),
            account_identifier_to_disburse_to: item
                .destination
                .as_ref()
                .and_then(|x| x.into_account_identifier_proto()),
            timestamp_of_disbursement_seconds: Some(item.timestamp_of_disbursement_seconds),
            finalize_disbursement_timestamp_seconds: Some(
                item.finalize_disbursement_timestamp_seconds,
            ),
        }
    }
}

impl From<pb::SelfDescribingValue> for pb_api::SelfDescribingValue {
    fn from(item: pb::SelfDescribingValue) -> Self {
        let Some(value) = item.value else {
            return Self::Map(HashMap::new());
        };
        match value {
            pb::self_describing_value::Value::Blob(v) => Self::Blob(v),
            pb::self_describing_value::Value::Text(v) => Self::Text(v),
            pb::self_describing_value::Value::Nat(v) => {
                let nat = Nat::decode(&mut v.as_slice()).unwrap();
                Self::Nat(nat)
            }
            pb::self_describing_value::Value::Int(v) => {
                let int = Int::decode(&mut v.as_slice()).unwrap();
                Self::Int(int)
            }
            pb::self_describing_value::Value::Array(v) => {
                Self::Array(v.values.into_iter().map(Self::from).collect())
            }
            pb::self_describing_value::Value::Map(v) => Self::Map(
                v.values
                    .into_iter()
                    .map(|(k, v)| (k, Self::from(v)))
                    .collect(),
            ),
        }
    }
}

impl From<pb_api::SelfDescribingValue> for pb::SelfDescribingValue {
    fn from(item: pb_api::SelfDescribingValue) -> Self {
        let value = match item {
            pb_api::SelfDescribingValue::Blob(v) => pb::self_describing_value::Value::Blob(v),
            pb_api::SelfDescribingValue::Text(v) => pb::self_describing_value::Value::Text(v),
            pb_api::SelfDescribingValue::Nat(v) => {
                let mut bytes = Vec::new();
                v.encode(&mut bytes).unwrap();
                pb::self_describing_value::Value::Nat(bytes)
            }
            pb_api::SelfDescribingValue::Int(v) => {
                let mut bytes = Vec::new();
                v.encode(&mut bytes).unwrap();
                pb::self_describing_value::Value::Int(bytes)
            }
            pb_api::SelfDescribingValue::Array(v) => {
                pb::self_describing_value::Value::Array(pb::SelfDescribingValueArray {
                    values: v.into_iter().map(Self::from).collect(),
                })
            }
            pb_api::SelfDescribingValue::Map(v) => {
                pb::self_describing_value::Value::Map(pb::SelfDescribingValueMap {
                    values: v.into_iter().map(|(k, v)| (k, Self::from(v))).collect(),
                })
            }
        };
        Self { value: Some(value) }
    }
}

impl From<pb::SelfDescribingProposalAction> for pb_api::SelfDescribingProposalAction {
    fn from(item: pb::SelfDescribingProposalAction) -> Self {
        Self {
            type_name: Some(item.type_name),
            type_description: Some(item.type_description),
            value: item.value.map(pb_api::SelfDescribingValue::from),
        }
    }
}
