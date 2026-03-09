use crate::pb::proposal_conversions::{ProposalDisplayOptions, convert_proposal};
use crate::pb::v1 as pb;

use ic_crypto_sha2::Sha256;
use ic_nns_governance_api as api;
use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement as PbGuestLaunchMeasurement,
    GuestLaunchMeasurementMetadata as PbGuestLaunchMeasurementMetadata,
    GuestLaunchMeasurements as PbGuestLaunchMeasurements,
};

#[cfg(test)]
mod tests;

impl From<pb::NodeProvider> for api::NodeProvider {
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
impl From<api::NodeProvider> for pb::NodeProvider {
    fn from(item: api::NodeProvider) -> Self {
        Self {
            id: item.id,
            reward_account: item.reward_account,
        }
    }
}

impl From<pb::UpdateNodeProvider> for api::UpdateNodeProvider {
    fn from(item: pb::UpdateNodeProvider) -> Self {
        Self {
            reward_account: item.reward_account,
        }
    }
}
impl From<api::UpdateNodeProvider> for pb::UpdateNodeProvider {
    fn from(item: api::UpdateNodeProvider) -> Self {
        Self {
            reward_account: item.reward_account,
        }
    }
}

impl From<api::DeregisterKnownNeuron> for pb::DeregisterKnownNeuron {
    fn from(item: api::DeregisterKnownNeuron) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::DeregisterKnownNeuron> for api::DeregisterKnownNeuron {
    fn from(item: pb::DeregisterKnownNeuron) -> Self {
        Self { id: item.id }
    }
}

impl From<pb::BallotInfo> for api::BallotInfo {
    fn from(item: pb::BallotInfo) -> Self {
        Self {
            proposal_id: item.proposal_id,
            vote: item.vote,
        }
    }
}
impl From<api::BallotInfo> for pb::BallotInfo {
    fn from(item: api::BallotInfo) -> Self {
        Self {
            proposal_id: item.proposal_id,
            vote: item.vote,
        }
    }
}

impl From<pb::NeuronStakeTransfer> for api::NeuronStakeTransfer {
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
impl From<api::NeuronStakeTransfer> for pb::NeuronStakeTransfer {
    fn from(item: api::NeuronStakeTransfer) -> Self {
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

impl From<pb::Followees> for api::neuron::Followees {
    fn from(item: pb::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}
impl From<api::neuron::Followees> for pb::Followees {
    fn from(item: api::neuron::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}

impl From<pb::Visibility> for api::Visibility {
    fn from(item: pb::Visibility) -> Self {
        match item {
            pb::Visibility::Unspecified => api::Visibility::Unspecified,
            pb::Visibility::Private => api::Visibility::Private,
            pb::Visibility::Public => api::Visibility::Public,
        }
    }
}

impl From<api::Visibility> for pb::Visibility {
    fn from(item: api::Visibility) -> Self {
        match item {
            api::Visibility::Unspecified => pb::Visibility::Unspecified,
            api::Visibility::Private => pb::Visibility::Private,
            api::Visibility::Public => pb::Visibility::Public,
        }
    }
}

impl From<pb::ExecuteNnsFunction> for api::ExecuteNnsFunction {
    fn from(item: pb::ExecuteNnsFunction) -> Self {
        Self {
            nns_function: item.nns_function,
            payload: item.payload,
        }
    }
}
impl From<api::ExecuteNnsFunction> for pb::ExecuteNnsFunction {
    fn from(item: api::ExecuteNnsFunction) -> Self {
        Self {
            nns_function: item.nns_function,
            payload: item.payload,
        }
    }
}

impl From<pb::Motion> for api::Motion {
    fn from(item: pb::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}
impl From<api::Motion> for pb::Motion {
    fn from(item: api::Motion) -> Self {
        Self {
            motion_text: item.motion_text,
        }
    }
}

impl From<pb::ApproveGenesisKyc> for api::ApproveGenesisKyc {
    fn from(item: pb::ApproveGenesisKyc) -> Self {
        Self {
            principals: item.principals,
        }
    }
}
impl From<api::ApproveGenesisKyc> for pb::ApproveGenesisKyc {
    fn from(item: api::ApproveGenesisKyc) -> Self {
        Self {
            principals: item.principals,
        }
    }
}

impl From<pb::AddOrRemoveNodeProvider> for api::AddOrRemoveNodeProvider {
    fn from(item: pb::AddOrRemoveNodeProvider) -> Self {
        Self {
            change: item.change.map(|x| x.into()),
        }
    }
}
impl From<api::AddOrRemoveNodeProvider> for pb::AddOrRemoveNodeProvider {
    fn from(item: api::AddOrRemoveNodeProvider) -> Self {
        Self {
            change: item.change.map(|x| x.into()),
        }
    }
}

impl From<pb::add_or_remove_node_provider::Change> for api::add_or_remove_node_provider::Change {
    fn from(item: pb::add_or_remove_node_provider::Change) -> Self {
        match item {
            pb::add_or_remove_node_provider::Change::ToAdd(v) => {
                api::add_or_remove_node_provider::Change::ToAdd(v.into())
            }
            pb::add_or_remove_node_provider::Change::ToRemove(v) => {
                api::add_or_remove_node_provider::Change::ToRemove(v.into())
            }
        }
    }
}
impl From<api::add_or_remove_node_provider::Change> for pb::add_or_remove_node_provider::Change {
    fn from(item: api::add_or_remove_node_provider::Change) -> Self {
        match item {
            api::add_or_remove_node_provider::Change::ToAdd(v) => {
                pb::add_or_remove_node_provider::Change::ToAdd(v.into())
            }
            api::add_or_remove_node_provider::Change::ToRemove(v) => {
                pb::add_or_remove_node_provider::Change::ToRemove(v.into())
            }
        }
    }
}

impl From<pb::RewardNodeProvider> for api::RewardNodeProvider {
    fn from(item: pb::RewardNodeProvider) -> Self {
        Self {
            node_provider: item.node_provider.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
            reward_mode: item.reward_mode.map(|x| x.into()),
        }
    }
}
impl From<api::RewardNodeProvider> for pb::RewardNodeProvider {
    fn from(item: api::RewardNodeProvider) -> Self {
        Self {
            node_provider: item.node_provider.map(|x| x.into()),
            amount_e8s: item.amount_e8s,
            reward_mode: item.reward_mode.map(|x| x.into()),
        }
    }
}

impl From<pb::reward_node_provider::RewardToNeuron> for api::reward_node_provider::RewardToNeuron {
    fn from(item: pb::reward_node_provider::RewardToNeuron) -> Self {
        Self {
            dissolve_delay_seconds: item.dissolve_delay_seconds,
        }
    }
}
impl From<api::reward_node_provider::RewardToNeuron> for pb::reward_node_provider::RewardToNeuron {
    fn from(item: api::reward_node_provider::RewardToNeuron) -> Self {
        Self {
            dissolve_delay_seconds: item.dissolve_delay_seconds,
        }
    }
}

impl From<pb::reward_node_provider::RewardToAccount>
    for api::reward_node_provider::RewardToAccount
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

impl From<api::reward_node_provider::RewardToAccount>
    for pb::reward_node_provider::RewardToAccount
{
    fn from(item: api::reward_node_provider::RewardToAccount) -> Self {
        Self {
            to_account: item.to_account,
        }
    }
}

impl From<pb::reward_node_provider::RewardMode> for api::reward_node_provider::RewardMode {
    fn from(item: pb::reward_node_provider::RewardMode) -> Self {
        match item {
            pb::reward_node_provider::RewardMode::RewardToNeuron(v) => {
                api::reward_node_provider::RewardMode::RewardToNeuron(v.into())
            }
            pb::reward_node_provider::RewardMode::RewardToAccount(v) => {
                api::reward_node_provider::RewardMode::RewardToAccount(v.into())
            }
        }
    }
}
impl From<api::reward_node_provider::RewardMode> for pb::reward_node_provider::RewardMode {
    fn from(item: api::reward_node_provider::RewardMode) -> Self {
        match item {
            api::reward_node_provider::RewardMode::RewardToNeuron(v) => {
                pb::reward_node_provider::RewardMode::RewardToNeuron(v.into())
            }
            api::reward_node_provider::RewardMode::RewardToAccount(v) => {
                pb::reward_node_provider::RewardMode::RewardToAccount(v.into())
            }
        }
    }
}

impl From<pb::RewardNodeProviders> for api::RewardNodeProviders {
    fn from(item: pb::RewardNodeProviders) -> Self {
        Self {
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            use_registry_derived_rewards: item.use_registry_derived_rewards,
        }
    }
}
impl From<api::RewardNodeProviders> for pb::RewardNodeProviders {
    fn from(item: api::RewardNodeProviders) -> Self {
        Self {
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            use_registry_derived_rewards: item.use_registry_derived_rewards,
        }
    }
}

impl From<pb::SetDefaultFollowees> for api::SetDefaultFollowees {
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
impl From<api::SetDefaultFollowees> for pb::SetDefaultFollowees {
    fn from(item: api::SetDefaultFollowees) -> Self {
        Self {
            default_followees: item
                .default_followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<pb::SetSnsTokenSwapOpenTimeWindow> for api::SetSnsTokenSwapOpenTimeWindow {
    fn from(item: pb::SetSnsTokenSwapOpenTimeWindow) -> Self {
        Self {
            swap_canister_id: item.swap_canister_id,
            request: item.request,
        }
    }
}
impl From<api::SetSnsTokenSwapOpenTimeWindow> for pb::SetSnsTokenSwapOpenTimeWindow {
    fn from(item: api::SetSnsTokenSwapOpenTimeWindow) -> Self {
        Self {
            swap_canister_id: item.swap_canister_id,
            request: item.request,
        }
    }
}

impl From<api::Proposal> for pb::Proposal {
    fn from(item: api::Proposal) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
            self_describing_action: None,
        }
    }
}
impl From<api::MakeProposalRequest> for pb::Proposal {
    fn from(item: api::MakeProposalRequest) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
            self_describing_action: None,
        }
    }
}

impl From<api::proposal::Action> for pb::proposal::Action {
    fn from(item: api::proposal::Action) -> Self {
        match item {
            api::proposal::Action::ManageNeuron(v) => {
                pb::proposal::Action::ManageNeuron(Box::new((*v).into()))
            }
            api::proposal::Action::ManageNetworkEconomics(v) => {
                pb::proposal::Action::ManageNetworkEconomics(v.into())
            }
            api::proposal::Action::Motion(v) => pb::proposal::Action::Motion(v.into()),
            api::proposal::Action::ExecuteNnsFunction(v) => {
                pb::proposal::Action::ExecuteNnsFunction(v.into())
            }
            api::proposal::Action::ApproveGenesisKyc(v) => {
                pb::proposal::Action::ApproveGenesisKyc(v.into())
            }
            api::proposal::Action::AddOrRemoveNodeProvider(v) => {
                pb::proposal::Action::AddOrRemoveNodeProvider(v.into())
            }
            api::proposal::Action::RewardNodeProvider(v) => {
                pb::proposal::Action::RewardNodeProvider(v.into())
            }
            api::proposal::Action::SetDefaultFollowees(v) => {
                pb::proposal::Action::SetDefaultFollowees(v.into())
            }
            api::proposal::Action::RewardNodeProviders(v) => {
                pb::proposal::Action::RewardNodeProviders(v.into())
            }
            api::proposal::Action::RegisterKnownNeuron(v) => {
                pb::proposal::Action::RegisterKnownNeuron(v.into())
            }
            api::proposal::Action::DeregisterKnownNeuron(v) => {
                pb::proposal::Action::DeregisterKnownNeuron(v.into())
            }
            api::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v) => {
                pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.into())
            }
            api::proposal::Action::OpenSnsTokenSwap(v) => {
                pb::proposal::Action::OpenSnsTokenSwap(v.into())
            }
            api::proposal::Action::CreateServiceNervousSystem(v) => {
                pb::proposal::Action::CreateServiceNervousSystem(v.into())
            }
            api::proposal::Action::InstallCode(v) => pb::proposal::Action::InstallCode(v.into()),
            api::proposal::Action::StopOrStartCanister(v) => {
                pb::proposal::Action::StopOrStartCanister(v.into())
            }
            api::proposal::Action::UpdateCanisterSettings(v) => {
                pb::proposal::Action::UpdateCanisterSettings(v.into())
            }
            api::proposal::Action::FulfillSubnetRentalRequest(v) => {
                pb::proposal::Action::FulfillSubnetRentalRequest(v.into())
            }
            api::proposal::Action::BlessAlternativeGuestOsVersion(v) => {
                pb::proposal::Action::BlessAlternativeGuestOsVersion(v.into())
            }
            api::proposal::Action::TakeCanisterSnapshot(v) => {
                pb::proposal::Action::TakeCanisterSnapshot(v.into())
            }
            api::proposal::Action::LoadCanisterSnapshot(v) => {
                pb::proposal::Action::LoadCanisterSnapshot(v.into())
            }
        }
    }
}
impl From<api::ProposalActionRequest> for pb::proposal::Action {
    fn from(item: api::ProposalActionRequest) -> Self {
        match item {
            api::ProposalActionRequest::ManageNeuron(v) => {
                pb::proposal::Action::ManageNeuron(Box::new((*v).into()))
            }
            api::ProposalActionRequest::ManageNetworkEconomics(v) => {
                pb::proposal::Action::ManageNetworkEconomics(v.into())
            }
            api::ProposalActionRequest::Motion(v) => pb::proposal::Action::Motion(v.into()),
            api::ProposalActionRequest::ExecuteNnsFunction(v) => {
                pb::proposal::Action::ExecuteNnsFunction(v.into())
            }
            api::ProposalActionRequest::ApproveGenesisKyc(v) => {
                pb::proposal::Action::ApproveGenesisKyc(v.into())
            }
            api::ProposalActionRequest::AddOrRemoveNodeProvider(v) => {
                pb::proposal::Action::AddOrRemoveNodeProvider(v.into())
            }
            api::ProposalActionRequest::RewardNodeProvider(v) => {
                pb::proposal::Action::RewardNodeProvider(v.into())
            }
            api::ProposalActionRequest::RewardNodeProviders(v) => {
                pb::proposal::Action::RewardNodeProviders(v.into())
            }
            api::ProposalActionRequest::RegisterKnownNeuron(v) => {
                pb::proposal::Action::RegisterKnownNeuron(v.into())
            }
            api::ProposalActionRequest::DeregisterKnownNeuron(v) => {
                pb::proposal::Action::DeregisterKnownNeuron(v.into())
            }
            api::ProposalActionRequest::CreateServiceNervousSystem(v) => {
                pb::proposal::Action::CreateServiceNervousSystem(v.into())
            }
            api::ProposalActionRequest::InstallCode(v) => {
                pb::proposal::Action::InstallCode(v.into())
            }
            api::ProposalActionRequest::StopOrStartCanister(v) => {
                pb::proposal::Action::StopOrStartCanister(v.into())
            }
            api::ProposalActionRequest::UpdateCanisterSettings(v) => {
                pb::proposal::Action::UpdateCanisterSettings(v.into())
            }
            api::ProposalActionRequest::FulfillSubnetRentalRequest(v) => {
                pb::proposal::Action::FulfillSubnetRentalRequest(v.into())
            }
            api::ProposalActionRequest::BlessAlternativeGuestOsVersion(v) => {
                pb::proposal::Action::BlessAlternativeGuestOsVersion(v.into())
            }
            api::ProposalActionRequest::TakeCanisterSnapshot(v) => {
                pb::proposal::Action::TakeCanisterSnapshot(v.into())
            }
            api::ProposalActionRequest::LoadCanisterSnapshot(v) => {
                pb::proposal::Action::LoadCanisterSnapshot(v.into())
            }
        }
    }
}

impl From<pb::Empty> for api::Empty {
    fn from(_: pb::Empty) -> Self {
        Self {}
    }
}
impl From<api::Empty> for pb::Empty {
    fn from(_: api::Empty) -> Self {
        Self {}
    }
}

impl From<pb::ManageNeuron> for api::ManageNeuronProposal {
    fn from(item: pb::ManageNeuron) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<api::ManageNeuronProposal> for pb::ManageNeuron {
    fn from(item: api::ManageNeuronProposal) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<api::ManageNeuronRequest> for pb::ManageNeuron {
    fn from(item: api::ManageNeuronRequest) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::IncreaseDissolveDelay> for api::manage_neuron::IncreaseDissolveDelay {
    fn from(item: pb::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}
impl From<api::manage_neuron::IncreaseDissolveDelay> for pb::manage_neuron::IncreaseDissolveDelay {
    fn from(item: api::manage_neuron::IncreaseDissolveDelay) -> Self {
        Self {
            additional_dissolve_delay_seconds: item.additional_dissolve_delay_seconds,
        }
    }
}

impl From<pb::manage_neuron::StartDissolving> for api::manage_neuron::StartDissolving {
    fn from(_: pb::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}
impl From<api::manage_neuron::StartDissolving> for pb::manage_neuron::StartDissolving {
    fn from(_: api::manage_neuron::StartDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::StopDissolving> for api::manage_neuron::StopDissolving {
    fn from(_: pb::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}
impl From<api::manage_neuron::StopDissolving> for pb::manage_neuron::StopDissolving {
    fn from(_: api::manage_neuron::StopDissolving) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::AddHotKey> for api::manage_neuron::AddHotKey {
    fn from(item: pb::manage_neuron::AddHotKey) -> Self {
        Self {
            new_hot_key: item.new_hot_key,
        }
    }
}
impl From<api::manage_neuron::AddHotKey> for pb::manage_neuron::AddHotKey {
    fn from(item: api::manage_neuron::AddHotKey) -> Self {
        Self {
            new_hot_key: item.new_hot_key,
        }
    }
}

impl From<pb::manage_neuron::RemoveHotKey> for api::manage_neuron::RemoveHotKey {
    fn from(item: pb::manage_neuron::RemoveHotKey) -> Self {
        Self {
            hot_key_to_remove: item.hot_key_to_remove,
        }
    }
}
impl From<api::manage_neuron::RemoveHotKey> for pb::manage_neuron::RemoveHotKey {
    fn from(item: api::manage_neuron::RemoveHotKey) -> Self {
        Self {
            hot_key_to_remove: item.hot_key_to_remove,
        }
    }
}

impl From<pb::manage_neuron::SetDissolveTimestamp> for api::manage_neuron::SetDissolveTimestamp {
    fn from(item: pb::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}
impl From<api::manage_neuron::SetDissolveTimestamp> for pb::manage_neuron::SetDissolveTimestamp {
    fn from(item: api::manage_neuron::SetDissolveTimestamp) -> Self {
        Self {
            dissolve_timestamp_seconds: item.dissolve_timestamp_seconds,
        }
    }
}

impl From<pb::manage_neuron::JoinCommunityFund> for api::manage_neuron::JoinCommunityFund {
    fn from(_: pb::manage_neuron::JoinCommunityFund) -> Self {
        Self {}
    }
}
impl From<api::manage_neuron::JoinCommunityFund> for pb::manage_neuron::JoinCommunityFund {
    fn from(_: api::manage_neuron::JoinCommunityFund) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::LeaveCommunityFund> for api::manage_neuron::LeaveCommunityFund {
    fn from(_: pb::manage_neuron::LeaveCommunityFund) -> Self {
        Self {}
    }
}
impl From<api::manage_neuron::LeaveCommunityFund> for pb::manage_neuron::LeaveCommunityFund {
    fn from(_: api::manage_neuron::LeaveCommunityFund) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron::ChangeAutoStakeMaturity>
    for api::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: pb::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}
impl From<api::manage_neuron::ChangeAutoStakeMaturity>
    for pb::manage_neuron::ChangeAutoStakeMaturity
{
    fn from(item: api::manage_neuron::ChangeAutoStakeMaturity) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity: item
                .requested_setting_for_auto_stake_maturity,
        }
    }
}

impl From<pb::manage_neuron::SetVisibility> for api::manage_neuron::SetVisibility {
    fn from(item: pb::manage_neuron::SetVisibility) -> Self {
        Self {
            visibility: item.visibility,
        }
    }
}
impl From<api::manage_neuron::SetVisibility> for pb::manage_neuron::SetVisibility {
    fn from(item: api::manage_neuron::SetVisibility) -> Self {
        Self {
            visibility: item.visibility,
        }
    }
}

impl From<pb::manage_neuron::Configure> for api::manage_neuron::Configure {
    fn from(item: pb::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}
impl From<api::manage_neuron::Configure> for pb::manage_neuron::Configure {
    fn from(item: api::manage_neuron::Configure) -> Self {
        Self {
            operation: item.operation.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::configure::Operation> for api::manage_neuron::configure::Operation {
    fn from(item: pb::manage_neuron::configure::Operation) -> Self {
        match item {
            pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            pb::manage_neuron::configure::Operation::StartDissolving(v) => {
                api::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::StopDissolving(v) => {
                api::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            pb::manage_neuron::configure::Operation::AddHotKey(v) => {
                api::manage_neuron::configure::Operation::AddHotKey(v.into())
            }
            pb::manage_neuron::configure::Operation::RemoveHotKey(v) => {
                api::manage_neuron::configure::Operation::RemoveHotKey(v.into())
            }
            pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                api::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            pb::manage_neuron::configure::Operation::JoinCommunityFund(v) => {
                api::manage_neuron::configure::Operation::JoinCommunityFund(v.into())
            }
            pb::manage_neuron::configure::Operation::LeaveCommunityFund(v) => {
                api::manage_neuron::configure::Operation::LeaveCommunityFund(v.into())
            }
            pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
            pb::manage_neuron::configure::Operation::SetVisibility(v) => {
                api::manage_neuron::configure::Operation::SetVisibility(v.into())
            }
        }
    }
}
impl From<api::manage_neuron::configure::Operation> for pb::manage_neuron::configure::Operation {
    fn from(item: api::manage_neuron::configure::Operation) -> Self {
        match item {
            api::manage_neuron::configure::Operation::IncreaseDissolveDelay(v) => {
                pb::manage_neuron::configure::Operation::IncreaseDissolveDelay(v.into())
            }
            api::manage_neuron::configure::Operation::StartDissolving(v) => {
                pb::manage_neuron::configure::Operation::StartDissolving(v.into())
            }
            api::manage_neuron::configure::Operation::StopDissolving(v) => {
                pb::manage_neuron::configure::Operation::StopDissolving(v.into())
            }
            api::manage_neuron::configure::Operation::AddHotKey(v) => {
                pb::manage_neuron::configure::Operation::AddHotKey(v.into())
            }
            api::manage_neuron::configure::Operation::RemoveHotKey(v) => {
                pb::manage_neuron::configure::Operation::RemoveHotKey(v.into())
            }
            api::manage_neuron::configure::Operation::SetDissolveTimestamp(v) => {
                pb::manage_neuron::configure::Operation::SetDissolveTimestamp(v.into())
            }
            api::manage_neuron::configure::Operation::JoinCommunityFund(v) => {
                pb::manage_neuron::configure::Operation::JoinCommunityFund(v.into())
            }
            api::manage_neuron::configure::Operation::LeaveCommunityFund(v) => {
                pb::manage_neuron::configure::Operation::LeaveCommunityFund(v.into())
            }
            api::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v) => {
                pb::manage_neuron::configure::Operation::ChangeAutoStakeMaturity(v.into())
            }
            api::manage_neuron::configure::Operation::SetVisibility(v) => {
                pb::manage_neuron::configure::Operation::SetVisibility(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::Disburse> for api::manage_neuron::Disburse {
    fn from(item: pb::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account,
        }
    }
}
impl From<api::manage_neuron::Disburse> for pb::manage_neuron::Disburse {
    fn from(item: api::manage_neuron::Disburse) -> Self {
        Self {
            amount: item.amount.map(|x| x.into()),
            to_account: item.to_account,
        }
    }
}

impl From<pb::manage_neuron::disburse::Amount> for api::manage_neuron::disburse::Amount {
    fn from(item: pb::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}
impl From<api::manage_neuron::disburse::Amount> for pb::manage_neuron::disburse::Amount {
    fn from(item: api::manage_neuron::disburse::Amount) -> Self {
        Self { e8s: item.e8s }
    }
}

impl From<pb::manage_neuron::Split> for api::manage_neuron::Split {
    fn from(item: pb::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}
impl From<api::manage_neuron::Split> for pb::manage_neuron::Split {
    fn from(item: api::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
            memo: item.memo,
        }
    }
}

impl From<pb::manage_neuron::Merge> for api::manage_neuron::Merge {
    fn from(item: pb::manage_neuron::Merge) -> Self {
        Self {
            source_neuron_id: item.source_neuron_id,
        }
    }
}
impl From<api::manage_neuron::Merge> for pb::manage_neuron::Merge {
    fn from(item: api::manage_neuron::Merge) -> Self {
        Self {
            source_neuron_id: item.source_neuron_id,
        }
    }
}

impl From<pb::manage_neuron::Spawn> for api::manage_neuron::Spawn {
    fn from(item: pb::manage_neuron::Spawn) -> Self {
        Self {
            new_controller: item.new_controller,
            nonce: item.nonce,
            percentage_to_spawn: item.percentage_to_spawn,
        }
    }
}
impl From<api::manage_neuron::Spawn> for pb::manage_neuron::Spawn {
    fn from(item: api::manage_neuron::Spawn) -> Self {
        Self {
            new_controller: item.new_controller,
            nonce: item.nonce,
            percentage_to_spawn: item.percentage_to_spawn,
        }
    }
}

impl From<pb::manage_neuron::MergeMaturity> for api::manage_neuron::MergeMaturity {
    fn from(item: pb::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}
impl From<api::manage_neuron::MergeMaturity> for pb::manage_neuron::MergeMaturity {
    fn from(item: api::manage_neuron::MergeMaturity) -> Self {
        Self {
            percentage_to_merge: item.percentage_to_merge,
        }
    }
}

impl From<pb::manage_neuron::StakeMaturity> for api::manage_neuron::StakeMaturity {
    fn from(item: pb::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}
impl From<api::manage_neuron::StakeMaturity> for pb::manage_neuron::StakeMaturity {
    fn from(item: api::manage_neuron::StakeMaturity) -> Self {
        Self {
            percentage_to_stake: item.percentage_to_stake,
        }
    }
}

impl From<pb::manage_neuron::RefreshVotingPower> for api::manage_neuron::RefreshVotingPower {
    fn from(_item: pb::manage_neuron::RefreshVotingPower) -> Self {
        Self {}
    }
}
impl From<api::manage_neuron::RefreshVotingPower> for pb::manage_neuron::RefreshVotingPower {
    fn from(_item: api::manage_neuron::RefreshVotingPower) -> Self {
        Self {}
    }
}
impl From<pb::manage_neuron::DisburseToNeuron> for api::manage_neuron::DisburseToNeuron {
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
impl From<api::manage_neuron::DisburseToNeuron> for pb::manage_neuron::DisburseToNeuron {
    fn from(item: api::manage_neuron::DisburseToNeuron) -> Self {
        Self {
            new_controller: item.new_controller,
            amount_e8s: item.amount_e8s,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            kyc_verified: item.kyc_verified,
            nonce: item.nonce,
        }
    }
}

impl From<pb::manage_neuron::Follow> for api::manage_neuron::Follow {
    fn from(item: pb::manage_neuron::Follow) -> Self {
        Self {
            topic: item.topic,
            followees: item.followees,
        }
    }
}
impl From<api::manage_neuron::Follow> for pb::manage_neuron::Follow {
    fn from(item: api::manage_neuron::Follow) -> Self {
        Self {
            topic: item.topic,
            followees: item.followees,
        }
    }
}

impl From<pb::manage_neuron::RegisterVote> for api::manage_neuron::RegisterVote {
    fn from(item: pb::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal,
            vote: item.vote,
        }
    }
}
impl From<api::manage_neuron::RegisterVote> for pb::manage_neuron::RegisterVote {
    fn from(item: api::manage_neuron::RegisterVote) -> Self {
        Self {
            proposal: item.proposal,
            vote: item.vote,
        }
    }
}

impl From<pb::manage_neuron::ClaimOrRefresh> for api::manage_neuron::ClaimOrRefresh {
    fn from(item: pb::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}
impl From<api::manage_neuron::ClaimOrRefresh> for pb::manage_neuron::ClaimOrRefresh {
    fn from(item: api::manage_neuron::ClaimOrRefresh) -> Self {
        Self {
            by: item.by.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron::DisburseMaturity> for api::manage_neuron::DisburseMaturity {
    fn from(item: pb::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
            to_account_identifier: item.to_account_identifier,
        }
    }
}
impl From<api::manage_neuron::DisburseMaturity> for pb::manage_neuron::DisburseMaturity {
    fn from(item: api::manage_neuron::DisburseMaturity) -> Self {
        Self {
            percentage_to_disburse: item.percentage_to_disburse,
            to_account: item.to_account.map(|x| x.into()),
            to_account_identifier: item.to_account_identifier,
        }
    }
}

impl From<pb::manage_neuron::SetFollowing> for api::manage_neuron::SetFollowing {
    fn from(item: pb::manage_neuron::SetFollowing) -> Self {
        Self {
            topic_following: Some(item.topic_following.into_iter().map(|x| x.into()).collect()),
        }
    }
}
impl From<api::manage_neuron::SetFollowing> for pb::manage_neuron::SetFollowing {
    fn from(item: api::manage_neuron::SetFollowing) -> Self {
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
    for api::manage_neuron::set_following::FolloweesForTopic
{
    fn from(item: pb::manage_neuron::set_following::FolloweesForTopic) -> Self {
        Self {
            followees: Some(item.followees),
            topic: item.topic,
        }
    }
}
impl From<api::manage_neuron::set_following::FolloweesForTopic>
    for pb::manage_neuron::set_following::FolloweesForTopic
{
    fn from(item: api::manage_neuron::set_following::FolloweesForTopic) -> Self {
        Self {
            followees: item.followees.unwrap_or_default(),
            topic: item.topic,
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::MemoAndController>
    for api::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: pb::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}
impl From<api::manage_neuron::claim_or_refresh::MemoAndController>
    for pb::manage_neuron::claim_or_refresh::MemoAndController
{
    fn from(item: api::manage_neuron::claim_or_refresh::MemoAndController) -> Self {
        Self {
            memo: item.memo,
            controller: item.controller,
        }
    }
}

impl From<pb::manage_neuron::claim_or_refresh::By> for api::manage_neuron::claim_or_refresh::By {
    fn from(item: pb::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            pb::manage_neuron::claim_or_refresh::By::Memo(v) => {
                api::manage_neuron::claim_or_refresh::By::Memo(v)
            }
            pb::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                api::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            pb::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v) => {
                api::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v.into())
            }
        }
    }
}
impl From<api::manage_neuron::claim_or_refresh::By> for pb::manage_neuron::claim_or_refresh::By {
    fn from(item: api::manage_neuron::claim_or_refresh::By) -> Self {
        match item {
            api::manage_neuron::claim_or_refresh::By::Memo(v) => {
                pb::manage_neuron::claim_or_refresh::By::Memo(v)
            }
            api::manage_neuron::claim_or_refresh::By::MemoAndController(v) => {
                pb::manage_neuron::claim_or_refresh::By::MemoAndController(v.into())
            }
            api::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v) => {
                pb::manage_neuron::claim_or_refresh::By::NeuronIdOrSubaccount(v.into())
            }
        }
    }
}

impl From<pb::manage_neuron::NeuronIdOrSubaccount> for api::manage_neuron::NeuronIdOrSubaccount {
    fn from(item: pb::manage_neuron::NeuronIdOrSubaccount) -> Self {
        match item {
            pb::manage_neuron::NeuronIdOrSubaccount::Subaccount(v) => {
                api::manage_neuron::NeuronIdOrSubaccount::Subaccount(v)
            }
            pb::manage_neuron::NeuronIdOrSubaccount::NeuronId(v) => {
                api::manage_neuron::NeuronIdOrSubaccount::NeuronId(v)
            }
        }
    }
}
impl From<api::manage_neuron::NeuronIdOrSubaccount> for pb::manage_neuron::NeuronIdOrSubaccount {
    fn from(item: api::manage_neuron::NeuronIdOrSubaccount) -> Self {
        match item {
            api::manage_neuron::NeuronIdOrSubaccount::Subaccount(v) => {
                pb::manage_neuron::NeuronIdOrSubaccount::Subaccount(v)
            }
            api::manage_neuron::NeuronIdOrSubaccount::NeuronId(v) => {
                pb::manage_neuron::NeuronIdOrSubaccount::NeuronId(v)
            }
        }
    }
}

// TODO: Remove this once the proposals exposed by Governance API no longer includes `Action` but
// only the self-describing version.
impl From<pb::manage_neuron::Command> for api::manage_neuron::ManageNeuronProposalCommand {
    fn from(item: pb::manage_neuron::Command) -> Self {
        match item {
            pb::manage_neuron::Command::Configure(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Configure(v.into())
            }
            pb::manage_neuron::Command::Disburse(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Disburse(v.into())
            }
            pb::manage_neuron::Command::Spawn(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Spawn(v.into())
            }
            pb::manage_neuron::Command::Follow(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Follow(v.into())
            }
            pb::manage_neuron::Command::MakeProposal(v) => {
                // Note: this case is actually impossible since we no longer allow creating
                // proposals through another ManageNeuron proposal. However this case cannot be
                // easily removed until the `manage_neuron` canister method no longer uses
                // `pb::manage_neuron::Command`.
                api::manage_neuron::ManageNeuronProposalCommand::MakeProposal(Box::new(
                    convert_proposal(&v, ProposalDisplayOptions::for_get_proposal_info()),
                ))
            }
            pb::manage_neuron::Command::RegisterVote(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::RegisterVote(v.into())
            }
            pb::manage_neuron::Command::Split(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Split(v.into())
            }
            pb::manage_neuron::Command::DisburseToNeuron(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::DisburseToNeuron(v.into())
            }
            pb::manage_neuron::Command::ClaimOrRefresh(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron::Command::MergeMaturity(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::MergeMaturity(v.into())
            }
            pb::manage_neuron::Command::Merge(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::Merge(v.into())
            }
            pb::manage_neuron::Command::StakeMaturity(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::StakeMaturity(v.into())
            }
            pb::manage_neuron::Command::RefreshVotingPower(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::RefreshVotingPower(v.into())
            }
            pb::manage_neuron::Command::DisburseMaturity(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::DisburseMaturity(v.into())
            }
            pb::manage_neuron::Command::SetFollowing(v) => {
                api::manage_neuron::ManageNeuronProposalCommand::SetFollowing(v.into())
            }
        }
    }
}
impl From<api::manage_neuron::ManageNeuronProposalCommand> for pb::manage_neuron::Command {
    fn from(item: api::manage_neuron::ManageNeuronProposalCommand) -> Self {
        match item {
            api::manage_neuron::ManageNeuronProposalCommand::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::Spawn(v) => {
                pb::manage_neuron::Command::Spawn(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            api::manage_neuron::ManageNeuronProposalCommand::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::Split(v) => {
                pb::manage_neuron::Command::Split(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::DisburseToNeuron(v) => {
                pb::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::Merge(v) => {
                pb::manage_neuron::Command::Merge(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::RefreshVotingPower(v) => {
                pb::manage_neuron::Command::RefreshVotingPower(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::DisburseMaturity(v) => {
                pb::manage_neuron::Command::DisburseMaturity(v.into())
            }
            api::manage_neuron::ManageNeuronProposalCommand::SetFollowing(v) => {
                pb::manage_neuron::Command::SetFollowing(v.into())
            }
        }
    }
}
impl From<api::ManageNeuronCommandRequest> for pb::manage_neuron::Command {
    fn from(item: api::ManageNeuronCommandRequest) -> Self {
        match item {
            api::ManageNeuronCommandRequest::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            api::ManageNeuronCommandRequest::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            api::ManageNeuronCommandRequest::Spawn(v) => {
                pb::manage_neuron::Command::Spawn(v.into())
            }
            api::ManageNeuronCommandRequest::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            api::ManageNeuronCommandRequest::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            api::ManageNeuronCommandRequest::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            api::ManageNeuronCommandRequest::Split(v) => {
                pb::manage_neuron::Command::Split(v.into())
            }
            api::ManageNeuronCommandRequest::DisburseToNeuron(v) => {
                pb::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            api::ManageNeuronCommandRequest::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            api::ManageNeuronCommandRequest::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            api::ManageNeuronCommandRequest::Merge(v) => {
                pb::manage_neuron::Command::Merge(v.into())
            }
            api::ManageNeuronCommandRequest::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
            }
            api::ManageNeuronCommandRequest::RefreshVotingPower(v) => {
                pb::manage_neuron::Command::RefreshVotingPower(v.into())
            }
            api::ManageNeuronCommandRequest::DisburseMaturity(v) => {
                pb::manage_neuron::Command::DisburseMaturity(v.into())
            }
            api::ManageNeuronCommandRequest::SetFollowing(v) => {
                pb::manage_neuron::Command::SetFollowing(v.into())
            }
        }
    }
}

impl From<pb::GovernanceError> for api::GovernanceError {
    fn from(item: pb::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}
impl From<api::GovernanceError> for pb::GovernanceError {
    fn from(item: api::GovernanceError) -> Self {
        Self {
            error_type: item.error_type,
            error_message: item.error_message,
        }
    }
}

impl From<pb::governance_error::ErrorType> for api::governance_error::ErrorType {
    fn from(item: pb::governance_error::ErrorType) -> Self {
        match item {
            pb::governance_error::ErrorType::Unspecified => {
                api::governance_error::ErrorType::Unspecified
            }
            pb::governance_error::ErrorType::Ok => api::governance_error::ErrorType::Ok,
            pb::governance_error::ErrorType::Unavailable => {
                api::governance_error::ErrorType::Unavailable
            }
            pb::governance_error::ErrorType::NotAuthorized => {
                api::governance_error::ErrorType::NotAuthorized
            }
            pb::governance_error::ErrorType::NotFound => api::governance_error::ErrorType::NotFound,
            pb::governance_error::ErrorType::InvalidCommand => {
                api::governance_error::ErrorType::InvalidCommand
            }
            pb::governance_error::ErrorType::RequiresNotDissolving => {
                api::governance_error::ErrorType::RequiresNotDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolving => {
                api::governance_error::ErrorType::RequiresDissolving
            }
            pb::governance_error::ErrorType::RequiresDissolved => {
                api::governance_error::ErrorType::RequiresDissolved
            }
            pb::governance_error::ErrorType::HotKey => api::governance_error::ErrorType::HotKey,
            pb::governance_error::ErrorType::ResourceExhausted => {
                api::governance_error::ErrorType::ResourceExhausted
            }
            pb::governance_error::ErrorType::PreconditionFailed => {
                api::governance_error::ErrorType::PreconditionFailed
            }
            pb::governance_error::ErrorType::External => api::governance_error::ErrorType::External,
            pb::governance_error::ErrorType::LedgerUpdateOngoing => {
                api::governance_error::ErrorType::LedgerUpdateOngoing
            }
            pb::governance_error::ErrorType::InsufficientFunds => {
                api::governance_error::ErrorType::InsufficientFunds
            }
            pb::governance_error::ErrorType::InvalidPrincipal => {
                api::governance_error::ErrorType::InvalidPrincipal
            }
            pb::governance_error::ErrorType::InvalidProposal => {
                api::governance_error::ErrorType::InvalidProposal
            }
            pb::governance_error::ErrorType::AlreadyJoinedCommunityFund => {
                api::governance_error::ErrorType::AlreadyJoinedCommunityFund
            }
            pb::governance_error::ErrorType::NotInTheCommunityFund => {
                api::governance_error::ErrorType::NotInTheCommunityFund
            }
            pb::governance_error::ErrorType::NeuronAlreadyVoted => {
                api::governance_error::ErrorType::NeuronAlreadyVoted
            }
        }
    }
}
impl From<api::governance_error::ErrorType> for pb::governance_error::ErrorType {
    fn from(item: api::governance_error::ErrorType) -> Self {
        match item {
            api::governance_error::ErrorType::Unspecified => {
                pb::governance_error::ErrorType::Unspecified
            }
            api::governance_error::ErrorType::Ok => pb::governance_error::ErrorType::Ok,
            api::governance_error::ErrorType::Unavailable => {
                pb::governance_error::ErrorType::Unavailable
            }
            api::governance_error::ErrorType::NotAuthorized => {
                pb::governance_error::ErrorType::NotAuthorized
            }
            api::governance_error::ErrorType::NotFound => pb::governance_error::ErrorType::NotFound,
            api::governance_error::ErrorType::InvalidCommand => {
                pb::governance_error::ErrorType::InvalidCommand
            }
            api::governance_error::ErrorType::RequiresNotDissolving => {
                pb::governance_error::ErrorType::RequiresNotDissolving
            }
            api::governance_error::ErrorType::RequiresDissolving => {
                pb::governance_error::ErrorType::RequiresDissolving
            }
            api::governance_error::ErrorType::RequiresDissolved => {
                pb::governance_error::ErrorType::RequiresDissolved
            }
            api::governance_error::ErrorType::HotKey => pb::governance_error::ErrorType::HotKey,
            api::governance_error::ErrorType::ResourceExhausted => {
                pb::governance_error::ErrorType::ResourceExhausted
            }
            api::governance_error::ErrorType::PreconditionFailed => {
                pb::governance_error::ErrorType::PreconditionFailed
            }
            api::governance_error::ErrorType::External => pb::governance_error::ErrorType::External,
            api::governance_error::ErrorType::LedgerUpdateOngoing => {
                pb::governance_error::ErrorType::LedgerUpdateOngoing
            }
            api::governance_error::ErrorType::InsufficientFunds => {
                pb::governance_error::ErrorType::InsufficientFunds
            }
            api::governance_error::ErrorType::InvalidPrincipal => {
                pb::governance_error::ErrorType::InvalidPrincipal
            }
            api::governance_error::ErrorType::InvalidProposal => {
                pb::governance_error::ErrorType::InvalidProposal
            }
            api::governance_error::ErrorType::AlreadyJoinedCommunityFund => {
                pb::governance_error::ErrorType::AlreadyJoinedCommunityFund
            }
            api::governance_error::ErrorType::NotInTheCommunityFund => {
                pb::governance_error::ErrorType::NotInTheCommunityFund
            }
            api::governance_error::ErrorType::NeuronAlreadyVoted => {
                pb::governance_error::ErrorType::NeuronAlreadyVoted
            }
        }
    }
}

impl From<pb::Ballot> for api::Ballot {
    fn from(item: pb::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
        }
    }
}
impl From<api::Ballot> for pb::Ballot {
    fn from(item: api::Ballot) -> Self {
        Self {
            vote: item.vote,
            voting_power: item.voting_power,
        }
    }
}

impl From<pb::Tally> for api::Tally {
    fn from(item: pb::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}
impl From<api::Tally> for pb::Tally {
    fn from(item: api::Tally) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            yes: item.yes,
            no: item.no,
            total: item.total,
        }
    }
}

impl From<api::ProposalData> for pb::ProposalData {
    fn from(item: api::ProposalData) -> Self {
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

impl From<pb::NeuronsFundData> for api::NeuronsFundData {
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
impl From<api::NeuronsFundData> for pb::NeuronsFundData {
    fn from(item: api::NeuronsFundData) -> Self {
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

impl From<pb::NeuronsFundAuditInfo> for api::NeuronsFundAuditInfo {
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
impl From<api::NeuronsFundAuditInfo> for pb::NeuronsFundAuditInfo {
    fn from(item: api::NeuronsFundAuditInfo) -> Self {
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

impl From<pb::GetNeuronsFundAuditInfoRequest> for api::GetNeuronsFundAuditInfoRequest {
    fn from(item: pb::GetNeuronsFundAuditInfoRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
        }
    }
}
impl From<api::GetNeuronsFundAuditInfoRequest> for pb::GetNeuronsFundAuditInfoRequest {
    fn from(item: api::GetNeuronsFundAuditInfoRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
        }
    }
}

impl From<pb::GetNeuronsFundAuditInfoResponse> for api::GetNeuronsFundAuditInfoResponse {
    fn from(item: pb::GetNeuronsFundAuditInfoResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<api::GetNeuronsFundAuditInfoResponse> for pb::GetNeuronsFundAuditInfoResponse {
    fn from(item: api::GetNeuronsFundAuditInfoResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::get_neurons_fund_audit_info_response::Ok>
    for api::get_neurons_fund_audit_info_response::Ok
{
    fn from(item: pb::get_neurons_fund_audit_info_response::Ok) -> Self {
        Self {
            neurons_fund_audit_info: item.neurons_fund_audit_info.map(|x| x.into()),
        }
    }
}
impl From<api::get_neurons_fund_audit_info_response::Ok>
    for pb::get_neurons_fund_audit_info_response::Ok
{
    fn from(item: api::get_neurons_fund_audit_info_response::Ok) -> Self {
        Self {
            neurons_fund_audit_info: item.neurons_fund_audit_info.map(|x| x.into()),
        }
    }
}

impl From<pb::get_neurons_fund_audit_info_response::Result>
    for api::get_neurons_fund_audit_info_response::Result
{
    fn from(item: pb::get_neurons_fund_audit_info_response::Result) -> Self {
        match item {
            pb::get_neurons_fund_audit_info_response::Result::Err(v) => {
                api::get_neurons_fund_audit_info_response::Result::Err(v.into())
            }
            pb::get_neurons_fund_audit_info_response::Result::Ok(v) => {
                api::get_neurons_fund_audit_info_response::Result::Ok(v.into())
            }
        }
    }
}
impl From<api::get_neurons_fund_audit_info_response::Result>
    for pb::get_neurons_fund_audit_info_response::Result
{
    fn from(item: api::get_neurons_fund_audit_info_response::Result) -> Self {
        match item {
            api::get_neurons_fund_audit_info_response::Result::Err(v) => {
                pb::get_neurons_fund_audit_info_response::Result::Err(v.into())
            }
            api::get_neurons_fund_audit_info_response::Result::Ok(v) => {
                pb::get_neurons_fund_audit_info_response::Result::Ok(v.into())
            }
        }
    }
}

impl From<pb::NeuronsFundParticipation> for api::NeuronsFundParticipation {
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
impl From<api::NeuronsFundParticipation> for pb::NeuronsFundParticipation {
    fn from(item: api::NeuronsFundParticipation) -> Self {
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

impl From<pb::IdealMatchedParticipationFunction> for api::IdealMatchedParticipationFunction {
    fn from(item: pb::IdealMatchedParticipationFunction) -> Self {
        Self {
            serialized_representation: item.serialized_representation,
        }
    }
}
impl From<api::IdealMatchedParticipationFunction> for pb::IdealMatchedParticipationFunction {
    fn from(item: api::IdealMatchedParticipationFunction) -> Self {
        Self {
            serialized_representation: item.serialized_representation,
        }
    }
}

impl From<pb::NeuronsFundSnapshot> for api::NeuronsFundSnapshot {
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
impl From<api::NeuronsFundSnapshot> for pb::NeuronsFundSnapshot {
    fn from(item: api::NeuronsFundSnapshot) -> Self {
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
    for api::neurons_fund_snapshot::NeuronsFundNeuronPortion
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
impl From<api::neurons_fund_snapshot::NeuronsFundNeuronPortion>
    for pb::neurons_fund_snapshot::NeuronsFundNeuronPortion
{
    fn from(item: api::neurons_fund_snapshot::NeuronsFundNeuronPortion) -> Self {
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

impl From<pb::SwapParticipationLimits> for api::SwapParticipationLimits {
    fn from(item: pb::SwapParticipationLimits) -> Self {
        Self {
            min_direct_participation_icp_e8s: item.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: item.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: item.min_participant_icp_e8s,
            max_participant_icp_e8s: item.max_participant_icp_e8s,
        }
    }
}
impl From<api::SwapParticipationLimits> for pb::SwapParticipationLimits {
    fn from(item: api::SwapParticipationLimits) -> Self {
        Self {
            min_direct_participation_icp_e8s: item.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: item.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: item.min_participant_icp_e8s,
            max_participant_icp_e8s: item.max_participant_icp_e8s,
        }
    }
}

impl From<pb::DerivedProposalInformation> for api::DerivedProposalInformation {
    fn from(item: pb::DerivedProposalInformation) -> Self {
        Self {
            swap_background_information: item.swap_background_information.map(|x| x.into()),
        }
    }
}
impl From<api::DerivedProposalInformation> for pb::DerivedProposalInformation {
    fn from(item: api::DerivedProposalInformation) -> Self {
        Self {
            swap_background_information: item.swap_background_information.map(|x| x.into()),
        }
    }
}

impl From<pb::SwapBackgroundInformation> for api::SwapBackgroundInformation {
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
impl From<api::SwapBackgroundInformation> for pb::SwapBackgroundInformation {
    fn from(item: api::SwapBackgroundInformation) -> Self {
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
    for api::swap_background_information::CanisterSummary
{
    fn from(item: pb::swap_background_information::CanisterSummary) -> Self {
        Self {
            canister_id: item.canister_id,
            status: item.status.map(|x| x.into()),
        }
    }
}
impl From<api::swap_background_information::CanisterSummary>
    for pb::swap_background_information::CanisterSummary
{
    fn from(item: api::swap_background_information::CanisterSummary) -> Self {
        Self {
            canister_id: item.canister_id,
            status: item.status.map(|x| x.into()),
        }
    }
}

impl From<pb::swap_background_information::CanisterStatusResultV2>
    for api::swap_background_information::CanisterStatusResultV2
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
impl From<api::swap_background_information::CanisterStatusResultV2>
    for pb::swap_background_information::CanisterStatusResultV2
{
    fn from(item: api::swap_background_information::CanisterStatusResultV2) -> Self {
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
    for api::swap_background_information::CanisterStatusType
{
    fn from(item: pb::swap_background_information::CanisterStatusType) -> Self {
        match item {
            pb::swap_background_information::CanisterStatusType::Unspecified => {
                api::swap_background_information::CanisterStatusType::Unspecified
            }
            pb::swap_background_information::CanisterStatusType::Running => {
                api::swap_background_information::CanisterStatusType::Running
            }
            pb::swap_background_information::CanisterStatusType::Stopping => {
                api::swap_background_information::CanisterStatusType::Stopping
            }
            pb::swap_background_information::CanisterStatusType::Stopped => {
                api::swap_background_information::CanisterStatusType::Stopped
            }
        }
    }
}
impl From<api::swap_background_information::CanisterStatusType>
    for pb::swap_background_information::CanisterStatusType
{
    fn from(item: api::swap_background_information::CanisterStatusType) -> Self {
        match item {
            api::swap_background_information::CanisterStatusType::Unspecified => {
                pb::swap_background_information::CanisterStatusType::Unspecified
            }
            api::swap_background_information::CanisterStatusType::Running => {
                pb::swap_background_information::CanisterStatusType::Running
            }
            api::swap_background_information::CanisterStatusType::Stopping => {
                pb::swap_background_information::CanisterStatusType::Stopping
            }
            api::swap_background_information::CanisterStatusType::Stopped => {
                pb::swap_background_information::CanisterStatusType::Stopped
            }
        }
    }
}

impl From<pb::WaitForQuietState> for api::WaitForQuietState {
    fn from(item: pb::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}
impl From<api::WaitForQuietState> for pb::WaitForQuietState {
    fn from(item: api::WaitForQuietState) -> Self {
        Self {
            current_deadline_timestamp_seconds: item.current_deadline_timestamp_seconds,
        }
    }
}

impl From<pb::NetworkEconomics> for api::NetworkEconomics {
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

impl From<api::NetworkEconomics> for pb::NetworkEconomics {
    fn from(item: api::NetworkEconomics) -> Self {
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

impl From<api::VotingPowerEconomics> for pb::VotingPowerEconomics {
    fn from(item: api::VotingPowerEconomics) -> Self {
        Self {
            start_reducing_voting_power_after_seconds: item
                .start_reducing_voting_power_after_seconds,
            clear_following_after_seconds: item.clear_following_after_seconds,
            neuron_minimum_dissolve_delay_to_vote_seconds: item
                .neuron_minimum_dissolve_delay_to_vote_seconds,
        }
    }
}

impl From<pb::VotingPowerEconomics> for api::VotingPowerEconomics {
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
    for api::NeuronsFundMatchedFundingCurveCoefficients
{
    fn from(item: pb::NeuronsFundMatchedFundingCurveCoefficients) -> Self {
        Self {
            contribution_threshold_xdr: item.contribution_threshold_xdr,
            one_third_participation_milestone_xdr: item.one_third_participation_milestone_xdr,
            full_participation_milestone_xdr: item.full_participation_milestone_xdr,
        }
    }
}
impl From<api::NeuronsFundMatchedFundingCurveCoefficients>
    for pb::NeuronsFundMatchedFundingCurveCoefficients
{
    fn from(item: api::NeuronsFundMatchedFundingCurveCoefficients) -> Self {
        Self {
            contribution_threshold_xdr: item.contribution_threshold_xdr,
            one_third_participation_milestone_xdr: item.one_third_participation_milestone_xdr,
            full_participation_milestone_xdr: item.full_participation_milestone_xdr,
        }
    }
}

impl From<pb::NeuronsFundEconomics> for api::NeuronsFundEconomics {
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
impl From<api::NeuronsFundEconomics> for pb::NeuronsFundEconomics {
    fn from(item: api::NeuronsFundEconomics) -> Self {
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

impl From<pb::RewardEvent> for api::RewardEvent {
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
impl From<api::RewardEvent> for pb::RewardEvent {
    fn from(item: api::RewardEvent) -> Self {
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

impl From<pb::KnownNeuron> for api::KnownNeuron {
    fn from(item: pb::KnownNeuron) -> Self {
        Self {
            id: item.id,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
        }
    }
}
impl From<api::KnownNeuron> for pb::KnownNeuron {
    fn from(item: api::KnownNeuron) -> Self {
        Self {
            id: item.id,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
        }
    }
}

impl From<pb::Topic> for api::TopicToFollow {
    fn from(topic: pb::Topic) -> Self {
        match topic {
            pb::Topic::Unspecified => api::TopicToFollow::CatchAll,
            pb::Topic::NeuronManagement => api::TopicToFollow::NeuronManagement,
            pb::Topic::ExchangeRate => api::TopicToFollow::ExchangeRate,
            pb::Topic::NetworkEconomics => api::TopicToFollow::NetworkEconomics,
            pb::Topic::Governance => api::TopicToFollow::Governance,
            pb::Topic::NodeAdmin => api::TopicToFollow::NodeAdmin,
            pb::Topic::ParticipantManagement => api::TopicToFollow::ParticipantManagement,
            pb::Topic::SubnetManagement => api::TopicToFollow::SubnetManagement,
            pb::Topic::ApplicationCanisterManagement => {
                api::TopicToFollow::ApplicationCanisterManagement
            }
            pb::Topic::Kyc => api::TopicToFollow::Kyc,
            pb::Topic::NodeProviderRewards => api::TopicToFollow::NodeProviderRewards,
            pb::Topic::IcOsVersionDeployment => api::TopicToFollow::IcOsVersionDeployment,
            pb::Topic::IcOsVersionElection => api::TopicToFollow::IcOsVersionElection,
            pb::Topic::SnsAndCommunityFund => api::TopicToFollow::SnsAndCommunityFund,
            pb::Topic::ApiBoundaryNodeManagement => api::TopicToFollow::ApiBoundaryNodeManagement,
            pb::Topic::SubnetRental => api::TopicToFollow::SubnetRental,
            pb::Topic::ProtocolCanisterManagement => api::TopicToFollow::ProtocolCanisterManagement,
            pb::Topic::ServiceNervousSystemManagement => {
                api::TopicToFollow::ServiceNervousSystemManagement
            }
        }
    }
}

impl From<api::TopicToFollow> for pb::Topic {
    fn from(topic: api::TopicToFollow) -> Self {
        match topic {
            api::TopicToFollow::CatchAll => pb::Topic::Unspecified,
            api::TopicToFollow::NeuronManagement => pb::Topic::NeuronManagement,
            api::TopicToFollow::ExchangeRate => pb::Topic::ExchangeRate,
            api::TopicToFollow::NetworkEconomics => pb::Topic::NetworkEconomics,
            api::TopicToFollow::Governance => pb::Topic::Governance,
            api::TopicToFollow::NodeAdmin => pb::Topic::NodeAdmin,
            api::TopicToFollow::ParticipantManagement => pb::Topic::ParticipantManagement,
            api::TopicToFollow::SubnetManagement => pb::Topic::SubnetManagement,
            api::TopicToFollow::Kyc => pb::Topic::Kyc,
            api::TopicToFollow::NodeProviderRewards => pb::Topic::NodeProviderRewards,
            api::TopicToFollow::IcOsVersionDeployment => pb::Topic::IcOsVersionDeployment,
            api::TopicToFollow::IcOsVersionElection => pb::Topic::IcOsVersionElection,
            api::TopicToFollow::SnsAndCommunityFund => pb::Topic::SnsAndCommunityFund,
            api::TopicToFollow::ApiBoundaryNodeManagement => pb::Topic::ApiBoundaryNodeManagement,
            api::TopicToFollow::SubnetRental => pb::Topic::SubnetRental,
            api::TopicToFollow::ApplicationCanisterManagement => {
                pb::Topic::ApplicationCanisterManagement
            }
            api::TopicToFollow::ProtocolCanisterManagement => pb::Topic::ProtocolCanisterManagement,
            api::TopicToFollow::ServiceNervousSystemManagement => {
                pb::Topic::ServiceNervousSystemManagement
            }
        }
    }
}

impl From<pb::KnownNeuronData> for api::KnownNeuronData {
    fn from(item: pb::KnownNeuronData) -> Self {
        let committed_topics = Some(
            item.committed_topics
                .iter()
                .map(|&topic_i32| {
                    let topic = pb::Topic::try_from(topic_i32).ok();
                    topic.map(api::TopicToFollow::from)
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

impl From<api::KnownNeuronData> for pb::KnownNeuronData {
    fn from(item: api::KnownNeuronData) -> Self {
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

impl From<pb::OpenSnsTokenSwap> for api::OpenSnsTokenSwap {
    fn from(item: pb::OpenSnsTokenSwap) -> Self {
        Self {
            target_swap_canister_id: item.target_swap_canister_id,
            params: item.params,
            community_fund_investment_e8s: item.community_fund_investment_e8s,
        }
    }
}
impl From<api::OpenSnsTokenSwap> for pb::OpenSnsTokenSwap {
    fn from(item: api::OpenSnsTokenSwap) -> Self {
        Self {
            target_swap_canister_id: item.target_swap_canister_id,
            params: item.params,
            community_fund_investment_e8s: item.community_fund_investment_e8s,
        }
    }
}

impl From<pb::CreateServiceNervousSystem> for api::CreateServiceNervousSystem {
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
impl From<api::CreateServiceNervousSystem> for pb::CreateServiceNervousSystem {
    fn from(item: api::CreateServiceNervousSystem) -> Self {
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
    for api::create_service_nervous_system::InitialTokenDistribution
{
    fn from(item: pb::create_service_nervous_system::InitialTokenDistribution) -> Self {
        Self {
            developer_distribution: item.developer_distribution.map(|x| x.into()),
            treasury_distribution: item.treasury_distribution.map(|x| x.into()),
            swap_distribution: item.swap_distribution.map(|x| x.into()),
        }
    }
}
impl From<api::create_service_nervous_system::InitialTokenDistribution>
    for pb::create_service_nervous_system::InitialTokenDistribution
{
    fn from(item: api::create_service_nervous_system::InitialTokenDistribution) -> Self {
        Self {
            developer_distribution: item.developer_distribution.map(|x| x.into()),
            treasury_distribution: item.treasury_distribution.map(|x| x.into()),
            swap_distribution: item.swap_distribution.map(|x| x.into()),
        }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::DeveloperDistribution>
    for api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution
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
impl From<api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::DeveloperDistribution
{
    fn from(
        item: api::create_service_nervous_system::initial_token_distribution::DeveloperDistribution,
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

impl From<pb::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution> for api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution {
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
impl From<api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution> for pb::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution {
    fn from(item: api::create_service_nervous_system::initial_token_distribution::developer_distribution::NeuronDistribution) -> Self {
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
    for api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution
{
    fn from(
        item: pb::create_service_nervous_system::initial_token_distribution::TreasuryDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}
impl From<api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::TreasuryDistribution
{
    fn from(
        item: api::create_service_nervous_system::initial_token_distribution::TreasuryDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}

impl From<pb::create_service_nervous_system::initial_token_distribution::SwapDistribution>
    for api::create_service_nervous_system::initial_token_distribution::SwapDistribution
{
    fn from(
        item: pb::create_service_nervous_system::initial_token_distribution::SwapDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}
impl From<api::create_service_nervous_system::initial_token_distribution::SwapDistribution>
    for pb::create_service_nervous_system::initial_token_distribution::SwapDistribution
{
    fn from(
        item: api::create_service_nervous_system::initial_token_distribution::SwapDistribution,
    ) -> Self {
        Self { total: item.total }
    }
}

impl From<pb::create_service_nervous_system::SwapParameters>
    for api::create_service_nervous_system::SwapParameters
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
impl From<api::create_service_nervous_system::SwapParameters>
    for pb::create_service_nervous_system::SwapParameters
{
    fn from(item: api::create_service_nervous_system::SwapParameters) -> Self {
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
    for api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters
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
impl From<api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters>
    for pb::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters
{
    fn from(
        item: api::create_service_nervous_system::swap_parameters::NeuronBasketConstructionParameters,
    ) -> Self {
        Self {
            count: item.count,
            dissolve_delay_interval: item.dissolve_delay_interval,
        }
    }
}

impl From<pb::create_service_nervous_system::LedgerParameters>
    for api::create_service_nervous_system::LedgerParameters
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
impl From<api::create_service_nervous_system::LedgerParameters>
    for pb::create_service_nervous_system::LedgerParameters
{
    fn from(item: api::create_service_nervous_system::LedgerParameters) -> Self {
        Self {
            transaction_fee: item.transaction_fee,
            token_name: item.token_name,
            token_symbol: item.token_symbol,
            token_logo: item.token_logo,
        }
    }
}

impl From<pb::create_service_nervous_system::GovernanceParameters>
    for api::create_service_nervous_system::GovernanceParameters
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
            custom_proposal_criticality: item.custom_proposal_criticality.map(|x| x.into()),
        }
    }
}
impl From<api::create_service_nervous_system::GovernanceParameters>
    for pb::create_service_nervous_system::GovernanceParameters
{
    fn from(item: api::create_service_nervous_system::GovernanceParameters) -> Self {
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
            custom_proposal_criticality: item.custom_proposal_criticality.map(|x| x.into()),
        }
    }
}

impl From<pb::create_service_nervous_system::governance_parameters::VotingRewardParameters>
    for api::create_service_nervous_system::governance_parameters::VotingRewardParameters
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
impl From<api::create_service_nervous_system::governance_parameters::VotingRewardParameters>
    for pb::create_service_nervous_system::governance_parameters::VotingRewardParameters
{
    fn from(
        item: api::create_service_nervous_system::governance_parameters::VotingRewardParameters,
    ) -> Self {
        Self {
            initial_reward_rate: item.initial_reward_rate,
            final_reward_rate: item.final_reward_rate,
            reward_rate_transition_duration: item.reward_rate_transition_duration,
        }
    }
}
impl From<pb::create_service_nervous_system::governance_parameters::CustomProposalCriticality>
    for api::create_service_nervous_system::governance_parameters::CustomProposalCriticality
{
    fn from(
        item: pb::create_service_nervous_system::governance_parameters::CustomProposalCriticality,
    ) -> Self {
        Self {
            additional_critical_native_action_ids: Some(item.additional_critical_native_action_ids),
        }
    }
}
impl From<api::create_service_nervous_system::governance_parameters::CustomProposalCriticality>
    for pb::create_service_nervous_system::governance_parameters::CustomProposalCriticality
{
    fn from(
        item: api::create_service_nervous_system::governance_parameters::CustomProposalCriticality,
    ) -> Self {
        Self {
            additional_critical_native_action_ids: item
                .additional_critical_native_action_ids
                .unwrap_or_default(),
        }
    }
}

impl From<pb::InstallCode> for api::InstallCode {
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
impl From<api::InstallCode> for pb::InstallCode {
    fn from(item: api::InstallCode) -> Self {
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
impl From<api::InstallCodeRequest> for pb::InstallCode {
    fn from(item: api::InstallCodeRequest) -> Self {
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

impl From<pb::install_code::CanisterInstallMode> for api::install_code::CanisterInstallMode {
    fn from(item: pb::install_code::CanisterInstallMode) -> Self {
        match item {
            pb::install_code::CanisterInstallMode::Unspecified => {
                api::install_code::CanisterInstallMode::Unspecified
            }
            pb::install_code::CanisterInstallMode::Install => {
                api::install_code::CanisterInstallMode::Install
            }
            pb::install_code::CanisterInstallMode::Reinstall => {
                api::install_code::CanisterInstallMode::Reinstall
            }
            pb::install_code::CanisterInstallMode::Upgrade => {
                api::install_code::CanisterInstallMode::Upgrade
            }
        }
    }
}
impl From<api::install_code::CanisterInstallMode> for pb::install_code::CanisterInstallMode {
    fn from(item: api::install_code::CanisterInstallMode) -> Self {
        match item {
            api::install_code::CanisterInstallMode::Unspecified => {
                pb::install_code::CanisterInstallMode::Unspecified
            }
            api::install_code::CanisterInstallMode::Install => {
                pb::install_code::CanisterInstallMode::Install
            }
            api::install_code::CanisterInstallMode::Reinstall => {
                pb::install_code::CanisterInstallMode::Reinstall
            }
            api::install_code::CanisterInstallMode::Upgrade => {
                pb::install_code::CanisterInstallMode::Upgrade
            }
        }
    }
}

impl From<pb::StopOrStartCanister> for api::StopOrStartCanister {
    fn from(item: pb::StopOrStartCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            action: item.action,
        }
    }
}

impl From<api::StopOrStartCanister> for pb::StopOrStartCanister {
    fn from(item: api::StopOrStartCanister) -> Self {
        Self {
            canister_id: item.canister_id,
            action: item.action,
        }
    }
}

impl From<pb::stop_or_start_canister::CanisterAction>
    for api::stop_or_start_canister::CanisterAction
{
    fn from(item: pb::stop_or_start_canister::CanisterAction) -> Self {
        match item {
            pb::stop_or_start_canister::CanisterAction::Unspecified => {
                api::stop_or_start_canister::CanisterAction::Unspecified
            }
            pb::stop_or_start_canister::CanisterAction::Stop => {
                api::stop_or_start_canister::CanisterAction::Stop
            }
            pb::stop_or_start_canister::CanisterAction::Start => {
                api::stop_or_start_canister::CanisterAction::Start
            }
        }
    }
}

impl From<api::stop_or_start_canister::CanisterAction>
    for pb::stop_or_start_canister::CanisterAction
{
    fn from(item: api::stop_or_start_canister::CanisterAction) -> Self {
        match item {
            api::stop_or_start_canister::CanisterAction::Unspecified => {
                pb::stop_or_start_canister::CanisterAction::Unspecified
            }
            api::stop_or_start_canister::CanisterAction::Stop => {
                pb::stop_or_start_canister::CanisterAction::Stop
            }
            api::stop_or_start_canister::CanisterAction::Start => {
                pb::stop_or_start_canister::CanisterAction::Start
            }
        }
    }
}

impl From<pb::UpdateCanisterSettings> for api::UpdateCanisterSettings {
    fn from(item: pb::UpdateCanisterSettings) -> Self {
        Self {
            canister_id: item.canister_id,
            settings: item.settings.map(|x| x.into()),
        }
    }
}

impl From<api::UpdateCanisterSettings> for pb::UpdateCanisterSettings {
    fn from(item: api::UpdateCanisterSettings) -> Self {
        Self {
            canister_id: item.canister_id,
            settings: item.settings.map(|x| x.into()),
        }
    }
}

impl From<pb::FulfillSubnetRentalRequest> for api::FulfillSubnetRentalRequest {
    fn from(item: pb::FulfillSubnetRentalRequest) -> Self {
        Self {
            user: item.user,
            node_ids: Some(item.node_ids),
            replica_version_id: Some(item.replica_version_id),
        }
    }
}

impl From<api::FulfillSubnetRentalRequest> for pb::FulfillSubnetRentalRequest {
    fn from(item: api::FulfillSubnetRentalRequest) -> Self {
        Self {
            user: item.user,
            node_ids: item.node_ids.unwrap_or_default(),
            replica_version_id: item.replica_version_id.unwrap_or_default(),
        }
    }
}

impl From<pb::BlessAlternativeGuestOsVersion> for api::BlessAlternativeGuestOsVersion {
    fn from(item: pb::BlessAlternativeGuestOsVersion) -> Self {
        Self {
            chip_ids: Some(item.chip_ids),
            rootfs_hash: Some(item.rootfs_hash),
            base_guest_launch_measurements: item
                .base_guest_launch_measurements
                .map(convert_guest_launch_measurements_from_pb_to_api),
        }
    }
}

impl From<api::BlessAlternativeGuestOsVersion> for pb::BlessAlternativeGuestOsVersion {
    fn from(item: api::BlessAlternativeGuestOsVersion) -> Self {
        Self {
            chip_ids: item.chip_ids.unwrap_or_default(),
            rootfs_hash: item.rootfs_hash.unwrap_or_default(),
            base_guest_launch_measurements: item
                .base_guest_launch_measurements
                .map(convert_guest_launch_measurements_from_api_to_pb),
        }
    }
}

fn convert_guest_launch_measurements_from_pb_to_api(
    item: PbGuestLaunchMeasurements,
) -> api::GuestLaunchMeasurements {
    api::GuestLaunchMeasurements {
        guest_launch_measurements: Some(
            item.guest_launch_measurements
                .into_iter()
                .map(convert_guest_launch_measurement_from_pb_to_api)
                .collect(),
        ),
    }
}

fn convert_guest_launch_measurements_from_api_to_pb(
    item: api::GuestLaunchMeasurements,
) -> PbGuestLaunchMeasurements {
    PbGuestLaunchMeasurements {
        guest_launch_measurements: item
            .guest_launch_measurements
            .unwrap_or_default()
            .into_iter()
            .map(convert_guest_launch_measurement_from_api_to_pb)
            .collect(),
    }
}

fn convert_guest_launch_measurement_from_pb_to_api(
    item: PbGuestLaunchMeasurement,
) -> api::GuestLaunchMeasurement {
    api::GuestLaunchMeasurement {
        measurement: Some(item.measurement),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_pb_to_api),
    }
}

fn convert_guest_launch_measurement_from_api_to_pb(
    item: api::GuestLaunchMeasurement,
) -> PbGuestLaunchMeasurement {
    PbGuestLaunchMeasurement {
        measurement: item.measurement.unwrap_or_default(),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_api_to_pb),
    }
}

fn convert_guest_launch_measurement_metadata_from_pb_to_api(
    item: PbGuestLaunchMeasurementMetadata,
) -> api::GuestLaunchMeasurementMetadata {
    api::GuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}

fn convert_guest_launch_measurement_metadata_from_api_to_pb(
    item: api::GuestLaunchMeasurementMetadata,
) -> PbGuestLaunchMeasurementMetadata {
    PbGuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}

impl From<pb::LoadCanisterSnapshot> for api::LoadCanisterSnapshot {
    fn from(item: pb::LoadCanisterSnapshot) -> Self {
        Self {
            canister_id: item.canister_id,
            snapshot_id: Some(item.snapshot_id),
        }
    }
}
impl From<api::LoadCanisterSnapshot> for pb::LoadCanisterSnapshot {
    fn from(item: api::LoadCanisterSnapshot) -> Self {
        Self {
            canister_id: item.canister_id,
            snapshot_id: item.snapshot_id.unwrap_or_default(),
        }
    }
}

impl From<pb::update_canister_settings::CanisterSettings>
    for api::update_canister_settings::CanisterSettings
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

impl From<api::update_canister_settings::CanisterSettings>
    for pb::update_canister_settings::CanisterSettings
{
    fn from(item: api::update_canister_settings::CanisterSettings) -> Self {
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
    for api::update_canister_settings::Controllers
{
    fn from(item: pb::update_canister_settings::Controllers) -> Self {
        Self {
            controllers: item.controllers,
        }
    }
}

impl From<api::update_canister_settings::Controllers>
    for pb::update_canister_settings::Controllers
{
    fn from(item: api::update_canister_settings::Controllers) -> Self {
        Self {
            controllers: item.controllers,
        }
    }
}

impl From<pb::update_canister_settings::LogVisibility>
    for api::update_canister_settings::LogVisibility
{
    fn from(item: pb::update_canister_settings::LogVisibility) -> Self {
        match item {
            pb::update_canister_settings::LogVisibility::Unspecified => {
                api::update_canister_settings::LogVisibility::Unspecified
            }
            pb::update_canister_settings::LogVisibility::Controllers => {
                api::update_canister_settings::LogVisibility::Controllers
            }
            pb::update_canister_settings::LogVisibility::Public => {
                api::update_canister_settings::LogVisibility::Public
            }
        }
    }
}

impl From<api::update_canister_settings::LogVisibility>
    for pb::update_canister_settings::LogVisibility
{
    fn from(item: api::update_canister_settings::LogVisibility) -> Self {
        match item {
            api::update_canister_settings::LogVisibility::Unspecified => {
                pb::update_canister_settings::LogVisibility::Unspecified
            }
            api::update_canister_settings::LogVisibility::Controllers => {
                pb::update_canister_settings::LogVisibility::Controllers
            }
            api::update_canister_settings::LogVisibility::Public => {
                pb::update_canister_settings::LogVisibility::Public
            }
        }
    }
}

impl From<api::governance::NeuronInFlightCommand> for pb::governance::NeuronInFlightCommand {
    fn from(item: api::governance::NeuronInFlightCommand) -> Self {
        Self {
            timestamp: item.timestamp,
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::neuron_in_flight_command::SyncCommand>
    for api::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: pb::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}
impl From<api::governance::neuron_in_flight_command::SyncCommand>
    for pb::governance::neuron_in_flight_command::SyncCommand
{
    fn from(_: api::governance::neuron_in_flight_command::SyncCommand) -> Self {
        Self {}
    }
}

impl From<api::governance::neuron_in_flight_command::Command>
    for pb::governance::neuron_in_flight_command::Command
{
    fn from(item: api::governance::neuron_in_flight_command::Command) -> Self {
        match item {
            api::governance::neuron_in_flight_command::Command::Disburse(v) => {
                pb::governance::neuron_in_flight_command::Command::Disburse(v.into())
            }
            api::governance::neuron_in_flight_command::Command::Split(v) => {
                pb::governance::neuron_in_flight_command::Command::Split(v.into())
            }
            api::governance::neuron_in_flight_command::Command::DisburseToNeuron(v) => {
                pb::governance::neuron_in_flight_command::Command::DisburseToNeuron(v.into())
            }
            api::governance::neuron_in_flight_command::Command::MergeMaturity(v) => {
                pb::governance::neuron_in_flight_command::Command::MergeMaturity(v.into())
            }
            api::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v) => {
                pb::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v.into())
            }
            api::governance::neuron_in_flight_command::Command::Configure(v) => {
                pb::governance::neuron_in_flight_command::Command::Configure(v.into())
            }
            api::governance::neuron_in_flight_command::Command::Merge(v) => {
                pb::governance::neuron_in_flight_command::Command::Merge(v.into())
            }
            api::governance::neuron_in_flight_command::Command::Spawn(v) => {
                pb::governance::neuron_in_flight_command::Command::Spawn(v)
            }
            api::governance::neuron_in_flight_command::Command::SyncCommand(v) => {
                pb::governance::neuron_in_flight_command::Command::SyncCommand(v.into())
            }
        }
    }
}

impl From<pb::governance::GovernanceCachedMetrics> for api::governance::GovernanceCachedMetrics {
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
impl From<api::governance::GovernanceCachedMetrics> for pb::governance::GovernanceCachedMetrics {
    fn from(item: api::governance::GovernanceCachedMetrics) -> Self {
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
    for api::governance::governance_cached_metrics::NeuronSubsetMetrics
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
impl From<api::governance::governance_cached_metrics::NeuronSubsetMetrics>
    for pb::governance::governance_cached_metrics::NeuronSubsetMetrics
{
    fn from(item: api::governance::governance_cached_metrics::NeuronSubsetMetrics) -> Self {
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
impl From<pb::DateUtc> for api::DateUtc {
    fn from(item: pb::DateUtc) -> Self {
        Self {
            year: item.year,
            month: item.month,
            day: item.day,
        }
    }
}
impl From<api::DateUtc> for pb::DateUtc {
    fn from(item: api::DateUtc) -> Self {
        Self {
            year: item.year,
            month: item.month,
            day: item.day,
        }
    }
}
impl From<pb::XdrConversionRate> for api::XdrConversionRate {
    fn from(item: pb::XdrConversionRate) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            xdr_permyriad_per_icp: item.xdr_permyriad_per_icp,
        }
    }
}
impl From<api::XdrConversionRate> for pb::XdrConversionRate {
    fn from(item: api::XdrConversionRate) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            xdr_permyriad_per_icp: item.xdr_permyriad_per_icp,
        }
    }
}

impl From<pb::ListKnownNeuronsResponse> for api::ListKnownNeuronsResponse {
    fn from(item: pb::ListKnownNeuronsResponse) -> Self {
        Self {
            known_neurons: item.known_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<api::ListKnownNeuronsResponse> for pb::ListKnownNeuronsResponse {
    fn from(item: api::ListKnownNeuronsResponse) -> Self {
        Self {
            known_neurons: item.known_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ListNodeProvidersResponse> for api::ListNodeProvidersResponse {
    fn from(item: pb::ListNodeProvidersResponse) -> Self {
        Self {
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<api::ListNodeProvidersResponse> for pb::ListNodeProvidersResponse {
    fn from(item: api::ListNodeProvidersResponse) -> Self {
        Self {
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb::MonthlyNodeProviderRewards> for api::MonthlyNodeProviderRewards {
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
impl From<api::MonthlyNodeProviderRewards> for pb::MonthlyNodeProviderRewards {
    fn from(item: api::MonthlyNodeProviderRewards) -> Self {
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

impl From<pb::SettleCommunityFundParticipation> for api::SettleCommunityFundParticipation {
    fn from(item: pb::SettleCommunityFundParticipation) -> Self {
        Self {
            open_sns_token_swap_proposal_id: item.open_sns_token_swap_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<api::SettleCommunityFundParticipation> for pb::SettleCommunityFundParticipation {
    fn from(item: api::SettleCommunityFundParticipation) -> Self {
        Self {
            open_sns_token_swap_proposal_id: item.open_sns_token_swap_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_community_fund_participation::Committed>
    for api::settle_community_fund_participation::Committed
{
    fn from(item: pb::settle_community_fund_participation::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_contribution_icp_e8s: item.total_direct_contribution_icp_e8s,
            total_neurons_fund_contribution_icp_e8s: item.total_neurons_fund_contribution_icp_e8s,
        }
    }
}
impl From<api::settle_community_fund_participation::Committed>
    for pb::settle_community_fund_participation::Committed
{
    fn from(item: api::settle_community_fund_participation::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_contribution_icp_e8s: item.total_direct_contribution_icp_e8s,
            total_neurons_fund_contribution_icp_e8s: item.total_neurons_fund_contribution_icp_e8s,
        }
    }
}

impl From<pb::settle_community_fund_participation::Aborted>
    for api::settle_community_fund_participation::Aborted
{
    fn from(_: pb::settle_community_fund_participation::Aborted) -> Self {
        Self {}
    }
}
impl From<api::settle_community_fund_participation::Aborted>
    for pb::settle_community_fund_participation::Aborted
{
    fn from(_: api::settle_community_fund_participation::Aborted) -> Self {
        Self {}
    }
}

impl From<pb::settle_community_fund_participation::Result>
    for api::settle_community_fund_participation::Result
{
    fn from(item: pb::settle_community_fund_participation::Result) -> Self {
        match item {
            pb::settle_community_fund_participation::Result::Committed(v) => {
                api::settle_community_fund_participation::Result::Committed(v.into())
            }
            pb::settle_community_fund_participation::Result::Aborted(v) => {
                api::settle_community_fund_participation::Result::Aborted(v.into())
            }
        }
    }
}
impl From<api::settle_community_fund_participation::Result>
    for pb::settle_community_fund_participation::Result
{
    fn from(item: api::settle_community_fund_participation::Result) -> Self {
        match item {
            api::settle_community_fund_participation::Result::Committed(v) => {
                pb::settle_community_fund_participation::Result::Committed(v.into())
            }
            api::settle_community_fund_participation::Result::Aborted(v) => {
                pb::settle_community_fund_participation::Result::Aborted(v.into())
            }
        }
    }
}

impl From<pb::SettleNeuronsFundParticipationRequest>
    for api::SettleNeuronsFundParticipationRequest
{
    fn from(item: pb::SettleNeuronsFundParticipationRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<api::SettleNeuronsFundParticipationRequest>
    for pb::SettleNeuronsFundParticipationRequest
{
    fn from(item: api::SettleNeuronsFundParticipationRequest) -> Self {
        Self {
            nns_proposal_id: item.nns_proposal_id,
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_neurons_fund_participation_request::Committed>
    for api::settle_neurons_fund_participation_request::Committed
{
    fn from(item: pb::settle_neurons_fund_participation_request::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_participation_icp_e8s: item.total_direct_participation_icp_e8s,
            total_neurons_fund_participation_icp_e8s: item.total_neurons_fund_participation_icp_e8s,
        }
    }
}
impl From<api::settle_neurons_fund_participation_request::Committed>
    for pb::settle_neurons_fund_participation_request::Committed
{
    fn from(item: api::settle_neurons_fund_participation_request::Committed) -> Self {
        Self {
            sns_governance_canister_id: item.sns_governance_canister_id,
            total_direct_participation_icp_e8s: item.total_direct_participation_icp_e8s,
            total_neurons_fund_participation_icp_e8s: item.total_neurons_fund_participation_icp_e8s,
        }
    }
}

impl From<pb::settle_neurons_fund_participation_request::Aborted>
    for api::settle_neurons_fund_participation_request::Aborted
{
    fn from(_: pb::settle_neurons_fund_participation_request::Aborted) -> Self {
        Self {}
    }
}
impl From<api::settle_neurons_fund_participation_request::Aborted>
    for pb::settle_neurons_fund_participation_request::Aborted
{
    fn from(_: api::settle_neurons_fund_participation_request::Aborted) -> Self {
        Self {}
    }
}

impl From<pb::settle_neurons_fund_participation_request::Result>
    for api::settle_neurons_fund_participation_request::Result
{
    fn from(item: pb::settle_neurons_fund_participation_request::Result) -> Self {
        match item {
            pb::settle_neurons_fund_participation_request::Result::Committed(v) => {
                api::settle_neurons_fund_participation_request::Result::Committed(v.into())
            }
            pb::settle_neurons_fund_participation_request::Result::Aborted(v) => {
                api::settle_neurons_fund_participation_request::Result::Aborted(v.into())
            }
        }
    }
}
impl From<api::settle_neurons_fund_participation_request::Result>
    for pb::settle_neurons_fund_participation_request::Result
{
    fn from(item: api::settle_neurons_fund_participation_request::Result) -> Self {
        match item {
            api::settle_neurons_fund_participation_request::Result::Committed(v) => {
                pb::settle_neurons_fund_participation_request::Result::Committed(v.into())
            }
            api::settle_neurons_fund_participation_request::Result::Aborted(v) => {
                pb::settle_neurons_fund_participation_request::Result::Aborted(v.into())
            }
        }
    }
}

impl From<pb::SettleNeuronsFundParticipationResponse>
    for api::SettleNeuronsFundParticipationResponse
{
    fn from(item: pb::SettleNeuronsFundParticipationResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<api::SettleNeuronsFundParticipationResponse>
    for pb::SettleNeuronsFundParticipationResponse
{
    fn from(item: api::SettleNeuronsFundParticipationResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::settle_neurons_fund_participation_response::NeuronsFundNeuron>
    for api::settle_neurons_fund_participation_response::NeuronsFundNeuron
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
impl From<api::settle_neurons_fund_participation_response::NeuronsFundNeuron>
    for pb::settle_neurons_fund_participation_response::NeuronsFundNeuron
{
    fn from(item: api::settle_neurons_fund_participation_response::NeuronsFundNeuron) -> Self {
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
    for api::settle_neurons_fund_participation_response::Ok
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
impl From<api::settle_neurons_fund_participation_response::Ok>
    for pb::settle_neurons_fund_participation_response::Ok
{
    fn from(item: api::settle_neurons_fund_participation_response::Ok) -> Self {
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
    for api::settle_neurons_fund_participation_response::Result
{
    fn from(item: pb::settle_neurons_fund_participation_response::Result) -> Self {
        match item {
            pb::settle_neurons_fund_participation_response::Result::Err(v) => {
                api::settle_neurons_fund_participation_response::Result::Err(v.into())
            }
            pb::settle_neurons_fund_participation_response::Result::Ok(v) => {
                api::settle_neurons_fund_participation_response::Result::Ok(v.into())
            }
        }
    }
}
impl From<api::settle_neurons_fund_participation_response::Result>
    for pb::settle_neurons_fund_participation_response::Result
{
    fn from(item: api::settle_neurons_fund_participation_response::Result) -> Self {
        match item {
            api::settle_neurons_fund_participation_response::Result::Err(v) => {
                pb::settle_neurons_fund_participation_response::Result::Err(v.into())
            }
            api::settle_neurons_fund_participation_response::Result::Ok(v) => {
                pb::settle_neurons_fund_participation_response::Result::Ok(v.into())
            }
        }
    }
}

impl From<pb::RestoreAgingSummary> for api::RestoreAgingSummary {
    fn from(item: pb::RestoreAgingSummary) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            groups: item.groups.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<api::RestoreAgingSummary> for pb::RestoreAgingSummary {
    fn from(item: api::RestoreAgingSummary) -> Self {
        Self {
            timestamp_seconds: item.timestamp_seconds,
            groups: item.groups.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::restore_aging_summary::RestoreAgingNeuronGroup>
    for api::restore_aging_summary::RestoreAgingNeuronGroup
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
impl From<api::restore_aging_summary::RestoreAgingNeuronGroup>
    for pb::restore_aging_summary::RestoreAgingNeuronGroup
{
    fn from(item: api::restore_aging_summary::RestoreAgingNeuronGroup) -> Self {
        Self {
            group_type: item.group_type,
            count: item.count,
            previous_total_stake_e8s: item.previous_total_stake_e8s,
            current_total_stake_e8s: item.current_total_stake_e8s,
        }
    }
}

impl From<pb::restore_aging_summary::NeuronGroupType>
    for api::restore_aging_summary::NeuronGroupType
{
    fn from(item: pb::restore_aging_summary::NeuronGroupType) -> Self {
        match item {
            pb::restore_aging_summary::NeuronGroupType::Unspecified => {
                api::restore_aging_summary::NeuronGroupType::Unspecified
            }
            pb::restore_aging_summary::NeuronGroupType::NotPreAging => {
                api::restore_aging_summary::NeuronGroupType::NotPreAging
            }
            pb::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved => {
                api::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved
            }
            pb::restore_aging_summary::NeuronGroupType::StakeChanged => {
                api::restore_aging_summary::NeuronGroupType::StakeChanged
            }
            pb::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged => {
                api::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged
            }
            pb::restore_aging_summary::NeuronGroupType::StakeSameAgingSame => {
                api::restore_aging_summary::NeuronGroupType::StakeSameAgingSame
            }
        }
    }
}
impl From<api::restore_aging_summary::NeuronGroupType>
    for pb::restore_aging_summary::NeuronGroupType
{
    fn from(item: api::restore_aging_summary::NeuronGroupType) -> Self {
        match item {
            api::restore_aging_summary::NeuronGroupType::Unspecified => {
                pb::restore_aging_summary::NeuronGroupType::Unspecified
            }
            api::restore_aging_summary::NeuronGroupType::NotPreAging => {
                pb::restore_aging_summary::NeuronGroupType::NotPreAging
            }
            api::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved => {
                pb::restore_aging_summary::NeuronGroupType::DissolvingOrDissolved
            }
            api::restore_aging_summary::NeuronGroupType::StakeChanged => {
                pb::restore_aging_summary::NeuronGroupType::StakeChanged
            }
            api::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged => {
                pb::restore_aging_summary::NeuronGroupType::StakeSameAgingChanged
            }
            api::restore_aging_summary::NeuronGroupType::StakeSameAgingSame => {
                pb::restore_aging_summary::NeuronGroupType::StakeSameAgingSame
            }
        }
    }
}

impl From<pb::Account> for api::Account {
    fn from(item: pb::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| x.subaccount),
        }
    }
}
impl From<api::Account> for pb::Account {
    fn from(item: api::Account) -> Self {
        Self {
            owner: item.owner,
            subaccount: item.subaccount.map(|x| pb::Subaccount { subaccount: x }),
        }
    }
}

impl From<pb::NeuronState> for api::NeuronState {
    fn from(item: pb::NeuronState) -> Self {
        match item {
            pb::NeuronState::Unspecified => api::NeuronState::Unspecified,
            pb::NeuronState::NotDissolving => api::NeuronState::NotDissolving,
            pb::NeuronState::Dissolving => api::NeuronState::Dissolving,
            pb::NeuronState::Dissolved => api::NeuronState::Dissolved,
            pb::NeuronState::Spawning => api::NeuronState::Spawning,
        }
    }
}
impl From<api::NeuronState> for pb::NeuronState {
    fn from(item: api::NeuronState) -> Self {
        match item {
            api::NeuronState::Unspecified => pb::NeuronState::Unspecified,
            api::NeuronState::NotDissolving => pb::NeuronState::NotDissolving,
            api::NeuronState::Dissolving => pb::NeuronState::Dissolving,
            api::NeuronState::Dissolved => pb::NeuronState::Dissolved,
            api::NeuronState::Spawning => pb::NeuronState::Spawning,
        }
    }
}

impl From<pb::NeuronType> for api::NeuronType {
    fn from(item: pb::NeuronType) -> Self {
        match item {
            pb::NeuronType::Unspecified => api::NeuronType::Unspecified,
            pb::NeuronType::Seed => api::NeuronType::Seed,
            pb::NeuronType::Ect => api::NeuronType::Ect,
        }
    }
}
impl From<api::NeuronType> for pb::NeuronType {
    fn from(item: api::NeuronType) -> Self {
        match item {
            api::NeuronType::Unspecified => pb::NeuronType::Unspecified,
            api::NeuronType::Seed => pb::NeuronType::Seed,
            api::NeuronType::Ect => pb::NeuronType::Ect,
        }
    }
}

impl From<pb::Vote> for api::Vote {
    fn from(item: pb::Vote) -> Self {
        match item {
            pb::Vote::Unspecified => api::Vote::Unspecified,
            pb::Vote::Yes => api::Vote::Yes,
            pb::Vote::No => api::Vote::No,
        }
    }
}
impl From<api::Vote> for pb::Vote {
    fn from(item: api::Vote) -> Self {
        match item {
            api::Vote::Unspecified => pb::Vote::Unspecified,
            api::Vote::Yes => pb::Vote::Yes,
            api::Vote::No => pb::Vote::No,
        }
    }
}

impl From<pb::NnsFunction> for api::NnsFunction {
    fn from(item: pb::NnsFunction) -> Self {
        match item {
            pb::NnsFunction::Unspecified => api::NnsFunction::Unspecified,
            pb::NnsFunction::CreateSubnet => api::NnsFunction::CreateSubnet,
            pb::NnsFunction::AddNodeToSubnet => api::NnsFunction::AddNodeToSubnet,
            pb::NnsFunction::NnsCanisterInstall => api::NnsFunction::NnsCanisterInstall,
            pb::NnsFunction::NnsCanisterUpgrade => api::NnsFunction::NnsCanisterUpgrade,
            pb::NnsFunction::BlessReplicaVersion => api::NnsFunction::BlessReplicaVersion,
            pb::NnsFunction::RecoverSubnet => api::NnsFunction::RecoverSubnet,
            pb::NnsFunction::UpdateConfigOfSubnet => api::NnsFunction::UpdateConfigOfSubnet,
            pb::NnsFunction::AssignNoid => api::NnsFunction::AssignNoid,
            pb::NnsFunction::NnsRootUpgrade => api::NnsFunction::NnsRootUpgrade,
            pb::NnsFunction::IcpXdrConversionRate => api::NnsFunction::IcpXdrConversionRate,
            pb::NnsFunction::DeployGuestosToAllSubnetNodes => {
                api::NnsFunction::DeployGuestosToAllSubnetNodes
            }
            pb::NnsFunction::ClearProvisionalWhitelist => {
                api::NnsFunction::ClearProvisionalWhitelist
            }
            pb::NnsFunction::RemoveNodesFromSubnet => api::NnsFunction::RemoveNodesFromSubnet,
            pb::NnsFunction::SetAuthorizedSubnetworks => api::NnsFunction::SetAuthorizedSubnetworks,
            pb::NnsFunction::SetFirewallConfig => api::NnsFunction::SetFirewallConfig,
            pb::NnsFunction::UpdateNodeOperatorConfig => api::NnsFunction::UpdateNodeOperatorConfig,
            pb::NnsFunction::StopOrStartNnsCanister => api::NnsFunction::StopOrStartNnsCanister,
            pb::NnsFunction::RemoveNodes => api::NnsFunction::RemoveNodes,
            pb::NnsFunction::UninstallCode => api::NnsFunction::UninstallCode,
            pb::NnsFunction::UpdateNodeRewardsTable => api::NnsFunction::UpdateNodeRewardsTable,
            pb::NnsFunction::AddOrRemoveDataCenters => api::NnsFunction::AddOrRemoveDataCenters,
            pb::NnsFunction::UpdateUnassignedNodesConfig => {
                api::NnsFunction::UpdateUnassignedNodesConfig
            }
            pb::NnsFunction::RemoveNodeOperators => api::NnsFunction::RemoveNodeOperators,
            pb::NnsFunction::RerouteCanisterRanges => api::NnsFunction::RerouteCanisterRanges,
            pb::NnsFunction::AddFirewallRules => api::NnsFunction::AddFirewallRules,
            pb::NnsFunction::RemoveFirewallRules => api::NnsFunction::RemoveFirewallRules,
            pb::NnsFunction::UpdateFirewallRules => api::NnsFunction::UpdateFirewallRules,
            pb::NnsFunction::PrepareCanisterMigration => api::NnsFunction::PrepareCanisterMigration,
            pb::NnsFunction::CompleteCanisterMigration => {
                api::NnsFunction::CompleteCanisterMigration
            }
            pb::NnsFunction::AddSnsWasm => api::NnsFunction::AddSnsWasm,
            pb::NnsFunction::ChangeSubnetMembership => api::NnsFunction::ChangeSubnetMembership,
            pb::NnsFunction::UpdateSubnetType => api::NnsFunction::UpdateSubnetType,
            pb::NnsFunction::ChangeSubnetTypeAssignment => {
                api::NnsFunction::ChangeSubnetTypeAssignment
            }
            pb::NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                api::NnsFunction::UpdateSnsWasmSnsSubnetIds
            }
            pb::NnsFunction::UpdateAllowedPrincipals => api::NnsFunction::UpdateAllowedPrincipals,
            pb::NnsFunction::RetireReplicaVersion => api::NnsFunction::RetireReplicaVersion,
            pb::NnsFunction::InsertSnsWasmUpgradePathEntries => {
                api::NnsFunction::InsertSnsWasmUpgradePathEntries
            }
            pb::NnsFunction::ReviseElectedGuestosVersions => {
                api::NnsFunction::ReviseElectedGuestosVersions
            }
            pb::NnsFunction::BitcoinSetConfig => api::NnsFunction::BitcoinSetConfig,
            pb::NnsFunction::UpdateElectedHostosVersions => {
                api::NnsFunction::UpdateElectedHostosVersions
            }
            pb::NnsFunction::UpdateNodesHostosVersion => api::NnsFunction::UpdateNodesHostosVersion,
            pb::NnsFunction::HardResetNnsRootToVersion => {
                api::NnsFunction::HardResetNnsRootToVersion
            }
            pb::NnsFunction::AddApiBoundaryNodes => api::NnsFunction::AddApiBoundaryNodes,
            pb::NnsFunction::RemoveApiBoundaryNodes => api::NnsFunction::RemoveApiBoundaryNodes,
            pb::NnsFunction::UpdateApiBoundaryNodesVersion => {
                api::NnsFunction::UpdateApiBoundaryNodesVersion
            }
            pb::NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                api::NnsFunction::DeployGuestosToSomeApiBoundaryNodes
            }
            pb::NnsFunction::DeployGuestosToAllUnassignedNodes => {
                api::NnsFunction::DeployGuestosToAllUnassignedNodes
            }
            pb::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                api::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes
            }
            pb::NnsFunction::ReviseElectedHostosVersions => {
                api::NnsFunction::ReviseElectedHostosVersions
            }
            pb::NnsFunction::DeployHostosToSomeNodes => api::NnsFunction::DeployHostosToSomeNodes,
            pb::NnsFunction::SubnetRentalRequest => api::NnsFunction::SubnetRentalRequest,
            pb::NnsFunction::PauseCanisterMigrations => api::NnsFunction::PauseCanisterMigrations,
            pb::NnsFunction::UnpauseCanisterMigrations => {
                api::NnsFunction::UnpauseCanisterMigrations
            }
            pb::NnsFunction::SetSubnetOperationalLevel => {
                api::NnsFunction::SetSubnetOperationalLevel
            }
        }
    }
}
impl From<api::NnsFunction> for pb::NnsFunction {
    fn from(item: api::NnsFunction) -> Self {
        match item {
            api::NnsFunction::Unspecified => pb::NnsFunction::Unspecified,
            api::NnsFunction::CreateSubnet => pb::NnsFunction::CreateSubnet,
            api::NnsFunction::AddNodeToSubnet => pb::NnsFunction::AddNodeToSubnet,
            api::NnsFunction::NnsCanisterInstall => pb::NnsFunction::NnsCanisterInstall,
            api::NnsFunction::NnsCanisterUpgrade => pb::NnsFunction::NnsCanisterUpgrade,
            api::NnsFunction::BlessReplicaVersion => pb::NnsFunction::BlessReplicaVersion,
            api::NnsFunction::RecoverSubnet => pb::NnsFunction::RecoverSubnet,
            api::NnsFunction::UpdateConfigOfSubnet => pb::NnsFunction::UpdateConfigOfSubnet,
            api::NnsFunction::AssignNoid => pb::NnsFunction::AssignNoid,
            api::NnsFunction::NnsRootUpgrade => pb::NnsFunction::NnsRootUpgrade,
            api::NnsFunction::IcpXdrConversionRate => pb::NnsFunction::IcpXdrConversionRate,
            api::NnsFunction::DeployGuestosToAllSubnetNodes => {
                pb::NnsFunction::DeployGuestosToAllSubnetNodes
            }
            api::NnsFunction::ClearProvisionalWhitelist => {
                pb::NnsFunction::ClearProvisionalWhitelist
            }
            api::NnsFunction::RemoveNodesFromSubnet => pb::NnsFunction::RemoveNodesFromSubnet,
            api::NnsFunction::SetAuthorizedSubnetworks => pb::NnsFunction::SetAuthorizedSubnetworks,
            api::NnsFunction::SetFirewallConfig => pb::NnsFunction::SetFirewallConfig,
            api::NnsFunction::UpdateNodeOperatorConfig => pb::NnsFunction::UpdateNodeOperatorConfig,
            api::NnsFunction::StopOrStartNnsCanister => pb::NnsFunction::StopOrStartNnsCanister,
            api::NnsFunction::RemoveNodes => pb::NnsFunction::RemoveNodes,
            api::NnsFunction::UninstallCode => pb::NnsFunction::UninstallCode,
            api::NnsFunction::UpdateNodeRewardsTable => pb::NnsFunction::UpdateNodeRewardsTable,
            api::NnsFunction::AddOrRemoveDataCenters => pb::NnsFunction::AddOrRemoveDataCenters,
            api::NnsFunction::UpdateUnassignedNodesConfig => {
                pb::NnsFunction::UpdateUnassignedNodesConfig
            }
            api::NnsFunction::RemoveNodeOperators => pb::NnsFunction::RemoveNodeOperators,
            api::NnsFunction::RerouteCanisterRanges => pb::NnsFunction::RerouteCanisterRanges,
            api::NnsFunction::AddFirewallRules => pb::NnsFunction::AddFirewallRules,
            api::NnsFunction::RemoveFirewallRules => pb::NnsFunction::RemoveFirewallRules,
            api::NnsFunction::UpdateFirewallRules => pb::NnsFunction::UpdateFirewallRules,
            api::NnsFunction::PrepareCanisterMigration => pb::NnsFunction::PrepareCanisterMigration,
            api::NnsFunction::CompleteCanisterMigration => {
                pb::NnsFunction::CompleteCanisterMigration
            }
            api::NnsFunction::AddSnsWasm => pb::NnsFunction::AddSnsWasm,
            api::NnsFunction::ChangeSubnetMembership => pb::NnsFunction::ChangeSubnetMembership,
            api::NnsFunction::UpdateSubnetType => pb::NnsFunction::UpdateSubnetType,
            api::NnsFunction::ChangeSubnetTypeAssignment => {
                pb::NnsFunction::ChangeSubnetTypeAssignment
            }
            api::NnsFunction::UpdateSnsWasmSnsSubnetIds => {
                pb::NnsFunction::UpdateSnsWasmSnsSubnetIds
            }
            api::NnsFunction::UpdateAllowedPrincipals => pb::NnsFunction::UpdateAllowedPrincipals,
            api::NnsFunction::RetireReplicaVersion => pb::NnsFunction::RetireReplicaVersion,
            api::NnsFunction::InsertSnsWasmUpgradePathEntries => {
                pb::NnsFunction::InsertSnsWasmUpgradePathEntries
            }
            api::NnsFunction::ReviseElectedGuestosVersions => {
                pb::NnsFunction::ReviseElectedGuestosVersions
            }
            api::NnsFunction::BitcoinSetConfig => pb::NnsFunction::BitcoinSetConfig,
            api::NnsFunction::UpdateElectedHostosVersions => {
                pb::NnsFunction::UpdateElectedHostosVersions
            }
            api::NnsFunction::UpdateNodesHostosVersion => pb::NnsFunction::UpdateNodesHostosVersion,
            api::NnsFunction::HardResetNnsRootToVersion => {
                pb::NnsFunction::HardResetNnsRootToVersion
            }
            api::NnsFunction::AddApiBoundaryNodes => pb::NnsFunction::AddApiBoundaryNodes,
            api::NnsFunction::RemoveApiBoundaryNodes => pb::NnsFunction::RemoveApiBoundaryNodes,
            api::NnsFunction::UpdateApiBoundaryNodesVersion => {
                pb::NnsFunction::UpdateApiBoundaryNodesVersion
            }
            api::NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                pb::NnsFunction::DeployGuestosToSomeApiBoundaryNodes
            }
            api::NnsFunction::DeployGuestosToAllUnassignedNodes => {
                pb::NnsFunction::DeployGuestosToAllUnassignedNodes
            }
            api::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                pb::NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes
            }
            api::NnsFunction::ReviseElectedHostosVersions => {
                pb::NnsFunction::ReviseElectedHostosVersions
            }
            api::NnsFunction::DeployHostosToSomeNodes => pb::NnsFunction::DeployHostosToSomeNodes,
            api::NnsFunction::SubnetRentalRequest => pb::NnsFunction::SubnetRentalRequest,
            api::NnsFunction::PauseCanisterMigrations => pb::NnsFunction::PauseCanisterMigrations,
            api::NnsFunction::UnpauseCanisterMigrations => {
                pb::NnsFunction::UnpauseCanisterMigrations
            }
            api::NnsFunction::SetSubnetOperationalLevel => {
                pb::NnsFunction::SetSubnetOperationalLevel
            }
        }
    }
}

impl From<pb::ProposalStatus> for api::ProposalStatus {
    fn from(item: pb::ProposalStatus) -> Self {
        match item {
            pb::ProposalStatus::Unspecified => api::ProposalStatus::Unspecified,
            pb::ProposalStatus::Open => api::ProposalStatus::Open,
            pb::ProposalStatus::Rejected => api::ProposalStatus::Rejected,
            pb::ProposalStatus::Adopted => api::ProposalStatus::Adopted,
            pb::ProposalStatus::Executed => api::ProposalStatus::Executed,
            pb::ProposalStatus::Failed => api::ProposalStatus::Failed,
        }
    }
}
impl From<api::ProposalStatus> for pb::ProposalStatus {
    fn from(item: api::ProposalStatus) -> Self {
        match item {
            api::ProposalStatus::Unspecified => pb::ProposalStatus::Unspecified,
            api::ProposalStatus::Open => pb::ProposalStatus::Open,
            api::ProposalStatus::Rejected => pb::ProposalStatus::Rejected,
            api::ProposalStatus::Adopted => pb::ProposalStatus::Adopted,
            api::ProposalStatus::Executed => pb::ProposalStatus::Executed,
            api::ProposalStatus::Failed => pb::ProposalStatus::Failed,
        }
    }
}

impl From<pb::ProposalRewardStatus> for api::ProposalRewardStatus {
    fn from(item: pb::ProposalRewardStatus) -> Self {
        match item {
            pb::ProposalRewardStatus::Unspecified => api::ProposalRewardStatus::Unspecified,
            pb::ProposalRewardStatus::AcceptVotes => api::ProposalRewardStatus::AcceptVotes,
            pb::ProposalRewardStatus::ReadyToSettle => api::ProposalRewardStatus::ReadyToSettle,
            pb::ProposalRewardStatus::Settled => api::ProposalRewardStatus::Settled,
            pb::ProposalRewardStatus::Ineligible => api::ProposalRewardStatus::Ineligible,
        }
    }
}
impl From<api::ProposalRewardStatus> for pb::ProposalRewardStatus {
    fn from(item: api::ProposalRewardStatus) -> Self {
        match item {
            api::ProposalRewardStatus::Unspecified => pb::ProposalRewardStatus::Unspecified,
            api::ProposalRewardStatus::AcceptVotes => pb::ProposalRewardStatus::AcceptVotes,
            api::ProposalRewardStatus::ReadyToSettle => pb::ProposalRewardStatus::ReadyToSettle,
            api::ProposalRewardStatus::Settled => pb::ProposalRewardStatus::Settled,
            api::ProposalRewardStatus::Ineligible => pb::ProposalRewardStatus::Ineligible,
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

impl From<pb::MaturityDisbursement> for api::MaturityDisbursement {
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

impl From<pb::TakeCanisterSnapshot> for api::TakeCanisterSnapshot {
    fn from(item: pb::TakeCanisterSnapshot) -> Self {
        Self {
            canister_id: item.canister_id,
            replace_snapshot: item.replace_snapshot,
        }
    }
}

impl From<api::TakeCanisterSnapshot> for pb::TakeCanisterSnapshot {
    fn from(item: api::TakeCanisterSnapshot) -> Self {
        Self {
            canister_id: item.canister_id,
            replace_snapshot: item.replace_snapshot,
        }
    }
}
