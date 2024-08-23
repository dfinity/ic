use crate::pb::v1 as pb;
use ic_nns_governance_api::pb::v1 as pb_api;

impl From<pb::NodeProvider> for pb_api::NodeProvider {
    fn from(item: pb::NodeProvider) -> Self {
        Self {
            id: item.id,
            reward_account: item.reward_account,
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

impl From<pb::NeuronInfo> for pb_api::NeuronInfo {
    fn from(item: pb::NeuronInfo) -> Self {
        Self {
            retrieved_at_timestamp_seconds: item.retrieved_at_timestamp_seconds,
            state: item.state,
            age_seconds: item.age_seconds,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            recent_ballots: item.recent_ballots.into_iter().map(|x| x.into()).collect(),
            voting_power: item.voting_power,
            created_timestamp_seconds: item.created_timestamp_seconds,
            stake_e8s: item.stake_e8s,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
            neuron_type: item.neuron_type,
            visibility: item.visibility,
        }
    }
}
impl From<pb_api::NeuronInfo> for pb::NeuronInfo {
    fn from(item: pb_api::NeuronInfo) -> Self {
        Self {
            retrieved_at_timestamp_seconds: item.retrieved_at_timestamp_seconds,
            state: item.state,
            age_seconds: item.age_seconds,
            dissolve_delay_seconds: item.dissolve_delay_seconds,
            recent_ballots: item.recent_ballots.into_iter().map(|x| x.into()).collect(),
            voting_power: item.voting_power,
            created_timestamp_seconds: item.created_timestamp_seconds,
            stake_e8s: item.stake_e8s,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
            neuron_type: item.neuron_type,
            visibility: item.visibility,
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

impl From<pb::Neuron> for pb_api::Neuron {
    fn from(item: pb::Neuron) -> Self {
        Self {
            id: item.id,
            account: item.account,
            controller: item.controller,
            hot_keys: item.hot_keys,
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: item.spawn_at_timestamp_seconds,
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            recent_ballots: item.recent_ballots.into_iter().map(|x| x.into()).collect(),
            kyc_verified: item.kyc_verified,
            transfer: item.transfer.map(|x| x.into()),
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            not_for_profit: item.not_for_profit,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
            neuron_type: item.neuron_type,
            dissolve_state: item.dissolve_state.map(|x| x.into()),
            visibility: item.visibility,
        }
    }
}
impl From<pb_api::Neuron> for pb::Neuron {
    fn from(item: pb_api::Neuron) -> Self {
        Self {
            id: item.id,
            account: item.account,
            controller: item.controller,
            hot_keys: item.hot_keys,
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: item.spawn_at_timestamp_seconds,
            followees: item
                .followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            recent_ballots: item.recent_ballots.into_iter().map(|x| x.into()).collect(),
            kyc_verified: item.kyc_verified,
            transfer: item.transfer.map(|x| x.into()),
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            not_for_profit: item.not_for_profit,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            known_neuron_data: item.known_neuron_data.map(|x| x.into()),
            neuron_type: item.neuron_type,
            dissolve_state: item.dissolve_state.map(|x| x.into()),
            visibility: item.visibility,
        }
    }
}

impl From<pb::neuron::Followees> for pb_api::neuron::Followees {
    fn from(item: pb::neuron::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}
impl From<pb_api::neuron::Followees> for pb::neuron::Followees {
    fn from(item: pb_api::neuron::Followees) -> Self {
        Self {
            followees: item.followees,
        }
    }
}

impl From<pb::neuron::DissolveState> for pb_api::neuron::DissolveState {
    fn from(item: pb::neuron::DissolveState) -> Self {
        match item {
            pb::neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb_api::neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb::neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb_api::neuron::DissolveState::DissolveDelaySeconds(v)
            }
        }
    }
}
impl From<pb_api::neuron::DissolveState> for pb::neuron::DissolveState {
    fn from(item: pb_api::neuron::DissolveState) -> Self {
        match item {
            pb_api::neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb::neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb_api::neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb::neuron::DissolveState::DissolveDelaySeconds(v)
            }
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

impl From<pb::AbridgedNeuron> for pb_api::AbridgedNeuron {
    fn from(item: pb::AbridgedNeuron) -> Self {
        Self {
            account: item.account,
            controller: item.controller,
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: item.spawn_at_timestamp_seconds,
            kyc_verified: item.kyc_verified,
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            not_for_profit: item.not_for_profit,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            neuron_type: item.neuron_type,
            dissolve_state: item.dissolve_state.map(|x| x.into()),
            visibility: item.visibility,
        }
    }
}
impl From<pb_api::AbridgedNeuron> for pb::AbridgedNeuron {
    fn from(item: pb_api::AbridgedNeuron) -> Self {
        Self {
            account: item.account,
            controller: item.controller,
            cached_neuron_stake_e8s: item.cached_neuron_stake_e8s,
            neuron_fees_e8s: item.neuron_fees_e8s,
            created_timestamp_seconds: item.created_timestamp_seconds,
            aging_since_timestamp_seconds: item.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: item.spawn_at_timestamp_seconds,
            kyc_verified: item.kyc_verified,
            maturity_e8s_equivalent: item.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: item.staked_maturity_e8s_equivalent,
            auto_stake_maturity: item.auto_stake_maturity,
            not_for_profit: item.not_for_profit,
            joined_community_fund_timestamp_seconds: item.joined_community_fund_timestamp_seconds,
            neuron_type: item.neuron_type,
            dissolve_state: item.dissolve_state.map(|x| x.into()),
            visibility: item.visibility,
        }
    }
}

impl From<pb::abridged_neuron::DissolveState> for pb_api::abridged_neuron::DissolveState {
    fn from(item: pb::abridged_neuron::DissolveState) -> Self {
        match item {
            pb::abridged_neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb_api::abridged_neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb::abridged_neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb_api::abridged_neuron::DissolveState::DissolveDelaySeconds(v)
            }
        }
    }
}
impl From<pb_api::abridged_neuron::DissolveState> for pb::abridged_neuron::DissolveState {
    fn from(item: pb_api::abridged_neuron::DissolveState) -> Self {
        match item {
            pb_api::abridged_neuron::DissolveState::WhenDissolvedTimestampSeconds(v) => {
                pb::abridged_neuron::DissolveState::WhenDissolvedTimestampSeconds(v)
            }
            pb_api::abridged_neuron::DissolveState::DissolveDelaySeconds(v) => {
                pb::abridged_neuron::DissolveState::DissolveDelaySeconds(v)
            }
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
        Self {
            to_account: item.to_account,
        }
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

impl From<pb::Proposal> for pb_api::Proposal {
    fn from(item: pb::Proposal) -> Self {
        Self {
            title: item.title,
            summary: item.summary,
            url: item.url,
            action: item.action.map(|x| x.into()),
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
        }
    }
}

impl From<pb::proposal::Action> for pb_api::proposal::Action {
    fn from(item: pb::proposal::Action) -> Self {
        match item {
            pb::proposal::Action::ManageNeuron(v) => {
                pb_api::proposal::Action::ManageNeuron(Box::new((*v).into()))
            }
            pb::proposal::Action::ManageNetworkEconomics(v) => {
                pb_api::proposal::Action::ManageNetworkEconomics(v.into())
            }
            pb::proposal::Action::Motion(v) => pb_api::proposal::Action::Motion(v.into()),
            pb::proposal::Action::ExecuteNnsFunction(v) => {
                pb_api::proposal::Action::ExecuteNnsFunction(v.into())
            }
            pb::proposal::Action::ApproveGenesisKyc(v) => {
                pb_api::proposal::Action::ApproveGenesisKyc(v.into())
            }
            pb::proposal::Action::AddOrRemoveNodeProvider(v) => {
                pb_api::proposal::Action::AddOrRemoveNodeProvider(v.into())
            }
            pb::proposal::Action::RewardNodeProvider(v) => {
                pb_api::proposal::Action::RewardNodeProvider(v.into())
            }
            pb::proposal::Action::SetDefaultFollowees(v) => {
                pb_api::proposal::Action::SetDefaultFollowees(v.into())
            }
            pb::proposal::Action::RewardNodeProviders(v) => {
                pb_api::proposal::Action::RewardNodeProviders(v.into())
            }
            pb::proposal::Action::RegisterKnownNeuron(v) => {
                pb_api::proposal::Action::RegisterKnownNeuron(v.into())
            }
            pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v) => {
                pb_api::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.into())
            }
            pb::proposal::Action::OpenSnsTokenSwap(v) => {
                pb_api::proposal::Action::OpenSnsTokenSwap(v.into())
            }
            pb::proposal::Action::CreateServiceNervousSystem(v) => {
                pb_api::proposal::Action::CreateServiceNervousSystem(v.into())
            }
            pb::proposal::Action::InstallCode(v) => pb_api::proposal::Action::InstallCode(v.into()),
            pb::proposal::Action::StopOrStartCanister(v) => {
                pb_api::proposal::Action::StopOrStartCanister(v.into())
            }
            pb::proposal::Action::UpdateCanisterSettings(v) => {
                pb_api::proposal::Action::UpdateCanisterSettings(v.into())
            }
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
            pb_api::ProposalActionRequest::SetDefaultFollowees(v) => {
                pb::proposal::Action::SetDefaultFollowees(v.into())
            }
            pb_api::ProposalActionRequest::RewardNodeProviders(v) => {
                pb::proposal::Action::RewardNodeProviders(v.into())
            }
            pb_api::ProposalActionRequest::RegisterKnownNeuron(v) => {
                pb::proposal::Action::RegisterKnownNeuron(v.into())
            }
            pb_api::ProposalActionRequest::SetSnsTokenSwapOpenTimeWindow(v) => {
                pb::proposal::Action::SetSnsTokenSwapOpenTimeWindow(v.into())
            }
            pb_api::ProposalActionRequest::OpenSnsTokenSwap(v) => {
                pb::proposal::Action::OpenSnsTokenSwap(v.into())
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

impl From<pb::ManageNeuron> for pb_api::ManageNeuron {
    fn from(item: pb::ManageNeuron) -> Self {
        Self {
            id: item.id,
            neuron_id_or_subaccount: item.neuron_id_or_subaccount.map(|x| x.into()),
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuron> for pb::ManageNeuron {
    fn from(item: pb_api::ManageNeuron) -> Self {
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
        }
    }
}
impl From<pb_api::manage_neuron::Split> for pb::manage_neuron::Split {
    fn from(item: pb_api::manage_neuron::Split) -> Self {
        Self {
            amount_e8s: item.amount_e8s,
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

impl From<pb::manage_neuron::Command> for pb_api::manage_neuron::Command {
    fn from(item: pb::manage_neuron::Command) -> Self {
        match item {
            pb::manage_neuron::Command::Configure(v) => {
                pb_api::manage_neuron::Command::Configure(v.into())
            }
            pb::manage_neuron::Command::Disburse(v) => {
                pb_api::manage_neuron::Command::Disburse(v.into())
            }
            pb::manage_neuron::Command::Spawn(v) => pb_api::manage_neuron::Command::Spawn(v.into()),
            pb::manage_neuron::Command::Follow(v) => {
                pb_api::manage_neuron::Command::Follow(v.into())
            }
            pb::manage_neuron::Command::MakeProposal(v) => {
                pb_api::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            pb::manage_neuron::Command::RegisterVote(v) => {
                pb_api::manage_neuron::Command::RegisterVote(v.into())
            }
            pb::manage_neuron::Command::Split(v) => pb_api::manage_neuron::Command::Split(v.into()),
            pb::manage_neuron::Command::DisburseToNeuron(v) => {
                pb_api::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            pb::manage_neuron::Command::ClaimOrRefresh(v) => {
                pb_api::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron::Command::MergeMaturity(v) => {
                pb_api::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb::manage_neuron::Command::Merge(v) => pb_api::manage_neuron::Command::Merge(v.into()),
            pb::manage_neuron::Command::StakeMaturity(v) => {
                pb_api::manage_neuron::Command::StakeMaturity(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron::Command> for pb::manage_neuron::Command {
    fn from(item: pb_api::manage_neuron::Command) -> Self {
        match item {
            pb_api::manage_neuron::Command::Configure(v) => {
                pb::manage_neuron::Command::Configure(v.into())
            }
            pb_api::manage_neuron::Command::Disburse(v) => {
                pb::manage_neuron::Command::Disburse(v.into())
            }
            pb_api::manage_neuron::Command::Spawn(v) => pb::manage_neuron::Command::Spawn(v.into()),
            pb_api::manage_neuron::Command::Follow(v) => {
                pb::manage_neuron::Command::Follow(v.into())
            }
            pb_api::manage_neuron::Command::MakeProposal(v) => {
                pb::manage_neuron::Command::MakeProposal(Box::new((*v).into()))
            }
            pb_api::manage_neuron::Command::RegisterVote(v) => {
                pb::manage_neuron::Command::RegisterVote(v.into())
            }
            pb_api::manage_neuron::Command::Split(v) => pb::manage_neuron::Command::Split(v.into()),
            pb_api::manage_neuron::Command::DisburseToNeuron(v) => {
                pb::manage_neuron::Command::DisburseToNeuron(v.into())
            }
            pb_api::manage_neuron::Command::ClaimOrRefresh(v) => {
                pb::manage_neuron::Command::ClaimOrRefresh(v.into())
            }
            pb_api::manage_neuron::Command::MergeMaturity(v) => {
                pb::manage_neuron::Command::MergeMaturity(v.into())
            }
            pb_api::manage_neuron::Command::Merge(v) => pb::manage_neuron::Command::Merge(v.into()),
            pb_api::manage_neuron::Command::StakeMaturity(v) => {
                pb::manage_neuron::Command::StakeMaturity(v.into())
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
        }
    }
}

impl From<pb::ManageNeuronResponse> for pb_api::ManageNeuronResponse {
    fn from(item: pb::ManageNeuronResponse) -> Self {
        Self {
            command: item.command.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ManageNeuronResponse> for pb::ManageNeuronResponse {
    fn from(item: pb_api::ManageNeuronResponse) -> Self {
        Self {
            command: item.command.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::ConfigureResponse>
    for pb_api::manage_neuron_response::ConfigureResponse
{
    fn from(_: pb::manage_neuron_response::ConfigureResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::ConfigureResponse>
    for pb::manage_neuron_response::ConfigureResponse
{
    fn from(_: pb_api::manage_neuron_response::ConfigureResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::DisburseResponse>
    for pb_api::manage_neuron_response::DisburseResponse
{
    fn from(item: pb::manage_neuron_response::DisburseResponse) -> Self {
        Self {
            transfer_block_height: item.transfer_block_height,
        }
    }
}
impl From<pb_api::manage_neuron_response::DisburseResponse>
    for pb::manage_neuron_response::DisburseResponse
{
    fn from(item: pb_api::manage_neuron_response::DisburseResponse) -> Self {
        Self {
            transfer_block_height: item.transfer_block_height,
        }
    }
}

impl From<pb::manage_neuron_response::SpawnResponse>
    for pb_api::manage_neuron_response::SpawnResponse
{
    fn from(item: pb::manage_neuron_response::SpawnResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}
impl From<pb_api::manage_neuron_response::SpawnResponse>
    for pb::manage_neuron_response::SpawnResponse
{
    fn from(item: pb_api::manage_neuron_response::SpawnResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}

impl From<pb::manage_neuron_response::MergeMaturityResponse>
    for pb_api::manage_neuron_response::MergeMaturityResponse
{
    fn from(item: pb::manage_neuron_response::MergeMaturityResponse) -> Self {
        Self {
            merged_maturity_e8s: item.merged_maturity_e8s,
            new_stake_e8s: item.new_stake_e8s,
        }
    }
}
impl From<pb_api::manage_neuron_response::MergeMaturityResponse>
    for pb::manage_neuron_response::MergeMaturityResponse
{
    fn from(item: pb_api::manage_neuron_response::MergeMaturityResponse) -> Self {
        Self {
            merged_maturity_e8s: item.merged_maturity_e8s,
            new_stake_e8s: item.new_stake_e8s,
        }
    }
}

impl From<pb::manage_neuron_response::StakeMaturityResponse>
    for pb_api::manage_neuron_response::StakeMaturityResponse
{
    fn from(item: pb::manage_neuron_response::StakeMaturityResponse) -> Self {
        Self {
            maturity_e8s: item.maturity_e8s,
            staked_maturity_e8s: item.staked_maturity_e8s,
        }
    }
}
impl From<pb_api::manage_neuron_response::StakeMaturityResponse>
    for pb::manage_neuron_response::StakeMaturityResponse
{
    fn from(item: pb_api::manage_neuron_response::StakeMaturityResponse) -> Self {
        Self {
            maturity_e8s: item.maturity_e8s,
            staked_maturity_e8s: item.staked_maturity_e8s,
        }
    }
}

impl From<pb::manage_neuron_response::FollowResponse>
    for pb_api::manage_neuron_response::FollowResponse
{
    fn from(_: pb::manage_neuron_response::FollowResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::FollowResponse>
    for pb::manage_neuron_response::FollowResponse
{
    fn from(_: pb_api::manage_neuron_response::FollowResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::MakeProposalResponse>
    for pb_api::manage_neuron_response::MakeProposalResponse
{
    fn from(item: pb::manage_neuron_response::MakeProposalResponse) -> Self {
        Self {
            proposal_id: item.proposal_id,
            message: item.message,
        }
    }
}
impl From<pb_api::manage_neuron_response::MakeProposalResponse>
    for pb::manage_neuron_response::MakeProposalResponse
{
    fn from(item: pb_api::manage_neuron_response::MakeProposalResponse) -> Self {
        Self {
            proposal_id: item.proposal_id,
            message: item.message,
        }
    }
}

impl From<pb::manage_neuron_response::RegisterVoteResponse>
    for pb_api::manage_neuron_response::RegisterVoteResponse
{
    fn from(_: pb::manage_neuron_response::RegisterVoteResponse) -> Self {
        Self {}
    }
}
impl From<pb_api::manage_neuron_response::RegisterVoteResponse>
    for pb::manage_neuron_response::RegisterVoteResponse
{
    fn from(_: pb_api::manage_neuron_response::RegisterVoteResponse) -> Self {
        Self {}
    }
}

impl From<pb::manage_neuron_response::SplitResponse>
    for pb_api::manage_neuron_response::SplitResponse
{
    fn from(item: pb::manage_neuron_response::SplitResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}
impl From<pb_api::manage_neuron_response::SplitResponse>
    for pb::manage_neuron_response::SplitResponse
{
    fn from(item: pb_api::manage_neuron_response::SplitResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}

impl From<pb::manage_neuron_response::MergeResponse>
    for pb_api::manage_neuron_response::MergeResponse
{
    fn from(item: pb::manage_neuron_response::MergeResponse) -> Self {
        Self {
            source_neuron: item.source_neuron.map(|x| x.into()),
            target_neuron: item.target_neuron.map(|x| x.into()),
            source_neuron_info: item.source_neuron_info.map(|x| x.into()),
            target_neuron_info: item.target_neuron_info.map(|x| x.into()),
        }
    }
}
impl From<pb_api::manage_neuron_response::MergeResponse>
    for pb::manage_neuron_response::MergeResponse
{
    fn from(item: pb_api::manage_neuron_response::MergeResponse) -> Self {
        Self {
            source_neuron: item.source_neuron.map(|x| x.into()),
            target_neuron: item.target_neuron.map(|x| x.into()),
            source_neuron_info: item.source_neuron_info.map(|x| x.into()),
            target_neuron_info: item.target_neuron_info.map(|x| x.into()),
        }
    }
}

impl From<pb::manage_neuron_response::DisburseToNeuronResponse>
    for pb_api::manage_neuron_response::DisburseToNeuronResponse
{
    fn from(item: pb::manage_neuron_response::DisburseToNeuronResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}
impl From<pb_api::manage_neuron_response::DisburseToNeuronResponse>
    for pb::manage_neuron_response::DisburseToNeuronResponse
{
    fn from(item: pb_api::manage_neuron_response::DisburseToNeuronResponse) -> Self {
        Self {
            created_neuron_id: item.created_neuron_id,
        }
    }
}

impl From<pb::manage_neuron_response::ClaimOrRefreshResponse>
    for pb_api::manage_neuron_response::ClaimOrRefreshResponse
{
    fn from(item: pb::manage_neuron_response::ClaimOrRefreshResponse) -> Self {
        Self {
            refreshed_neuron_id: item.refreshed_neuron_id,
        }
    }
}
impl From<pb_api::manage_neuron_response::ClaimOrRefreshResponse>
    for pb::manage_neuron_response::ClaimOrRefreshResponse
{
    fn from(item: pb_api::manage_neuron_response::ClaimOrRefreshResponse) -> Self {
        Self {
            refreshed_neuron_id: item.refreshed_neuron_id,
        }
    }
}

impl From<pb::manage_neuron_response::Command> for pb_api::manage_neuron_response::Command {
    fn from(item: pb::manage_neuron_response::Command) -> Self {
        match item {
            pb::manage_neuron_response::Command::Error(v) => {
                pb_api::manage_neuron_response::Command::Error(v.into())
            }
            pb::manage_neuron_response::Command::Configure(v) => {
                pb_api::manage_neuron_response::Command::Configure(v.into())
            }
            pb::manage_neuron_response::Command::Disburse(v) => {
                pb_api::manage_neuron_response::Command::Disburse(v.into())
            }
            pb::manage_neuron_response::Command::Spawn(v) => {
                pb_api::manage_neuron_response::Command::Spawn(v.into())
            }
            pb::manage_neuron_response::Command::Follow(v) => {
                pb_api::manage_neuron_response::Command::Follow(v.into())
            }
            pb::manage_neuron_response::Command::MakeProposal(v) => {
                pb_api::manage_neuron_response::Command::MakeProposal(v.into())
            }
            pb::manage_neuron_response::Command::RegisterVote(v) => {
                pb_api::manage_neuron_response::Command::RegisterVote(v.into())
            }
            pb::manage_neuron_response::Command::Split(v) => {
                pb_api::manage_neuron_response::Command::Split(v.into())
            }
            pb::manage_neuron_response::Command::DisburseToNeuron(v) => {
                pb_api::manage_neuron_response::Command::DisburseToNeuron(v.into())
            }
            pb::manage_neuron_response::Command::ClaimOrRefresh(v) => {
                pb_api::manage_neuron_response::Command::ClaimOrRefresh(v.into())
            }
            pb::manage_neuron_response::Command::MergeMaturity(v) => {
                pb_api::manage_neuron_response::Command::MergeMaturity(v.into())
            }
            pb::manage_neuron_response::Command::Merge(v) => {
                pb_api::manage_neuron_response::Command::Merge(v.into())
            }
            pb::manage_neuron_response::Command::StakeMaturity(v) => {
                pb_api::manage_neuron_response::Command::StakeMaturity(v.into())
            }
        }
    }
}
impl From<pb_api::manage_neuron_response::Command> for pb::manage_neuron_response::Command {
    fn from(item: pb_api::manage_neuron_response::Command) -> Self {
        match item {
            pb_api::manage_neuron_response::Command::Error(v) => {
                pb::manage_neuron_response::Command::Error(v.into())
            }
            pb_api::manage_neuron_response::Command::Configure(v) => {
                pb::manage_neuron_response::Command::Configure(v.into())
            }
            pb_api::manage_neuron_response::Command::Disburse(v) => {
                pb::manage_neuron_response::Command::Disburse(v.into())
            }
            pb_api::manage_neuron_response::Command::Spawn(v) => {
                pb::manage_neuron_response::Command::Spawn(v.into())
            }
            pb_api::manage_neuron_response::Command::Follow(v) => {
                pb::manage_neuron_response::Command::Follow(v.into())
            }
            pb_api::manage_neuron_response::Command::MakeProposal(v) => {
                pb::manage_neuron_response::Command::MakeProposal(v.into())
            }
            pb_api::manage_neuron_response::Command::RegisterVote(v) => {
                pb::manage_neuron_response::Command::RegisterVote(v.into())
            }
            pb_api::manage_neuron_response::Command::Split(v) => {
                pb::manage_neuron_response::Command::Split(v.into())
            }
            pb_api::manage_neuron_response::Command::DisburseToNeuron(v) => {
                pb::manage_neuron_response::Command::DisburseToNeuron(v.into())
            }
            pb_api::manage_neuron_response::Command::ClaimOrRefresh(v) => {
                pb::manage_neuron_response::Command::ClaimOrRefresh(v.into())
            }
            pb_api::manage_neuron_response::Command::MergeMaturity(v) => {
                pb::manage_neuron_response::Command::MergeMaturity(v.into())
            }
            pb_api::manage_neuron_response::Command::Merge(v) => {
                pb::manage_neuron_response::Command::Merge(v.into())
            }
            pb_api::manage_neuron_response::Command::StakeMaturity(v) => {
                pb::manage_neuron_response::Command::StakeMaturity(v.into())
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

impl From<pb::ProposalData> for pb_api::ProposalData {
    fn from(item: pb::ProposalData) -> Self {
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
        #[allow(deprecated)]
        Self {
            nns_neuron_id: item.nns_neuron_id,
            amount_icp_e8s: item.amount_icp_e8s,
            maturity_equivalent_icp_e8s: item.maturity_equivalent_icp_e8s,
            is_capped: item.is_capped,
            controller: item.controller,
            hotkeys: item.hotkeys,
            hotkey_principal: item.hotkey_principal,
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
            hotkey_principal: item.hotkey_principal,
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

impl From<pb::ProposalInfo> for pb_api::ProposalInfo {
    fn from(item: pb::ProposalInfo) -> Self {
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
            topic: item.topic,
            status: item.status,
            reward_status: item.reward_status,
            deadline_timestamp_seconds: item.deadline_timestamp_seconds,
            derived_proposal_information: item.derived_proposal_information.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ProposalInfo> for pb::ProposalInfo {
    fn from(item: pb_api::ProposalInfo) -> Self {
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
            topic: item.topic,
            status: item.status,
            reward_status: item.reward_status,
            deadline_timestamp_seconds: item.deadline_timestamp_seconds,
            derived_proposal_information: item.derived_proposal_information.map(|x| x.into()),
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

impl From<pb::KnownNeuronData> for pb_api::KnownNeuronData {
    fn from(item: pb::KnownNeuronData) -> Self {
        Self {
            name: item.name,
            description: item.description,
        }
    }
}
impl From<pb_api::KnownNeuronData> for pb::KnownNeuronData {
    fn from(item: pb_api::KnownNeuronData) -> Self {
        Self {
            name: item.name,
            description: item.description,
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
        let wasm_module_hash = item
            .wasm_module
            .map(|wasm_module| super::calculate_hash(&wasm_module).to_vec());
        let arg = item.arg.unwrap_or_default();
        let arg_hash = if arg.is_empty() {
            Some(vec![])
        } else {
            Some(super::calculate_hash(&arg).to_vec())
        };

        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
            wasm_module_hash,
            arg_hash,
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
        }
    }
}
impl From<pb_api::InstallCodeRequest> for pb::InstallCode {
    fn from(item: pb_api::InstallCodeRequest) -> Self {
        Self {
            canister_id: item.canister_id,
            install_mode: item.install_mode,
            wasm_module: item.wasm_module,
            arg: item.arg,
            skip_stopping_before_installing: item.skip_stopping_before_installing,
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

impl From<pb::Governance> for pb_api::Governance {
    fn from(item: pb::Governance) -> Self {
        Self {
            neurons: item
                .neurons
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            proposals: item
                .proposals
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            to_claim_transfers: item
                .to_claim_transfers
                .into_iter()
                .map(|x| x.into())
                .collect(),
            wait_for_quiet_threshold_seconds: item.wait_for_quiet_threshold_seconds,
            economics: item.economics.map(|x| x.into()),
            latest_reward_event: item.latest_reward_event.map(|x| x.into()),
            in_flight_commands: item
                .in_flight_commands
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            genesis_timestamp_seconds: item.genesis_timestamp_seconds,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
            default_followees: item
                .default_followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            short_voting_period_seconds: item.short_voting_period_seconds,
            neuron_management_voting_period_seconds: item.neuron_management_voting_period_seconds,
            metrics: item.metrics.map(|x| x.into()),
            most_recent_monthly_node_provider_rewards: item
                .most_recent_monthly_node_provider_rewards
                .map(|x| x.into()),
            cached_daily_maturity_modulation_basis_points: item
                .cached_daily_maturity_modulation_basis_points,
            maturity_modulation_last_updated_at_timestamp_seconds: item
                .maturity_modulation_last_updated_at_timestamp_seconds,
            spawning_neurons: item.spawning_neurons,
            making_sns_proposal: item.making_sns_proposal.map(|x| x.into()),
            migrations: item.migrations.map(|x| x.into()),
            topic_followee_index: item
                .topic_followee_index
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            restore_aging_summary: item.restore_aging_summary.map(|x| x.into()),
        }
    }
}
impl From<pb_api::Governance> for pb::Governance {
    fn from(item: pb_api::Governance) -> Self {
        Self {
            neurons: item
                .neurons
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            proposals: item
                .proposals
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            to_claim_transfers: item
                .to_claim_transfers
                .into_iter()
                .map(|x| x.into())
                .collect(),
            wait_for_quiet_threshold_seconds: item.wait_for_quiet_threshold_seconds,
            economics: item.economics.map(|x| x.into()),
            latest_reward_event: item.latest_reward_event.map(|x| x.into()),
            in_flight_commands: item
                .in_flight_commands
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            genesis_timestamp_seconds: item.genesis_timestamp_seconds,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
            default_followees: item
                .default_followees
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            short_voting_period_seconds: item.short_voting_period_seconds,
            neuron_management_voting_period_seconds: item.neuron_management_voting_period_seconds,
            metrics: item.metrics.map(|x| x.into()),
            most_recent_monthly_node_provider_rewards: item
                .most_recent_monthly_node_provider_rewards
                .map(|x| x.into()),
            cached_daily_maturity_modulation_basis_points: item
                .cached_daily_maturity_modulation_basis_points,
            maturity_modulation_last_updated_at_timestamp_seconds: item
                .maturity_modulation_last_updated_at_timestamp_seconds,
            spawning_neurons: item.spawning_neurons,
            making_sns_proposal: item.making_sns_proposal.map(|x| x.into()),
            migrations: item.migrations.map(|x| x.into()),
            topic_followee_index: item
                .topic_followee_index
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            restore_aging_summary: item.restore_aging_summary.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::NeuronInFlightCommand> for pb_api::governance::NeuronInFlightCommand {
    fn from(item: pb::governance::NeuronInFlightCommand) -> Self {
        Self {
            timestamp: item.timestamp,
            command: item.command.map(|x| x.into()),
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

impl From<pb::governance::neuron_in_flight_command::Command>
    for pb_api::governance::neuron_in_flight_command::Command
{
    fn from(item: pb::governance::neuron_in_flight_command::Command) -> Self {
        match item {
            pb::governance::neuron_in_flight_command::Command::Disburse(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Disburse(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::Split(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Split(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::DisburseToNeuron(v) => {
                pb_api::governance::neuron_in_flight_command::Command::DisburseToNeuron(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::MergeMaturity(v) => {
                pb_api::governance::neuron_in_flight_command::Command::MergeMaturity(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(v) => {
                pb_api::governance::neuron_in_flight_command::Command::ClaimOrRefreshNeuron(
                    v.into(),
                )
            }
            pb::governance::neuron_in_flight_command::Command::Configure(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Configure(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::Merge(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Merge(v.into())
            }
            pb::governance::neuron_in_flight_command::Command::Spawn(v) => {
                pb_api::governance::neuron_in_flight_command::Command::Spawn(v)
            }
            pb::governance::neuron_in_flight_command::Command::SyncCommand(v) => {
                pb_api::governance::neuron_in_flight_command::Command::SyncCommand(v.into())
            }
        }
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
            non_self_authenticating_controller_neuron_subset_metrics: item
                .non_self_authenticating_controller_neuron_subset_metrics
                .map(|x| x.into()),
            public_neuron_subset_metrics: item.public_neuron_subset_metrics.map(|x| x.into()),
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
            non_self_authenticating_controller_neuron_subset_metrics: item
                .non_self_authenticating_controller_neuron_subset_metrics
                .map(|x| x.into()),
            public_neuron_subset_metrics: item.public_neuron_subset_metrics.map(|x| x.into()),
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
            count_buckets: item.count_buckets,
            staked_e8s_buckets: item.staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets: item.staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets: item.maturity_e8s_equivalent_buckets,
            voting_power_buckets: item.voting_power_buckets,
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
            count_buckets: item.count_buckets,
            staked_e8s_buckets: item.staked_e8s_buckets,
            staked_maturity_e8s_equivalent_buckets: item.staked_maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent_buckets: item.maturity_e8s_equivalent_buckets,
            voting_power_buckets: item.voting_power_buckets,
        }
    }
}

impl From<pb::governance::MakingSnsProposal> for pb_api::governance::MakingSnsProposal {
    fn from(item: pb::governance::MakingSnsProposal) -> Self {
        Self {
            proposer_id: item.proposer_id,
            caller: item.caller,
            proposal: item.proposal.map(|x| x.into()),
        }
    }
}
impl From<pb_api::governance::MakingSnsProposal> for pb::governance::MakingSnsProposal {
    fn from(item: pb_api::governance::MakingSnsProposal) -> Self {
        Self {
            proposer_id: item.proposer_id,
            caller: item.caller,
            proposal: item.proposal.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::Migration> for pb_api::governance::Migration {
    fn from(item: pb::governance::Migration) -> Self {
        Self {
            status: item.status,
            failure_reason: item.failure_reason,
            progress: item.progress.map(|x| x.into()),
        }
    }
}
impl From<pb_api::governance::Migration> for pb::governance::Migration {
    fn from(item: pb_api::governance::Migration) -> Self {
        Self {
            status: item.status,
            failure_reason: item.failure_reason,
            progress: item.progress.map(|x| x.into()),
        }
    }
}

impl From<pb::governance::migration::MigrationStatus>
    for pb_api::governance::migration::MigrationStatus
{
    fn from(item: pb::governance::migration::MigrationStatus) -> Self {
        match item {
            pb::governance::migration::MigrationStatus::Unspecified => {
                pb_api::governance::migration::MigrationStatus::Unspecified
            }
            pb::governance::migration::MigrationStatus::InProgress => {
                pb_api::governance::migration::MigrationStatus::InProgress
            }
            pb::governance::migration::MigrationStatus::Succeeded => {
                pb_api::governance::migration::MigrationStatus::Succeeded
            }
            pb::governance::migration::MigrationStatus::Failed => {
                pb_api::governance::migration::MigrationStatus::Failed
            }
        }
    }
}
impl From<pb_api::governance::migration::MigrationStatus>
    for pb::governance::migration::MigrationStatus
{
    fn from(item: pb_api::governance::migration::MigrationStatus) -> Self {
        match item {
            pb_api::governance::migration::MigrationStatus::Unspecified => {
                pb::governance::migration::MigrationStatus::Unspecified
            }
            pb_api::governance::migration::MigrationStatus::InProgress => {
                pb::governance::migration::MigrationStatus::InProgress
            }
            pb_api::governance::migration::MigrationStatus::Succeeded => {
                pb::governance::migration::MigrationStatus::Succeeded
            }
            pb_api::governance::migration::MigrationStatus::Failed => {
                pb::governance::migration::MigrationStatus::Failed
            }
        }
    }
}

impl From<pb::governance::migration::Progress> for pb_api::governance::migration::Progress {
    fn from(item: pb::governance::migration::Progress) -> Self {
        match item {
            pb::governance::migration::Progress::LastNeuronId(v) => {
                pb_api::governance::migration::Progress::LastNeuronId(v)
            }
        }
    }
}
impl From<pb_api::governance::migration::Progress> for pb::governance::migration::Progress {
    fn from(item: pb_api::governance::migration::Progress) -> Self {
        match item {
            pb_api::governance::migration::Progress::LastNeuronId(v) => {
                pb::governance::migration::Progress::LastNeuronId(v)
            }
        }
    }
}

impl From<pb::governance::Migrations> for pb_api::governance::Migrations {
    fn from(item: pb::governance::Migrations) -> Self {
        Self {
            neuron_indexes_migration: item.neuron_indexes_migration.map(|x| x.into()),
            copy_inactive_neurons_to_stable_memory_migration: item
                .copy_inactive_neurons_to_stable_memory_migration
                .map(|x| x.into()),
        }
    }
}
impl From<pb_api::governance::Migrations> for pb::governance::Migrations {
    fn from(item: pb_api::governance::Migrations) -> Self {
        Self {
            neuron_indexes_migration: item.neuron_indexes_migration.map(|x| x.into()),
            copy_inactive_neurons_to_stable_memory_migration: item
                .copy_inactive_neurons_to_stable_memory_migration
                .map(|x| x.into()),
        }
    }
}

impl From<pb::governance::FollowersMap> for pb_api::governance::FollowersMap {
    fn from(item: pb::governance::FollowersMap) -> Self {
        Self {
            followers_map: item
                .followers_map
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}
impl From<pb_api::governance::FollowersMap> for pb::governance::FollowersMap {
    fn from(item: pb_api::governance::FollowersMap) -> Self {
        Self {
            followers_map: item
                .followers_map
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

impl From<pb::governance::followers_map::Followers>
    for pb_api::governance::followers_map::Followers
{
    fn from(item: pb::governance::followers_map::Followers) -> Self {
        Self {
            followers: item.followers,
        }
    }
}
impl From<pb_api::governance::followers_map::Followers>
    for pb::governance::followers_map::Followers
{
    fn from(item: pb_api::governance::followers_map::Followers) -> Self {
        Self {
            followers: item.followers,
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

impl From<pb::ListProposalInfo> for pb_api::ListProposalInfo {
    fn from(item: pb::ListProposalInfo) -> Self {
        Self {
            limit: item.limit,
            before_proposal: item.before_proposal,
            exclude_topic: item.exclude_topic,
            include_reward_status: item.include_reward_status,
            include_status: item.include_status,
            include_all_manage_neuron_proposals: item.include_all_manage_neuron_proposals,
            omit_large_fields: item.omit_large_fields,
        }
    }
}
impl From<pb_api::ListProposalInfo> for pb::ListProposalInfo {
    fn from(item: pb_api::ListProposalInfo) -> Self {
        Self {
            limit: item.limit,
            before_proposal: item.before_proposal,
            exclude_topic: item.exclude_topic,
            include_reward_status: item.include_reward_status,
            include_status: item.include_status,
            include_all_manage_neuron_proposals: item.include_all_manage_neuron_proposals,
            omit_large_fields: item.omit_large_fields,
        }
    }
}

impl From<pb::ListProposalInfoResponse> for pb_api::ListProposalInfoResponse {
    fn from(item: pb::ListProposalInfoResponse) -> Self {
        Self {
            proposal_info: item.proposal_info.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::ListProposalInfoResponse> for pb::ListProposalInfoResponse {
    fn from(item: pb_api::ListProposalInfoResponse) -> Self {
        Self {
            proposal_info: item.proposal_info.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<pb::ListNeurons> for pb_api::ListNeurons {
    fn from(item: pb::ListNeurons) -> Self {
        Self {
            neuron_ids: item.neuron_ids,
            include_neurons_readable_by_caller: item.include_neurons_readable_by_caller,
            include_empty_neurons_readable_by_caller: item.include_empty_neurons_readable_by_caller,
            include_public_neurons_in_full_neurons: item.include_public_neurons_in_full_neurons,
        }
    }
}
impl From<pb_api::ListNeurons> for pb::ListNeurons {
    fn from(item: pb_api::ListNeurons) -> Self {
        Self {
            neuron_ids: item.neuron_ids,
            include_neurons_readable_by_caller: item.include_neurons_readable_by_caller,
            include_empty_neurons_readable_by_caller: item.include_empty_neurons_readable_by_caller,
            include_public_neurons_in_full_neurons: item.include_public_neurons_in_full_neurons,
        }
    }
}

impl From<pb::ListNeuronsResponse> for pb_api::ListNeuronsResponse {
    fn from(item: pb::ListNeuronsResponse) -> Self {
        Self {
            neuron_infos: item
                .neuron_infos
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            full_neurons: item.full_neurons.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::ListNeuronsResponse> for pb::ListNeuronsResponse {
    fn from(item: pb_api::ListNeuronsResponse) -> Self {
        Self {
            neuron_infos: item
                .neuron_infos
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
            full_neurons: item.full_neurons.into_iter().map(|x| x.into()).collect(),
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

impl From<pb::ClaimOrRefreshNeuronFromAccount> for pb_api::ClaimOrRefreshNeuronFromAccount {
    fn from(item: pb::ClaimOrRefreshNeuronFromAccount) -> Self {
        Self {
            controller: item.controller,
            memo: item.memo,
        }
    }
}
impl From<pb_api::ClaimOrRefreshNeuronFromAccount> for pb::ClaimOrRefreshNeuronFromAccount {
    fn from(item: pb_api::ClaimOrRefreshNeuronFromAccount) -> Self {
        Self {
            controller: item.controller,
            memo: item.memo,
        }
    }
}

impl From<pb::ClaimOrRefreshNeuronFromAccountResponse>
    for pb_api::ClaimOrRefreshNeuronFromAccountResponse
{
    fn from(item: pb::ClaimOrRefreshNeuronFromAccountResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}
impl From<pb_api::ClaimOrRefreshNeuronFromAccountResponse>
    for pb::ClaimOrRefreshNeuronFromAccountResponse
{
    fn from(item: pb_api::ClaimOrRefreshNeuronFromAccountResponse) -> Self {
        Self {
            result: item.result.map(|x| x.into()),
        }
    }
}

impl From<pb::claim_or_refresh_neuron_from_account_response::Result>
    for pb_api::claim_or_refresh_neuron_from_account_response::Result
{
    fn from(item: pb::claim_or_refresh_neuron_from_account_response::Result) -> Self {
        match item {
            pb::claim_or_refresh_neuron_from_account_response::Result::Error(v) => {
                pb_api::claim_or_refresh_neuron_from_account_response::Result::Error(v.into())
            }
            pb::claim_or_refresh_neuron_from_account_response::Result::NeuronId(v) => {
                pb_api::claim_or_refresh_neuron_from_account_response::Result::NeuronId(v)
            }
        }
    }
}
impl From<pb_api::claim_or_refresh_neuron_from_account_response::Result>
    for pb::claim_or_refresh_neuron_from_account_response::Result
{
    fn from(item: pb_api::claim_or_refresh_neuron_from_account_response::Result) -> Self {
        match item {
            pb_api::claim_or_refresh_neuron_from_account_response::Result::Error(v) => {
                pb::claim_or_refresh_neuron_from_account_response::Result::Error(v.into())
            }
            pb_api::claim_or_refresh_neuron_from_account_response::Result::NeuronId(v) => {
                pb::claim_or_refresh_neuron_from_account_response::Result::NeuronId(v)
            }
        }
    }
}

impl From<pb::MonthlyNodeProviderRewards> for pb_api::MonthlyNodeProviderRewards {
    fn from(item: pb::MonthlyNodeProviderRewards) -> Self {
        Self {
            timestamp: item.timestamp,
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            minimum_xdr_permyriad_per_icp: item.minimum_xdr_permyriad_per_icp,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            registry_version: item.registry_version,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
        }
    }
}
impl From<pb_api::MonthlyNodeProviderRewards> for pb::MonthlyNodeProviderRewards {
    fn from(item: pb_api::MonthlyNodeProviderRewards) -> Self {
        Self {
            timestamp: item.timestamp,
            rewards: item.rewards.into_iter().map(|x| x.into()).collect(),
            xdr_conversion_rate: item.xdr_conversion_rate.map(|x| x.into()),
            minimum_xdr_permyriad_per_icp: item.minimum_xdr_permyriad_per_icp,
            maximum_node_provider_rewards_e8s: item.maximum_node_provider_rewards_e8s,
            registry_version: item.registry_version,
            node_providers: item.node_providers.into_iter().map(|x| x.into()).collect(),
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
            hotkey_principal: item.hotkey_principal,
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
            hotkey_principal: item.hotkey_principal,
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

impl From<pb::Topic> for pb_api::Topic {
    fn from(item: pb::Topic) -> Self {
        match item {
            pb::Topic::Unspecified => pb_api::Topic::Unspecified,
            pb::Topic::NeuronManagement => pb_api::Topic::NeuronManagement,
            pb::Topic::ExchangeRate => pb_api::Topic::ExchangeRate,
            pb::Topic::NetworkEconomics => pb_api::Topic::NetworkEconomics,
            pb::Topic::Governance => pb_api::Topic::Governance,
            pb::Topic::NodeAdmin => pb_api::Topic::NodeAdmin,
            pb::Topic::ParticipantManagement => pb_api::Topic::ParticipantManagement,
            pb::Topic::SubnetManagement => pb_api::Topic::SubnetManagement,
            pb::Topic::NetworkCanisterManagement => pb_api::Topic::NetworkCanisterManagement,
            pb::Topic::Kyc => pb_api::Topic::Kyc,
            pb::Topic::NodeProviderRewards => pb_api::Topic::NodeProviderRewards,
            pb::Topic::IcOsVersionDeployment => pb_api::Topic::IcOsVersionDeployment,
            pb::Topic::IcOsVersionElection => pb_api::Topic::IcOsVersionElection,
            pb::Topic::SnsAndCommunityFund => pb_api::Topic::SnsAndCommunityFund,
            pb::Topic::ApiBoundaryNodeManagement => pb_api::Topic::ApiBoundaryNodeManagement,
            pb::Topic::SubnetRental => pb_api::Topic::SubnetRental,
            pb::Topic::ProtocolCanisterManagement => pb_api::Topic::ProtocolCanisterManagement,
            pb::Topic::ServiceNervousSystemManagement => {
                pb_api::Topic::ServiceNervousSystemManagement
            }
        }
    }
}
impl From<pb_api::Topic> for pb::Topic {
    fn from(item: pb_api::Topic) -> Self {
        match item {
            pb_api::Topic::Unspecified => pb::Topic::Unspecified,
            pb_api::Topic::NeuronManagement => pb::Topic::NeuronManagement,
            pb_api::Topic::ExchangeRate => pb::Topic::ExchangeRate,
            pb_api::Topic::NetworkEconomics => pb::Topic::NetworkEconomics,
            pb_api::Topic::Governance => pb::Topic::Governance,
            pb_api::Topic::NodeAdmin => pb::Topic::NodeAdmin,
            pb_api::Topic::ParticipantManagement => pb::Topic::ParticipantManagement,
            pb_api::Topic::SubnetManagement => pb::Topic::SubnetManagement,
            pb_api::Topic::NetworkCanisterManagement => pb::Topic::NetworkCanisterManagement,
            pb_api::Topic::Kyc => pb::Topic::Kyc,
            pb_api::Topic::NodeProviderRewards => pb::Topic::NodeProviderRewards,
            pb_api::Topic::IcOsVersionDeployment => pb::Topic::IcOsVersionDeployment,
            pb_api::Topic::IcOsVersionElection => pb::Topic::IcOsVersionElection,
            pb_api::Topic::SnsAndCommunityFund => pb::Topic::SnsAndCommunityFund,
            pb_api::Topic::ApiBoundaryNodeManagement => pb::Topic::ApiBoundaryNodeManagement,
            pb_api::Topic::SubnetRental => pb::Topic::SubnetRental,
            pb_api::Topic::ProtocolCanisterManagement => pb::Topic::ProtocolCanisterManagement,
            pb_api::Topic::ServiceNervousSystemManagement => {
                pb::Topic::ServiceNervousSystemManagement
            }
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
