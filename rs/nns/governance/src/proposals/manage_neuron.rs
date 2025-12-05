use crate::{
    pb::v1::{
        Account, ManageNeuron, SelfDescribingValue, Subaccount, Topic, Visibility,
        manage_neuron::{
            AddHotKey, ChangeAutoStakeMaturity, ClaimOrRefresh, Command, Configure, Disburse,
            DisburseMaturity, DisburseToNeuron, Follow, IncreaseDissolveDelay, JoinCommunityFund,
            LeaveCommunityFund, Merge, MergeMaturity, NeuronIdOrSubaccount, RefreshVotingPower,
            RegisterVote, RemoveHotKey, SetDissolveTimestamp, SetFollowing, SetVisibility, Spawn,
            Split, StakeMaturity, StartDissolving, StopDissolving, claim_or_refresh, configure,
            disburse, set_following,
        },
    },
    proposals::self_describing::{LocallyDescribableProposalAction, ValueBuilder},
};

use ic_nns_common::pb::v1::NeuronId;

fn account_identifier_to_hex(acc: &icp_ledger::protobuf::AccountIdentifier) -> String {
    acc.hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

impl LocallyDescribableProposalAction for ManageNeuron {
    const TYPE_NAME: &'static str = "Manage Neuron";
    const TYPE_DESCRIPTION: &'static str = "Manages a neuron by executing a command such as \
        configuring its settings, disbursing its stake, spawning a new neuron, following other \
        neurons, registering a vote, or performing other neuron management operations.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        // Convert id/neuron_id_or_subaccount using the helper method
        let neuron_id_or_subaccount = self.get_neuron_id_or_subaccount().unwrap_or(None);

        ValueBuilder::new()
            .add_field_with_empty_as_fallback("neuron_id_or_subaccount", neuron_id_or_subaccount)
            .add_field_with_empty_as_fallback("command", self.command.clone())
            .build()
    }
}

impl From<NeuronIdOrSubaccount> for SelfDescribingValue {
    fn from(id: NeuronIdOrSubaccount) -> Self {
        match id {
            NeuronIdOrSubaccount::NeuronId(neuron_id) => ValueBuilder::new()
                .add_field("NeuronId", neuron_id.id)
                .build(),
            NeuronIdOrSubaccount::Subaccount(subaccount) => ValueBuilder::new()
                .add_field("Subaccount", subaccount)
                .build(),
        }
    }
}

impl From<Command> for SelfDescribingValue {
    fn from(command: Command) -> Self {
        match command {
            Command::Configure(configure) => ValueBuilder::new()
                .add_field("Configure", configure)
                .build(),
            Command::Disburse(disburse) => {
                ValueBuilder::new().add_field("Disburse", disburse).build()
            }
            Command::Spawn(spawn) => ValueBuilder::new().add_field("Spawn", spawn).build(),
            Command::Follow(follow) => ValueBuilder::new().add_field("Follow", follow).build(),
            Command::MakeProposal(_proposal) => ValueBuilder::new()
                // This is impossible since a `MakeProposal` command is not allowed to be used in a
                // `ManageNeuron` proposal.
                .add_empty_field("MakeProposal")
                .build(),
            Command::RegisterVote(register_vote) => ValueBuilder::new()
                .add_field("RegisterVote", register_vote)
                .build(),
            Command::Split(split) => ValueBuilder::new().add_field("Split", split).build(),
            Command::DisburseToNeuron(disburse_to_neuron) => ValueBuilder::new()
                .add_field("DisburseToNeuron", disburse_to_neuron)
                .build(),
            Command::ClaimOrRefresh(claim_or_refresh) => ValueBuilder::new()
                .add_field("ClaimOrRefresh", claim_or_refresh)
                .build(),
            Command::MergeMaturity(merge_maturity) => ValueBuilder::new()
                .add_field("MergeMaturity", merge_maturity)
                .build(),
            Command::Merge(merge) => ValueBuilder::new().add_field("Merge", merge).build(),
            Command::StakeMaturity(stake_maturity) => ValueBuilder::new()
                .add_field("StakeMaturity", stake_maturity)
                .build(),
            Command::RefreshVotingPower(_) => ValueBuilder::new()
                .add_empty_field("RefreshVotingPower")
                .build(),
            Command::DisburseMaturity(disburse_maturity) => ValueBuilder::new()
                .add_field("DisburseMaturity", disburse_maturity)
                .build(),
            Command::SetFollowing(set_following) => ValueBuilder::new()
                .add_field("SetFollowing", set_following)
                .build(),
        }
    }
}

impl From<Configure> for SelfDescribingValue {
    fn from(configure: Configure) -> Self {
        ValueBuilder::new()
            .add_field("operation", configure.operation)
            .build()
    }
}

impl From<configure::Operation> for SelfDescribingValue {
    fn from(operation: configure::Operation) -> Self {
        match operation {
            configure::Operation::IncreaseDissolveDelay(increase) => ValueBuilder::new()
                .add_field("IncreaseDissolveDelay", increase)
                .build(),
            configure::Operation::StartDissolving(_) => ValueBuilder::new()
                .add_empty_field("StartDissolving")
                .build(),
            configure::Operation::StopDissolving(_) => ValueBuilder::new()
                .add_empty_field("StopDissolving")
                .build(),
            configure::Operation::AddHotKey(add) => {
                ValueBuilder::new().add_field("AddHotKey", add).build()
            }
            configure::Operation::RemoveHotKey(remove) => ValueBuilder::new()
                .add_field("RemoveHotKey", remove)
                .build(),
            configure::Operation::SetDissolveTimestamp(set) => ValueBuilder::new()
                .add_field("SetDissolveTimestamp", set)
                .build(),
            configure::Operation::JoinCommunityFund(_) => ValueBuilder::new()
                .add_empty_field("JoinCommunityFund")
                .build(),
            configure::Operation::LeaveCommunityFund(_) => ValueBuilder::new()
                .add_empty_field("LeaveCommunityFund")
                .build(),
            configure::Operation::ChangeAutoStakeMaturity(change) => ValueBuilder::new()
                .add_field("ChangeAutoStakeMaturity", change)
                .build(),
            configure::Operation::SetVisibility(set) => {
                ValueBuilder::new().add_field("SetVisibility", set).build()
            }
        }
    }
}

impl From<IncreaseDissolveDelay> for SelfDescribingValue {
    fn from(increase: IncreaseDissolveDelay) -> Self {
        ValueBuilder::new()
            .add_field(
                "additional_dissolve_delay_seconds",
                increase.additional_dissolve_delay_seconds,
            )
            .build()
    }
}

impl From<StartDissolving> for SelfDescribingValue {
    fn from(_: StartDissolving) -> Self {
        ValueBuilder::new()
            .add_empty_field("StartDissolving")
            .build()
    }
}

impl From<StopDissolving> for SelfDescribingValue {
    fn from(_: StopDissolving) -> Self {
        ValueBuilder::new()
            .add_empty_field("StopDissolving")
            .build()
    }
}

impl From<AddHotKey> for SelfDescribingValue {
    fn from(add: AddHotKey) -> Self {
        ValueBuilder::new()
            .add_field("new_hot_key", add.new_hot_key)
            .build()
    }
}

impl From<RemoveHotKey> for SelfDescribingValue {
    fn from(remove: RemoveHotKey) -> Self {
        ValueBuilder::new()
            .add_field("hot_key_to_remove", remove.hot_key_to_remove)
            .build()
    }
}

impl From<SetDissolveTimestamp> for SelfDescribingValue {
    fn from(set: SetDissolveTimestamp) -> Self {
        ValueBuilder::new()
            .add_field("dissolve_timestamp_seconds", set.dissolve_timestamp_seconds)
            .build()
    }
}

impl From<JoinCommunityFund> for SelfDescribingValue {
    fn from(_: JoinCommunityFund) -> Self {
        ValueBuilder::new()
            .add_empty_field("JoinCommunityFund")
            .build()
    }
}

impl From<LeaveCommunityFund> for SelfDescribingValue {
    fn from(_: LeaveCommunityFund) -> Self {
        ValueBuilder::new()
            .add_empty_field("LeaveCommunityFund")
            .build()
    }
}

impl From<ChangeAutoStakeMaturity> for SelfDescribingValue {
    fn from(change: ChangeAutoStakeMaturity) -> Self {
        ValueBuilder::new()
            .add_field(
                "requested_setting_for_auto_stake_maturity",
                change.requested_setting_for_auto_stake_maturity,
            )
            .build()
    }
}

impl From<SetVisibility> for SelfDescribingValue {
    fn from(set: SetVisibility) -> Self {
        let visibility = set
            .visibility
            .and_then(|v| Visibility::try_from(v).ok())
            .map(|v| match v {
                Visibility::Unspecified => "Unspecified".to_string(),
                Visibility::Public => "Public".to_string(),
                Visibility::Private => "Private".to_string(),
            });
        ValueBuilder::new()
            .add_field("visibility", visibility)
            .build()
    }
}

impl From<Disburse> for SelfDescribingValue {
    fn from(disburse: Disburse) -> Self {
        let to_account = disburse
            .to_account
            .map(|acc| account_identifier_to_hex(&acc));
        ValueBuilder::new()
            .add_field("amount", disburse.amount)
            .add_field("to_account", to_account)
            .build()
    }
}

impl From<disburse::Amount> for SelfDescribingValue {
    fn from(amount: disburse::Amount) -> Self {
        ValueBuilder::new().add_field("e8s", amount.e8s).build()
    }
}

impl From<Split> for SelfDescribingValue {
    fn from(split: Split) -> Self {
        ValueBuilder::new()
            .add_field("amount_e8s", split.amount_e8s)
            .add_field("memo", split.memo)
            .build()
    }
}

impl From<Spawn> for SelfDescribingValue {
    fn from(spawn: Spawn) -> Self {
        ValueBuilder::new()
            .add_field("new_controller", spawn.new_controller)
            .add_field("nonce", spawn.nonce)
            .add_field("percentage_to_spawn", spawn.percentage_to_spawn)
            .build()
    }
}

impl From<MergeMaturity> for SelfDescribingValue {
    fn from(merge: MergeMaturity) -> Self {
        ValueBuilder::new()
            .add_field("percentage_to_merge", merge.percentage_to_merge)
            .build()
    }
}

impl From<StakeMaturity> for SelfDescribingValue {
    fn from(stake: StakeMaturity) -> Self {
        ValueBuilder::new()
            .add_field("percentage_to_stake", stake.percentage_to_stake)
            .build()
    }
}

impl From<DisburseToNeuron> for SelfDescribingValue {
    fn from(disburse: DisburseToNeuron) -> Self {
        ValueBuilder::new()
            .add_field("new_controller", disburse.new_controller)
            .add_field("amount_e8s", disburse.amount_e8s)
            .add_field("dissolve_delay_seconds", disburse.dissolve_delay_seconds)
            .add_field("kyc_verified", disburse.kyc_verified)
            .add_field("nonce", disburse.nonce)
            .build()
    }
}

impl From<Follow> for SelfDescribingValue {
    fn from(follow: Follow) -> Self {
        let topic = Topic::try_from(follow.topic)
            .map(|t| format!("{:?}", t))
            .unwrap_or_else(|_| "Unknown".to_string());
        let followees: Vec<u64> = follow.followees.iter().map(|f| f.id).collect();
        ValueBuilder::new()
            .add_field("topic", topic)
            .add_field("followees", followees)
            .build()
    }
}

impl From<RegisterVote> for SelfDescribingValue {
    fn from(vote: RegisterVote) -> Self {
        use crate::pb::v1::Vote;
        let vote_str = Vote::try_from(vote.vote)
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|_| "Unknown".to_string());
        ValueBuilder::new()
            .add_field("proposal", vote.proposal.map(|p| p.id))
            .add_field("vote", vote_str)
            .build()
    }
}

impl From<ClaimOrRefresh> for SelfDescribingValue {
    fn from(claim: ClaimOrRefresh) -> Self {
        ValueBuilder::new().add_field("by", claim.by).build()
    }
}

impl From<claim_or_refresh::By> for SelfDescribingValue {
    fn from(by: claim_or_refresh::By) -> Self {
        match by {
            claim_or_refresh::By::MemoAndController(memo_and_controller) => ValueBuilder::new()
                .add_field("MemoAndController", memo_and_controller)
                .build(),
            claim_or_refresh::By::Memo(memo) => ValueBuilder::new().add_field("Memo", memo).build(),
            claim_or_refresh::By::NeuronIdOrSubaccount(_) => ValueBuilder::new()
                .add_field("NeuronIdOrSubaccount", "".to_string())
                .build(),
        }
    }
}

impl From<claim_or_refresh::MemoAndController> for SelfDescribingValue {
    fn from(memo_and_controller: claim_or_refresh::MemoAndController) -> Self {
        ValueBuilder::new()
            .add_field("memo", memo_and_controller.memo)
            .add_field("controller", memo_and_controller.controller)
            .build()
    }
}

impl From<Merge> for SelfDescribingValue {
    fn from(merge: Merge) -> Self {
        ValueBuilder::new()
            .add_field("source_neuron_id", merge.source_neuron_id.map(|n| n.id))
            .build()
    }
}

impl From<RefreshVotingPower> for SelfDescribingValue {
    fn from(_: RefreshVotingPower) -> Self {
        ValueBuilder::new()
            .add_empty_field("RefreshVotingPower")
            .build()
    }
}

impl From<DisburseMaturity> for SelfDescribingValue {
    fn from(disburse: DisburseMaturity) -> Self {
        let to_account_identifier = disburse
            .to_account_identifier
            .map(|acc| account_identifier_to_hex(&acc));
        ValueBuilder::new()
            .add_field("percentage_to_disburse", disburse.percentage_to_disburse)
            .add_field("to_account", disburse.to_account)
            .add_field("to_account_identifier", to_account_identifier)
            .build()
    }
}

impl From<SetFollowing> for SelfDescribingValue {
    fn from(set_following: SetFollowing) -> Self {
        ValueBuilder::new()
            .add_field("topic_following", set_following.topic_following)
            .build()
    }
}

impl From<set_following::FolloweesForTopic> for SelfDescribingValue {
    fn from(followees_for_topic: set_following::FolloweesForTopic) -> Self {
        let topic = followees_for_topic
            .topic
            .and_then(|t| Topic::try_from(t).ok())
            .map(|t| format!("{:?}", t));
        let followees: Vec<u64> = followees_for_topic.followees.iter().map(|f| f.id).collect();

        ValueBuilder::new()
            .add_field("topic", topic)
            .add_field("followees", followees)
            .build()
    }
}

impl From<NeuronId> for SelfDescribingValue {
    fn from(neuron_id: NeuronId) -> Self {
        SelfDescribingValue::from(neuron_id.id)
    }
}

impl From<Account> for SelfDescribingValue {
    fn from(account: Account) -> Self {
        ValueBuilder::new()
            .add_field("owner", account.owner)
            .add_field("subaccount", account.subaccount)
            .build()
    }
}

impl From<Subaccount> for SelfDescribingValue {
    fn from(subaccount: Subaccount) -> Self {
        // Subaccount is just a wrapper around Vec<u8>, so we unwrap it
        SelfDescribingValue::from(subaccount.subaccount)
    }
}

#[cfg(test)]
#[path = "manage_neuron_tests.rs"]
mod tests;
