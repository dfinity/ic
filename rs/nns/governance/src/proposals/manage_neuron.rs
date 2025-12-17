use crate::{
    pb::v1::{
        Account, Empty, ManageNeuron, SelfDescribingValue, Topic, Visibility, Vote,
        manage_neuron::{
            AddHotKey, ChangeAutoStakeMaturity, ClaimOrRefresh, Command, Configure, Disburse,
            DisburseMaturity, DisburseToNeuron, Follow, IncreaseDissolveDelay, JoinCommunityFund,
            LeaveCommunityFund, Merge, NeuronIdOrSubaccount, RefreshVotingPower, RegisterVote,
            RemoveHotKey, SetDissolveTimestamp, SetFollowing, SetVisibility, Spawn, Split,
            StakeMaturity, StartDissolving, StopDissolving,
            claim_or_refresh::{By as ClaimOrRefreshBy, MemoAndController},
            configure::Operation,
            set_following::FolloweesForTopic,
        },
    },
    proposals::self_describing::{
        LocallyDescribableProposalAction, SelfDescribingProstEnum, ValueBuilder,
    },
};

use ic_cdk::println;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use icp_ledger::protobuf::AccountIdentifier;

impl LocallyDescribableProposalAction for ManageNeuron {
    const TYPE_NAME: &'static str = "Manage Neuron";
    const TYPE_DESCRIPTION: &'static str = "Manages a neuron by executing a command such as \
        configuring its settings, disbursing its stake, spawning a new neuron, following other \
        neurons, registering a vote, or performing other neuron management operations.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        // Convert id/neuron_id_or_subaccount using the helper method used by validation.
        let neuron_id_or_subaccount = match self.get_neuron_id_or_subaccount() {
            Ok(Some(neuron_id_or_subaccount)) => Some(neuron_id_or_subaccount),
            _ => {
                println!(
                    "A ManageNeuron proposal is created with an empty or conflicting \
                    values of id and neuron_id_or_subaccount. This should never happen."
                );
                None
            }
        };

        ValueBuilder::new()
            .add_field_with_empty_as_fallback("neuron_id_or_subaccount", neuron_id_or_subaccount)
            .add_field_with_empty_as_fallback("command", self.command.clone())
            .build()
    }
}

impl From<NeuronIdOrSubaccount> for SelfDescribingValue {
    fn from(id: NeuronIdOrSubaccount) -> Self {
        match id {
            NeuronIdOrSubaccount::NeuronId(neuron_id) => {
                ValueBuilder::new().add_field("NeuronId", neuron_id).build()
            }
            NeuronIdOrSubaccount::Subaccount(subaccount) => ValueBuilder::new()
                .add_field("Subaccount", subaccount)
                .build(),
        }
    }
}

impl From<Command> for SelfDescribingValue {
    fn from(command: Command) -> Self {
        use Command::*;

        let builder = ValueBuilder::new();

        let builder = match command {
            Configure(command) => builder.add_field("Configure", command),
            Disburse(command) => builder.add_field("Disburse", command),
            Spawn(command) => builder.add_field("Spawn", command),
            Follow(command) => builder.add_field("Follow", command),
            RegisterVote(command) => builder.add_field("RegisterVote", command),
            Split(command) => builder.add_field("Split", command),
            DisburseToNeuron(command) => builder.add_field("DisburseToNeuron", command),
            ClaimOrRefresh(command) => builder.add_field("ClaimOrRefresh", command),
            Merge(command) => builder.add_field("Merge", command),
            StakeMaturity(command) => builder.add_field("StakeMaturity", command),
            RefreshVotingPower(command) => builder.add_field("RefreshVotingPower", command),
            DisburseMaturity(command) => builder.add_field("DisburseMaturity", command),
            SetFollowing(command) => builder.add_field("SetFollowing", command),

            MergeMaturity(_) => {
                println!(
                    "MergeMaturity is obsolete and should not be allowed in a ManageNeuron proposal"
                );
                builder.add_empty_field("MergeMaturity")
            }
            MakeProposal(_) => {
                println!("MakeProposal is not allowed in a ManageNeuron proposal");
                builder.add_empty_field("MakeProposal")
            }
        };
        builder.build()
    }
}

impl From<Configure> for SelfDescribingValue {
    fn from(configure: Configure) -> Self {
        use Operation::*;

        let Some(operation) = configure.operation else {
            println!(
                "A ManageNeuron proposal is created with an empty operation. This should never happen."
            );
            return Self::EMPTY;
        };

        let builder = ValueBuilder::new();
        let builder = match operation {
            IncreaseDissolveDelay(operation) => {
                builder.add_field("IncreaseDissolveDelay", operation)
            }
            StartDissolving(operation) => builder.add_field("StartDissolving", operation),
            StopDissolving(operation) => builder.add_field("StopDissolving", operation),
            AddHotKey(operation) => builder.add_field("AddHotKey", operation),
            RemoveHotKey(operation) => builder.add_field("RemoveHotKey", operation),
            SetDissolveTimestamp(operation) => builder.add_field("SetDissolveTimestamp", operation),
            JoinCommunityFund(operation) => builder.add_field("JoinCommunityFund", operation),
            LeaveCommunityFund(operation) => builder.add_field("LeaveCommunityFund", operation),
            ChangeAutoStakeMaturity(operation) => {
                builder.add_field("ChangeAutoStakeMaturity", operation)
            }
            SetVisibility(operation) => builder.add_field("SetVisibility", operation),
        };
        builder.build()
    }
}

impl From<IncreaseDissolveDelay> for SelfDescribingValue {
    fn from(value: IncreaseDissolveDelay) -> Self {
        let IncreaseDissolveDelay {
            additional_dissolve_delay_seconds,
        } = value;
        ValueBuilder::new()
            .add_field(
                "additional_dissolve_delay_seconds",
                additional_dissolve_delay_seconds,
            )
            .build()
    }
}

impl From<StartDissolving> for SelfDescribingValue {
    fn from(value: StartDissolving) -> Self {
        let StartDissolving {} = value;
        SelfDescribingValue::EMPTY
    }
}

impl From<StopDissolving> for SelfDescribingValue {
    fn from(value: StopDissolving) -> Self {
        let StopDissolving {} = value;
        SelfDescribingValue::EMPTY
    }
}

impl From<AddHotKey> for SelfDescribingValue {
    fn from(value: AddHotKey) -> Self {
        let AddHotKey { new_hot_key } = value;
        Self::singleton("new_hot_key", new_hot_key)
    }
}

impl From<RemoveHotKey> for SelfDescribingValue {
    fn from(value: RemoveHotKey) -> Self {
        let RemoveHotKey { hot_key_to_remove } = value;
        Self::singleton("hot_key_to_remove", hot_key_to_remove)
    }
}

impl From<SetDissolveTimestamp> for SelfDescribingValue {
    fn from(value: SetDissolveTimestamp) -> Self {
        let SetDissolveTimestamp {
            dissolve_timestamp_seconds,
        } = value;
        Self::singleton("dissolve_timestamp_seconds", dissolve_timestamp_seconds)
    }
}

impl From<JoinCommunityFund> for SelfDescribingValue {
    fn from(value: JoinCommunityFund) -> Self {
        let JoinCommunityFund {} = value;
        SelfDescribingValue::EMPTY
    }
}

impl From<LeaveCommunityFund> for SelfDescribingValue {
    fn from(value: LeaveCommunityFund) -> Self {
        let LeaveCommunityFund {} = value;
        SelfDescribingValue::EMPTY
    }
}

impl From<ChangeAutoStakeMaturity> for SelfDescribingValue {
    fn from(value: ChangeAutoStakeMaturity) -> Self {
        let ChangeAutoStakeMaturity {
            requested_setting_for_auto_stake_maturity,
        } = value;
        Self::singleton(
            "requested_setting_for_auto_stake_maturity",
            requested_setting_for_auto_stake_maturity,
        )
    }
}

impl From<SetVisibility> for SelfDescribingValue {
    fn from(value: SetVisibility) -> Self {
        let SetVisibility { visibility } = value;
        let visibility = visibility.map(SelfDescribingProstEnum::<Visibility>::new);
        Self::singleton("visibility", visibility)
    }
}

impl From<Disburse> for SelfDescribingValue {
    fn from(value: Disburse) -> Self {
        let Disburse { amount, to_account } = value;
        let amount_e8s = amount.map(|amount| amount.e8s);
        ValueBuilder::new()
            .add_field("amount_e8s", amount_e8s)
            .add_field("to_account", to_account)
            .build()
    }
}

impl From<Split> for SelfDescribingValue {
    fn from(value: Split) -> Self {
        let Split { amount_e8s, memo } = value;
        ValueBuilder::new()
            .add_field("amount_e8s", amount_e8s)
            .add_field("memo", memo)
            .build()
    }
}

impl From<Spawn> for SelfDescribingValue {
    fn from(value: Spawn) -> Self {
        let Spawn {
            new_controller,
            nonce,
            percentage_to_spawn,
        } = value;
        ValueBuilder::new()
            .add_field("new_controller", new_controller)
            .add_field("nonce", nonce)
            .add_field("percentage_to_spawn", percentage_to_spawn)
            .build()
    }
}

impl From<StakeMaturity> for SelfDescribingValue {
    fn from(value: StakeMaturity) -> Self {
        let StakeMaturity {
            percentage_to_stake,
        } = value;
        Self::singleton("percentage_to_stake", percentage_to_stake)
    }
}

impl From<DisburseToNeuron> for SelfDescribingValue {
    fn from(value: DisburseToNeuron) -> Self {
        let DisburseToNeuron {
            new_controller,
            amount_e8s,
            dissolve_delay_seconds,
            kyc_verified,
            nonce,
        } = value;
        ValueBuilder::new()
            .add_field("new_controller", new_controller)
            .add_field("amount_e8s", amount_e8s)
            .add_field("dissolve_delay_seconds", dissolve_delay_seconds)
            .add_field("kyc_verified", kyc_verified)
            .add_field("nonce", nonce)
            .build()
    }
}

impl From<Follow> for SelfDescribingValue {
    fn from(follow: Follow) -> Self {
        let Follow { topic, followees } = follow;

        ValueBuilder::new()
            .add_field("topic", SelfDescribingProstEnum::<Topic>::new(topic))
            .add_field("followees", followees)
            .build()
    }
}

impl From<RegisterVote> for SelfDescribingValue {
    fn from(vote: RegisterVote) -> Self {
        let RegisterVote { proposal, vote } = vote;
        ValueBuilder::new()
            .add_field("proposal", proposal)
            .add_field("vote", SelfDescribingProstEnum::<Vote>::new(vote))
            .build()
    }
}

impl From<ClaimOrRefresh> for SelfDescribingValue {
    fn from(value: ClaimOrRefresh) -> Self {
        let Some(by) = value.by else {
            println!(
                "A ManageNeuron proposal is created with an empty by. This should never happen."
            );
            return Self::EMPTY;
        };

        match by {
            ClaimOrRefreshBy::MemoAndController(memo_and_controller) => {
                let MemoAndController { memo, controller } = memo_and_controller;
                ValueBuilder::new()
                    .add_field("By", "MemoAndController")
                    .add_field("memo", memo)
                    .add_field("controller", controller)
                    .build()
            }
            ClaimOrRefreshBy::Memo(memo) => ValueBuilder::new()
                .add_field("By", "Memo")
                .add_field("memo", memo)
                .build(),
            ClaimOrRefreshBy::NeuronIdOrSubaccount(empty) => {
                // There is no meaningful value to use here. NeuronIdOrSubaccount is already
                // specified in the ManageNeuron proposal, and this enum simply specifies that the
                // one on the upper level should be used. Using destructuring so that if there is a
                // field in the future, we will get a compile error.
                let Empty {} = empty;
                ValueBuilder::new()
                    .add_field("By", "NeuronIdOrSubaccount")
                    .build()
            }
        }
    }
}

impl From<Merge> for SelfDescribingValue {
    fn from(merge: Merge) -> Self {
        let Merge { source_neuron_id } = merge;
        Self::singleton("source_neuron_id", source_neuron_id)
    }
}

impl From<RefreshVotingPower> for SelfDescribingValue {
    fn from(value: RefreshVotingPower) -> Self {
        let RefreshVotingPower {} = value;
        SelfDescribingValue::EMPTY
    }
}

impl From<DisburseMaturity> for SelfDescribingValue {
    fn from(value: DisburseMaturity) -> Self {
        let DisburseMaturity {
            percentage_to_disburse,
            to_account,
            to_account_identifier,
        } = value;
        ValueBuilder::new()
            .add_field("percentage_to_disburse", percentage_to_disburse)
            .add_field("to_account", to_account)
            .add_field("to_account_identifier", to_account_identifier)
            .build()
    }
}

impl From<SetFollowing> for SelfDescribingValue {
    fn from(value: SetFollowing) -> Self {
        let SetFollowing { topic_following } = value;
        Self::from(topic_following)
    }
}

impl From<FolloweesForTopic> for SelfDescribingValue {
    fn from(value: FolloweesForTopic) -> Self {
        let FolloweesForTopic { topic, followees } = value;

        let topic = topic.map(SelfDescribingProstEnum::<Topic>::new);

        ValueBuilder::new()
            .add_field("topic", topic)
            .add_field("followees", followees)
            .build()
    }
}

impl From<NeuronId> for SelfDescribingValue {
    fn from(value: NeuronId) -> Self {
        Self::from(value.id)
    }
}

impl From<ProposalId> for SelfDescribingValue {
    fn from(value: ProposalId) -> Self {
        Self::from(value.id)
    }
}

impl From<AccountIdentifier> for SelfDescribingValue {
    fn from(value: AccountIdentifier) -> Self {
        Self::from(value.hash)
    }
}

impl From<Account> for SelfDescribingValue {
    fn from(account: Account) -> Self {
        let Account { owner, subaccount } = account;
        let subaccount = subaccount.map(|subaccount| subaccount.subaccount);
        ValueBuilder::new()
            .add_field_with_empty_as_fallback("owner", owner)
            .add_field("subaccount", subaccount)
            .build()
    }
}

#[cfg(test)]
#[path = "manage_neuron_tests.rs"]
mod tests;
