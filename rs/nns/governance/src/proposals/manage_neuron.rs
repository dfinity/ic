use crate::{
    pb::v1::{
        Empty, ManageNeuron, SelfDescribingValue, Topic, Visibility, Vote,
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

impl LocallyDescribableProposalAction for ManageNeuron {
    const TYPE_NAME: &'static str = "Manage Neuron";
    const TYPE_DESCRIPTION: &'static str = "Manages a neuron by executing a command such as \
        configuring its settings, disbursing its stake, spawning a new neuron, following other \
        neurons, registering a vote, or performing other neuron management operations.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        let builder = ValueBuilder::new();

        // Flatten all the id/neuron_id_or_subaccount cases into a single field (either "neuron_id" or "subaccount")
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
        let builder = match neuron_id_or_subaccount {
            Some(NeuronIdOrSubaccount::NeuronId(neuron_id)) => {
                builder.add_field("neuron_id", neuron_id)
            }
            Some(NeuronIdOrSubaccount::Subaccount(subaccount)) => {
                builder.add_field("subaccount", subaccount)
            }
            None => {
                println!(
                    "A ManageNeuron proposal is created with an empty or conflicting \
                    values of id and neuron_id_or_subaccount. This should never happen."
                );
                builder.add_empty_field("neuron_id_or_subaccount")
            }
        };

        builder
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
        use Command as C;

        match command {
            // Flatten the `Configure` into the same level as the other commands.
            C::Configure(command) => SelfDescribingValue::from(command),

            C::Disburse(command) => Self::singleton_map("Disburse", command),
            C::Spawn(command) => Self::singleton_map("Spawn", command),
            C::Follow(command) => Self::singleton_map("Follow", command),
            C::RegisterVote(command) => Self::singleton_map("RegisterVote", command),
            C::Split(command) => Self::singleton_map("Split", command),
            C::DisburseToNeuron(command) => Self::singleton_map("DisburseToNeuron", command),
            C::ClaimOrRefresh(command) => Self::singleton_map("ClaimOrRefresh", command),
            C::Merge(command) => Self::singleton_map("Merge", command),
            C::StakeMaturity(command) => Self::singleton_map("StakeMaturity", command),
            C::RefreshVotingPower(command) => Self::singleton_map("RefreshVotingPower", command),
            C::DisburseMaturity(command) => Self::singleton_map("DisburseMaturity", command),
            C::SetFollowing(command) => Self::singleton_map("SetFollowing", command),

            C::MergeMaturity(_) => {
                println!(
                    "A ManageNeuron proposal is created with a MergeMaturity command. This should never happen."
                );
                Self::singleton_map("MergeMaturity", Self::EMPTY)
            }
            C::MakeProposal(_) => {
                println!(
                    "A ManageNeuron proposal is created with a MakeProposal command. This should never happen."
                );
                Self::singleton_map("MakeProposal", Self::EMPTY)
            }
        }
    }
}

impl From<Configure> for SelfDescribingValue {
    fn from(configure: Configure) -> Self {
        let Some(operation) = configure.operation else {
            println!(
                "A ManageNeuron proposal is created with an empty operation. This should never happen."
            );
            return Self::EMPTY;
        };

        use Operation as O;
        let builder = ValueBuilder::new();
        let builder = match operation {
            O::IncreaseDissolveDelay(operation) => {
                builder.add_field("IncreaseDissolveDelay", operation)
            }
            O::StartDissolving(operation) => builder.add_field("StartDissolving", operation),
            O::StopDissolving(operation) => builder.add_field("StopDissolving", operation),
            O::AddHotKey(operation) => builder.add_field("AddHotKey", operation),
            O::RemoveHotKey(operation) => builder.add_field("RemoveHotKey", operation),
            O::SetDissolveTimestamp(operation) => {
                builder.add_field("SetDissolveTimestamp", operation)
            }
            O::JoinCommunityFund(operation) => builder.add_field("JoinCommunityFund", operation),
            O::LeaveCommunityFund(operation) => builder.add_field("LeaveCommunityFund", operation),
            O::ChangeAutoStakeMaturity(operation) => {
                builder.add_field("ChangeAutoStakeMaturity", operation)
            }
            O::SetVisibility(operation) => builder.add_field("SetVisibility", operation),
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
        Self::singleton_map("new_hot_key", new_hot_key)
    }
}

impl From<RemoveHotKey> for SelfDescribingValue {
    fn from(value: RemoveHotKey) -> Self {
        let RemoveHotKey { hot_key_to_remove } = value;
        Self::singleton_map("hot_key_to_remove", hot_key_to_remove)
    }
}

impl From<SetDissolveTimestamp> for SelfDescribingValue {
    fn from(value: SetDissolveTimestamp) -> Self {
        let SetDissolveTimestamp {
            dissolve_timestamp_seconds,
        } = value;
        Self::singleton_map("dissolve_timestamp_seconds", dissolve_timestamp_seconds)
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
        Self::singleton_map(
            "requested_setting_for_auto_stake_maturity",
            requested_setting_for_auto_stake_maturity,
        )
    }
}

impl From<SetVisibility> for SelfDescribingValue {
    fn from(value: SetVisibility) -> Self {
        let SetVisibility { visibility } = value;
        let visibility = visibility.map(SelfDescribingProstEnum::<Visibility>::new);
        Self::singleton_map("visibility", visibility)
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
        Self::singleton_map("percentage_to_stake", percentage_to_stake)
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
                // one on the upper level should be used.
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
        Self::singleton_map("source_neuron_id", source_neuron_id)
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

#[cfg(test)]
#[path = "manage_neuron_tests.rs"]
mod tests;
