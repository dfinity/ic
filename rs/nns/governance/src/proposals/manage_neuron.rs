use crate::{
    pb::v1::{
        Empty, ManageNeuron, SelfDescribingValue, Topic, Visibility, Vote,
        manage_neuron::{
            ClaimOrRefresh, Command, Configure, Disburse, Follow, JoinCommunityFund,
            LeaveCommunityFund, NeuronIdOrSubaccount, RefreshVotingPower, RegisterVote,
            SetFollowing, SetVisibility, StartDissolving, StopDissolving,
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
    const TYPE_DESCRIPTION: &'static str = "Call a major function on a specified target neuron. \
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
        balance.";

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
                builder.add_field("neuron_id_or_subaccount", SelfDescribingValue::NULL)
            }
        };

        builder.add_field("command", self.command.clone()).build()
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
                Self::singleton_map("MergeMaturity", Self::NULL)
            }
            C::MakeProposal(_) => {
                println!(
                    "A ManageNeuron proposal is created with a MakeProposal command. This should never happen."
                );
                Self::singleton_map("MakeProposal", Self::NULL)
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
            return Self::NULL;
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

impl From<StartDissolving> for SelfDescribingValue {
    fn from(value: StartDissolving) -> Self {
        let StartDissolving {} = value;
        SelfDescribingValue::NULL
    }
}

impl From<StopDissolving> for SelfDescribingValue {
    fn from(value: StopDissolving) -> Self {
        let StopDissolving {} = value;
        SelfDescribingValue::NULL
    }
}

impl From<JoinCommunityFund> for SelfDescribingValue {
    fn from(value: JoinCommunityFund) -> Self {
        let JoinCommunityFund {} = value;
        SelfDescribingValue::NULL
    }
}

impl From<LeaveCommunityFund> for SelfDescribingValue {
    fn from(value: LeaveCommunityFund) -> Self {
        let LeaveCommunityFund {} = value;
        SelfDescribingValue::NULL
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
            return Self::NULL;
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

impl From<RefreshVotingPower> for SelfDescribingValue {
    fn from(value: RefreshVotingPower) -> Self {
        let RefreshVotingPower {} = value;
        SelfDescribingValue::NULL
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
