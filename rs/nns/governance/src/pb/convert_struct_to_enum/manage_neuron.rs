use crate::pb::v1::{
    Proposal,
    manage_neuron::{
        ClaimOrRefresh, Command, Configure, Disburse, DisburseToNeuron, Follow, Merge,
        MergeMaturity, RegisterVote, Spawn, Split, StakeMaturity,
    },
};

mod configure;

/// This is a special snowflake! Instead of converting from MakeProposal, we
/// convert from Proposal. Also, box is used for some reason...
/// (Special snowflakes are evil! Ad hoc bad. Uniform good.)
impl From<Proposal> for Command {
    fn from(src: Proposal) -> Command {
        Command::MakeProposal(Box::new(src))
    }
}

impl From<Configure> for Command {
    fn from(src: Configure) -> Command {
        Command::Configure(src)
    }
}

impl From<Disburse> for Command {
    fn from(src: Disburse) -> Command {
        Command::Disburse(src)
    }
}

impl From<Spawn> for Command {
    fn from(src: Spawn) -> Command {
        Command::Spawn(src)
    }
}

impl From<Follow> for Command {
    fn from(src: Follow) -> Command {
        Command::Follow(src)
    }
}

impl From<RegisterVote> for Command {
    fn from(src: RegisterVote) -> Command {
        Command::RegisterVote(src)
    }
}

impl From<Split> for Command {
    fn from(src: Split) -> Command {
        Command::Split(src)
    }
}

impl From<DisburseToNeuron> for Command {
    fn from(src: DisburseToNeuron) -> Command {
        Command::DisburseToNeuron(src)
    }
}

impl From<ClaimOrRefresh> for Command {
    fn from(src: ClaimOrRefresh) -> Command {
        Command::ClaimOrRefresh(src)
    }
}

impl From<MergeMaturity> for Command {
    fn from(src: MergeMaturity) -> Command {
        Command::MergeMaturity(src)
    }
}

impl From<Merge> for Command {
    fn from(src: Merge) -> Command {
        Command::Merge(src)
    }
}

impl From<StakeMaturity> for Command {
    fn from(src: StakeMaturity) -> Command {
        Command::StakeMaturity(src)
    }
}
