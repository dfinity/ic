use crate::pb::v1::manage_neuron::{
    configure::Operation, AddHotKey, ChangeAutoStakeMaturity, IncreaseDissolveDelay,
    JoinCommunityFund, LeaveCommunityFund, RemoveHotKey, SetDissolveTimestamp, SetVisibility,
    StartDissolving, StopDissolving,
};

impl From<IncreaseDissolveDelay> for Operation {
    fn from(src: IncreaseDissolveDelay) -> Operation {
        Operation::IncreaseDissolveDelay(src)
    }
}

impl From<StartDissolving> for Operation {
    fn from(src: StartDissolving) -> Operation {
        Operation::StartDissolving(src)
    }
}

impl From<StopDissolving> for Operation {
    fn from(src: StopDissolving) -> Operation {
        Operation::StopDissolving(src)
    }
}

impl From<AddHotKey> for Operation {
    fn from(src: AddHotKey) -> Operation {
        Operation::AddHotKey(src)
    }
}

impl From<RemoveHotKey> for Operation {
    fn from(src: RemoveHotKey) -> Operation {
        Operation::RemoveHotKey(src)
    }
}

impl From<SetDissolveTimestamp> for Operation {
    fn from(src: SetDissolveTimestamp) -> Operation {
        Operation::SetDissolveTimestamp(src)
    }
}

impl From<JoinCommunityFund> for Operation {
    fn from(src: JoinCommunityFund) -> Operation {
        Operation::JoinCommunityFund(src)
    }
}

impl From<LeaveCommunityFund> for Operation {
    fn from(src: LeaveCommunityFund) -> Operation {
        Operation::LeaveCommunityFund(src)
    }
}

impl From<ChangeAutoStakeMaturity> for Operation {
    fn from(src: ChangeAutoStakeMaturity) -> Operation {
        Operation::ChangeAutoStakeMaturity(src)
    }
}

impl From<SetVisibility> for Operation {
    fn from(src: SetVisibility) -> Operation {
        Operation::SetVisibility(src)
    }
}
