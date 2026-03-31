use ic_protobuf::registry::subnet::v1 as proto;
use serde::{Deserialize, Serialize};

/// How to charge canisters for their use of computational resources (such as
/// executing instructions, storing data, network, etc.)
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanisterCyclesCostSchedule {
    #[default]
    Normal,
    Free,
}

impl From<proto::CanisterCyclesCostSchedule> for CanisterCyclesCostSchedule {
    fn from(value: proto::CanisterCyclesCostSchedule) -> Self {
        match value {
            proto::CanisterCyclesCostSchedule::Unspecified => CanisterCyclesCostSchedule::Normal,
            proto::CanisterCyclesCostSchedule::Normal => CanisterCyclesCostSchedule::Normal,
            proto::CanisterCyclesCostSchedule::Free => CanisterCyclesCostSchedule::Free,
        }
    }
}

impl From<CanisterCyclesCostSchedule> for proto::CanisterCyclesCostSchedule {
    fn from(value: CanisterCyclesCostSchedule) -> Self {
        match value {
            CanisterCyclesCostSchedule::Normal => proto::CanisterCyclesCostSchedule::Normal,
            CanisterCyclesCostSchedule::Free => proto::CanisterCyclesCostSchedule::Free,
        }
    }
}
