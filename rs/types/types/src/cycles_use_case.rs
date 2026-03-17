use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1 as pb;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Enumerates use cases of consumed cycles.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, EnumIter, Serialize)]
pub enum CyclesUseCase {
    Memory = 1,
    ComputeAllocation = 2,
    IngressInduction = 3,
    Instructions = 4,
    RequestAndResponseTransmission = 5,
    Uninstall = 6,
    CanisterCreation = 7,
    ECDSAOutcalls = 8,
    HTTPOutcalls = 9,
    DeletedCanisters = 10,
    NonConsumed = 11,
    BurnedCycles = 12,
    SchnorrOutcalls = 13,
    VetKd = 14,
    DroppedMessages = 15,
}

impl CyclesUseCase {
    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "Memory",
            Self::ComputeAllocation => "ComputeAllocation",
            Self::IngressInduction => "IngressInduction",
            Self::Instructions => "Instructions",
            Self::RequestAndResponseTransmission => "RequestAndResponseTransmission",
            Self::Uninstall => "Uninstall",
            Self::CanisterCreation => "CanisterCreation",
            Self::ECDSAOutcalls => "ECDSAOutcalls",
            Self::HTTPOutcalls => "HTTPOutcalls",
            Self::DeletedCanisters => "DeletedCanisters",
            Self::NonConsumed => "NonConsumed",
            Self::BurnedCycles => "BurnedCycles",
            Self::SchnorrOutcalls => "SchnorrOutcalls",
            Self::VetKd => "VetKd",
            Self::DroppedMessages => "DroppedMessages",
        }
    }
}

impl From<CyclesUseCase> for pb::CyclesUseCase {
    fn from(item: CyclesUseCase) -> Self {
        match item {
            CyclesUseCase::Memory => pb::CyclesUseCase::Memory,
            CyclesUseCase::ComputeAllocation => pb::CyclesUseCase::ComputeAllocation,
            CyclesUseCase::IngressInduction => pb::CyclesUseCase::IngressInduction,
            CyclesUseCase::Instructions => pb::CyclesUseCase::Instructions,
            CyclesUseCase::RequestAndResponseTransmission => {
                pb::CyclesUseCase::RequestAndResponseTransmission
            }
            CyclesUseCase::Uninstall => pb::CyclesUseCase::Uninstall,
            CyclesUseCase::CanisterCreation => pb::CyclesUseCase::CanisterCreation,
            CyclesUseCase::ECDSAOutcalls => pb::CyclesUseCase::EcdsaOutcalls,
            CyclesUseCase::HTTPOutcalls => pb::CyclesUseCase::HttpOutcalls,
            CyclesUseCase::DeletedCanisters => pb::CyclesUseCase::DeletedCanisters,
            CyclesUseCase::NonConsumed => pb::CyclesUseCase::NonConsumed,
            CyclesUseCase::BurnedCycles => pb::CyclesUseCase::BurnedCycles,
            CyclesUseCase::SchnorrOutcalls => pb::CyclesUseCase::SchnorrOutcalls,
            CyclesUseCase::VetKd => pb::CyclesUseCase::VetKd,
            CyclesUseCase::DroppedMessages => pb::CyclesUseCase::DroppedMessages,
        }
    }
}

impl TryFrom<pb::CyclesUseCase> for CyclesUseCase {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::CyclesUseCase) -> Result<Self, Self::Error> {
        match item {
            pb::CyclesUseCase::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "CyclesUseCase",
                err: format!("Unexpected value of cycles use case: {item:?}"),
            }),

            pb::CyclesUseCase::Memory => Ok(Self::Memory),
            pb::CyclesUseCase::ComputeAllocation => Ok(Self::ComputeAllocation),
            pb::CyclesUseCase::IngressInduction => Ok(Self::IngressInduction),
            pb::CyclesUseCase::Instructions => Ok(Self::Instructions),
            pb::CyclesUseCase::RequestAndResponseTransmission => {
                Ok(Self::RequestAndResponseTransmission)
            }
            pb::CyclesUseCase::Uninstall => Ok(Self::Uninstall),
            pb::CyclesUseCase::CanisterCreation => Ok(Self::CanisterCreation),
            pb::CyclesUseCase::EcdsaOutcalls => Ok(Self::ECDSAOutcalls),
            pb::CyclesUseCase::HttpOutcalls => Ok(Self::HTTPOutcalls),
            pb::CyclesUseCase::DeletedCanisters => Ok(Self::DeletedCanisters),
            pb::CyclesUseCase::NonConsumed => Ok(Self::NonConsumed),
            pb::CyclesUseCase::BurnedCycles => Ok(Self::BurnedCycles),
            pb::CyclesUseCase::SchnorrOutcalls => Ok(Self::SchnorrOutcalls),
            pb::CyclesUseCase::VetKd => Ok(Self::VetKd),
            pb::CyclesUseCase::DroppedMessages => Ok(Self::DroppedMessages),
        }
    }
}
