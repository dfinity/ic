use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1 as pb;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
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

/// The following trait helps bound what kind of types can be used as the
/// first generic argument to `CompoundCycles` that represent the various
/// use cases for cycles accounting.
pub trait CyclesUseCaseKind: Copy + Clone + Debug {
    fn cycles_use_case() -> CyclesUseCase;
}

/// Marker trait to identify which use cases of `CyclesUseCase` are refundable,
/// i.e. the ones that are prepaid and expected to be refunded if not fully consumed.
pub trait CyclesUseCaseRefundableKind: CyclesUseCaseKind {}

/*
 * Empty structs are added for each use case to act like tags that can be used
 * to allow the compiler to enforce type-safe operations on `CompoundCycles`
 * but also make it more clear to the reader which use case is handled as it
 * will be part of the type they see.
*/

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Memory;

impl CyclesUseCaseKind for Memory {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::Memory
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct ComputeAllocation;

impl CyclesUseCaseKind for ComputeAllocation {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::ComputeAllocation
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct IngressInduction;

impl CyclesUseCaseKind for IngressInduction {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::IngressInduction
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub struct Instructions;

impl CyclesUseCaseKind for Instructions {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::Instructions
    }
}

impl CyclesUseCaseRefundableKind for Instructions {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub struct RequestAndResponseTransmission;

impl CyclesUseCaseKind for RequestAndResponseTransmission {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::RequestAndResponseTransmission
    }
}

impl CyclesUseCaseRefundableKind for RequestAndResponseTransmission {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Uninstall;

impl CyclesUseCaseKind for Uninstall {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::Uninstall
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct CanisterCreation;

impl CyclesUseCaseKind for CanisterCreation {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::CanisterCreation
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct ECDSAOutcalls;

impl CyclesUseCaseKind for ECDSAOutcalls {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::ECDSAOutcalls
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct HTTPOutcalls;

impl CyclesUseCaseKind for HTTPOutcalls {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::HTTPOutcalls
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DeletedCanisters;

impl CyclesUseCaseKind for DeletedCanisters {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::DeletedCanisters
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct NonConsumed;

impl CyclesUseCaseKind for NonConsumed {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::NonConsumed
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct BurnedCycles;

impl CyclesUseCaseKind for BurnedCycles {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::BurnedCycles
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct SchnorrOutcalls;

impl CyclesUseCaseKind for SchnorrOutcalls {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::SchnorrOutcalls
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct VetKd;

impl CyclesUseCaseKind for VetKd {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::VetKd
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct DroppedMessages;

impl CyclesUseCaseKind for DroppedMessages {
    fn cycles_use_case() -> CyclesUseCase {
        CyclesUseCase::DroppedMessages
    }
}
