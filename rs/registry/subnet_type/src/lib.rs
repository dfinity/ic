use candid::CandidType;
use ic_protobuf::{proxy::ProxyDecodeError, registry::subnet::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use strum_macros::{EnumIter, EnumString};

/// Defines the different types of subnets that can exist on the IC.
#[derive(
    CandidType, Clone, Copy, Deserialize, Debug, Eq, EnumIter, EnumString, PartialEq, Serialize,
)]
pub enum SubnetType {
    /// The application subnet type where most of the normal applications will
    /// be hosted.
    #[strum(serialize = "application")]
    #[serde(rename = "application")]
    Application,
    /// System subnet type is allowed special privileges. The NNS subnet is of
    /// this type.
    #[strum(serialize = "system")]
    #[serde(rename = "system")]
    System,
    /// Similar to application subnet type. The main differences are that the
    /// prices are lower, and only whitelisted principals can use them.
    #[strum(serialize = "verified_application")]
    #[serde(rename = "verified_application")]
    VerifiedApplication,
}

impl Default for SubnetType {
    fn default() -> Self {
        SubnetType::Application
    }
}

impl From<SubnetType> for i32 {
    fn from(subnet_type: SubnetType) -> i32 {
        match subnet_type {
            SubnetType::Application => 1,
            SubnetType::System => 2,
            SubnetType::VerifiedApplication => 4,
        }
    }
}

impl TryFrom<i32> for SubnetType {
    type Error = ProxyDecodeError;

    fn try_from(input: i32) -> Result<Self, Self::Error> {
        if input == 1 {
            Ok(SubnetType::Application)
        } else if input == 2 {
            Ok(SubnetType::System)
        } else if input == 4 {
            Ok(SubnetType::VerifiedApplication)
        } else {
            Err(ProxyDecodeError::ValueOutOfRange {
                typ: "SubnetType",
                err: format!(
                    "Expected 1 (application), 2 (system), or 4 (VerifiedApplication), got {}",
                    input
                ),
            })
        }
    }
}

impl From<SubnetType> for pb::SubnetType {
    fn from(subnet_type: SubnetType) -> Self {
        match subnet_type {
            SubnetType::Application => Self::Application,
            SubnetType::System => Self::System,
            SubnetType::VerifiedApplication => Self::VerifiedApplication,
        }
    }
}

impl TryFrom<pb::SubnetType> for SubnetType {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::SubnetType) -> Result<Self, Self::Error> {
        match src {
            pb::SubnetType::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "SubnetType",
                err: format!(
                    "{:?} is not one of the expected variants of SubnetType.",
                    src,
                ),
            }),
            pb::SubnetType::Application => Ok(SubnetType::Application),
            pb::SubnetType::System => Ok(SubnetType::System),
            pb::SubnetType::VerifiedApplication => Ok(SubnetType::VerifiedApplication),
        }
    }
}
