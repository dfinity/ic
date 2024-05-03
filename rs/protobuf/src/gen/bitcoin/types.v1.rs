#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum RejectCode {
    Unspecified = 0,
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}
impl RejectCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RejectCode::Unspecified => "REJECT_CODE_UNSPECIFIED",
            RejectCode::SysFatal => "REJECT_CODE_SYS_FATAL",
            RejectCode::SysTransient => "REJECT_CODE_SYS_TRANSIENT",
            RejectCode::DestinationInvalid => "REJECT_CODE_DESTINATION_INVALID",
            RejectCode::CanisterReject => "REJECT_CODE_CANISTER_REJECT",
            RejectCode::CanisterError => "REJECT_CODE_CANISTER_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "REJECT_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "REJECT_CODE_SYS_FATAL" => Some(Self::SysFatal),
            "REJECT_CODE_SYS_TRANSIENT" => Some(Self::SysTransient),
            "REJECT_CODE_DESTINATION_INVALID" => Some(Self::DestinationInvalid),
            "REJECT_CODE_CANISTER_REJECT" => Some(Self::CanisterReject),
            "REJECT_CODE_CANISTER_ERROR" => Some(Self::CanisterError),
            _ => None,
        }
    }
}
