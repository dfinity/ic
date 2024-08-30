// NOTE: This file's types are all from other canisters where a current dependency cycle prevents
// including them directly.
// TODO(NNS1-1589): Remove all these types after dependency cycle is fixed.

#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RegisterDappCanisterRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RegisterDappCanisterResponse {}
/// This message has an identical message defined in governace.proto, both need to be changed together
/// TODO(NNS1-1589)
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RegisterDappCanistersRequest {
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RegisterDappCanistersResponse {}
/// Change control of the listed canisters to the listed principal id.
/// Same proto in governance.proto. TODO(NNS1-1589)
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetDappControllersRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_ids: ::core::option::Option<set_dapp_controllers_request::CanisterIds>,
    #[prost(message, repeated, tag = "2")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// Nested message and enum types in `SetDappControllersRequest`.
pub mod set_dapp_controllers_request {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Message,
    )]
    pub struct CanisterIds {
        #[prost(message, repeated, tag = "1")]
        pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    }
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag = "1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Message,
    )]
    pub struct FailedUpdate {
        #[prost(message, optional, tag = "1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag = "2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag = "1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
}

#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
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
pub enum LogVisibility {
    Unspecified = 0,
    /// The log is visible to the controllers of the dapp canister.
    Controllers = 1,
    /// The log is visible to the public.
    Public = 2,
}
impl LogVisibility {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            LogVisibility::Unspecified => "LOG_VISIBILITY_UNSPECIFIED",
            LogVisibility::Controllers => "LOG_VISIBILITY_CONTROLLERS",
            LogVisibility::Public => "LOG_VISIBILITY_PUBLIC",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "LOG_VISIBILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "LOG_VISIBILITY_CONTROLLERS" => Some(Self::Controllers),
            "LOG_VISIBILITY_PUBLIC" => Some(Self::Public),
            _ => None,
        }
    }
}

#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageDappCanisterSettingsRequest {
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(uint64, optional, tag = "2")]
    pub compute_allocation: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub memory_allocation: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    pub freezing_threshold: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub reserved_cycles_limit: ::core::option::Option<u64>,
    #[prost(enumeration = "LogVisibility", optional, tag = "6")]
    pub log_visibility: ::core::option::Option<i32>,
    #[prost(uint64, optional, tag = "7")]
    pub wasm_memory_limit: ::core::option::Option<u64>,
}

#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageDappCanisterSettingsResponse {
    /// Absense of failure_reason indicates success.
    #[prost(string, optional, tag = "1")]
    pub failure_reason: ::core::option::Option<::prost::alloc::string::String>,
}
