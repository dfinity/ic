/// All essential state of an SNS root canister.
///
/// When canister_init is called in the SNS root canister, it is expected that a
/// serialized version of this was passed via ic_management_canister_types::InstallCodeArgs::args,
/// which can be retrieved by the canister via ic_cdk::api::call::arg_data().
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsRootCanister {
    /// Required.
    ///
    /// The SNS root canister is supposed to be able to control this canister.  The
    /// governance canister sends the SNS root canister change_governance_canister
    /// update method calls (and possibly other things).
    #[prost(message, optional, tag = "1")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Required.
    ///
    /// The SNS Ledger canister ID
    #[prost(message, optional, tag = "2")]
    pub ledger_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Dapp canister IDs.
    #[prost(message, repeated, tag = "3")]
    pub dapp_canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    /// Required.
    ///
    /// The swap canister ID.
    #[prost(message, optional, tag = "4")]
    pub swap_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// CanisterIds of the archives of the SNS Ledger blocks.
    #[prost(message, repeated, tag = "5")]
    pub archive_canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    /// The timestamp of the latest poll for archives of the ledger canister,
    /// in seconds since the Unix epoch.
    #[prost(uint64, optional, tag = "6")]
    pub latest_ledger_archive_poll_timestamp_seconds: ::core::option::Option<u64>,
    /// Required.
    ///
    /// The SNS Index canister ID
    #[prost(message, optional, tag = "7")]
    pub index_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// True if the SNS is running in testflight mode. Then additional
    /// controllers beyond SNS root are allowed when registering a dapp.
    #[prost(bool, tag = "8")]
    pub testflight: bool,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterResponse {}
/// This message has an identical message defined in governace.proto, both need to be changed together
/// TODO(NNS1-1589)
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanistersRequest {
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanistersResponse {}
/// Change control of the listed canisters to the listed principal id.
/// Same proto in governance.proto. TODO(NNS1-1589)
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_ids: ::core::option::Option<set_dapp_controllers_request::CanisterIds>,
    #[prost(message, repeated, tag = "2")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// Nested message and enum types in `SetDappControllersRequest`.
pub mod set_dapp_controllers_request {
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterIds {
        #[prost(message, repeated, tag = "1")]
        pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    }
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag = "1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FailedUpdate {
        #[prost(message, optional, tag = "1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag = "2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag = "1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
}
/// Request struct for the ListSnsCanisters API on the
/// SNS Root canister. ListSnsCanisters will return Principals
/// of all the associated canisters in an SNS.
///
/// This struct intentionally left blank (for now).
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSnsCanistersRequest {}
/// Response struct for the ListSnsCanisters API on the
/// SNS Root canister. ListSnsCanisters will return Principals
/// of all the associated canisters in an SNS.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSnsCanistersResponse {
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "2")]
    pub governance: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "3")]
    pub ledger: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "4")]
    pub swap: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag = "5")]
    pub dapps: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, repeated, tag = "6")]
    pub archives: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "7")]
    pub index: ::core::option::Option<::ic_base_types::PrincipalId>,
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
