/// All essential state of an SNS root canister.
///
/// When canister_init is called in the SNS root canister, it is expected that a
/// serialized version of this was passed via ic_ic00_types::InstallCodeArgs::args,
/// which can be retrieved by the canister via dfn_core::api::arg_data().
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
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
}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterResponse {}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersRequest {
    #[prost(message, repeated, tag = "1")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag = "1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(candid::CandidType, candid::Deserialize)]
    #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FailedUpdate {
        #[prost(message, optional, tag = "1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag = "2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
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
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSnsCanistersRequest {}
/// Response struct for the ListSnsCanisters API on the
/// SNS Root canister. ListSnsCanisters will return Principals
/// of all the associated canisters in an SNS.
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
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
}
