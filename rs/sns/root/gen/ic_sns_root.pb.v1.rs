/// All essential state of an SNS root canister.
///
/// When canister_init is called in the SNS root canister, it is expected that a
/// serialized version of this was passed via ic_ic00_types::InstallCodeArgs::args,
/// which can be retrieved by the canister via dfn_core::api::arg_data().
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsRootCanister {
    /// Required.
    ///
    /// The SNS root canister is supposed to be able to control this canister.  The
    /// governance canister sends the SNS root canister change_governance_canister
    /// update method calls (and possibly other things).
    #[prost(message, optional, tag="1")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The SNS Ledger canister ID
    #[prost(message, optional, tag="2")]
    pub ledger_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
