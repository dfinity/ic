use crate::types::Environment;
use candid::{Decode, Encode};
use ic_base_types::CanisterId;

/// Returns all SNS canisters known by the Root canister.
pub async fn get_all_sns_canisters(
    env: &dyn Environment,
    root_canister_id: CanisterId,
) -> ListSnsCanistersResponse {
    let arg = Encode!(&ListSnsCanistersRequest {}).unwrap();

    let response = env
        .call_canister(root_canister_id, "list_sns_canisters", arg)
        .await
        .expect("Did not get a valid response from root canister for list_sns_canisters request");

    return Decode!(&response, ListSnsCanistersResponse).expect("Could not decode response");
}

// TODO(NNS1-1590) Remove these and split the protos into their own crates
/// Duplicated from ic-sns-root to avoid circular dependency as a temporary workaround
/// See ic_sns_root::pb::v1::ListSnsCanistersRequest
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct ListSnsCanistersRequest {}

/// Duplicated from ic-sns-root to avoid circular dependency as a temporary workaround
/// See ic_sns_root::pb::v1::ListSnsCanistersRequest
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq, ::prost::Message)]
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
