/// Information about an NNS canister.
///
/// Corresponding mutations are handled by the `root` handler:
/// See /rs/nns/handlers/root/impl
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NnsCanisterRecord {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
}
/// All of the post-genesis NNS canisters.
///
/// There is a number of NNS canisters that exist at genesis. Those are not installed through
/// proposals, and are not reflected in the registry. After genesis, new NNS canisters can only
/// be added through proposals (see AddNnsCanisterProposalPayload in particular). NNS canisters
/// added post-genesis are registered in this record.
#[derive(serde::Deserialize, serde::Serialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NnsCanisterRecords {
    /// Mapping name (arbitrary string) -> canister id.
    #[prost(btree_map = "string, message", tag = "1")]
    pub canisters:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NnsCanisterRecord>,
}
