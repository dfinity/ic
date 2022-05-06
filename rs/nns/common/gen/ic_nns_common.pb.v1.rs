/// A PB container for a CanisterId, which uniquely identifies
/// a principal.
#[derive(candid::CandidType, candid::Deserialize, Eq)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(bytes="vec", tag="1")]
    pub serialized_id: ::prost::alloc::vec::Vec<u8>,
}
/// A container for a NeuronId blob, which uniquely identifies
/// a Neuron.
#[derive(candid::CandidType, candid::Deserialize, Eq, std::hash::Hash)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(uint64, tag="2")]
    pub id: u64,
}
/// The id of a specific proposal.
#[derive(candid::CandidType, candid::Deserialize, Eq, Copy)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalId {
    #[prost(uint64, tag="1")]
    pub id: u64,
}
/// A descriptor of the authorization of a single method.
/// Any of the principals in the list are authorized to execute
/// the method.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MethodAuthzInfo {
    #[prost(string, tag="1")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(bytes="vec", repeated, tag="2")]
    pub principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// A descriptor of the authorization of all the update methods in a
/// canister that require authorization.
/// Methods that should be accessible to anyone should not appear in this list
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterAuthzInfo {
    #[prost(message, repeated, tag="1")]
    pub methods_authz: ::prost::alloc::vec::Vec<MethodAuthzInfo>,
}
