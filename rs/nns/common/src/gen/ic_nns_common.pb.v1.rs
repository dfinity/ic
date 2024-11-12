// This file is @generated by prost-build.
/// A container for a NeuronId blob, which uniquely identifies
/// a Neuron.
#[derive(serde::Serialize, candid::CandidType, candid::Deserialize, comparable::Comparable, Eq)]
#[self_describing]
#[derive(PartialOrd, Ord, std::hash::Hash, Clone, Copy, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(uint64, tag = "2")]
    pub id: u64,
}
/// The id of a specific proposal.
#[derive(serde::Serialize, candid::CandidType, candid::Deserialize, comparable::Comparable, Eq)]
#[self_describing]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct ProposalId {
    #[prost(uint64, tag = "1")]
    pub id: u64,
}