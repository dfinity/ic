/// A container for a NeuronId blob, which uniquely identifies
/// a Neuron.
#[derive(serde::Serialize, candid::CandidType, candid::Deserialize, comparable::Comparable, Eq)]
#[self_describing]
#[derive(PartialOrd, Ord, Copy, std::hash::Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(uint64, tag = "2")]
    pub id: u64,
}
/// The id of a specific proposal.
#[derive(serde::Serialize, candid::CandidType, candid::Deserialize, comparable::Comparable, Eq)]
#[self_describing]
#[derive(Copy)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalId {
    #[prost(uint64, tag = "1")]
    pub id: u64,
}
