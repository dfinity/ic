/// A container for a NeuronId blob, which uniquely identifies
/// a Neuron.
#[derive(Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize)]
#[self_describing]
#[derive(Copy, Ord, PartialOrd, std::hash::Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(uint64, tag = "2")]
    pub id: u64,
}
/// The id of a specific proposal.
#[derive(Eq, candid::CandidType, candid::Deserialize, comparable::Comparable, serde::Serialize)]
#[self_describing]
#[derive(Copy)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalId {
    #[prost(uint64, tag = "1")]
    pub id: u64,
}
