/// Request struct for the method `get_derived_state`
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    comparable::Comparable,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct GetDerivedStateRequest {}
/// Response struct for the method `get_derived_state`
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    comparable::Comparable,
    Clone,
    Copy,
    PartialEq,
    ::prost::Message,
)]
pub struct GetDerivedStateResponse {
    #[prost(uint64, optional, tag = "1")]
    pub buyer_total_icp_e8s: ::core::option::Option<u64>,
    /// Current number of non-Neurons' Fund swap participants
    #[prost(uint64, optional, tag = "3")]
    pub direct_participant_count: ::core::option::Option<u64>,
    /// Current number of Neurons' Fund swap participants. In particular, it's the
    /// number of unique controllers of the neurons participating
    /// in the Neurons' Fund.
    #[prost(uint64, optional, tag = "4")]
    pub cf_participant_count: ::core::option::Option<u64>,
    /// Current number of Neurons' Fund neurons participating in the swap
    /// May be greater than cf_participant_count if multiple neurons in
    /// the Neurons' Fund have the same controller.
    #[prost(uint64, optional, tag = "5")]
    pub cf_neuron_count: ::core::option::Option<u64>,
    #[prost(double, optional, tag = "2")]
    pub sns_tokens_per_icp: ::core::option::Option<f64>,
    /// Current amount of contributions from direct swap participants.
    #[prost(uint64, optional, tag = "6")]
    pub direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// Current amount of contributions from the Neurons' Fund.
    #[prost(uint64, optional, tag = "7")]
    pub neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
}
