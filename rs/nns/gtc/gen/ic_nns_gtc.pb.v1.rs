/// The internal state of the Genesis Token Canister
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gtc {
    /// Maps account addresses to the state of the account
    #[prost(map="string, message", tag="1")]
    pub accounts: ::std::collections::HashMap<::prost::alloc::string::String, AccountState>,
    /// The total amount of ICP allocated by the GTC
    #[prost(uint32, tag="2")]
    pub total_alloc: u32,
    /// The timestamp, in seconds since the unix epoch, at which `canister_init` was run for
    /// the GTC, considered the genesis of the IC.
    #[prost(uint64, tag="3")]
    pub genesis_timestamp_seconds: u64,
    /// The ID of the Neuron that GTC account owners will have their funds donated
    /// to when they call the GTC's `donate_account` method.
    #[prost(message, optional, tag="4")]
    pub donate_account_recipient_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    //// The ID of the Neuron that the funds of all unclaimed GTC accounts will be
    //// transferred to when the `forward_whitelisted_unclaimed_accounts` GTC method is called.
    #[prost(message, optional, tag="5")]
    pub forward_whitelisted_unclaimed_accounts_recipient_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// The accounts that are whitelisted to be forwarded, once forwarding is available.
    #[prost(string, repeated, tag="6")]
    pub whitelisted_accounts_to_forward: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// The state of a GTC account
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountState {
    /// The neuron IDs of the neurons that exist in the Governance canister that
    /// were created on behalf of this account. These neurons, which initially
    /// have the GTC as the controller, can be claimed by the owner of this
    /// account, after which ownership of these neurons will be transferred from
    /// the GTC to the owner of this account.
    #[prost(message, repeated, tag="1")]
    pub neuron_ids: ::prost::alloc::vec::Vec<::ic_nns_common::pb::v1::NeuronId>,
    /// The account value, in ICPTs. The sum of the stake of all neurons
    /// corresponding to `neuron_ids` must add up to `icpts`.
    #[prost(uint32, tag="2")]
    pub icpts: u32,
    /// If `true`, the neurons in `neuron_ids` have been claimed by this account
    /// owner.
    #[prost(bool, tag="3")]
    pub has_claimed: bool,
    /// If `true`, the neurons in `neuron_ids` have been donated.
    #[prost(bool, tag="6")]
    pub has_donated: bool,
    /// If `true`, the neurons in `neuron_ids` have been forwarded.
    #[prost(bool, tag="7")]
    pub has_forwarded: bool,
    /// The `PrincipalId` that has been authenticated as the owner of this
    /// account.
    ///
    /// Both GTC methods `claim_neurons` and `donate_account` authenticate that
    /// the caller is the owner of this account, and either method may set this
    /// value.
    #[prost(message, optional, tag="8")]
    pub authenticated_principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The neurons that have been successfully transferred
    #[prost(message, repeated, tag="9")]
    pub successfully_transferred_neurons: ::prost::alloc::vec::Vec<TransferredNeuron>,
    /// The neurons that failed to be transferred
    #[prost(message, repeated, tag="10")]
    pub failed_transferred_neurons: ::prost::alloc::vec::Vec<TransferredNeuron>,
    /// The account is whitelisted for forwarding.
    #[prost(bool, tag="11")]
    pub is_whitelisted_for_forwarding: bool,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferredNeuron {
    /// The ID of the transferred neuron
    #[prost(message, optional, tag="1")]
    pub neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// The UNIX timestamp (in seconds) at which the neuron was transferred
    #[prost(uint64, tag="2")]
    pub timestamp_seconds: u64,
    /// The failure encountered when transferring the neuron, if any
    #[prost(message, optional, tag="3")]
    pub error: ::core::option::Option<::prost::alloc::string::String>,
}
