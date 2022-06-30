/// This struct contains all the parameters necessary to initialize an SNS. All fields are optional
/// to avoid future candid compatibility problems. However, for the struct to be "valid", all fields
/// must be populated.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsInitPayload {
    /// Fee of a transaction.
    #[prost(uint64, optional, tag="1")]
    pub transaction_fee_e8s: ::core::option::Option<u64>,
    /// The name of the token issued by an SNS Ledger.
    /// This field has no default, a value must be provided by the user.
    /// Must be a string length between {} and {} characters
    ///
    /// Example: Bitcoin
    #[prost(string, optional, tag="2")]
    pub token_name: ::core::option::Option<::prost::alloc::string::String>,
    /// The symbol of the token issued by an SNS Ledger. This field has no
    /// default, a value must be provided by the user. Must be a string length
    /// between 3 and 10 characters
    #[prost(string, optional, tag="3")]
    pub token_symbol: ::core::option::Option<::prost::alloc::string::String>,
    /// Cost of making a proposal that doesnt pass.
    #[prost(uint64, optional, tag="4")]
    pub proposal_reject_cost_e8s: ::core::option::Option<u64>,
    /// The minimum amount a neuron needs to have staked.
    #[prost(uint64, optional, tag="5")]
    pub neuron_minimum_stake_e8s: ::core::option::Option<u64>,
    /// This field sets the initial token distribution between Treasury, Developers and Swap.
    /// This field has no default, a value must be provided by the user.
    ///
    /// -Treasury is of type "TokenDistribution", it has two fields:
    ///    - total_e8: The total amount of tokens in the Treasury bucket.
    ///    - token_distributions: A map between PrincipalId and amount, it specifies the amount and
    ///    recipients of Airdrops.
    ///
    /// -Developers is also of type "TokenDistribution", with two fields:
    ///    - total_e8: The total amount of tokens in the Developers bucket.
    ///    - token_distributions: A map between PrincipalId and amount, a neuron will be created for
    ///    each PrincipalId with the given amount
    ///
    /// -Swap is of type u64 and specifies the amount of token that will be up for sale.
    ///
    /// Example (Prost):
    /// InitialTokenDistribution {
    ///     developers: TokenDistribution {
    ///         total_e8s: 30_00000000,
    ///         distributions: hashmap! {
    ///             "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe" => 10_00000000,
    ///             "x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae" => 15_00000000,
    ///         },
    ///     }
    ///     treasury: TokenDistribution {
    ///         total_e8s: 50_00000000,
    ///         distributions: hashmap! {
    ///             "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe" => 5_00000000,
    ///         },
    ///     },
    ///     swap: 60_00000000,
    /// }
    #[prost(message, optional, tag="6")]
    pub initial_token_distribution: ::core::option::Option<InitialTokenDistribution>,
    /// Amount targeted by the swap, if the amount is reached the swap is triggered. Must be at least
    /// min_participants * min_participant_icp_e8.
    #[prost(uint64, optional, tag="7")]
    pub max_icp_e8s: ::core::option::Option<u64>,
    /// Minimum number of participants for the swap to take place. Must be greater than zero.
    #[prost(uint32, optional, tag="9")]
    pub min_participants: ::core::option::Option<u32>,
    /// The minimum amount of icp that each buyer must contribute to participate.
    #[prost(uint64, optional, tag="10")]
    pub min_participant_icp_e8s: ::core::option::Option<u64>,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, optional, tag="11")]
    pub max_participant_icp_e8s: ::core::option::Option<u64>,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag="12")]
    pub min_icp_e8s: ::core::option::Option<u64>,
    /// If the swap fails, control of the dapp canister(s) will be set to these
    /// principal IDs. In most use-cases, this would be the same as the original
    /// set of controller(s). Must not be empty.
    #[prost(string, repeated, tag="13")]
    pub fallback_controller_principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// An `InitialTokenDistribution` structures the configuration of the SNS Ledger and SNS
/// Governance at genesis. Developers can allocate tokens to the different buckets needed
/// for a decentralization swap.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialTokenDistribution {
    /// The developer bucket distributes tokens to the original developers of the dapp.
    /// Each distribution will create a neuron in `PreInitializationSwap` mode controlled
    /// by the PrincipalId and with the provided stake. The tokens will be distributed
    /// to the neuron's subaccount in the SNS Ledger, and the amount will be funded by
    /// this bucket. The ratio between the bucket's `TokenDistribution::total_e8s` and
    /// the sum of each distribution's stake determines how many tokens are swapped in
    /// the first decentralization swap. This ratio will also determine how many
    /// neurons will be created for the developers in future swaps. Any undistributed
    /// tokens between swaps will remain in a subaccount of Governance until used to
    /// fund the developer neurons in the future.
    #[prost(message, optional, tag="1")]
    pub developers: ::core::option::Option<TokenDistribution>,
    /// The treasury bucket distributes tokens to the SNS's treasury account and creates neurons
    /// for the SNS community for use at genesis. Each distribution will create a one-time neuron
    /// in `PreInitializationSwap` mode controlled by the PrincipalId and with the provided stake.
    /// The tokens used to fund these one-time neurons comes from the treasury's total distribution.
    /// The remaining tokens will be distributed to a subaccount of Governance for use after the
    /// first decentralization swap.
    #[prost(message, optional, tag="2")]
    pub treasury: ::core::option::Option<TokenDistribution>,
    /// The total amount of tokens denominated in e8s (1 token = 100,000,000 e8s) used to fund
    /// the Swap Canister for the decentralization swap. These tokens will be distributed to the
    /// Swap Canister's main account on the SNS Ledger at genesis. The amount of these tokens
    /// used in each swap is determined by the ratio configured by the developers
    /// `TokenDistribution`. Any unused tokens will be distributed to a subaccount of Governance
    /// for use in future swaps. For example if the developers want 25% of their neurons issued for
    /// each during swap, only 25% of the swap bucket's total amount will be swapped
    /// via the Swap Canister. The rest will be in a protected subaccount of Governance for
    /// future swaps.
    #[prost(uint64, tag="3")]
    pub swap: u64,
}
/// A `TokenDistribution` couples a bucket's total distribution, and distributions
/// of neurons created at genesis from that bucket's total distribution.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenDistribution {
    /// The total number of tokens denominated in e8s (1 token = 100,000,000 e8s)
    /// for a bucket at genesis. The stake of neurons created from this bucket
    /// will be pulled from `total_e8s`.
    #[prost(uint64, tag="1")]
    pub total_e8s: u64,
    /// A map of string `PrincipalId` to tokens denominated in e8s (1 token = 100,000,000 e8s)
    /// that represent Neurons and their stakes available at genesis. These neurons
    /// will have reduced functionality until the decentralization swap has completed.
    /// The ledger accounts containing the stake will be funded from `total_e8s`.
    #[prost(map="string, uint64", tag="2")]
    pub distributions: ::std::collections::HashMap<::prost::alloc::string::String, u64>,
}
