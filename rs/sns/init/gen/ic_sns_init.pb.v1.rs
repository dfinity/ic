/// This struct contains all the parameters necessary to initialize an SNS. All fields are optional
/// to avoid future candid compatibility problems. However, for the struct to be "valid", all fields
/// must be populated.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SnsInitPayload {
    /// Fee of a transaction.
    #[prost(uint64, optional, tag = "1")]
    pub transaction_fee_e8s: ::core::option::Option<u64>,
    /// The name of the token issued by an SNS Ledger.
    /// This field has no default, a value must be provided by the user.
    /// Must be a string length between {} and {} characters
    ///
    /// Example: Bitcoin
    #[prost(string, optional, tag = "2")]
    pub token_name: ::core::option::Option<::prost::alloc::string::String>,
    /// The symbol of the token issued by an SNS Ledger. This field has no
    /// default, a value must be provided by the user. Must be a string length
    /// between 3 and 10 characters
    #[prost(string, optional, tag = "3")]
    pub token_symbol: ::core::option::Option<::prost::alloc::string::String>,
    /// Cost of making a proposal that doesnt pass.
    #[prost(uint64, optional, tag = "4")]
    pub proposal_reject_cost_e8s: ::core::option::Option<u64>,
    /// The minimum amount of SNS Token e8s an SNS Ledger account must have to stake a neuron.
    #[prost(uint64, optional, tag = "5")]
    pub neuron_minimum_stake_e8s: ::core::option::Option<u64>,
    /// If the swap fails, control of the dapp canister(s) will be set to these
    /// principal IDs. In most use-cases, this would be the same as the original
    /// set of controller(s). Must not be empty.
    #[prost(string, repeated, tag = "7")]
    pub fallback_controller_principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The logo for the SNS project represented as a base64 encoded string.
    #[prost(string, optional, tag = "8")]
    pub logo: ::core::option::Option<::prost::alloc::string::String>,
    /// Url to the dapp controlled by the SNS project.
    #[prost(string, optional, tag = "9")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    /// Name of the SNS project. This may differ from the name of the associated token.
    #[prost(string, optional, tag = "10")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    /// Description of the SNS project.
    #[prost(string, optional, tag = "11")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    /// The minimum dissolve_delay in seconds a neuron must have to be able to cast votes on proposals.
    #[prost(uint64, optional, tag = "12")]
    pub neuron_minimum_dissolve_delay_to_vote_seconds: ::core::option::Option<u64>,
    /// The initial config file used to set up this SNS.
    #[prost(string, optional, tag = "13")]
    pub sns_initialization_parameters: ::core::option::Option<::prost::alloc::string::String>,
    /// The amount of rewards is proportional to token_supply * current_rate. In
    /// turn, current_rate is somewhere between these two values. In the first
    /// reward period, it is the initial growth rate, and after the growth rate
    /// transition period has elapsed, the growth rate becomes the final growth
    /// rate, and remains at that value for the rest of time. The transition
    /// between the initial and final growth rates is quadratic, and levels out at
    /// the end of the growth rate transition period.
    ///
    /// (A basis point is one in ten thousand.)
    #[prost(uint64, optional, tag = "14")]
    pub initial_reward_rate_basis_points: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "15")]
    pub final_reward_rate_basis_points: ::core::option::Option<u64>,
    /// The amount of time that the growth rate changes (presumably, decreases)
    /// from the initial growth rate to the final growth rate. (See the two
    /// *_reward_rate_basis_points fields bellow.) The transition is quadratic, and
    /// levels out at the end of the growth rate transition period.
    #[prost(uint64, optional, tag = "16")]
    pub reward_rate_transition_duration_seconds: ::core::option::Option<u64>,
    /// The maximum dissolve delay that a neuron can have. That is, the maximum
    /// that a neuron's dissolve delay can be increased to. The maximum is also enforced
    /// when saturating the dissolve delay bonus in the voting power computation.
    #[prost(uint64, optional, tag = "17")]
    pub max_dissolve_delay_seconds: ::core::option::Option<u64>,
    /// The age of a neuron that saturates the age bonus for the voting power computation.
    #[prost(uint64, optional, tag = "18")]
    pub max_neuron_age_seconds_for_age_bonus: ::core::option::Option<u64>,
    /// E.g. if a large dissolve delay can double the voting power of a neuron,
    /// then this field would have a value of 2.0.
    ///
    /// For no bonus, this should be set to 1.
    ///
    /// To achieve functionality equivalent to NNS, this should be set to 2.
    #[prost(uint64, optional, tag = "19")]
    pub max_dissolve_delay_bonus_percentage: ::core::option::Option<u64>,
    /// Analogous to the previous field (see the previous comment),
    /// but this one relates to neuron age instead of dissolve delay.
    ///
    /// To achieve functionality equivalent to NNS, this should be set to 1.25.
    #[prost(uint64, optional, tag = "20")]
    pub max_age_bonus_percentage: ::core::option::Option<u64>,
    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    #[prost(oneof = "sns_init_payload::InitialTokenDistribution", tags = "6")]
    pub initial_token_distribution:
        ::core::option::Option<sns_init_payload::InitialTokenDistribution>,
}
/// Nested message and enum types in `SnsInitPayload`.
pub mod sns_init_payload {
    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Eq,
        Clone,
        PartialEq,
        ::prost::Oneof,
    )]
    pub enum InitialTokenDistribution {
        /// See `FractionalDeveloperVotingPower`
        #[prost(message, tag = "6")]
        FractionalDeveloperVotingPower(super::FractionalDeveloperVotingPower),
    }
}
/// The FractionalDeveloperVotingPower token distribution strategy configures
/// how tokens and neurons are distributed via four "buckets": developers,
/// treasury, swap, and airdrops. This strategy will distribute all developer tokens
/// at genesis in restricted neurons with an additional voting power
/// multiplier applied. This voting power multiplier is calculated as
/// `swap_distribution.initial_swap_amount_e8s / swap_distribution.total_e8s`.
/// As more of the swap funds are swapped in future rounds, the voting power
/// multiplier will approach 1.0. The following preconditions must be met for
/// it to be a valid distribution:
///    - developer_distribution.developer_neurons.stake_e8s.sum <= u64:MAX
///    - developer_neurons.developer_neurons.stake_e8s.sum <= swap_distribution.total_e8s
///    - airdrop_distribution.airdrop_neurons.stake_e8s.sum <= u64:MAX
///    - swap_distribution.initial_swap_amount_e8s > 0
///    - swap_distribution.initial_swap_amount_e8s <= swap_distribution.total_e8s
///    - swap_distribution.total_e8s >= developer_distribution.developer_neurons.stake_e8s.sum
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct FractionalDeveloperVotingPower {
    /// The developer bucket.
    #[prost(message, optional, tag = "1")]
    pub developer_distribution: ::core::option::Option<DeveloperDistribution>,
    /// The treasury bucket.
    #[prost(message, optional, tag = "2")]
    pub treasury_distribution: ::core::option::Option<TreasuryDistribution>,
    /// The swap bucket.
    #[prost(message, optional, tag = "3")]
    pub swap_distribution: ::core::option::Option<SwapDistribution>,
    /// The airdrop bucket.
    #[prost(message, optional, tag = "4")]
    pub airdrop_distribution: ::core::option::Option<AirdropDistribution>,
}
/// The distributions awarded to developers at SNS genesis.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct DeveloperDistribution {
    /// List of `NeuronDistribution` that specify a Neuron controller and Neuron stake in e8s (10E-8 of a token).
    /// For each entry in the developer_neurons list, a neuron will be created with a voting multiplier applied
    /// (see `FractionalDeveloperVotingPower`) and will start in PreInitializationSwap mode.
    #[prost(message, repeated, tag = "1")]
    pub developer_neurons: ::prost::alloc::vec::Vec<NeuronDistribution>,
}
/// The funds for the SNS' Treasury account on the SNS Ledger. These funds are
/// in the SNS Ledger at genesis, but unavailable until after the initial swap
/// has successfully completed.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct TreasuryDistribution {
    /// The total token distribution denominated in e8s (10E-8 of a token) of the
    /// treasury bucket.
    #[prost(uint64, tag = "1")]
    pub total_e8s: u64,
}
/// The funds for token swaps to decentralize an SNS. These funds are in the
/// SNS Ledger at genesis.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SwapDistribution {
    /// The total token distribution denominated in e8s (10E-8 of a token) of the
    /// swap bucket. All tokens used in initial_swap_amount_e8s will be
    /// deducted from total_e8s. The remaining tokens will be distributed to
    /// a subaccount of Governance for use in future token swaps.
    #[prost(uint64, tag = "1")]
    pub total_e8s: u64,
    /// The initial number of tokens denominated in e8s (10E-8 of a token)
    /// deposited in the swap canister's account for the initial token swap.
    #[prost(uint64, tag = "2")]
    pub initial_swap_amount_e8s: u64,
}
/// The distributions airdropped at SNS genesis.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct AirdropDistribution {
    /// List of `NeuronDistribution` that specify a Neuron controller and Neuron stake in e8s
    /// (10E-8 of a token). For each entry in the airdrop_neurons list, a neuron will be
    /// created with NO voting multiplier applied and will start in PreInitializationSwap mode.
    #[prost(message, repeated, tag = "1")]
    pub airdrop_neurons: ::prost::alloc::vec::Vec<NeuronDistribution>,
}
/// A tuple of values used to create a Neuron available at SNS genesis.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Eq,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct NeuronDistribution {
    /// The initial `PrincipalId` given permissions on a neuron available at genesis.
    /// The permissions granted to the controller will be set to the SNS' configured
    /// `NervousSystemParameters.neuron_claimer_permissions`. This controller
    /// will be the first available `PrincipalId` to manage a neuron.
    #[prost(message, optional, tag = "1")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The stake denominated in e8s (10E-8 of a token) that the neuron will have
    /// at genesis. The `Neuron.cached_neuron_stake_e8s` in SNS Governance and the
    /// Neuron's account in the SNS Ledger will have this value.
    #[prost(uint64, tag = "2")]
    pub stake_e8s: u64,
    /// The `memo` used along with the controller's `PrincipalId` to generate the subaccount
    /// of the neuron. This allows for a single `PrincipalId` to have multiple neurons as
    /// the identifier will be unique as long as the memo is unique.
    #[prost(uint64, tag = "3")]
    pub memo: u64,
    /// The amount of time denominated in seconds that the neuron will have its dissolve delay
    /// set to. This value cannot be changed until after the decentralization sale is complete.
    #[prost(uint64, tag = "4")]
    pub dissolve_delay_seconds: u64,
}
