/// This struct contains all the parameters necessary to initialize an SNS. All fields are optional
/// to avoid future candid compatibility problems. However, for the struct to be "valid", all fields
/// must be populated.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
    /// The initial voting period of a newly created proposal.
    /// A proposal's voting period may then be further increased during
    /// a proposal's lifecycle due to the wait-for-quiet algorithm.
    ///
    /// The voting period must be between (inclusive) the defined floor
    /// INITIAL_VOTING_PERIOD_SECONDS_FLOOR and ceiling
    /// INITIAL_VOTING_PERIOD_SECONDS_CEILING.
    #[prost(uint64, optional, tag = "21")]
    pub initial_voting_period_seconds: ::core::option::Option<u64>,
    /// The wait for quiet algorithm extends the voting period of a proposal when
    /// there is a flip in the majority vote during the proposal's voting period.
    /// This parameter determines the maximum time period that the voting period
    /// may be extended after a flip. If there is a flip at the very end of the
    /// original proposal deadline, the remaining time will be set to this parameter.
    /// If there is a flip before or after the original deadline, the deadline will
    /// extended by somewhat less than this parameter.
    /// The maximum total voting period extension is 2 * wait_for_quiet_deadline_increase_seconds.
    /// For more information, see the wiki page on the wait-for-quiet algorithm:
    /// <https://wiki.internetcomputer.org/wiki/Network_Nervous_System#Proposal_decision_and_wait-for-quiet>
    #[prost(uint64, optional, tag = "22")]
    pub wait_for_quiet_deadline_increase_seconds: ::core::option::Option<u64>,
    /// An optional text that swap participants should confirm before they may
    /// participate in the swap. If the field is set, its value should be plain text
    /// with at least 1 and at most 1,000 characters.
    #[prost(string, optional, tag = "23")]
    pub confirmation_text: ::core::option::Option<::prost::alloc::string::String>,
    /// An optional set of countries that should not participate in the swap.
    #[prost(message, optional, tag = "24")]
    pub restricted_countries: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Countries>,
    /// / Canisters that will be transferred to an SNS.
    #[prost(message, optional, tag = "25")]
    pub dapp_canisters: ::core::option::Option<DappCanisters>,
    /// The minimum number of buyers that must participate for the swap
    /// to take place. Must be greater than zero.
    #[prost(uint64, optional, tag = "26")]
    pub min_participants: ::core::option::Option<u64>,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "27")]
    pub min_icp_e8s: ::core::option::Option<u64>,
    /// The number of ICP that is "targeted" by this token swap. If this
    /// amount is achieved with sufficient participation, the swap will be
    /// triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, optional, tag = "28")]
    pub max_icp_e8s: ::core::option::Option<u64>,
    /// The amount of ICP that is required to be directly contributed for this
    /// token swap to take place. This number + the minimum NF contribution divided
    /// by the number of SNS tokens being offered gives the seller's reserve price
    /// for the swap, i.e., the minimum number of ICP per SNS tokens that the
    /// seller of SNS tokens is willing to accept. If this amount is not achieved,
    /// the swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "38")]
    pub min_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// The amount of ICP that this token swap is "targeting" for direct
    /// contribution. If this amount is achieved with sufficient participation, the
    /// swap will be triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, optional, tag = "39")]
    pub max_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// The minimum amount of ICP that each buyer must contribute to
    /// participate. Must be greater than zero.
    #[prost(uint64, optional, tag = "29")]
    pub min_participant_icp_e8s: ::core::option::Option<u64>,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "30")]
    pub max_participant_icp_e8s: ::core::option::Option<u64>,
    /// The date/time when the swap should start.
    #[prost(uint64, optional, tag = "31")]
    pub swap_start_timestamp_seconds: ::core::option::Option<u64>,
    /// The date/time when the swap is due, i.e., it will automatically
    /// end and commit or abort depending on whether the parameters have
    /// been fulfilled.
    #[prost(uint64, optional, tag = "32")]
    pub swap_due_timestamp_seconds: ::core::option::Option<u64>,
    /// The construction parameters for the basket of neurons created for all
    /// investors in the decentralization swap. Each investor, whether via
    /// the Neurons' Fund or direct, will receive `count` Neurons with
    /// increasing dissolve delays. The total number of Tokens swapped for
    /// by the investor will be evenly distributed across the basket. This is
    /// effectively a vesting schedule to ensure there is a gradual release of
    /// SNS Tokens available to all investors instead of being liquid immediately.
    /// See `NeuronBasketConstructionParameters` for more details on how
    /// the basket is configured.
    #[prost(message, optional, tag = "33")]
    pub neuron_basket_construction_parameters:
        ::core::option::Option<::ic_sns_swap::pb::v1::NeuronBasketConstructionParameters>,
    /// The ID of the NNS proposal submitted to launch this SNS decentralization
    /// swap.
    #[prost(uint64, optional, tag = "34")]
    pub nns_proposal_id: ::core::option::Option<u64>,
    /// Whether or not the neurons' fund is participating
    #[prost(bool, optional, tag = "40")]
    pub neurons_fund_participation: ::core::option::Option<bool>,
    /// The token_logo for the SNS project represented as a base64 encoded string.
    #[prost(string, optional, tag = "36")]
    pub token_logo: ::core::option::Option<::prost::alloc::string::String>,
    /// Constraints for the Neurons' Fund participation in this swap. These constraints passed from
    /// the NNS Governance (via SNS-W) to an SNS Swap to determine the Neurons' Fund participation
    /// amount as a function of the direct participation amount.
    #[prost(message, optional, tag = "37")]
    pub neurons_fund_participation_constraints:
        ::core::option::Option<::ic_sns_swap::pb::v1::NeuronsFundParticipationConstraints>,
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
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
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
///     - developer_distribution.developer_neurons.stake_e8s.sum <= u64:MAX
///     - developer_neurons.developer_neurons.stake_e8s.sum <= swap_distribution.total_e8s
///     - airdrop_distribution.airdrop_neurons.stake_e8s.sum <= u64:MAX
///     - swap_distribution.initial_swap_amount_e8s > 0
///     - swap_distribution.initial_swap_amount_e8s <= swap_distribution.total_e8s
///     - swap_distribution.total_e8s >= developer_distribution.developer_neurons.stake_e8s.sum
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TreasuryDistribution {
    /// The total token distribution denominated in e8s (10E-8 of a token) of the
    /// treasury bucket.
    #[prost(uint64, tag = "1")]
    pub total_e8s: u64,
}
/// The funds for token swaps to decentralize an SNS. These funds are in the
/// SNS Ledger at genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AirdropDistribution {
    /// List of `NeuronDistribution` that specify a Neuron controller and Neuron stake in e8s
    /// (10E-8 of a token). For each entry in the airdrop_neurons list, a neuron will be
    /// created with NO voting multiplier applied and will start in PreInitializationSwap mode.
    #[prost(message, repeated, tag = "1")]
    pub airdrop_neurons: ::prost::alloc::vec::Vec<NeuronDistribution>,
}
/// A tuple of values used to create a Neuron available at SNS genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
    /// The duration that this neuron is vesting.
    ///
    /// A neuron that is vesting is non-dissolving and cannot start dissolving until the vesting duration has elapsed.
    /// Vesting can be used to lock a neuron more than the max allowed dissolve delay. This allows devs and members of
    /// a particular SNS instance to prove their long-term commitment to the community. For example, the max dissolve delay
    /// for a particular SNS instance might be 1 year, but the devs of the project may set their vesting duration to 3
    /// years and dissolve delay to 1 year in order to prove that they are making a minimum 4 year commitment to the
    /// project.
    #[prost(uint64, optional, tag = "5")]
    pub vesting_period_seconds: ::core::option::Option<u64>,
}
/// / A Canister that will be transferred to an SNS.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DappCanisters {
    #[prost(message, repeated, tag = "1")]
    pub canisters: ::prost::alloc::vec::Vec<::ic_nervous_system_proto::pb::v1::Canister>,
}
