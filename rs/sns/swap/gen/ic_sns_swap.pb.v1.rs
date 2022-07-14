/// The initialisation data of the canister. Always specified on
/// canister creation, and cannot be modified afterwards.
///
/// If the initialization parameters are incorrect, the swap will
/// immediately become aborted.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Init {
    /// The canister ID of the NNS governance canister. This is the only
    /// principal that can open the swap.
    #[prost(string, tag="1")]
    pub nns_governance_canister_id: ::prost::alloc::string::String,
    /// The canister ID of the governance canister of the SNS that this
    /// token swap pertains to.
    #[prost(string, tag="2")]
    pub sns_governance_canister_id: ::prost::alloc::string::String,
    /// The ledger canister of the SNS.
    #[prost(string, tag="3")]
    pub sns_ledger_canister_id: ::prost::alloc::string::String,
    /// The ledger canister for the base token, typically ICP. The base
    /// token is typically ICP, but this assumption is not used anywhere,
    /// so, in principle, any token type can be used as base token.
    #[prost(string, tag="4")]
    pub icp_ledger_canister_id: ::prost::alloc::string::String,
    /// The number of ICP that is "targetted" by this token swap. If this
    /// amount is achieved, the swap can be triggered immediately,
    /// without waiting for the due date (end_timestamp_seconds). Must be
    /// at least `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, tag="5")]
    pub max_icp_e8s: u64,
    /// The minimum number of buyers that must participate for the swap
    /// to take place. Must be greater than zero.
    #[prost(uint32, tag="7")]
    pub min_participants: u32,
    /// The minimum amount of ICP that each buyer must contribute to
    /// participate. Must be greater than zero.
    #[prost(uint64, tag="8")]
    pub min_participant_icp_e8s: u64,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, tag="9")]
    pub max_participant_icp_e8s: u64,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, tag="10")]
    pub min_icp_e8s: u64,
    /// If the swap is aborted, control of the canister(s) should be set to these
    /// principal(s). Must not be empty.
    #[prost(string, repeated, tag="11")]
    pub fallback_controller_principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BuyerState {
    /// Can only be set when a buyer state record for a new buyer is
    /// created, which can only happen when the lifecycle state is
    /// `Open`. Must be at least `init.min_participant_icp_e8s` on
    /// initialization. Can never be more than
    /// `init.max_participant_icp_e8s`. Will be set to zero once the
    /// tokens have been transferred out - either to the governance
    /// canister when the swap is committed or (back) to the buyer when
    /// the swap is aborted.
    ///
    /// Invariant between canisters:
    ///
    ///  ```text
    ///  amount_icp_e8 <= icp_ledger.balance_of(subaccount(swap_canister, P)),
    ///  ```
    ///
    /// where `P` is the principal ID associated with this buyer's state.
    ///
    /// ownership
    /// * pending - a `BuyerState` cannot exists
    /// * open - owned by the buyer, cannot be transferred out
    /// * committed - owned by the SNS governance canister, can be transferred out
    /// * aborted - owned by the buyer, can be transferred out
    #[prost(uint64, tag="1")]
    pub amount_icp_e8s: u64,
    /// Computed when world lifecycle changes to Committed.
    ///
    /// ownership:
    /// * pending - a `BuyerState` cannot exists
    /// * open - must be zero
    /// * committed - owned by the buyer, can be transferred out
    /// * aborted - must be zero
    #[prost(uint64, tag="2")]
    pub amount_sns_e8s: u64,
    /// Only used in state Committed or Aborted: ICP tokens are being
    /// transferred either to the governance canister when the swap is
    /// committed or to the buyer when the swap is aborted.
    #[prost(bool, tag="3")]
    pub icp_disbursing: bool,
    /// Only used in state Committed, when a transfer of
    /// `amount_sns_e8s` is in progress.
    #[prost(bool, tag="4")]
    pub sns_disbursing: bool,
}
/// Mutable state of the swap canister.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct State {
    /// The number of tokens (of `init.sns_ledger_canister_id`) that are
    /// being offered. The tokens are held in escrow for the the Governance
    /// canister.
    ///
    /// Invariant:
    /// ```text
    /// state.sns_token_e8s <= token_ledger.balance_of(<swap-canister>)
    /// ```
    ///
    /// When the swap is committed or aborted, this value is set to
    /// zero. Any remaining balance, either due to fractions or due to an
    /// aborted swap can be reclaimed by the Governance canister.
    #[prost(uint64, tag="1")]
    pub sns_token_e8s: u64,
    /// Invariant:
    /// ```text
    /// state.buyer_total_icp_e8s <= init.max_icp_e8s
    /// ```
    #[prost(btree_map="string, message", tag="2")]
    pub buyers: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, BuyerState>,
    /// The current lifecycle state of the swap.
    #[prost(enumeration="Lifecycle", tag="3")]
    pub lifecycle: i32,
    /// Initially, empty. Later, set by the set_open_time_window Candid method,
    /// while the canister is in the Pending state. This eventually allows the
    /// canister to enter the Open state.
    #[prost(message, optional, tag="4")]
    pub open_time_window: ::core::option::Option<TimeWindow>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Copy)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeWindow {
    #[prost(uint64, tag="1")]
    pub start_timestamp_seconds: u64,
    #[prost(uint64, tag="2")]
    pub end_timestamp_seconds: u64,
}
/// The complete state of the swap canister.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Swap {
    #[prost(message, optional, tag="1")]
    pub init: ::core::option::Option<Init>,
    #[prost(message, optional, tag="2")]
    pub state: ::core::option::Option<State>,
}
//
// === Request/Response Messages
//

#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetCanisterStatusRequest {
}
/// TODO: introduce a limits on the number of buyers to include?
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStateRequest {
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStateResponse {
    #[prost(message, optional, tag="1")]
    pub swap: ::core::option::Option<Swap>,
    #[prost(message, optional, tag="2")]
    pub derived: ::core::option::Option<DerivedState>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DerivedState {
    #[prost(uint64, tag="1")]
    pub buyer_total_icp_e8s: u64,
    /// Current approximate rate SNS tokens per ICP.
    #[prost(float, tag="2")]
    pub sns_tokens_per_icp: f32,
}
/// See `set_open_time_window` for details.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetOpenTimeWindowRequest {
    /// Duration must be between 1 and 90 days. The TimeWindow's
    /// end time but be greater than or equal to the TimeWindow's
    /// start time.
    #[prost(message, optional, tag="1")]
    pub open_time_window: ::core::option::Option<TimeWindow>,
}
/// Response if setting the open time window succeeded.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetOpenTimeWindowResponse {
}
/// Informs the swap canister that the swap has been funded. That is, the initial
/// pot of tokens being offered has been transferred to the swap canister.
///
/// Only in lifecycle state 'pending'.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshSnsTokensRequest {
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshSnsTokensResponse {
}
/// Informs the swap canister that a buyer has sent funds to participate in the
/// swap.
///
/// Only in lifecycle state 'open'.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshBuyerTokensRequest {
    /// If not specified, the caller is used.
    #[prost(string, tag="1")]
    pub buyer: ::prost::alloc::string::String,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshBuyerTokensResponse {
}
/// Once a swap is committed or aborted, the tokens need to be
/// distributed, and, if the swap was committed, neurons created.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizeSwapRequest {
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizeSwapResponse {
    #[prost(message, optional, tag="1")]
    pub sweep_icp: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag="2")]
    pub sweep_sns: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag="3")]
    pub create_neuron: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag="4")]
    pub sns_governance_normal_mode_enabled: ::core::option::Option<SetModeCallResult>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SweepResult {
    #[prost(uint32, tag="1")]
    pub success: u32,
    #[prost(uint32, tag="2")]
    pub failure: u32,
    #[prost(uint32, tag="3")]
    pub skipped: u32,
}
/// Analogous to Rust type Result<SetModeResponse, CanisterCallError>.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetModeCallResult {
    #[prost(oneof="set_mode_call_result::Possibility", tags="2")]
    pub possibility: ::core::option::Option<set_mode_call_result::Possibility>,
}
/// Nested message and enum types in `SetModeCallResult`.
pub mod set_mode_call_result {
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Possibility {
        /// TODO ic_sns_governance.pb.v1.SetModeResponse ok = 1;
        #[prost(message, tag="2")]
        Err(super::CanisterCallError),
    }
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag="1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag="2")]
    pub description: ::prost::alloc::string::String,
}
/// Request a refund of tokens that were sent to the canister in
/// error. The refund is always on the ICP ledger, from this canister's
/// subaccount of the caller to the account of the caller.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorRefundIcpRequest {
    /// The amount of ICP to transfer.
    #[prost(uint64, tag="1")]
    pub icp_e8s: u64,
    /// If specified, use this as 'fee' instead of the default.
    #[prost(uint64, tag="2")]
    pub fee_override_e8s: u64,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorRefundIcpResponse {
}
/// Lifecycle states of the swap cansiter's world state. The details of
/// their meanings is provided in the documentation of the `Swap`.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Lifecycle {
    /// Canister is incorrectly configured. Not a real lifecycle state.
    Unspecified = 0,
    /// The canister is correctly initialized and waiting for ALL of the
    /// following conditions to be met in order to transition to OPEN:
    ///   1. Funded. More precisely, this means that
    ///     a. SNS tokens have been sent to the canister, and
    ///     b. The refresh_sns_tokens Candid method has been called
    ///        (to notify that the funds have been sent).
    ///   2. The current time is not before start_timestamp_seconds, which is set
    ///      via the set_open_time_window Candid method.
    Pending = 1,
    /// Users can register for the token swap.
    Open = 2,
    /// The token price has been determined and buyers can collect
    /// their tokens.
    Committed = 3,
    /// The token swap has been aborted.
    Aborted = 4,
}
