/// The 'swap' canister smart contract is used to perform a type of
/// single-price auction (SNS/ICP) of one token type SNS for another token
/// type ICP (this is typically ICP, but can be treated as a variable) at a
/// specific date/time in the future.
///
/// Such a single-price auction is typically used to decentralize an SNS,
/// i.e., to ensure that a sufficient number of governance tokens of the
/// SNS are distributed among different participants.
///
/// State (lifecycle) diagram for the swap canister's state.
///
/// ```text
///                                  sufficient_participantion && (swap_due || icp_target_reached)
/// PENDING ------------------> OPEN ------------------------------------------------------------> COMMITTED
///                             |                                                                  |
///                             | swap_due && not sufficient_participation                         |
///                             v                                                                  v
///                             ABORTED -------------------------------------------------------> <DELETED>
/// ```
///
/// Here `sufficient_participation` means that the minimum number of
/// participants `min_participants` has been reached, each contributing
/// between `min_participant_icp_e8s` and `max_participant_icp_e8s`, and
/// their total contributions add up to at least `min_icp_e8s` and at most
/// `max_icp_e8s`.
///
///
/// The dramatis personae of the 'swap' canister are as follows:
///
/// - The swap canister itself.
///
/// - The NNS governance canister - which is the only principal that can open the swap.
///
/// - The governance canister of the SNS to be decentralized.
///
/// - The ledger canister of the SNS, i.e., the ledger of the token type
///   being sold.
///
/// - The ICP ledger cansiter, or more generally of the base currency of
///   the auction.
///
/// - The root canister of the SNS to control aspects of the SNS not
///   controlled by the SNS governance canister.
///
/// When the swap canister is initialized, it must be configured with
/// the canister IDs of the other participant canisters.
///
/// The next step is to provide SNS tokens for the swap. This normally
/// happens when the canister is in the PENDING state, and the amount
/// is validated in the call to `open`.
///
/// The request to open the swap has to originate from the NNS governance
/// cansiter. The request specifies the parameters of the swap, i.e., the
/// date/time at which the token swap will take place, the minimal number
/// of participants, the minimum number of base tokens (ICP) of each
/// paricipant, as well as the minimum and maximum number (reserve and
/// target) of base tokens (ICP) of the swap.
///
/// Step 0. The canister is created, specifying the initalization
/// parameters, which are henceforth fixed for the lifetime of the
/// canister.
///
/// Step 1 (State PENDING). The swap canister is loaded with the right
/// amount of SNS tokens. A call to `open` will then transition the
/// canister to the OPEN state.
///
/// Step 2. (State OPEN). The field `params` is received as an argument
/// to the call to `open` and is henceforth immutable. The amount of
/// SNS token is verified against the SNS ledger. The swap is open for
/// paricipants who can enter into the auction with a number of ICP
/// tokens until either the target amount has been reached or the
/// auction is due, i.e., the date/time of the auction has been
/// reached. The transition to COMMITTED or ABORTED happens
/// automatically (on the canister heartbeat) when the necessary
/// conditions are fulfilled.
///
/// Step 3a. (State COMMITTED). Tokens are allocated to partcipants at
/// a single clearing price, i.e., the number of SNS tokens being
/// offered divided by the total number of ICP tokens contributed to
/// the swap. In this state, a call to `finalize` will create SNS
/// neurons for each participant and transfer ICP to the SNS governance
/// canister. The call to `finalize` does not happen automatically
/// (i.e., on the canister heartbeat) so that there is a caller to
/// respond to with potential errors.
///
/// Step 3b. (State ABORTED). If the parameters of the swap have not
/// been satisfied before the due date/time, the swap is aborted and
/// the ICP tokens transferred back to their respective owners.
///
/// The 'swap' canister can be deleted when all tokens registered with the
/// 'swap' canister have been disbursed to their rightful owners.
///
/// The logic of this canister is based on the following principles.
///
/// * Message fields are never removed.
///
/// * Integer and enum fields can only have their values increase (with
/// one exception, viz., the timestamp field for the start of a
/// transfer is reset if the transfer fails).
///
/// Data flow for the community fund.
///
/// - A SNS is created.
/// - Proposal to open a decentralization sale for the SNS is submitted to the NNS.
///   - ProposalToOpenDecentralizationSale
///     - The Community Fund investment amount
///     - The parameters of the decentralization sale (`Params`).
///   - Call to open swap:
///     - Parameters
///     - CF Investments
///     - NNS Proposal ID of the NNS proposal to open the swap.
/// - On accept of proposal to open decentralization sale:
///   - Compute the maturity contribution of each CF neuron and deduct this amount from the CF neuron.
///   - The swap is informed about the corresponding amount of ICP (`CfParticipant`) in the call to open.
///   - Call back to NNS governance after the swap is committed or aborted:
///     - On committed swap:
///       - Ask the NNS to mint the right amount of ICP for the SNS corresponding to the CF investment (the NNS governance canister keeps track of the total).
///     - On aborted swap:
///       - Send the information about CF participants (`CfParticipant`) back to NNS governance which will return it to the corresponding neurons. Assign the control of the dapp (now under the SNS control) back to the specified principals.
/// - On reject of proposal to open decentralization sale:
///   - Assign the control of the dapp (now under the SNS control) back to the specified principals.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Swap {
    /// The current lifecycle of the swap.
    #[prost(enumeration = "Lifecycle", tag = "3")]
    pub lifecycle: i32,
    /// Specified on creation. That is, always specified and immutable.
    #[prost(message, optional, tag = "1")]
    pub init: ::core::option::Option<Init>,
    /// Specified in the transition from PENDING to OPEN and immutable
    /// thereafter.
    #[prost(message, optional, tag = "4")]
    pub params: ::core::option::Option<Params>,
    /// Community fund participation.  Specified in the transition from
    /// PENDING to OPEN and immutable thereafter.
    #[prost(message, repeated, tag = "5")]
    pub cf_participants: ::prost::alloc::vec::Vec<CfParticipant>,
    /// Empty in the PENDING state. In the OPEN state, new buyers can be
    /// added and existing buyers can increase their bids. In the
    /// COMMITTED and ABORTED states, the amount cannot be modified, and
    /// the transfer timestamps are filled in.
    ///
    /// The key is the textual representation of the buyer's principal
    /// and the value represents the bid.
    #[prost(btree_map = "string, message", tag = "6")]
    pub buyers: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, BuyerState>,
    /// When the swap is committed, this field is initialized according
    /// to the outcome of the swap.
    #[prost(message, repeated, tag = "7")]
    pub neuron_recipes: ::prost::alloc::vec::Vec<SnsNeuronRecipe>,
    /// This field represents the request to NNS governance to mint ICP
    /// for SNS governance on behalf of the community fund investments.
    #[prost(message, optional, tag = "8")]
    pub cf_minting: ::core::option::Option<TransferableAmount>,
}
/// The initialisation data of the canister. Always specified on
/// canister creation, and cannot be modified afterwards.
///
/// If the initialization parameters are incorrect, the swap will
/// immediately be aborted.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Init {
    /// The canister ID of the NNS governance canister. This is the only
    /// principal that can open the swap.
    #[prost(string, tag = "1")]
    pub nns_governance_canister_id: ::prost::alloc::string::String,
    /// The canister ID of the governance canister of the SNS that this
    /// token swap pertains to.
    #[prost(string, tag = "2")]
    pub sns_governance_canister_id: ::prost::alloc::string::String,
    /// The ledger canister of the SNS.
    #[prost(string, tag = "3")]
    pub sns_ledger_canister_id: ::prost::alloc::string::String,
    /// The ledger canister for the base token, typically ICP. The base
    /// token is typically ICP, but this assumption is not used anywhere,
    /// so, in principle, any token type can be used as base token.
    #[prost(string, tag = "4")]
    pub icp_ledger_canister_id: ::prost::alloc::string::String,
    /// Analogous to `sns_governance_canister_id`, but for the "root"
    /// canister instead of the governance canister.
    #[prost(string, tag = "12")]
    pub sns_root_canister_id: ::prost::alloc::string::String,
    /// If the swap is aborted, control of the canister(s) should be set to these
    /// principals. Must not be empty.
    #[prost(string, repeated, tag = "11")]
    pub fallback_controller_principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Represents one NNS neuron from the community fund participating in this swap.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct CfNeuron {
    /// The NNS neuron ID of the participating neuron.
    #[prost(fixed64, tag = "1")]
    pub nns_neuron_id: u64,
    /// The amount of ICP that the community fund invests associated
    /// with this neuron.
    #[prost(uint64, tag = "2")]
    pub amount_icp_e8s: u64,
}
/// Represent CF participant, possibly with several neurons.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct CfParticipant {
    /// The principal that can vote on behalf of these CF neurons.
    #[prost(string, tag = "1")]
    pub hotkey_principal: ::prost::alloc::string::String,
    /// Information about the participating neurons. Must not be empty.
    #[prost(message, repeated, tag = "2")]
    pub cf_neurons: ::prost::alloc::vec::Vec<CfNeuron>,
}
/// The parameters of the swap, provided in the call to 'open'. Cannot
/// be modified after the call to 'open'.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct Params {
    /// The minimum number of buyers that must participate for the swap
    /// to take place. Must be greater than zero.
    #[prost(uint32, tag = "1")]
    pub min_participants: u32,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, tag = "2")]
    pub min_icp_e8s: u64,
    /// The number of ICP that is "targetted" by this token swap. If this
    /// amount is achieved, the swap will be triggered immediately,
    /// without waiting for the due date (`end_timestamp_seconds`). This
    /// means that an investor knows the minimum number of SNS tokens
    /// received per invested ICP. Must be at least `min_participants *
    /// min_participant_icp_e8s`.
    #[prost(uint64, tag = "3")]
    pub max_icp_e8s: u64,
    /// The minimum amount of ICP that each buyer must contribute to
    /// participate. Must be greater than zero.
    #[prost(uint64, tag = "4")]
    pub min_participant_icp_e8s: u64,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, tag = "5")]
    pub max_participant_icp_e8s: u64,
    /// The date/time when the swap is due, i.e., it will automatically
    /// end and commit or abort depending on whether the parameters have
    /// been fulfilled.
    #[prost(uint64, tag = "6")]
    pub swap_due_timestamp_seconds: u64,
    /// The number of tokens (of `init.sns_ledger_canister_id`) that are
    /// being offered. The tokens are held in escrow for the the SNS
    /// governance canister.
    ///
    /// Invariant for the OPEN state:
    /// ```text
    /// state.sns_token_e8s <= token_ledger.balance_of(<swap-canister>)
    /// ```
    #[prost(uint64, tag = "7")]
    pub sns_token_e8s: u64,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct TransferableAmount {
    #[prost(uint64, tag = "1")]
    pub amount_e8s: u64,
    #[prost(uint64, tag = "2")]
    pub transfer_start_timestamp_seconds: u64,
    #[prost(uint64, tag = "3")]
    pub transfer_success_timestamp_seconds: u64,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct BuyerState {
    /// The amount of ICP accepted from this buyer. ICP is accepted by
    /// first making a ledger transfer and then calling the method
    /// `refresh_buyer_token_e8s`.
    ///
    /// Can only be set when a buyer state record for a new buyer is
    /// created, which can only happen when the lifecycle state is
    /// `Open`. Must be at least `min_participant_icp_e8s`, and at most
    /// `max_participant_icp_e8s`.
    ///
    /// Invariant between canisters in the OPEN state:
    ///
    ///  ```text
    ///  icp.amount_e8 <= icp_ledger.balance_of(subaccount(swap_canister, P)),
    ///  ```
    ///
    /// where `P` is the principal ID associated with this buyer's state.
    ///
    /// ownership
    /// * PENDING - a `BuyerState` cannot exists
    /// * OPEN - owned by the buyer, cannot be transferred out
    /// * COMMITTED - owned by the SNS governance canister, can be transferred out
    /// * ABORTED - owned by the buyer, can be transferred out
    #[prost(message, optional, tag = "5")]
    pub icp: ::core::option::Option<TransferableAmount>,
}
/// Information about a direct investor.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct DirectInvestment {
    #[prost(string, tag = "1")]
    pub buyer_principal: ::prost::alloc::string::String,
}
/// Information about a community fund investment. The NNS Governance
/// canister is the controller of these neurons.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct CfInvestment {
    #[prost(string, tag = "1")]
    pub hotkey_principal: ::prost::alloc::string::String,
    #[prost(fixed64, tag = "2")]
    pub nns_neuron_id: u64,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SnsNeuronRecipe {
    #[prost(message, optional, tag = "1")]
    pub sns: ::core::option::Option<TransferableAmount>,
    #[prost(oneof = "sns_neuron_recipe::Investor", tags = "2, 3")]
    pub investor: ::core::option::Option<sns_neuron_recipe::Investor>,
}
/// Nested message and enum types in `SnsNeuronRecipe`.
pub mod sns_neuron_recipe {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Oneof,
    )]
    pub enum Investor {
        #[prost(message, tag = "2")]
        Direct(super::DirectInvestment),
        #[prost(message, tag = "3")]
        CommunityFund(super::CfInvestment),
    }
}
//
// === Request/Response Messages
//

#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct OpenRequest {
    /// The parameters of the swap.
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
    /// Community fund participation.
    #[prost(message, repeated, tag = "2")]
    pub cf_participants: ::prost::alloc::vec::Vec<CfParticipant>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct OpenResponse {}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetCanisterStatusRequest {}
/// TODO: introduce a limits on the number of buyers to include?
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetStateRequest {}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetStateResponse {
    #[prost(message, optional, tag = "1")]
    pub swap: ::core::option::Option<Swap>,
    #[prost(message, optional, tag = "2")]
    pub derived: ::core::option::Option<DerivedState>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetBuyerStateRequest {
    /// The principal_id of the user who's buyer state is being queried for.
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetBuyerStateResponse {
    #[prost(message, optional, tag = "1")]
    pub buyer_state: ::core::option::Option<BuyerState>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetBuyersTotalRequest {}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct GetBuyersTotalResponse {
    /// The total amount of ICP deposited by buyers.
    #[prost(uint64, tag = "1")]
    pub buyers_total: u64,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct DerivedState {
    #[prost(uint64, tag = "1")]
    pub buyer_total_icp_e8s: u64,
    /// Current approximate rate SNS tokens per ICP.
    #[prost(float, tag = "2")]
    pub sns_tokens_per_icp: f32,
}
/// Informs the swap canister that a buyer has sent funds to participate in the
/// swap.
///
/// Only in lifecycle state 'open'.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RefreshBuyerTokensRequest {
    /// If not specified, the caller is used.
    #[prost(string, tag = "1")]
    pub buyer: ::prost::alloc::string::String,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct RefreshBuyerTokensResponse {
    #[prost(uint64, tag = "1")]
    pub icp_accepted_partipation_e8s: u64,
    #[prost(uint64, tag = "2")]
    pub icp_ledger_account_balance_e8s: u64,
}
/// Once a swap is committed or aborted, the tokens need to be
/// distributed, and, if the swap was committed, neurons created.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct FinalizeSwapRequest {}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct FinalizeSwapResponse {
    #[prost(message, optional, tag = "1")]
    pub sweep_icp: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "2")]
    pub sweep_sns: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "3")]
    pub create_neuron: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "4")]
    pub sns_governance_normal_mode_enabled: ::core::option::Option<SetModeCallResult>,
    #[prost(message, optional, tag = "5")]
    pub set_dapp_controllers_result: ::core::option::Option<SetDappControllersCallResult>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SweepResult {
    #[prost(uint32, tag = "1")]
    pub success: u32,
    #[prost(uint32, tag = "2")]
    pub failure: u32,
    #[prost(uint32, tag = "3")]
    pub skipped: u32,
}
/// Analogous to Rust type Result<SetModeResponse, CanisterCallError>.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetModeCallResult {
    #[prost(oneof = "set_mode_call_result::Possibility", tags = "2")]
    pub possibility: ::core::option::Option<set_mode_call_result::Possibility>,
}
/// Nested message and enum types in `SetModeCallResult`.
pub mod set_mode_call_result {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Oneof,
    )]
    pub enum Possibility {
        /// TODO ic_sns_governance.pb.v1.SetModeResponse ok = 1;
        #[prost(message, tag = "2")]
        Err(super::CanisterCallError),
    }
}
/// Analogous to Rust type Result<SetModeResponse, CanisterCallError>.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetDappControllersCallResult {
    #[prost(oneof = "set_dapp_controllers_call_result::Possibility", tags = "1, 2")]
    pub possibility: ::core::option::Option<set_dapp_controllers_call_result::Possibility>,
}
/// Nested message and enum types in `SetDappControllersCallResult`.
pub mod set_dapp_controllers_call_result {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Oneof,
    )]
    pub enum Possibility {
        /// TODO(NNS1-1589): Uncomment.
        /// ic_sns_root.pb.v1.
        #[prost(message, tag = "1")]
        Ok(super::SetDappControllersResponse),
        #[prost(message, tag = "2")]
        Err(super::CanisterCallError),
    }
}
/// TODO(NNS1-1589): Delete these.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetDappControllersRequest {
    #[prost(message, repeated, tag = "1")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag = "1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        PartialEq,
        ::prost::Message,
    )]
    pub struct FailedUpdate {
        #[prost(message, optional, tag = "1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag = "2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag = "1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
}
/// Request a refund of tokens that were sent to the canister in
/// error. The refund is always on the ICP ledger, from this canister's
/// subaccount of the caller to the account of the caller.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct ErrorRefundIcpRequest {
    /// The amount of ICP to transfer.
    #[prost(uint64, tag = "1")]
    pub icp_e8s: u64,
    /// If specified, use this as 'fee' instead of the default.
    #[prost(uint64, tag = "2")]
    pub fee_override_e8s: u64,
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    PartialEq,
    ::prost::Message,
)]
pub struct ErrorRefundIcpResponse {}
/// Lifecycle states of the swap canister. The details of their meanings
/// are provided in the documentation of the `Swap` message.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum Lifecycle {
    /// The canister is incorrectly configured. Not a real lifecycle state.
    Unspecified = 0,
    /// In this state, the canister is correctly initialized. Once SNS
    /// tokens have been transferred to the swap canister's account on
    /// the SNS ledger, a call to `open` with valid parameters will start
    /// the swap.
    Pending = 1,
    /// In this state, prospective buyers can register for the token
    /// swap. The swap will be committed when the target (max) ICP has
    /// been reached or the swap's due date/time occurs, whichever
    /// happens first.
    Open = 2,
    /// The token price has been determined; on a call to `finalize`,
    /// buyers receive their SNS neurons and the SNS governance canister
    /// receives the ICP.
    Committed = 3,
    /// The token swap has been aborted, e.g., because the due date/time
    /// occured before the minimum (reserve) amount of ICP has been
    /// retrieved. On a call to `finalize`, participants get their ICP refunded.
    Aborted = 4,
}
