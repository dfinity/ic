/// The `swap` canister smart contract is used to perform a type of
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
///                                                                      sufficient_participation
///                                                                      && (swap_due || icp_target_reached)
/// PENDING -------------------> ADOPTED ---------------------> OPEN -----------------------------------------> COMMITTED
///          Swap receives a request        The opening delay      |                                                |
///          from NNS governance to         has elapsed            | not sufficient_participation                   |
///          schedule opening                                      | && (swap_due || icp_target_reached)            |
///                                                                v                                                v
///                                                             ABORTED ---------------------------------------> <DELETED>
/// ```
///
/// Here `sufficient_participation` means that the minimum number of
/// participants `min_participants` has been reached, each contributing
/// between `min_participant_icp_e8s` and `max_participant_icp_e8s`, and
/// their total contributions add up to at least `min_icp_e8s` and at most
/// `max_icp_e8s`.
///
/// `icp_target_reached` means that the total amount of ICP contributed is
/// equal to `max_icp_e8s`. (The total amount of ICP contributed should
/// never be greater than `max_icp_e8s`.)
///
///
/// The dramatis personae of the `swap` canister are as follows:
///
/// - The swap canister itself.
///
/// - The NNS governance canister - which is the only principal that can open
///    the swap.
///
/// - The governance canister of the SNS to be decentralized.
///
/// - The ledger canister of the SNS, i.e., the ledger of the token type
///    being sold.
///
/// - The ICP ledger canister, or more generally of the base currency of
///    the auction.
///
/// - The root canister of the SNS to control aspects of the SNS not
///    controlled by the SNS governance canister.
///
/// When the swap canister is initialized, it must be configured with
/// the canister IDs of the other participant canisters.
///
/// The next step is to provide SNS tokens for the swap. This normally
/// happens when the canister is in the PENDING state, and the amount
/// is validated in the call to `open`.
///
/// The request to open the swap has to originate from the NNS governance
/// canister. The request specifies the parameters of the swap, i.e., the
/// date/time at which the token swap will take place, the minimal number
/// of participants, the minimum number of base tokens (ICP) of each
/// participant, as well as the minimum and maximum number (reserve and
/// target) of base tokens (ICP) of the swap.
///
/// Step 0. The canister is created, specifying the initialization
/// parameters, which are henceforth fixed for the lifetime of the
/// canister.
///
/// Step 1 (State PENDING). The swap canister is loaded with the right
/// amount of SNS tokens. A call to `open` will then transition the
/// canister to the OPEN state.
///
/// Step 2a. (State ADOPTED). The field `params` is received as an argument
/// to the call to `open` and is henceforth immutable. The amount of
/// SNS token is verified against the SNS ledger. The swap will be
/// opened after an optional delay. The transition to OPEN happens
/// automatically (on the canister heartbeat) when the delay elapses.
///
/// Step 2a. (State OPEN). The delay has elapsed and the swap is open
/// for participants who can enter into the auction with a number of ICP
/// tokens until either the target amount has been reached or the
/// auction is due, i.e., the date/time of the auction has been
/// reached. The transition to COMMITTED or ABORTED happens
/// automatically (on the canister heartbeat) when the necessary
/// conditions are fulfilled.
///
/// Step 3a. (State COMMITTED). Tokens are allocated to participants at
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
/// the ICP tokens transferred back to their respective owners. The
/// swap can also be aborted early if it is determined that the
/// swap cannot possibly succeed, e.g., because the ICP ceiling has
/// been reached and the minimum number of participants has not been.
///
/// The `swap` canister can be deleted when all tokens registered with the
/// `swap` canister have been disbursed to their rightful owners.
///
/// The logic of this canister is based on the following principles.
///
/// * Message fields are never removed.
///
/// * Integer and enum fields can only have their values increase (with
/// one exception, viz., the timestamp field for the start of a
/// transfer is reset if the transfer fails).
///
/// Data flow for the Neurons' Fund.
///
/// - A SNS is created.
/// - Proposal to open a decentralization swap for the SNS is submitted to
///    the NNS.
///    - ProposalToOpenDecentralizationSale
///      - The Neurons' Fund investment amount
///      - The parameters of the decentralization swap (`Params`).
///    - Call to open swap:
///      - Parameters
///      - Neurons' Fund investments
///      - NNS Proposal ID of the NNS proposal to open the swap.
/// - On accept of proposal to open decentralization swap:
///    - Compute the maturity contribution of each Neurons' Fund neuron and deduct
///      this amount from the Neurons' Fund neuron.
///    - The swap is informed about the corresponding amount of ICP
///      (`CfParticipant`) in the call to open.
///    - Call back to NNS governance after the swap is committed or aborted:
///      - On committed swap:
///        - Ask the NNS to mint the right amount of ICP for the SNS corresponding
///          to the Neurons' Fund investment (the NNS governance canister keeps
///          track of the total).
///      - On aborted swap:
///        - Send the information about Neurons' Fund participants
///          (`CfParticipant`) back to NNS governance which will return it to
///          the corresponding neurons. Assign the control of the dapp (now under
///          the SNS control) back to the specified principals.
/// - On reject of proposal to open decentralization swap:
///    - Assign the control of the dapp (now under the SNS control) back to the
///      specified principals.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Swap {
    /// The current lifecycle of the swap.
    #[prost(enumeration = "Lifecycle", tag = "3")]
    pub lifecycle: i32,
    /// Specified on creation. That is, always specified and immutable.
    #[prost(message, optional, tag = "1")]
    pub init: ::core::option::Option<Init>,
    /// Derived from `init`, always specified and immutable. In most cases `init`
    /// should be used instead.
    /// TODO(NNS1-3213): Deprecate this field
    #[prost(message, optional, tag = "4")]
    pub params: ::core::option::Option<Params>,
    /// Neurons' Fund participation.  Specified in the transition from
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
    /// The proposal ID that was used to create the SNS that opened this swap.
    /// Note: the name is a historical artifact because the swap used to be opened
    /// with an OpenSnsTokenSwap request.
    /// This is set at installation from `init.nns_proposal_id`, and that field should be used instead.
    /// TODO(NNS1-3213): Deprecate this field
    #[prost(uint64, optional, tag = "9")]
    pub open_sns_token_swap_proposal_id: ::core::option::Option<u64>,
    /// A lock stored in Swap state. If set to true, then a finalize_swap
    /// call is in progress. In that case, new finalize_swap calls return
    /// immediately without doing any real work.
    ///
    /// The implementation of the lock should result in the lock being
    /// released when the finalize_swap method returns. If
    /// a lock is not released, upgrades of the Swap canister can
    /// release the lock in the post upgrade hook.
    #[prost(bool, optional, tag = "10")]
    pub finalize_swap_in_progress: ::core::option::Option<bool>,
    /// The timestamp for the actual opening of the swap, with an optional delay
    /// (specified via params.sale_delay_seconds) after the adoption of the swap
    /// proposal. Gets set when NNS calls `open` upon the adoption of
    /// the swap proposal.
    #[prost(uint64, optional, tag = "11")]
    pub decentralization_sale_open_timestamp_seconds: ::core::option::Option<u64>,
    /// The timestamp for the actual termination of the swap (committed or aborted).
    #[prost(uint64, optional, tag = "21")]
    pub decentralization_swap_termination_timestamp_seconds: ::core::option::Option<u64>,
    /// This ticket id counter keeps track of the latest ticket id. Whenever a new
    /// ticket is created this counter is incremented. It ensures that ticket ids
    /// are unique. The ticket IDs are sequential and next_ticket_id is assigned to
    /// a  users new ticket upon successfully requesting a new ticket. It is
    /// incremented after a user requests a new ticket successfully.
    #[prost(uint64, optional, tag = "12")]
    pub next_ticket_id: ::core::option::Option<u64>,
    /// The last time the purge_old_tickets routine was completed.
    #[prost(uint64, optional, tag = "13")]
    pub purge_old_tickets_last_completion_timestamp_nanoseconds: ::core::option::Option<u64>,
    /// The next principal bytes that should be checked by the next
    /// running purge_old_tickets routine.
    #[prost(bytes = "vec", optional, tag = "14")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub purge_old_tickets_next_principal: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Set to true when auto-finalization is attempted. Prevents auto-finalization
    /// from being attempted more than once.
    #[prost(bool, optional, tag = "17")]
    pub already_tried_to_auto_finalize: ::core::option::Option<bool>,
    /// Set when auto-finalization finishes. Calling finalize manually has no effect
    /// on this parameter.
    #[prost(message, optional, tag = "18")]
    pub auto_finalize_swap_response: ::core::option::Option<FinalizeSwapResponse>,
    /// Amount of contributions from direct participants committed to this SNS so far.
    #[prost(uint64, optional, tag = "19")]
    pub direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// Amount of contributions from the Neurons' Fund committed to this SNS so far.
    #[prost(uint64, optional, tag = "20")]
    pub neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
}
/// The initialisation data of the canister. Always specified on
/// canister creation, and cannot be modified afterwards.
///
/// If the initialization parameters are incorrect, the swap will
/// immediately be aborted.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
    /// Same as SNS ledger. Must hold the same value as SNS ledger. Whether the
    /// values match is not checked. If they don't match things will break.
    #[prost(uint64, optional, tag = "13")]
    pub transaction_fee_e8s: ::core::option::Option<u64>,
    /// Same as SNS governance. Must hold the same value as SNS governance. Whether
    /// the values match is not checked. If they don't match things will break.
    #[prost(uint64, optional, tag = "14")]
    pub neuron_minimum_stake_e8s: ::core::option::Option<u64>,
    /// An optional text that swap participants should confirm before they may
    /// participate in the swap. If the field is set, its value should be plain
    /// text with at least 1 and at most 1,000 characters.
    #[prost(string, optional, tag = "15")]
    pub confirmation_text: ::core::option::Option<::prost::alloc::string::String>,
    /// An optional set of countries that should not participate in the swap.
    #[prost(message, optional, tag = "16")]
    pub restricted_countries: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Countries>,
    /// The minimum number of buyers that must participate for the swap
    /// to take place. Must be greater than zero.
    #[prost(uint32, optional, tag = "17")]
    pub min_participants: ::core::option::Option<u32>,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "18")]
    pub min_icp_e8s: ::core::option::Option<u64>,
    /// The number of ICP that is "targeted" by this token swap. If this
    /// amount is achieved with sufficient participation, the swap will be
    /// triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`
    #[prost(uint64, optional, tag = "19")]
    pub max_icp_e8s: ::core::option::Option<u64>,
    /// The total number of ICP that is required to be "directly contributed"
    /// for this token swap to take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "30")]
    pub min_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// The number of ICP that is "targeted" by this token swap. If this
    /// amount is achieved with sufficient participation, the swap will be
    /// triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, optional, tag = "31")]
    pub max_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// The minimum amount of ICP that each buyer must contribute to
    /// participate. Must be greater than zero.
    #[prost(uint64, optional, tag = "20")]
    pub min_participant_icp_e8s: ::core::option::Option<u64>,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "21")]
    pub max_participant_icp_e8s: ::core::option::Option<u64>,
    /// The date/time when the swap should start.
    #[prost(uint64, optional, tag = "22")]
    pub swap_start_timestamp_seconds: ::core::option::Option<u64>,
    /// The date/time when the swap is due, i.e., it will automatically
    /// end and commit or abort depending on whether the parameters have
    /// been fulfilled.
    #[prost(uint64, optional, tag = "23")]
    pub swap_due_timestamp_seconds: ::core::option::Option<u64>,
    /// The number of tokens (of `init.sns_ledger_canister_id`) that are
    /// being offered. The tokens are held in escrow for the SNS
    /// governance canister.
    ///
    /// Invariant for the OPEN state:
    /// ```text
    /// state.sns_token_e8s <= token_ledger.balance_of(<swap-canister>)
    /// ```
    #[prost(uint64, optional, tag = "24")]
    pub sns_token_e8s: ::core::option::Option<u64>,
    /// The construction parameters for the basket of neurons created for all
    /// investors in the decentralization swap. Each investor, whether via
    /// the Neurons' Fund or direct, will receive `count` Neurons with
    /// increasing dissolve delays. The total number of Tokens swapped for
    /// by the investor will be evenly distributed across the basket. This is
    /// effectively a vesting schedule to ensure there is a gradual release of
    /// SNS Tokens available to all investors instead of being liquid immediately.
    /// See `NeuronBasketConstructionParameters` for more details on how
    /// the basket is configured.
    #[prost(message, optional, tag = "25")]
    pub neuron_basket_construction_parameters:
        ::core::option::Option<NeuronBasketConstructionParameters>,
    /// The ID of the NNS proposal submitted to launch this SNS decentralization
    /// swap.
    #[prost(uint64, optional, tag = "26")]
    pub nns_proposal_id: ::core::option::Option<u64>,
    /// Controls whether swap finalization should be attempted automatically in the
    /// canister heartbeat. If set to false, `finalize_swap` must be called
    /// manually. Note: it is safe to call `finalize_swap` multiple times
    /// (regardless of the value of this field).
    #[prost(bool, optional, tag = "28")]
    pub should_auto_finalize: ::core::option::Option<bool>,
    /// Constraints for the Neurons' Fund participation in this swap.
    #[prost(message, optional, tag = "29")]
    pub neurons_fund_participation_constraints:
        ::core::option::Option<NeuronsFundParticipationConstraints>,
    /// Whether Neurons' Fund participation is requested.
    #[prost(bool, optional, tag = "32")]
    pub neurons_fund_participation: ::core::option::Option<bool>,
}
/// Constraints for the Neurons' Fund participation in an SNS swap.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronsFundParticipationConstraints {
    /// The Neurons' Fund will not participate in this swap unless the direct
    /// contributions reach this threshold (in ICP e8s).
    #[prost(uint64, optional, tag = "1")]
    pub min_direct_participation_threshold_icp_e8s: ::core::option::Option<u64>,
    /// Maximum amount (in ICP e8s) of contributions from the Neurons' Fund to this swap.
    #[prost(uint64, optional, tag = "2")]
    pub max_neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
    /// List of intervals in which the given linear coefficients apply for scaling the
    /// ideal Neurons' Fund participation amount (down) to the effective Neurons' Fund
    /// participation amount.
    #[prost(message, repeated, tag = "3")]
    pub coefficient_intervals: ::prost::alloc::vec::Vec<LinearScalingCoefficient>,
    /// The function used in the implementation of Matched Funding for mapping amounts of direct
    /// participation to "ideal" Neurons' Fund participation amounts. The value needs to be adjusted
    /// to a potentially smaller value due to SNS-specific participation constraints and
    /// the configuration of the Neurons' Fund at the time of the CreateServiceNervousSystem proposal
    /// execution.
    #[prost(message, optional, tag = "4")]
    pub ideal_matched_participation_function:
        ::core::option::Option<IdealMatchedParticipationFunction>,
}
/// This function is called "ideal" because it serves as the guideline that the Neurons' Fund will
/// try to follow, but may deviate from in order to satisfy SNS-specific participation constraints
/// while allocating its overall participation amount among its neurons' maturity. In contrast,
/// The "effective" matched participation function `crate::neurons_fund::MatchedParticipationFunction`
/// is computed *based* on this one.
/// TODO(NNS1-1589): Until the Jira ticket gets solved, this definition needs to be synchronized with
/// that from nns/governance/proto/ic_nns_governance/pb/v1/governance.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdealMatchedParticipationFunction {
    /// The encoding of the "ideal" matched participation function is defined in `crate::neurons_fund`.
    /// In the future, we could change this message to represent full abstract syntactic trees
    /// comprised of elementary mathematical operators, with literals and variables as tree leaves.
    #[prost(string, optional, tag = "1")]
    pub serialized_representation: ::core::option::Option<::prost::alloc::string::String>,
}
/// Some Neurons' Fund neurons might be too small, and some might be too large to participate in a
/// given SNS swap. This causes the need to adjust Neurons' Fund participation from an "ideal" amount
/// to an "effective" amount.
/// * The ideal-participation of the Neurons' Fund refers to the value dictated by some curve that
///    specifies how direct contributions should be matched with Neurons' Fund maturity.
/// * The effective-participation of the Neurons' Fund refers to the value that the NNS Governance
///    can actually allocate, given (1) the configuration of the Neurons' Fund at the time of
///    execution of the corresponding CreateServiceNervousSystem proposal and (2) the amount of direct
///    participation.
///
/// This structure represents the coefficients of a linear transformation used for
/// mapping the Neurons' Fund ideal-participation to effective-participation on a given
/// linear (semi-open) interval. Say we have the following function for matching direct
/// participants' contributions: `f: ICP e8s -> ICP e8s`; then the *ideal* Neuron's Fund
/// participation amount corresponding to the direct participation of `x` ICP e8s is
/// `f(x)`, while the Neuron's Fund *effective* participation amount is:
/// ```
/// g(x) = (c.slope_numerator / c.slope_denominator) * f(x) + c.intercept
/// ```
/// where `c: LinearScalingCoefficient` with
/// `c.from_direct_participation_icp_e8s <= x < c.to_direct_participation_icp_e8s`.
/// Note that we represent the slope as a rational number (as opposed to floating point),
/// enabling equality comparison between two instances of this structure.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LinearScalingCoefficient {
    /// (Included) lower bound on the amount of direct participation (in ICP e8s) at which
    /// these coefficients apply.
    #[prost(uint64, optional, tag = "1")]
    pub from_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// (Excluded) upper bound on the amount of direct participation (in ICP e8s) at which
    /// these coefficients apply.
    #[prost(uint64, optional, tag = "2")]
    pub to_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// Numerator or the slope of the linear transformation.
    #[prost(uint64, optional, tag = "3")]
    pub slope_numerator: ::core::option::Option<u64>,
    /// Denominator or the slope of the linear transformation.
    #[prost(uint64, optional, tag = "4")]
    pub slope_denominator: ::core::option::Option<u64>,
    /// Intercept of the linear transformation (in ICP e8s).
    #[prost(uint64, optional, tag = "5")]
    pub intercept_icp_e8s: ::core::option::Option<u64>,
}
/// Represents one NNS neuron from the Neurons' Fund participating in this swap.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CfNeuron {
    /// The NNS neuron ID of the participating neuron.
    #[prost(fixed64, tag = "1")]
    pub nns_neuron_id: u64,
    /// The amount of ICP that the Neurons' Fund invests associated
    /// with this neuron.
    #[prost(uint64, tag = "2")]
    pub amount_icp_e8s: u64,
    /// The principals that can vote, propose, and follow on behalf of this neuron.
    #[prost(message, optional, tag = "4")]
    pub hotkeys: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Principals>,
    /// Idempotency flag indicating whether the neuron recipes have been created for
    /// the CfNeuron. When set to true, it signifies that the action of creating neuron
    /// recipes has been performed on this structure. If the action is retried, this flag
    /// can be checked to avoid duplicate operations.
    #[prost(bool, optional, tag = "3")]
    pub has_created_neuron_recipes: ::core::option::Option<bool>,
}
/// Represents a Neurons' Fund participant, possibly with several neurons.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CfParticipant {
    /// The principal that can manage the NNS neuron that participated in the Neurons' Fund.
    #[prost(message, optional, tag = "3")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Information about the participating neurons. Must not be empty.
    #[prost(message, repeated, tag = "2")]
    pub cf_neurons: ::prost::alloc::vec::Vec<CfNeuron>,
    /// The principal that can vote on behalf of these Neurons' Fund neurons.
    /// Deprecated. Please use `controller` instead (not `hotkeys`!)
    /// TODO(NNS1-3198): Remove
    #[deprecated]
    #[prost(string, tag = "1")]
    pub hotkey_principal: ::prost::alloc::string::String,
}
/// The construction parameters for the basket of neurons created for all
/// investors in the decentralization swap.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Eq)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronBasketConstructionParameters {
    /// The number of neurons each investor will receive after the
    /// decentralization swap. The total tokens swapped for will be
    /// evenly distributed across the `count` neurons.
    #[prost(uint64, tag = "1")]
    pub count: u64,
    /// The amount of additional time it takes for the next neuron to dissolve.
    #[prost(uint64, tag = "2")]
    pub dissolve_delay_interval_seconds: u64,
}
/// The parameters of the swap, provided in the call to `open`. Cannot
/// be modified after the call to `open`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
    /// The number of ICP that is "targeted" by this token swap. If this
    /// amount is achieved with sufficient participation, the swap will be
    /// triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, tag = "3")]
    pub max_icp_e8s: u64,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag = "10")]
    pub min_direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// The number of ICP that is "targeted" by this token swap. If this
    /// amount is achieved with sufficient participation, the swap will be
    /// triggered immediately, without waiting for the due date
    /// (`end_timestamp_seconds`). This means that an investor knows the minimum
    /// number of SNS tokens received per invested ICP. If this amount is achieved
    /// without reaching sufficient_participation, the swap will abort without
    /// waiting for the due date. Must be at least
    /// `min_participants * min_participant_icp_e8s`.
    #[prost(uint64, optional, tag = "11")]
    pub max_direct_participation_icp_e8s: ::core::option::Option<u64>,
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
    /// being offered. The tokens are held in escrow for the SNS
    /// governance canister.
    ///
    /// Invariant for the OPEN state:
    /// ```text
    /// state.sns_token_e8s <= token_ledger.balance_of(<swap-canister>)
    /// ```
    #[prost(uint64, tag = "7")]
    pub sns_token_e8s: u64,
    /// The construction parameters for the basket of neurons created for all
    /// investors in the decentralization swap. Each investor, whether via
    /// the Neurons' Fund or direct, will receive `count` Neurons with
    /// increasing dissolve delays. The total number of Tokens swapped for
    /// by the investor will be evenly distributed across the basket. This is
    /// effectively a vesting schedule to ensure there is a gradual release of
    /// SNS Tokens available to all investors instead of being liquid immediately.
    /// See `NeuronBasketConstructionParameters` for more details on how
    /// the basket is configured.
    #[prost(message, optional, tag = "8")]
    pub neuron_basket_construction_parameters:
        ::core::option::Option<NeuronBasketConstructionParameters>,
    /// An optional delay, so that the actual swap does not get opened immediately
    /// after the adoption of the swap proposal.
    #[prost(uint64, optional, tag = "9")]
    pub sale_delay_seconds: ::core::option::Option<u64>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferableAmount {
    /// The amount in e8s equivalent that the participant committed to the Swap,
    /// which is held by the swap canister until the swap is committed or aborted.
    #[prost(uint64, tag = "1")]
    pub amount_e8s: u64,
    /// When the transfer to refund or commit funds starts.
    #[prost(uint64, tag = "2")]
    pub transfer_start_timestamp_seconds: u64,
    /// When the transfer to refund or commit succeeds.
    #[prost(uint64, tag = "3")]
    pub transfer_success_timestamp_seconds: u64,
    /// The amount that was successfully transferred when swap commits or aborts
    /// (minus fees).
    #[prost(uint64, optional, tag = "4")]
    pub amount_transferred_e8s: ::core::option::Option<u64>,
    /// The fee charged when transferring from the swap canister;
    #[prost(uint64, optional, tag = "5")]
    pub transfer_fee_paid_e8s: ::core::option::Option<u64>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
    ///   ```text
    ///   icp.amount_e8 <= icp_ledger.balance_of(subaccount(swap_canister, P)),
    ///   ```
    ///
    /// where `P` is the principal ID associated with this buyer's state.
    ///
    /// ownership
    /// * PENDING - a `BuyerState` cannot exist
    /// * OPEN - owned by the buyer, cannot be transferred out
    /// * COMMITTED - owned by the SNS governance canister, can be transferred out
    /// * ABORTED - owned by the buyer, can be transferred out
    #[prost(message, optional, tag = "5")]
    pub icp: ::core::option::Option<TransferableAmount>,
    /// Idempotency flag indicating whether the neuron recipes have been created for
    /// the BuyerState. When set to true, it signifies that the action of creating neuron
    /// recipes has been performed on this structure. If the action is retried, this flag
    /// can be checked to avoid duplicate operations.
    #[prost(bool, optional, tag = "6")]
    pub has_created_neuron_recipes: ::core::option::Option<bool>,
}
/// Information about a direct investor.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DirectInvestment {
    #[prost(string, tag = "1")]
    pub buyer_principal: ::prost::alloc::string::String,
}
/// Information about a Neurons' Fund investment. The NNS Governance
/// canister is the controller of these neurons.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CfInvestment {
    /// The principal that can manage the NNS neuron that participated in the Neurons' Fund.
    #[prost(message, optional, tag = "3")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The principals that can vote, propose, and follow on behalf of this neuron.
    /// The controller of the corresponding NNS neuron is in the CfParticipant,
    /// which contains a vector of CfInvestments. This is because the controller
    /// is the same for all CfInvestments but the hotkeys may differ.
    #[prost(message, optional, tag = "7")]
    pub hotkeys: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Principals>,
    #[prost(fixed64, tag = "2")]
    pub nns_neuron_id: u64,
    /// Deprecated. Please use `controller` instead (not `hotkey_principal`)!
    /// TODO(NNS1-3198): Remove
    #[deprecated]
    #[prost(string, tag = "1")]
    pub hotkey_principal: ::prost::alloc::string::String,
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable, Copy,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeWindow {
    #[prost(uint64, tag = "1")]
    pub start_timestamp_seconds: u64,
    #[prost(uint64, tag = "2")]
    pub end_timestamp_seconds: u64,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsNeuronRecipe {
    #[prost(message, optional, tag = "1")]
    pub sns: ::core::option::Option<TransferableAmount>,
    /// Attributes of the Neuron to be created from the SnsNeuronRecipe
    #[prost(message, optional, tag = "4")]
    pub neuron_attributes: ::core::option::Option<sns_neuron_recipe::NeuronAttributes>,
    /// The status of the SnsNeuronRecipe's creation within SNS Governance. This
    /// field is used as a journal between calls of `finalize`.
    #[prost(enumeration = "sns_neuron_recipe::ClaimedStatus", optional, tag = "5")]
    pub claimed_status: ::core::option::Option<i32>,
    #[prost(oneof = "sns_neuron_recipe::Investor", tags = "2, 3")]
    pub investor: ::core::option::Option<sns_neuron_recipe::Investor>,
}
/// Nested message and enum types in `SnsNeuronRecipe`.
pub mod sns_neuron_recipe {
    /// Attributes of the Neuron to be created from the SnsNeuronRecipe
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronAttributes {
        /// The memo to be used when calculating the Neuron's staking account
        /// in the SNS Ledger.
        /// See `nervous_system_common::compute_neuron_staking_subaccount`.
        /// The memo is used along with the a principal_id of the "controller" of
        /// the neuron. In the case of the decentralization sale, that will either be
        /// the PrincipalId of NNS Governance canister for Neurons' Fund investors,
        /// or the PrincipalId of the direct investor.
        #[prost(uint64, tag = "1")]
        pub memo: u64,
        /// The dissolve delay in seconds that the Neuron will be created with.
        #[prost(uint64, tag = "2")]
        pub dissolve_delay_seconds: u64,
        /// The list of NeuronIds that the created Neuron will follow on all SNS
        /// proposal actions known to governance at the time. Additional followees
        /// and following relations can be added after neuron creation.
        ///
        /// TODO\[NNS1-1589\] Due to the dependency cycle, the `swap` canister's
        /// protobuf cannot directly depend on SNS Governance NeuronId type.
        /// The followees NeuronId's are of a duplicated type, which is converted to
        /// SNS governance NeuronId at the time.
        /// of claiming.
        #[prost(message, repeated, tag = "3")]
        pub followees: ::prost::alloc::vec::Vec<super::NeuronId>,
    }
    /// The various statuses of creation that a SnsNeuronRecipe can have in an SNS.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
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
    pub enum ClaimedStatus {
        /// Unused, here for PB lint purposes.
        Unspecified = 0,
        /// The Neuron is pending creation and can be claimed in SNS Governance.
        Pending = 1,
        /// The Neuron has been created successfully in SNS Governance.
        Success = 2,
        /// The Neuron has previously failed to be created in SNS Governance, but can
        /// be retried in the future.
        Failed = 3,
        /// The Neuron is invalid and was not created in SNS Governance. This neuron
        /// cannot be retried without manual intervention to update its
        /// `NeuronParameters`.
        Invalid = 4,
    }
    impl ClaimedStatus {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ClaimedStatus::Unspecified => "CLAIMED_STATUS_UNSPECIFIED",
                ClaimedStatus::Pending => "CLAIMED_STATUS_PENDING",
                ClaimedStatus::Success => "CLAIMED_STATUS_SUCCESS",
                ClaimedStatus::Failed => "CLAIMED_STATUS_FAILED",
                ClaimedStatus::Invalid => "CLAIMED_STATUS_INVALID",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "CLAIMED_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
                "CLAIMED_STATUS_PENDING" => Some(Self::Pending),
                "CLAIMED_STATUS_SUCCESS" => Some(Self::Success),
                "CLAIMED_STATUS_FAILED" => Some(Self::Failed),
                "CLAIMED_STATUS_INVALID" => Some(Self::Invalid),
                _ => None,
            }
        }
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Investor {
        #[prost(message, tag = "2")]
        Direct(super::DirectInvestment),
        #[prost(message, tag = "3")]
        CommunityFund(super::CfInvestment),
    }
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetCanisterStatusRequest {}
/// TODO: introduce a limits on the number of buyers to include?
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStateRequest {}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStateResponse {
    #[prost(message, optional, tag = "1")]
    pub swap: ::core::option::Option<Swap>,
    #[prost(message, optional, tag = "2")]
    pub derived: ::core::option::Option<DerivedState>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBuyerStateRequest {
    /// The principal_id of the user who's buyer state is being queried for.
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBuyerStateResponse {
    #[prost(message, optional, tag = "1")]
    pub buyer_state: ::core::option::Option<BuyerState>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBuyersTotalRequest {}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBuyersTotalResponse {
    /// The total amount of ICP deposited by buyers.
    #[prost(uint64, tag = "1")]
    pub buyers_total: u64,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DerivedState {
    #[prost(uint64, tag = "1")]
    pub buyer_total_icp_e8s: u64,
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
    /// Current approximate rate SNS tokens per ICP. Note that this should not be used for super
    /// precise financial accounting, because this is floating point.
    #[prost(float, tag = "2")]
    pub sns_tokens_per_icp: f32,
    /// Current amount of contributions from direct swap participants.
    #[prost(uint64, optional, tag = "6")]
    pub direct_participation_icp_e8s: ::core::option::Option<u64>,
    /// Current amount that the Neurons' Fund promises to participate with if the swap were to
    /// successfully finalize now. Until the swap's success criterium is satisfied, this value is
    /// merely a progress indicator.
    #[prost(uint64, optional, tag = "7")]
    pub neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetOpenTimeWindowRequest {
    /// Duration must be between 1 and 90 days. The TimeWindow's
    /// end time but be greater than or equal to the TimeWindow's
    /// start time.
    #[prost(message, optional, tag = "1")]
    pub open_time_window: ::core::option::Option<TimeWindow>,
}
/// Response if setting the open time window succeeded.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetOpenTimeWindowResponse {}
/// Informs the swap canister that a buyer has sent funds to participate in the
/// swap.
///
/// Only in lifecycle state `open`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshBuyerTokensRequest {
    /// If not specified, the caller is used.
    #[prost(string, tag = "1")]
    pub buyer: ::prost::alloc::string::String,
    /// To accept the swap participation confirmation, a participant should send
    /// the confirmation text via refresh_buyer_tokens, matching the text set
    /// during SNS initialization.
    #[prost(string, optional, tag = "2")]
    pub confirmation_text: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RefreshBuyerTokensResponse {
    #[prost(uint64, tag = "1")]
    pub icp_accepted_participation_e8s: u64,
    #[prost(uint64, tag = "2")]
    pub icp_ledger_account_balance_e8s: u64,
}
/// Once a swap is committed or aborted, the tokens need to be
/// distributed, and, if the swap was committed, neurons created.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizeSwapRequest {}
/// Response from the `finalize_swap` canister API.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizeSwapResponse {
    #[prost(message, optional, tag = "1")]
    pub sweep_icp_result: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "2")]
    pub sweep_sns_result: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "3")]
    pub claim_neuron_result: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "4")]
    pub set_mode_call_result: ::core::option::Option<SetModeCallResult>,
    #[prost(message, optional, tag = "5")]
    pub set_dapp_controllers_call_result: ::core::option::Option<SetDappControllersCallResult>,
    #[prost(message, optional, tag = "6")]
    pub settle_community_fund_participation_result:
        ::core::option::Option<SettleCommunityFundParticipationResult>,
    #[prost(message, optional, tag = "8")]
    pub create_sns_neuron_recipes_result: ::core::option::Option<SweepResult>,
    #[prost(message, optional, tag = "9")]
    pub settle_neurons_fund_participation_result:
        ::core::option::Option<SettleNeuronsFundParticipationResult>,
    /// Explains what (if anything) went wrong.
    #[prost(string, optional, tag = "7")]
    pub error_message: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SweepResult {
    /// Success means that on this call to finalize, the item in the
    /// sweep succeeded.
    #[prost(uint32, tag = "1")]
    pub success: u32,
    /// Failure means that on this call to finalize, the item in the
    /// sweep failed but may be successful in the future.
    #[prost(uint32, tag = "2")]
    pub failure: u32,
    /// Skipped means that on a previous call to finalize, the item
    /// in the sweep was successful.
    #[prost(uint32, tag = "3")]
    pub skipped: u32,
    /// Invalid means that on this call and all future calls to finalize,
    /// this item will not be successful, and will need intervention to
    /// succeed.
    #[prost(uint32, tag = "4")]
    pub invalid: u32,
    /// Global_failures does not map to individual items in the sweep, but
    /// number of global failures encountered in the sweep.
    #[prost(uint32, tag = "5")]
    pub global_failures: u32,
}
/// Analogous to Rust type Result<SetModeResponse, CanisterCallError>.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetModeCallResult {
    #[prost(oneof = "set_mode_call_result::Possibility", tags = "1, 2")]
    pub possibility: ::core::option::Option<set_mode_call_result::Possibility>,
}
/// Nested message and enum types in `SetModeCallResult`.
pub mod set_mode_call_result {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SetModeResult {}
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Possibility {
        #[prost(message, tag = "1")]
        Ok(SetModeResult),
        #[prost(message, tag = "2")]
        Err(super::CanisterCallError),
    }
}
/// Analogous to Rust type Result<SetDappControllersResponse, CanisterCallError>.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersCallResult {
    #[prost(oneof = "set_dapp_controllers_call_result::Possibility", tags = "1, 2")]
    pub possibility: ::core::option::Option<set_dapp_controllers_call_result::Possibility>,
}
/// Nested message and enum types in `SetDappControllersCallResult`.
pub mod set_dapp_controllers_call_result {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Possibility {
        /// TODO(NNS1-1589): Uncomment.
        /// ic_sns_root.pb.v1.
        #[prost(message, tag = "1")]
        Ok(super::SetDappControllersResponse),
        #[prost(message, tag = "2")]
        Err(super::CanisterCallError),
    }
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SettleCommunityFundParticipationResult {
    #[prost(
        oneof = "settle_community_fund_participation_result::Possibility",
        tags = "1, 2"
    )]
    pub possibility:
        ::core::option::Option<settle_community_fund_participation_result::Possibility>,
}
/// Nested message and enum types in `SettleCommunityFundParticipationResult`.
pub mod settle_community_fund_participation_result {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Response {
        /// Can be blank.
        #[prost(message, optional, tag = "1")]
        pub governance_error: ::core::option::Option<super::GovernanceError>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Possibility {
        #[prost(message, tag = "1")]
        Ok(Response),
        #[prost(message, tag = "2")]
        Err(super::CanisterCallError),
    }
}
/// The result from settling the neurons' fund participation in finalization.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SettleNeuronsFundParticipationResult {
    #[prost(
        oneof = "settle_neurons_fund_participation_result::Possibility",
        tags = "1, 2"
    )]
    pub possibility: ::core::option::Option<settle_neurons_fund_participation_result::Possibility>,
}
/// Nested message and enum types in `SettleNeuronsFundParticipationResult`.
pub mod settle_neurons_fund_participation_result {
    /// The successful branch of the result. On subsequent attempts to settle
    /// neurons fund participation (for example: due to some later stage of
    /// finalization failing and a manual retry is invoked), this branch
    /// will be set with the results of the original successful attempt.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        #[prost(uint64, optional, tag = "1")]
        pub neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
        #[prost(uint64, optional, tag = "2")]
        pub neurons_fund_neurons_count: ::core::option::Option<u64>,
    }
    /// The failure branch of the result. This message can be set for a
    /// number of reasons not limited to
    ///     - invalid state
    ///     - replica errors
    ///     - canister errors
    ///
    /// While some of these errors are transient and can immediately retried,
    /// others require manual intervention. The error messages and logs of the
    /// canister should provide enough context to debug.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Error {
        #[prost(string, optional, tag = "1")]
        pub message: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Possibility {
        #[prost(message, tag = "1")]
        Ok(Ok),
        #[prost(message, tag = "2")]
        Err(Error),
    }
}
/// Change control of the listed canisters to the listed principal id.
/// Copy of the type in root.proto. TODO(NNS1-1589)
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersRequest {
    #[prost(message, optional, tag = "1")]
    pub canister_ids: ::core::option::Option<set_dapp_controllers_request::CanisterIds>,
    #[prost(message, repeated, tag = "2")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// Nested message and enum types in `SetDappControllersRequest`.
pub mod set_dapp_controllers_request {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterIds {
        #[prost(message, repeated, tag = "1")]
        pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    }
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag = "1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FailedUpdate {
        #[prost(message, optional, tag = "1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag = "2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
/// Copied from nns governance.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GovernanceError {
    #[prost(enumeration = "governance_error::ErrorType", tag = "1")]
    pub error_type: i32,
    #[prost(string, tag = "2")]
    pub error_message: ::prost::alloc::string::String,
}
/// Nested message and enum types in `GovernanceError`.
pub mod governance_error {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
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
    pub enum ErrorType {
        Unspecified = 0,
        /// The operation was successfully completed.
        Ok = 1,
        /// This operation is not available, e.g., not implemented.
        Unavailable = 2,
        /// The caller is not authorized to perform this operation.
        NotAuthorized = 3,
        /// Some entity required for the operation (for example, a neuron) was
        /// not found.
        NotFound = 4,
        /// The command was missing or invalid. This is a permanent error.
        InvalidCommand = 5,
        /// The neuron is dissolving or dissolved and the operation requires it to
        /// be not dissolving (that is, having a non-zero dissolve delay that is
        /// accumulating age).
        RequiresNotDissolving = 6,
        /// The neuron is not dissolving or dissolved and the operation requires
        /// it to be dissolving (that is, having a non-zero dissolve delay with
        /// zero age that is not accumulating).
        RequiresDissolving = 7,
        /// The neuron is not dissolving and not dissolved and the operation
        /// requires it to be dissolved (that is, having a dissolve delay of zero
        /// and an age of zero).
        RequiresDissolved = 8,
        /// When adding or removing a hot key: the key to add was already
        /// present or the key to remove was not present or the key to add
        /// was invalid or adding another hot key would bring the total
        /// number of the maximum number of allowed hot keys per neuron.
        HotKey = 9,
        /// Some canister side resource is exhausted, so this operation cannot be
        /// performed.
        ResourceExhausted = 10,
        /// Some precondition for executing this method was not met (e.g. the
        /// neuron's dissolve time is too short). There could be a change in the
        /// state of the system such that the operation becomes allowed (e.g. the
        /// owner of the neuron increases its dissolve delay).
        PreconditionFailed = 11,
        /// Executing this method failed for some reason external to the
        /// governance canister.
        External = 12,
        /// A neuron has an ongoing ledger update and thus can't be
        /// changed.
        LedgerUpdateOngoing = 13,
        /// There wasn't enough funds to perform the operation.
        InsufficientFunds = 14,
        /// The principal provided was invalid.
        InvalidPrincipal = 15,
        /// The proposal is defective in some way (e.g. title is too long). If the
        /// same proposal is submitted again without modification, it will be
        /// rejected regardless of changes in the system's state (e.g. increasing
        /// the neuron's dissolve delay will not make the proposal acceptable).
        InvalidProposal = 16,
        /// The neuron attempted to join the Neurons' Fund while already
        /// a member.
        AlreadyJoinedCommunityFund = 17,
        /// The neuron attempted to leave the Neurons' Fund but is not a member.
        NotInTheCommunityFund = 18,
    }
    impl ErrorType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ErrorType::Unspecified => "ERROR_TYPE_UNSPECIFIED",
                ErrorType::Ok => "ERROR_TYPE_OK",
                ErrorType::Unavailable => "ERROR_TYPE_UNAVAILABLE",
                ErrorType::NotAuthorized => "ERROR_TYPE_NOT_AUTHORIZED",
                ErrorType::NotFound => "ERROR_TYPE_NOT_FOUND",
                ErrorType::InvalidCommand => "ERROR_TYPE_INVALID_COMMAND",
                ErrorType::RequiresNotDissolving => "ERROR_TYPE_REQUIRES_NOT_DISSOLVING",
                ErrorType::RequiresDissolving => "ERROR_TYPE_REQUIRES_DISSOLVING",
                ErrorType::RequiresDissolved => "ERROR_TYPE_REQUIRES_DISSOLVED",
                ErrorType::HotKey => "ERROR_TYPE_HOT_KEY",
                ErrorType::ResourceExhausted => "ERROR_TYPE_RESOURCE_EXHAUSTED",
                ErrorType::PreconditionFailed => "ERROR_TYPE_PRECONDITION_FAILED",
                ErrorType::External => "ERROR_TYPE_EXTERNAL",
                ErrorType::LedgerUpdateOngoing => "ERROR_TYPE_LEDGER_UPDATE_ONGOING",
                ErrorType::InsufficientFunds => "ERROR_TYPE_INSUFFICIENT_FUNDS",
                ErrorType::InvalidPrincipal => "ERROR_TYPE_INVALID_PRINCIPAL",
                ErrorType::InvalidProposal => "ERROR_TYPE_INVALID_PROPOSAL",
                ErrorType::AlreadyJoinedCommunityFund => "ERROR_TYPE_ALREADY_JOINED_COMMUNITY_FUND",
                ErrorType::NotInTheCommunityFund => "ERROR_TYPE_NOT_IN_THE_COMMUNITY_FUND",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "ERROR_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "ERROR_TYPE_OK" => Some(Self::Ok),
                "ERROR_TYPE_UNAVAILABLE" => Some(Self::Unavailable),
                "ERROR_TYPE_NOT_AUTHORIZED" => Some(Self::NotAuthorized),
                "ERROR_TYPE_NOT_FOUND" => Some(Self::NotFound),
                "ERROR_TYPE_INVALID_COMMAND" => Some(Self::InvalidCommand),
                "ERROR_TYPE_REQUIRES_NOT_DISSOLVING" => Some(Self::RequiresNotDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVING" => Some(Self::RequiresDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVED" => Some(Self::RequiresDissolved),
                "ERROR_TYPE_HOT_KEY" => Some(Self::HotKey),
                "ERROR_TYPE_RESOURCE_EXHAUSTED" => Some(Self::ResourceExhausted),
                "ERROR_TYPE_PRECONDITION_FAILED" => Some(Self::PreconditionFailed),
                "ERROR_TYPE_EXTERNAL" => Some(Self::External),
                "ERROR_TYPE_LEDGER_UPDATE_ONGOING" => Some(Self::LedgerUpdateOngoing),
                "ERROR_TYPE_INSUFFICIENT_FUNDS" => Some(Self::InsufficientFunds),
                "ERROR_TYPE_INVALID_PRINCIPAL" => Some(Self::InvalidPrincipal),
                "ERROR_TYPE_INVALID_PROPOSAL" => Some(Self::InvalidProposal),
                "ERROR_TYPE_ALREADY_JOINED_COMMUNITY_FUND" => {
                    Some(Self::AlreadyJoinedCommunityFund)
                }
                "ERROR_TYPE_NOT_IN_THE_COMMUNITY_FUND" => Some(Self::NotInTheCommunityFund),
                _ => None,
            }
        }
    }
}
/// Copied from nns governance.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SettleCommunityFundParticipation {
    /// The caller's principal ID must match the value in the
    /// target_swap_canister_id field in the proposal (more precisely, in the
    /// OpenSnsTokenSwap).
    #[prost(uint64, optional, tag = "1")]
    pub open_sns_token_swap_proposal_id: ::core::option::Option<u64>,
    /// Each of the possibilities here corresponds to one of two ways that a swap
    /// can terminate. See also sns_swap_pb::Lifecycle::is_terminal.
    #[prost(oneof = "settle_community_fund_participation::Result", tags = "2, 3")]
    pub result: ::core::option::Option<settle_community_fund_participation::Result>,
}
/// Nested message and enum types in `SettleCommunityFundParticipation`.
pub mod settle_community_fund_participation {
    /// When this happens, ICP needs to be minted, and sent to the SNS governance
    /// canister's main account on the ICP Ledger. As with Aborted, the amount of
    /// ICP that needs to be minted can be deduced from the ProposalData's
    /// cf_participants field.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Committed {
        /// This is where the minted ICP will be sent. In principal, this could be
        /// fetched using the swap canister's get_state method.
        #[prost(message, optional, tag = "1")]
        pub sns_governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// Total amount of contributions from direct swap participants.
        #[prost(uint64, optional, tag = "2")]
        pub total_direct_contribution_icp_e8s: ::core::option::Option<u64>,
        /// Total amount of contributions from the Neuron's Fund.
        /// TODO\[NNS1-2570\]: Ensure this field is set.
        #[prost(uint64, optional, tag = "3")]
        pub total_neurons_fund_contribution_icp_e8s: ::core::option::Option<u64>,
    }
    /// When this happens, maturity needs to be restored to Neurons' Fund neurons.
    /// The amounts to be refunded can be found in the ProposalData's
    /// `cf_participants` field.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Aborted {}
    /// Each of the possibilities here corresponds to one of two ways that a swap
    /// can terminate. See also sns_swap_pb::Lifecycle::is_terminal.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "2")]
        Committed(Committed),
        #[prost(message, tag = "3")]
        Aborted(Aborted),
    }
}
/// Request to settle the Neurons' Fund participation in this SNS Swap.
///
/// When a swap ends, the Swap canister notifies the Neurons' Fund of the swap's ultimate result,
/// which can be either `Committed` or `Aborted`. Note that currently, the Neurons' Fund is managed
/// by the NNS Governance canister.
/// * If the result is `Committed`:
///    - Neurons' Fund computes the "effective" participation amount for each of its neurons (as per
///      the Matched Funding rules). This computation is based on the total direct participation
///      amount, which is thus a field of `Committed`.
///    - Neurons' Fund converts the "effective" amount of maturity into ICP by:
///      - Requesting the ICP Ledger to mint an appropriate amount of ICP tokens and sending them
///        to the SNS treasury.
///      - Refunding whatever maturity is left over (the maximum possible maturity is reserved by
///        the Neurons' Fund before the swap begins).
///    - Neurons' Fund returns the Neurons' Fund participants back to the Swap canister
///      (see SettleNeuronsFundParticipationResponse).
///    - The Swap canister then creates SNS neurons for the Neurons' Fund participants.
/// * If the result is Aborted, the Neurons' Fund is refunded for all maturity reserved for this SNS.
///
/// This design assumes trust between the Neurons' Fund and the SNS Swap canisters. In the one hand,
/// the Swap trusts that the Neurons' Fund sends the correct amount of ICP to the SNS treasury,
/// and that the Neurons' Fund allocates its participants following the Matched Funding rules. On the
/// other hand, the Neurons' Fund trusts that the Swap will indeed create appropriate SNS neurons
/// for the Neurons' Fund participants.
///
/// The justification for this trust assumption is as follows. The Neurons' Fund can be trusted as
/// it is controlled by the NNS. The SNS Swap can be trusted as it is (1) deployed by SNS-W, which is
/// also part of the NNS and (2) upgraded via an NNS proposal (unlike all other SNS canisters).
///
/// This request may be submitted only by the Swap canister of an SNS instance created by
/// a CreateServiceNervousSystem proposal.
///
/// TODO(NNS1-1589): Until the Jira ticket gets solved, changes here need to be
/// manually propagated to (sns) swap.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SettleNeuronsFundParticipationRequest {
    /// Proposal ID of the CreateServiceNervousSystem proposal that created this SNS instance.
    #[prost(uint64, optional, tag = "1")]
    pub nns_proposal_id: ::core::option::Option<u64>,
    /// Each of the possibilities here corresponds to one of two ways that a swap can terminate.
    /// See also sns_swap_pb::Lifecycle::is_terminal.
    #[prost(
        oneof = "settle_neurons_fund_participation_request::Result",
        tags = "2, 3"
    )]
    pub result: ::core::option::Option<settle_neurons_fund_participation_request::Result>,
}
/// Nested message and enum types in `SettleNeuronsFundParticipationRequest`.
pub mod settle_neurons_fund_participation_request {
    /// When this happens, the NNS Governance needs to do several things:
    /// (1) Compute the effective amount of ICP per neuron of the Neurons' Fund as a function of
    ///      `total_direct_participation_icp_e8s`. The overall Neurons' Fund participation should
    ///      equal `total_neurons_fund_contribution_icp_e8s`.
    /// (2) Mint (via the ICP Ledger) and sent to the SNS governance the amount of
    ///      `total_neurons_fund_contribution_icp_e8s`.
    /// (3) Respond to this request with `SettleNeuronsFundParticipationResponse`, providing
    ///      the set of `NeuronsFundParticipant`s with the effective amount of ICP per neuron,
    ///      as computed in step (1).
    /// (4) Refund each neuron of the Neurons' Fund with (reserved - effective) amount of ICP.
    /// Effective amounts depend on `total_direct_participation_icp_e8s` and the participation limits
    /// of a particular SNS instance, namely, each participation must be between
    /// `min_participant_icp_e8s` and `max_participant_icp_e8s`.
    /// - If a neuron of the Neurons' Fund has less than `min_participant_icp_e8s` worth of maturity,
    ///    then it is ineligible to participate.
    /// - If a neuron of the Neurons' Fund has more than `max_participant_icp_e8s` worth of maturity,
    ///    then its participation amount is limited to `max_participant_icp_e8s`.
    /// Reserved amounts are computed as the minimal upper bound on the effective amounts, i.e., when
    /// the value `total_direct_participation_icp_e8s` reaches its theoretical maximum.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Committed {
        /// This is where the minted ICP will be sent.
        #[prost(message, optional, tag = "1")]
        pub sns_governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// Total amount of participation from direct swap participants.
        #[prost(uint64, optional, tag = "2")]
        pub total_direct_participation_icp_e8s: ::core::option::Option<u64>,
        /// Total amount of participation from the Neurons' Fund.
        /// TODO\[NNS1-2570\]: Ensure this field is set.
        #[prost(uint64, optional, tag = "3")]
        pub total_neurons_fund_participation_icp_e8s: ::core::option::Option<u64>,
    }
    /// When this happens, all priorly reserved maturity for this SNS instance needs to be restored to
    /// the Neurons' Fund neurons.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Aborted {}
    /// Each of the possibilities here corresponds to one of two ways that a swap can terminate.
    /// See also sns_swap_pb::Lifecycle::is_terminal.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "2")]
        Committed(Committed),
        #[prost(message, tag = "3")]
        Aborted(Aborted),
    }
}
/// Handling the Neurons' Fund and transferring some of its maturity to an SNS treasury is
/// thus the responsibility of the NNS Governance. When a swap succeeds, a Swap canister should send
/// a `settle_neurons_fund_participation` request to the NNS Governance, specifying its `result`
/// field as `committed`. The NNS Governance then computes the ultimate distribution of maturity in
/// the Neurons' Fund. However, this distribution also needs to be made available to the SNS Swap
/// that will use this information to create SNS neurons of an appropriate size for each
/// Neurons' Fund (as well as direct) participant. That is why in the `committed` case,
/// the NNS Governance provides `neurons_fund_neuron_portions`, while in the `aborted`
/// case it does not.
///
/// TODO(NNS1-1589): Until the Jira ticket gets solved, changes here need to be
/// manually propagated to (sns) swap.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SettleNeuronsFundParticipationResponse {
    #[prost(
        oneof = "settle_neurons_fund_participation_response::Result",
        tags = "1, 2"
    )]
    pub result: ::core::option::Option<settle_neurons_fund_participation_response::Result>,
}
/// Nested message and enum types in `SettleNeuronsFundParticipationResponse`.
pub mod settle_neurons_fund_participation_response {
    /// Represents one NNS neuron from the Neurons' Fund participating in this swap.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronsFundNeuron {
        /// The NNS neuron ID of the participating neuron.
        #[prost(uint64, optional, tag = "1")]
        pub nns_neuron_id: ::core::option::Option<u64>,
        /// The amount of Neurons' Fund participation associated with this neuron.
        #[prost(uint64, optional, tag = "2")]
        pub amount_icp_e8s: ::core::option::Option<u64>,
        /// The principal that can manage this neuron.
        #[prost(message, optional, tag = "6")]
        pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The principals that can vote, propose, and follow on behalf of this neuron.
        #[prost(message, optional, tag = "7")]
        pub hotkeys: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Principals>,
        /// Whether the amount maturity amount of Neurons' Fund participation associated with this neuron
        /// has been capped to reflect the maximum participation amount for this SNS swap.
        #[prost(bool, optional, tag = "4")]
        pub is_capped: ::core::option::Option<bool>,
    }
    /// Request was completed successfully.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        #[prost(message, repeated, tag = "1")]
        pub neurons_fund_neuron_portions: ::prost::alloc::vec::Vec<NeuronsFundNeuron>,
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Err(super::GovernanceError),
        #[prost(message, tag = "2")]
        Ok(Ok),
    }
}
/// The id of a specific neuron, which equals the neuron's subaccount on
/// the ledger canister (the account that holds the neuron's staked tokens).
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    comparable::Comparable,
    Eq,
    Ord,
    PartialOrd,
)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub id: ::prost::alloc::vec::Vec<u8>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag = "1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
}
/// Request a refund of tokens that were sent to the canister in
/// error. The refund is always on the ICP ledger, from this canister's
/// subaccount of the caller to the account of the caller.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorRefundIcpRequest {
    /// Principal who originally sent the funds to us, and is now asking for any
    /// unaccepted balance to be returned.
    #[prost(message, optional, tag = "1")]
    pub source_principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorRefundIcpResponse {
    #[prost(oneof = "error_refund_icp_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<error_refund_icp_response::Result>,
}
/// Nested message and enum types in `ErrorRefundIcpResponse`.
pub mod error_refund_icp_response {
    /// Request was completed successfully.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        /// The ledger transfer went through at this block height.
        #[prost(uint64, optional, tag = "1")]
        pub block_height: ::core::option::Option<u64>,
    }
    /// Request was not successful, and no funds were transferred.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Err {
        #[prost(enumeration = "err::Type", optional, tag = "1")]
        pub error_type: ::core::option::Option<i32>,
        #[prost(string, optional, tag = "2")]
        pub description: ::core::option::Option<::prost::alloc::string::String>,
    }
    /// Nested message and enum types in `Err`.
    pub mod err {
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
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
        pub enum Type {
            Unspecified = 0,
            /// There is something wrong with the request. If repeated, the request
            /// will always be rejected.
            InvalidRequest = 1,
            /// Most likely, the canister is in the wrong Lifecycle. More generally,
            /// the system is not yet in a state where the request can be fulfilled,
            /// but it might enter a suitable state later. In this case, the same
            /// request might be accepted later.
            Precondition = 2,
            /// Most likely, a request to the ledger failed, in which case, it can be
            /// assumed that no funds were transferred. In general, this is caused by
            /// something outside this canister, which usually means some other
            /// canister (such as ledger).
            External = 3,
        }
        impl Type {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    Type::Unspecified => "TYPE_UNSPECIFIED",
                    Type::InvalidRequest => "TYPE_INVALID_REQUEST",
                    Type::Precondition => "TYPE_PRECONDITION",
                    Type::External => "TYPE_EXTERNAL",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "TYPE_INVALID_REQUEST" => Some(Self::InvalidRequest),
                    "TYPE_PRECONDITION" => Some(Self::Precondition),
                    "TYPE_EXTERNAL" => Some(Self::External),
                    _ => None,
                }
            }
        }
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Ok(Ok),
        #[prost(message, tag = "2")]
        Err(Err),
    }
}
/// Request struct for the method `get_lifecycle`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLifecycleRequest {}
/// Response struct for the method `get_lifecycle`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLifecycleResponse {
    #[prost(enumeration = "Lifecycle", optional, tag = "1")]
    pub lifecycle: ::core::option::Option<i32>,
    #[prost(uint64, optional, tag = "2")]
    pub decentralization_sale_open_timestamp_seconds: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub decentralization_swap_termination_timestamp_seconds: ::core::option::Option<u64>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAutoFinalizationStatusRequest {}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAutoFinalizationStatusResponse {
    /// Reflects whether auto-finalization has been enabled via in the init
    /// parameters (`should_auto_finalize`).
    #[prost(bool, optional, tag = "1")]
    pub is_auto_finalize_enabled: ::core::option::Option<bool>,
    /// True if and only if auto-finalization has been started.
    #[prost(bool, optional, tag = "2")]
    pub has_auto_finalize_been_attempted: ::core::option::Option<bool>,
    /// Will be populated with the FinalizeSwapResponse once auto-finalization has
    /// completed.
    #[prost(message, optional, tag = "3")]
    pub auto_finalize_swap_response: ::core::option::Option<FinalizeSwapResponse>,
}
/// Request struct for the method `get_init`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetInitRequest {}
/// Response struct for the method `get_init`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetInitResponse {
    #[prost(message, optional, tag = "1")]
    pub init: ::core::option::Option<Init>,
}
/// Request struct for the method `get_derived_state`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetDerivedStateRequest {}
/// Response struct for the method `get_derived_state`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
/// ICRC-1 Account. See <https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1>
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Icrc1Account {
    #[prost(message, optional, tag = "1")]
    pub owner: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(bytes = "vec", optional, tag = "2")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub subaccount: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// A device for ensuring that retrying (direct) participation does not result
/// in multiple participation. Basically, this records a user's intent to
/// participate BEFORE moving any funds.
///
/// How this is used: before any money is sent, a user's agent must first look
/// for an existing ticket. If one does not exist, then, a new one is created
/// for the current participation that is now being attempted (for
/// the first time).
///
/// If there is already a ticket, then the new participation must be aborted.
/// The surprise existence of the ticket indicates that there is a pending
/// participation. In this case the user's agent must attempt to perform the same
/// participation as stated in the ticket before doing anything else.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ticket {
    /// Unique ID of the ticket
    #[prost(uint64, tag = "1")]
    pub ticket_id: u64,
    /// The account of the ticket.
    ///
    /// account.owner is the owner of this ticket.
    #[prost(message, optional, tag = "2")]
    pub account: ::core::option::Option<Icrc1Account>,
    /// The user-set amount of the ticket in ICP e8s
    #[prost(uint64, tag = "3")]
    pub amount_icp_e8s: u64,
    /// The timestamp of creation of this ticket
    #[prost(uint64, tag = "4")]
    pub creation_time: u64,
}
/// Request struct for the method `get_open_ticket`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetOpenTicketRequest {}
/// Response struct for the method `get_open_ticket`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetOpenTicketResponse {
    #[prost(oneof = "get_open_ticket_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<get_open_ticket_response::Result>,
}
/// Nested message and enum types in `GetOpenTicketResponse`.
pub mod get_open_ticket_response {
    /// Request was completed successfully.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        /// If there is an open swap ticket for the caller then this field
        /// contains it.
        #[prost(message, optional, tag = "1")]
        pub ticket: ::core::option::Option<super::Ticket>,
    }
    /// Request was not successful, and no ticket was created.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Err {
        #[prost(enumeration = "err::Type", optional, tag = "1")]
        pub error_type: ::core::option::Option<i32>,
    }
    /// Nested message and enum types in `Err`.
    pub mod err {
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
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
        pub enum Type {
            Unspecified = 0,
            SaleNotOpen = 1,
            SaleClosed = 2,
        }
        impl Type {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    Type::Unspecified => "TYPE_UNSPECIFIED",
                    Type::SaleNotOpen => "TYPE_SALE_NOT_OPEN",
                    Type::SaleClosed => "TYPE_SALE_CLOSED",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "TYPE_SALE_NOT_OPEN" => Some(Self::SaleNotOpen),
                    "TYPE_SALE_CLOSED" => Some(Self::SaleClosed),
                    _ => None,
                }
            }
        }
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Ok(Ok),
        #[prost(message, tag = "2")]
        Err(Err),
    }
}
/// Request struct for the method `new_sale_ticket`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewSaleTicketRequest {
    /// The user-set amount of the ticket in ICP e8s
    #[prost(uint64, tag = "1")]
    pub amount_icp_e8s: u64,
    /// The subaccount of the caller to be used for the ticket
    #[prost(bytes = "vec", optional, tag = "2")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub subaccount: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
/// Response struct for the method `new_sale_ticket`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewSaleTicketResponse {
    #[prost(oneof = "new_sale_ticket_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<new_sale_ticket_response::Result>,
}
/// Nested message and enum types in `NewSaleTicketResponse`.
pub mod new_sale_ticket_response {
    /// Request was completed successfully.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ok {
        /// The created ticket.
        #[prost(message, optional, tag = "1")]
        pub ticket: ::core::option::Option<super::Ticket>,
    }
    /// Request was not successful, and no ticket was created.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Err {
        #[prost(enumeration = "err::Type", tag = "1")]
        pub error_type: i32,
        /// When `error_type` is `INVALID_USER_AMOUNT` then this field
        /// describes the minimum and maximum amounts.
        #[prost(message, optional, tag = "2")]
        pub invalid_user_amount: ::core::option::Option<err::InvalidUserAmount>,
        /// When `error_type` is `TICKET_EXISTS` then this field
        /// contains the ticket that already exists.
        #[prost(message, optional, tag = "3")]
        pub existing_ticket: ::core::option::Option<super::Ticket>,
    }
    /// Nested message and enum types in `Err`.
    pub mod err {
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable,
        )]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct InvalidUserAmount {
            #[prost(uint64, tag = "1")]
            pub min_amount_icp_e8s_included: u64,
            #[prost(uint64, tag = "2")]
            pub max_amount_icp_e8s_included: u64,
        }
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
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
        pub enum Type {
            Unspecified = 0,
            SaleNotOpen = 1,
            SaleClosed = 2,
            /// There is already an open ticket associated with the caller.
            ///
            /// When this is the `error_type`, then the field existing_ticket
            /// is set and contains the ticket itself.
            TicketExists = 3,
            /// The amount sent by the user is not within the Swap parameters.
            ///
            /// When this is the `error_type`, then the field invalid_user_amount
            /// is set and describes minimum and maximum amounts.
            InvalidUserAmount = 4,
            /// The specified subaccount is not a valid subaccount
            /// (length != 32 bytes).
            InvalidSubaccount = 5,
            /// The specified principal is forbidden from creating tickets.
            InvalidPrincipal = 6,
        }
        impl Type {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    Type::Unspecified => "TYPE_UNSPECIFIED",
                    Type::SaleNotOpen => "TYPE_SALE_NOT_OPEN",
                    Type::SaleClosed => "TYPE_SALE_CLOSED",
                    Type::TicketExists => "TYPE_TICKET_EXISTS",
                    Type::InvalidUserAmount => "TYPE_INVALID_USER_AMOUNT",
                    Type::InvalidSubaccount => "TYPE_INVALID_SUBACCOUNT",
                    Type::InvalidPrincipal => "TYPE_INVALID_PRINCIPAL",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                    "TYPE_SALE_NOT_OPEN" => Some(Self::SaleNotOpen),
                    "TYPE_SALE_CLOSED" => Some(Self::SaleClosed),
                    "TYPE_TICKET_EXISTS" => Some(Self::TicketExists),
                    "TYPE_INVALID_USER_AMOUNT" => Some(Self::InvalidUserAmount),
                    "TYPE_INVALID_SUBACCOUNT" => Some(Self::InvalidSubaccount),
                    "TYPE_INVALID_PRINCIPAL" => Some(Self::InvalidPrincipal),
                    _ => None,
                }
            }
        }
    }
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Ok(Ok),
        #[prost(message, tag = "2")]
        Err(Err),
    }
}
/// Request struct for the method `list_direct_participants`. This method
/// paginates over all direct participants in the decentralization swap.
/// Direct participants are participants who did not participate via the
/// Neurons' Fund.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDirectParticipantsRequest {
    /// The limit of the number of Participants returned in each page, in range
    /// \[0, 30,000\].
    /// If no value, or a value outside of this range is requested, 30,000 will be
    /// used.
    #[prost(uint32, optional, tag = "1")]
    pub limit: ::core::option::Option<u32>,
    /// Skip the first `offset` elements when constructing the response.
    #[prost(uint32, optional, tag = "2")]
    pub offset: ::core::option::Option<u32>,
}
/// Response struct for the method `list_direct_participants`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListDirectParticipantsResponse {
    /// The list of Participants returned from the invocation of
    /// `list_direct_participants`.
    /// The list is a page of all the buyers in the Swap canister at the time of
    /// the method call. The size of the page is equal to either:
    /// - the max page size (30,000),
    /// - the corresponding `ListDirectParticipantsRequest.limit`,
    /// - the remaining Participants, if there are fewer than `limit` participants
    ///    left.
    ///
    /// Pagination through the entire list of participants is complete if
    /// len(participants) < `ListDirectParticipantsRequest.limit`.
    #[prost(message, repeated, tag = "1")]
    pub participants: ::prost::alloc::vec::Vec<Participant>,
}
/// A direct Participant in the decentralization swap.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Participant {
    /// The PrincipalId of the participant.
    #[prost(message, optional, tag = "1")]
    pub participant_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The BuyerState of the participant, which includes the
    /// amount of participation in e8s of a Token, and the transfer
    /// status of those tokens.
    #[prost(message, optional, tag = "2")]
    pub participation: ::core::option::Option<BuyerState>,
}
/// Request struct for the method `get_sale_parameters`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSaleParametersRequest {}
/// Response struct for the method `get_sale_parameters`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSaleParametersResponse {
    #[prost(message, optional, tag = "1")]
    pub params: ::core::option::Option<Params>,
}
/// Request struct for the method `list_community_fund_participants`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListCommunityFundParticipantsRequest {
    /// The maximum number of elements that will be in the response.
    /// This is capped at 10_000.
    #[prost(uint32, optional, tag = "1")]
    pub limit: ::core::option::Option<u32>,
    /// Skip the first `offset` elements when constructing the response
    #[prost(uint64, optional, tag = "2")]
    pub offset: ::core::option::Option<u64>,
}
/// Response struct for the method `list_community_fund_participants`.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListCommunityFundParticipantsResponse {
    #[prost(message, repeated, tag = "1")]
    pub cf_participants: ::prost::alloc::vec::Vec<CfParticipant>,
}
/// Request for the method `list_sns_neuron_recipes`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSnsNeuronRecipesRequest {
    /// The maximum number of elements that will be in the response.
    /// This is capped at 10_000.
    #[prost(uint32, optional, tag = "1")]
    pub limit: ::core::option::Option<u32>,
    /// Skip the first `offset` elements when constructing the response
    #[prost(uint64, optional, tag = "2")]
    pub offset: ::core::option::Option<u64>,
}
/// Response for the method `list_sns_neuron_recipes`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSnsNeuronRecipesResponse {
    #[prost(message, repeated, tag = "1")]
    pub sns_neuron_recipes: ::prost::alloc::vec::Vec<SnsNeuronRecipe>,
}
/// Request struct for the method `notify_payment_failure`
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyPaymentFailureRequest {}
/// Response for the method `notify_payment_failure`
/// Returns the ticket if a ticket was found for the caller and the ticket
/// was removed successfully. Returns None if no ticket was found for the caller.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotifyPaymentFailureResponse {
    #[prost(message, optional, tag = "1")]
    pub ticket: ::core::option::Option<Ticket>,
}
/// TODO(NNS1-3306): Remove this message once SNS Governance uses the same request type.
/// A sequence of NeuronIds, which is used to get prost to generate a type isomorphic to Option<Vec<NeuronId>>.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronIds {
    #[prost(message, repeated, tag = "1")]
    pub neuron_ids: ::prost::alloc::vec::Vec<NeuronId>,
}
/// The request for the `claim_swap_neurons` method.
/// Copied from sns governance.proto. TODO(NNS1-3306): Remove this message once
/// SNS Governance uses the same request type.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimSwapNeuronsRequest {
    /// The set of parameters that define the neurons created in `claim_swap_neurons`. For
    /// each NeuronRecipe, one neuron will be created.
    #[prost(message, optional, tag = "2")]
    pub neuron_recipes: ::core::option::Option<claim_swap_neurons_request::NeuronRecipes>,
    /// The set of parameters that define the neurons created in `claim_swap_neurons`. For
    /// each NeuronParameter, one neuron will be created.
    /// Deprecated. Use \[`neuron_recipes`\] instead.
    #[deprecated]
    #[prost(message, repeated, tag = "1")]
    pub neuron_parameters: ::prost::alloc::vec::Vec<claim_swap_neurons_request::NeuronParameters>,
}
/// Nested message and enum types in `ClaimSwapNeuronsRequest`.
pub mod claim_swap_neurons_request {
    /// This type has been replaced by NeuronRecipe and should not be used.
    /// TODO(NNS1-3198): Remove this message once `NeuronRecipe` is used systematically.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronParameters {
        /// The PrincipalId that will have permissions when the neuron is created.
        /// The permissions that are granted are controlled my
        /// `NervousSystemParameters::neuron_claimer_permissions`. This field
        /// is required.
        #[prost(message, optional, tag = "1")]
        pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// For Community Fund participants, in addition to the controller (that is
        /// set to the NNS governance), this is another PrincipalId with permissions.
        /// Specifically, the PrincipalId who is the controller of the NNS neuron
        /// that invested in the decentralization sale via the Community Fund will
        /// be granted the following permissions:
        ///     - NeuronPermissionType::SubmitProposal
        ///     - NeuronPermissionType::Vote
        /// This field is not set for other types of participants, therefore it is optional.
        #[prost(message, optional, tag = "2")]
        pub hotkey: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The stake of the neuron in e8s (10E-8 of a token) that the neuron will be
        /// created with. This field is required.
        #[prost(uint64, optional, tag = "3")]
        pub stake_e8s: ::core::option::Option<u64>,
        /// The duration in seconds that the neuron's dissolve delay will be set to. Neurons
        /// that are for Community Fund investors will be automatically set to dissolving,
        /// while direct investors will be automatically set to non-dissolving.
        #[prost(uint64, optional, tag = "5")]
        pub dissolve_delay_seconds: ::core::option::Option<u64>,
        /// The ID of the NNS neuron whose Community Fund participation resulted in the
        /// creation of this SNS neuron.
        #[prost(uint64, optional, tag = "6")]
        pub source_nns_neuron_id: ::core::option::Option<u64>,
        /// The ID of the SNS Neuron to be created for the participant. If a Neuron with
        /// this NeuronId already exists in SNS Governance, the `ClaimSwapNeuronsResponse`
        /// will return a`ClaimedSwapNeuronStatus::AlreadyExists` for this NeuronId.
        /// This field is required.
        #[prost(message, optional, tag = "7")]
        pub neuron_id: ::core::option::Option<super::NeuronId>,
        /// The list of NeuronIds that the created Neuron will follow on all SNS Proposal
        /// Actions known to governance at the time. Additional followees and following
        /// relations can be added after neuron creation.
        #[prost(message, repeated, tag = "8")]
        pub followees: ::prost::alloc::vec::Vec<super::NeuronId>,
    }
    /// Replacement for NeuronParameters. Contains the information needed to set up
    /// a neuron for a swap participant.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronRecipe {
        /// The principal that should be the controller of the SNS neuron
        #[prost(message, optional, tag = "1")]
        pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The ID of the SNS neuron
        #[prost(message, optional, tag = "2")]
        pub neuron_id: ::core::option::Option<super::NeuronId>,
        /// The SNS neuron's stake in e8s (10E-8 of a token)
        #[prost(uint64, optional, tag = "3")]
        pub stake_e8s: ::core::option::Option<u64>,
        /// The duration in seconds that the neuron's dissolve delay will be set to.
        #[prost(uint64, optional, tag = "4")]
        pub dissolve_delay_seconds: ::core::option::Option<u64>,
        /// The neurons this neuron should follow
        #[prost(message, optional, tag = "5")]
        pub followees: ::core::option::Option<super::NeuronIds>,
        #[prost(oneof = "neuron_recipe::Participant", tags = "6, 7")]
        pub participant: ::core::option::Option<neuron_recipe::Participant>,
    }
    /// Nested message and enum types in `NeuronRecipe`.
    pub mod neuron_recipe {
        /// The info that for a participant in the Neurons' Fund
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable,
        )]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct NeuronsFund {
            /// The neuron ID of the NNS neuron that participated in the Neurons' Fund.
            #[prost(uint64, optional, tag = "1")]
            pub nns_neuron_id: ::core::option::Option<u64>,
            /// The controller of the NNS neuron that participated in the Neurons' Fund.
            #[prost(message, optional, tag = "2")]
            pub nns_neuron_controller: ::core::option::Option<::ic_base_types::PrincipalId>,
            /// The hotkeys of the NNS neuron that participated in the Neurons' Fund.
            #[prost(message, optional, tag = "3")]
            pub nns_neuron_hotkeys:
                ::core::option::Option<::ic_nervous_system_proto::pb::v1::Principals>,
        }
        /// The info that for a direct participant
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable,
        )]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Direct {}
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable,
        )]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Participant {
            #[prost(message, tag = "6")]
            Direct(Direct),
            #[prost(message, tag = "7")]
            NeuronsFund(NeuronsFund),
        }
    }
    /// Needed to cause prost to generate a type isomorphic to
    /// Optional<Vec<NeuronRecipe>>.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronRecipes {
        #[prost(message, repeated, tag = "1")]
        pub neuron_recipes: ::prost::alloc::vec::Vec<NeuronRecipe>,
    }
}
/// Lifecycle states of the swap canister. The details of their meanings
/// are provided in the documentation of the `Swap` message.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
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
    /// In PENDING state, the canister is correctly initialized. Once SNS
    /// tokens have been transferred to the swap canister's account on
    /// the SNS ledger, a call to `open` with valid parameters will start
    /// the swap.
    Pending = 1,
    /// In ADOPTED state, the proposal to start the decentralization swap
    /// has been adopted, and the swap will be automatically opened after a delay.
    /// In the legacy (non-one-proposal) flow, the swap delay is specified by
    /// params.sale_delay_seconds. In the one-proposal flow, the swap delay is
    /// specified by `init.swap_start_timestamp_seconds`.
    Adopted = 5,
    /// In OPEN state, prospective buyers can register for the token
    /// swap. The swap will be committed when the target (max) ICP has
    /// been reached or the swap's due date/time occurs, whichever
    /// happens first.
    Open = 2,
    /// In COMMITTED state the token price has been determined; on a call to
    /// finalize`, buyers receive their SNS neurons and the SNS governance canister
    /// receives the ICP.
    Committed = 3,
    /// In ABORTED state the token swap has been aborted, e.g., because the due
    /// date/time occurred before the minimum (reserve) amount of ICP has been
    /// retrieved. On a call to `finalize`, participants get their ICP refunded.
    Aborted = 4,
}
impl Lifecycle {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Lifecycle::Unspecified => "LIFECYCLE_UNSPECIFIED",
            Lifecycle::Pending => "LIFECYCLE_PENDING",
            Lifecycle::Adopted => "LIFECYCLE_ADOPTED",
            Lifecycle::Open => "LIFECYCLE_OPEN",
            Lifecycle::Committed => "LIFECYCLE_COMMITTED",
            Lifecycle::Aborted => "LIFECYCLE_ABORTED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "LIFECYCLE_UNSPECIFIED" => Some(Self::Unspecified),
            "LIFECYCLE_PENDING" => Some(Self::Pending),
            "LIFECYCLE_ADOPTED" => Some(Self::Adopted),
            "LIFECYCLE_OPEN" => Some(Self::Open),
            "LIFECYCLE_COMMITTED" => Some(Self::Committed),
            "LIFECYCLE_ABORTED" => Some(Self::Aborted),
            _ => None,
        }
    }
}
