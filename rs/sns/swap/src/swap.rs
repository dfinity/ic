use crate::pb::v1::Params;
use crate::{
    clients::{NnsGovernanceClient, SnsGovernanceClient, SnsRootClient},
    environment::CanisterEnvironment,
    logs::{ERROR, INFO},
    memory,
    pb::v1::{
        get_open_ticket_response, new_sale_ticket_response, set_dapp_controllers_call_result,
        set_mode_call_result,
        set_mode_call_result::SetModeResult,
        settle_neurons_fund_participation_request, settle_neurons_fund_participation_response,
        sns_neuron_recipe::{ClaimedStatus, Investor, NeuronAttributes},
        BuyerState, CanisterCallError, CfInvestment, CfNeuron, CfParticipant, DerivedState,
        DirectInvestment, ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapResponse,
        GetAutoFinalizationStatusRequest, GetAutoFinalizationStatusResponse, GetBuyerStateRequest,
        GetBuyerStateResponse, GetBuyersTotalResponse, GetDerivedStateResponse, GetInitRequest,
        GetInitResponse, GetLifecycleRequest, GetLifecycleResponse, GetOpenTicketRequest,
        GetOpenTicketResponse, GetSaleParametersRequest, GetSaleParametersResponse,
        GetStateResponse, Icrc1Account, Init, Lifecycle, ListCommunityFundParticipantsRequest,
        ListCommunityFundParticipantsResponse, ListDirectParticipantsRequest,
        ListDirectParticipantsResponse, ListSnsNeuronRecipesRequest, ListSnsNeuronRecipesResponse,
        NeuronBasketConstructionParameters, NeuronId as SwapNeuronId, NewSaleTicketRequest,
        NewSaleTicketResponse, NotifyPaymentFailureResponse, Participant,
        RefreshBuyerTokensResponse, SetDappControllersCallResult, SetDappControllersRequest,
        SetDappControllersResponse, SetModeCallResult, SettleNeuronsFundParticipationRequest,
        SettleNeuronsFundParticipationResponse, SettleNeuronsFundParticipationResult,
        SnsNeuronRecipe, Swap, SweepResult, Ticket, TransferableAmount,
    },
    types::{NeuronsFundNeuron, ScheduledVestingEvent, TransferResult},
};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_ledger_core::Tokens;
use ic_nervous_system_clients::ledger_client::ICRC1Ledger;
use ic_nervous_system_common::{
    i2d, ledger::compute_neuron_staking_subaccount_bytes, MAX_NEURONS_FOR_DIRECT_PARTICIPANTS,
};
use ic_nervous_system_proto::pb::v1::Principals;
use ic_neurons_fund::{MatchedParticipationFunction, PolynomialNeuronsFundParticipation};
use ic_sns_governance::pb::v1::claim_swap_neurons_request::{
    neuron_recipe, NeuronRecipe, NeuronRecipes,
};
use ic_sns_governance::pb::v1::NeuronIds;
use ic_sns_governance::pb::v1::{
    claim_swap_neurons_response::{ClaimSwapNeuronsResult, SwapNeuron},
    governance, ClaimSwapNeuronsError, ClaimSwapNeuronsRequest, ClaimedSwapNeuronStatus, NeuronId,
    SetMode, SetModeResponse,
};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{storable::Blob, GrowFailed, Storable};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use itertools::{Either, Itertools};
use maplit::btreemap;
use prost::Message;
use rust_decimal::prelude::ToPrimitive;
use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
    num::{NonZeroU128, NonZeroU64},
    ops::{
        Bound::{Included, Unbounded},
        Div,
    },
    str::FromStr,
    time::Duration,
};

/// The maximum count of participants that can be returned by ListDirectParticipants
pub const MAX_LIST_DIRECT_PARTICIPANTS_LIMIT: u32 = 20_000;

/// The default count of Neurons' Fund participants that can be returned
/// by ListCommunityFundParticipants
const DEFAULT_LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT: u32 = 10_000;

/// The maximum count of Neurons' Fund participants that can be returned
/// by ListCommunityFundParticipants
const LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT_CAP: u32 = 10_000;

/// The default count of sns neuron recipes that can be returned
/// by ListSnsNeuronRecipes
const DEFAULT_LIST_SNS_NEURON_RECIPES_LIMIT: u32 = 10_000;

/// Range of allowed memos for neurons distributed via an SNS swap. This range is used to choose
/// the memos of neurons in the neuron basket, and to enforce that other memos (e.g. for Airdrop
/// neurons) do not conflict with the neuron basket memos.
pub const NEURON_BASKET_MEMO_RANGE_START: u64 = 1_000_000;
pub const SALE_NEURON_MEMO_RANGE_END: u64 = 10_000_000;

/// The principal with all bytes set to zero. The main property
/// of this principal is that for any principal p, the following condition holds:
/// (p != FIRST_PRINCIPAL_BYTES) ==> FIRST_PRINCIPAL_BYTES.as_slice() < p.as_slice()
/// Here, the `<` symbol means lexicographical comparison of sequences of bytes.
pub const FIRST_PRINCIPAL_BYTES: [u8; PrincipalId::MAX_LENGTH_IN_BYTES] =
    [0; PrincipalId::MAX_LENGTH_IN_BYTES];

/// The maximum batch size of NeuronParameters included in a ClaimSwapNeuronsRequest. This
/// value was discovered empirically and was set to 500 to:
/// 1. Avoid the XNET message size limit of 2mb
/// 2. Avoid having the SNS Governance canister hit the instruction limit per message.
pub const CLAIM_SWAP_NEURONS_BATCH_SIZE: usize = 500;

impl From<(Option<i32>, String)> for CanisterCallError {
    fn from((code, description): (Option<i32>, String)) -> Self {
        Self { code, description }
    }
}

impl From<Result<SetModeResponse, CanisterCallError>> for SetModeCallResult {
    fn from(native_result: Result<SetModeResponse, CanisterCallError>) -> Self {
        let possibility = match native_result {
            Ok(_ok) => Some(set_mode_call_result::Possibility::Ok(SetModeResult {})),
            Err(err) => Some(set_mode_call_result::Possibility::Err(err)),
        };

        Self { possibility }
    }
}

impl From<Result<SetDappControllersResponse, CanisterCallError>> for SetDappControllersCallResult {
    fn from(native_result: Result<SetDappControllersResponse, CanisterCallError>) -> Self {
        use set_dapp_controllers_call_result::Possibility as P;
        let possibility = Some(match native_result {
            Ok(response) => P::Ok(response),
            Err(err) => P::Err(err),
        });

        Self { possibility }
    }
}

impl From<DerivedState> for GetDerivedStateResponse {
    fn from(state: DerivedState) -> GetDerivedStateResponse {
        GetDerivedStateResponse {
            buyer_total_icp_e8s: Some(state.buyer_total_icp_e8s),
            direct_participant_count: state.direct_participant_count,
            cf_participant_count: state.cf_participant_count,
            cf_neuron_count: state.cf_neuron_count,
            sns_tokens_per_icp: Some(state.sns_tokens_per_icp as f64),
            direct_participation_icp_e8s: state.direct_participation_icp_e8s,
            neurons_fund_participation_icp_e8s: state.neurons_fund_participation_icp_e8s,
        }
    }
}

impl NeuronBasketConstructionParameters {
    /// Chops `total_amount_e8s` into `self.count` pieces. Each gets doled out
    /// every `self.dissolve_delay_seconds`, starting from 0.
    ///
    /// # Arguments
    /// * `total_amount_e8s` - The total amount of tokens (in e8s) to be chopped up.
    fn generate_vesting_schedule(
        &self,
        total_amount_e8s: u64,
    ) -> Result<Vec<ScheduledVestingEvent>, String> {
        if self.count == 0 {
            return Err(
                "NeuronBasketConstructionParameters.count must be greater than zero".to_string(),
            );
        }

        let dissolve_delay_seconds_list = (0..(self.count))
            .map(|i| i * self.dissolve_delay_interval_seconds)
            .collect::<Vec<u64>>();

        let chunks_e8s = apportion_approximately_equally(total_amount_e8s, self.count)?;
        Ok(dissolve_delay_seconds_list
            .into_iter()
            .zip(chunks_e8s)
            .map(
                |(dissolve_delay_seconds, amount_e8s)| ScheduledVestingEvent {
                    dissolve_delay_seconds,
                    amount_e8s,
                },
            )
            .collect())
    }
}

/// Chops up `total` in to `len` pieces.
///
/// More precisely, result.len() == len. result.sum() == total. Each element of
/// result is approximately equal to the others. However, unless len divides
/// total evenly, the elements of result will inevitably be not equal.
///
/// There are two ways that Err can be returned:
///
///   1. Caller mistake: len == 0
///
///   2. This has a bug. See implementation comments for why we know of know way
///      this can happen, but can detect if it does.
pub fn apportion_approximately_equally(total: u64, len: u64) -> Result<Vec<u64>, String> {
    let quotient = total
        .checked_div(len)
        .ok_or_else(|| format!("Unable to divide total={} by len={}", total, len))?;
    let remainder = total % len; // For unsigned integers, % cannot overflow.

    // So far, we have only apportioned quotient * len. To reach the desired
    // total, we must still somehow add remainder (per Euclid's Division
    // Theorem). That is accomplished right after this.
    let mut result = vec![quotient; len as usize];

    // Divvy out the remainder: Starting from the last element, increment
    // elements by 1. The number of such increments performed here is remainder,
    // bringing our total back to the desired amount.
    if remainder >= result.len() as u64 {
        return Err(format!("Could not apportion {total} into {len} pieces"));
    }
    let mut iter_mut = result.iter_mut();
    for _ in 0..remainder {
        let element: &mut u64 = iter_mut
            .next_back()
            // We can prove that this will not panic:
            // The number of iterations of this loop is total % len.
            // This must be < len (by Euclid's Division Theorem).
            // Thus, the number of iterations that this loop goes through is < len.
            // Thus, the number of times next_back is called is < len.
            // next_back only returns None after len calls.
            // Therefore, next_back does not return None here.
            // Therefore, this expect will never panic.
            .ok_or_else(|| {
                format!(
                    "Ran out of elements to increment. total={}, len={}",
                    total, len,
                )
            })?;

        // This cannot overflow because the result must be <= total. Thus, this
        // will not panic.
        *element = element.checked_add(1).ok_or_else(|| {
            format!(
                "Incrementing element by 1 resulted in overflow. total={}, len={}",
                total, len,
            )
        })?;
    }

    Ok(result)
}

/// This structure allows checking the direct amount of swap participation
/// at any state of the SNS lifecycle.
#[derive(Debug)]
pub enum IcpTargetProgress {
    /// This value is reserved for the situations in which the ICP target has not
    /// been reached, e.g., at the beginning and during the swap, or at the ond of
    /// a swap that did not reach the target.
    NotReached {
        current_direct_participation_e8s: u64,
        max_direct_participation_e8s: u64,
    },
    /// This value is reserved for the situation in which the ICP target has been
    /// reached *exactly*.
    Reached(u64),
    /// This value is reserved for situations in which the ICP target has been
    /// somehow exceeded. This should not happen under normal circumstances.
    Exceeded {
        current_direct_participation_e8s: u64,
        max_direct_participation_e8s: u64,
    },
    /// The ICP target cannot be defined or reached in some abnormal situations, e.g.,
    /// when the Swap Params is not available. This value covers such cases.
    Undefined,
}

pub enum IcpTargetError {
    /// Specifies excess in ICP e8s.
    TargetExceededBy(u64),
    TargetUndefined,
}

impl fmt::Display for IcpTargetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Self::TargetExceededBy(excess_amount_e8s) = self {
            write!(
                f,
                "Total amount of ICP e8s committed exceeds the target by {} ICP e8s",
                excess_amount_e8s
            )
        } else {
            write!(f, "ICP target undefined")
        }
    }
}

impl IcpTargetProgress {
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    pub fn is_reached_or_exceeded(&self) -> bool {
        matches!(self, Self::Reached(_) | Self::Exceeded { .. })
    }

    /// Validates if the ICP target has somehow been exceeded, i.e., there is an excess amount
    /// of ICP that has been accepted. In that case, the excess amount (in ICP e8s) is returned
    /// as the `Err` result. Otherwise, the result is `Ok`.
    pub fn validate(&self) -> Result<(), IcpTargetError> {
        match self {
            Self::Exceeded {
                current_direct_participation_e8s,
                max_direct_participation_e8s,
            } => {
                let excess = current_direct_participation_e8s
                    .checked_sub(*max_direct_participation_e8s)
                    .unwrap_or_else(|| {
                        log!(
                            ERROR,
                            "Invariant violated in IcpTargetProgress::Exceeded: \
                            current_direct_participation_e8s = {current_direct_participation_e8s} \
                            <= max_direct_participation_e8s = {max_direct_participation_e8s}",
                        );
                        0
                    });
                Err(IcpTargetError::TargetExceededBy(excess))
            }
            Self::Undefined => Err(IcpTargetError::TargetUndefined),
            _ => Ok(()),
        }
    }
}

/// This module includes helper functions for implementing Swap participation logic.
mod swap_participation {
    use crate::{
        logs::ERROR,
        swap::{Lifecycle, Swap},
    };
    use ic_canister_log::log;

    impl Swap {
        pub fn validate_possibility_of_direct_participation(&self) -> Result<(), String> {
            let icp_target = self.icp_target_progress();
            if let Err(icp_target_error) = icp_target.validate() {
                log!(ERROR, "{}", icp_target_error);
            }
            if icp_target.is_reached_or_exceeded() {
                Err("The ICP target for this token swap has already been reached.".to_string())
            } else {
                Ok(())
            }
        }

        pub fn validate_lifecycle_is_open(&self) -> Result<(), String> {
            let lifecycle: Lifecycle = self.lifecycle();
            if lifecycle == Lifecycle::Open {
                Ok(())
            } else {
                Err(
                    format!(
                        "Participation is possible only when the Swap is in the OPEN state. Current state is {:?}.",
                        lifecycle,
                    ),
                )
            }
        }

        /// Validate the confirmation text from the caller who wishes to participate in the swap.
        /// This is conceptually just comparing the text against what has been specified in
        /// the SnsInitPayload structure, but we provide precise errors in case something
        /// does not match.
        pub fn validate_confirmation_text(
            &self,
            confirmation_text: Option<String>,
        ) -> Result<(), String> {
            match (
                self.init_or_panic().confirmation_text.as_ref(),
                confirmation_text,
            ) {
                (Some(expected_text), Some(text)) => {
                    if &text != expected_text {
                        Err("The value of `confirmation_text` does not match the value provided in SNS init payload.".to_string())
                    } else {
                        Ok(())
                    }
                }
                (Some(_), None) => Err("No value provided for `confirmation_text`.".to_string()),
                (None, Some(_)) => {
                    Err("Found a value for `confirmation_text`, expected none.".to_string())
                }
                (None, None) => Ok(()),
            }
        }
    }

    pub fn context_before_awaiting_icp_ledger_response(err: String) -> String {
        format!("{err} (before awaiting ICP ledger response)")
    }

    pub fn context_after_awaiting_icp_ledger_response(err: String) -> String {
        format!("{err} (after awaiting ICP ledger response)")
    }
}

// High level documentation in the corresponding Protobuf message.
impl Swap {
    /// Create state from an `Init` object.
    ///
    /// Requires that `init` is valid; otherwise it panics.
    pub fn new(init: Init) -> Self {
        if let Err(e) = init.validate() {
            panic!("Invalid init arg, reason: {e}\nArg: {init:#?}\n");
        }
        let mut res = Self {
            lifecycle: Lifecycle::Pending as i32,
            init: None, // Postpone setting this field to avoid cloning.
            params: None,
            cf_participants: vec![],
            buyers: Default::default(), // Btree map
            neuron_recipes: vec![],
            open_sns_token_swap_proposal_id: None,
            finalize_swap_in_progress: Some(false),
            decentralization_sale_open_timestamp_seconds: None,
            decentralization_swap_termination_timestamp_seconds: None,
            next_ticket_id: Some(0),
            purge_old_tickets_last_completion_timestamp_nanoseconds: Some(0),
            purge_old_tickets_next_principal: Some(FIRST_PRINCIPAL_BYTES.to_vec()),
            already_tried_to_auto_finalize: Some(false),
            auto_finalize_swap_response: None,
            direct_participation_icp_e8s: None,
            neurons_fund_participation_icp_e8s: None,
        };
        if init.validate_swap_init_for_one_proposal_flow().is_ok() {
            // Automatically fill out the fields that the (legacy) open request
            // used to provide, supporting clients who read legacy Swap fields.
            {
                res.cf_participants = vec![];
                match Params::try_from(&init) {
                    Err(err) => {
                        log!(
                            ERROR,
                            "Failed filling out the legacy Param structure: {}. \
                            Falling back to None.",
                            err
                        );
                        res.params = None;
                    }
                    Ok(params) => {
                        res.params = Some(params);
                    }
                }
            }
            res.open_sns_token_swap_proposal_id = init.nns_proposal_id;
            res.decentralization_sale_open_timestamp_seconds = init.swap_start_timestamp_seconds;
            // Transit to the next SNS lifecycle state.
            res.lifecycle = Lifecycle::Adopted as i32;
        }
        res.init = Some(init);
        res
    }

    /// Retrieve a reference to the `init` field. The `init` field
    /// is unlikely to be `None` given how `new` is implemented.
    pub fn init_or_panic(&self) -> &Init {
        self.init
            .as_ref()
            .expect("Expected the init field to be populated in the Swap canister state")
    }

    /// Retrieves a reference to the `init` field.
    pub fn init(&self) -> Result<&Init, String> {
        self.init
            .as_ref()
            .ok_or_else(|| "The Init field is not populated in the Swap canister state".to_string())
    }

    pub fn init_and_validate(&self) -> Result<&Init, String> {
        match &self.init {
            None => Err("Missing Init in the Swap canister state".to_string()),
            Some(init) => init.validate().map(|_| init),
        }
    }

    /// A Result with the number of SNS tokens to be swapped, or an Err if the swap hasn't
    /// been opened yet.
    pub fn sns_token_e8s(&self) -> Result<u64, String> {
        self.params
            .as_ref()
            .map(|params| params.sns_token_e8s)
            .ok_or_else(|| "Swap not open, no tokens available.".to_string())
    }

    /// The total amount of ICP e8s contributed by direct investors and the
    /// Neurons' Fund.
    pub fn current_total_participation_e8s(&self) -> u64 {
        let current_direct_participation_e8s = self.current_direct_participation_e8s();
        let current_neurons_fund_participation_e8s = self.current_neurons_fund_participation_e8s();
        current_direct_participation_e8s
            .checked_add(current_neurons_fund_participation_e8s)
            .unwrap_or_else(|| {
                log!(
                    ERROR,
                    "current_direct_participation_e8s ({current_direct_participation_e8s}) \
                    + current_neurons_fund_participation_e8s ({current_neurons_fund_participation_e8s}) \
                    > u64::MAX",
                );
                u64::MAX
            })
    }

    /// The total amount of ICP e8s contributed by the Neurons' Fund.
    pub fn current_neurons_fund_participation_e8s(&self) -> u64 {
        self.neurons_fund_participation_icp_e8s.unwrap_or(0)
    }

    /// The total amount of ICP e8s contributed by direct participants.
    pub fn current_direct_participation_e8s(&self) -> u64 {
        self.direct_participation_icp_e8s.unwrap_or(0)
    }

    /// The maximum direct participation amount (in ICP e8s).
    pub fn max_direct_participation_e8s(&self) -> u64 {
        self.params
            .clone()
            .expect("Expected params to be set")
            .max_direct_participation_icp_e8s
            .expect("Expected params.max_direct_participation_icp_e8s to be set")
    }

    /// The amount of ICP e8s currently available for direct participation.
    pub fn available_direct_participation_e8s(&self) -> u64 {
        let max_direct_participation_e8s = self.max_direct_participation_e8s();
        let current_direct_participation_e8s = self.current_direct_participation_e8s();
        max_direct_participation_e8s
            .checked_sub(current_direct_participation_e8s)
            .unwrap_or_else(|| {
                log!(
                    ERROR,
                    "max_direct_participation_e8s ({max_direct_participation_e8s}) \
                    < current_direct_participation_e8s ({current_direct_participation_e8s})"
                );
                0
            })
    }

    /// Update derived fields:
    /// - direct_participation_icp_e8s (derived from self.buyers)
    /// - neurons_fund_participation_icp_e8s (derived from `direct_participation_icp_e8s`)
    fn update_total_participation_amounts(&mut self) {
        let direct_participation_icp_e8s = self
            .buyers
            .values()
            .map(|x| x.amount_icp_e8s())
            .fold(0_u64, |sum, v| sum.saturating_add(v));
        self.direct_participation_icp_e8s = Some(direct_participation_icp_e8s);

        let (neurons_fund_participation, neurons_fund_participation_constraints) =
            if let Some(init) = &self.init {
                (
                    &init.neurons_fund_participation,
                    &init.neurons_fund_participation_constraints,
                )
            } else {
                return;
            };
        match (
            neurons_fund_participation,
            neurons_fund_participation_constraints,
        ) {
            (Some(true), Some(constraints)) => {
                // Matched funding scheme
                let participation: PolynomialNeuronsFundParticipation = match constraints.try_into()
                {
                    Ok(participation) => participation,
                    Err(err) => {
                        log!(
                            ERROR,
                            "Cannot validate swap.init.neurons_fund_participation_constraints: {}",
                            err.to_string(),
                        );
                        return;
                    }
                };
                let neurons_fund_participation_icp_e8s = match MatchedParticipationFunction::apply(
                    &participation,
                    direct_participation_icp_e8s,
                ) {
                    Ok(neurons_fund_participation_icp_e8s) => {
                        // Capping mitigates a potentially confusing situation in which the Swap's
                        // best `neurons_fund_participation_icp_e8s` estimate for whatever reason
                        // exceeds the amount allocated by the Neurons' Fund before the swap started.
                        neurons_fund_participation_icp_e8s.min(
                            // Defaulting to `u64::MAX` since we are computing minimum. Practically,
                            // this shouldn't happen, as `max_neurons_fund_participation_icp_e8s`
                            // is expected to be set here.
                            constraints
                                .max_neurons_fund_participation_icp_e8s
                                .unwrap_or(u64::MAX),
                        )
                    }
                    Err(err) => {
                        log!(
                            ERROR,
                            "Cannot compute neurons_fund_participation_icp_e8s for \
                        direct_participation_icp_e8s={}: {}",
                            direct_participation_icp_e8s,
                            err.to_string(),
                        );
                        return;
                    }
                };
                self.neurons_fund_participation_icp_e8s = Some(neurons_fund_participation_icp_e8s);
            }
            (Some(true), None) => {
                log!(
                    ERROR,
                    "neurons_fund_participation=true, but neurons_fund_participation_constraints \
                    is not set."
                );
                self.neurons_fund_participation_icp_e8s = Some(0);
            }
            (Some(false), _) => {
                // No Neurons' Fund participation
                self.neurons_fund_participation_icp_e8s = Some(0);
            }
            (None, _) => {
                // Fixed funding scheme
                self.neurons_fund_participation_icp_e8s = Some(
                    self.cf_participants
                        .iter()
                        .map(|x| x.participant_total_icp_e8s())
                        .fold(0, |sum, v| sum.saturating_add(v)),
                )
            }
        }
    }

    /// This function updates the current contribution from direct and Neurons' Fund participants.
    ///
    /// This function should be called directly exclusively in the following two cases:
    /// (1) In `Swap.try_open` to ensure that the fields are initialized.
    /// (2) Directly in unit tests (see `update_derived_fields`).
    #[cfg(target_arch = "wasm32")]
    fn update_derived_fields(&mut self) {
        self.update_total_participation_amounts()
    }

    /// This function helps unit testing the Swap canister. Normally, the derived fields should be
    /// updated as soon as the old values are invalid. However, in unit testing, we cannot rely on
    /// all the right functions being called. For example, refresh_buyer_token_e8s is
    /// responsible for calling update_total_participation_amounts. While writing a unit test
    /// expressing consistency between several fields of Swap, we might not want to also call
    /// refresh_buyer_token_e8s. Thus, in such scenarios we need update_derived_fields to ensure
    /// that the derived fields are updated.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn update_derived_fields(&mut self) {
        // More update_${specific_field} methods might be added here in the future.
        self.update_total_participation_amounts()
    }

    /// The count of unique CommunityFund Neurons.
    pub fn cf_neuron_count(&self) -> u64 {
        self.cf_participants
            .iter()
            .flat_map(|cf_participant| &cf_participant.cf_neurons)
            .count() as u64
    }

    /// Determines if the Swap is in it's terminal state
    /// based on it's lifecycle.
    fn lifecycle_is_terminal(&self) -> bool {
        self.lifecycle().is_terminal()
    }

    //
    // --- state transition functions ------------------------------------------
    //

    /// Tries to transition the Swap Lifecycle to `Lifecycle::Open`.
    /// Returns true if a transition was made, and false otherwise.
    pub fn try_open(&mut self, now_seconds: u64) -> bool {
        if !self.can_open(now_seconds) {
            return false;
        }
        // set the purge_old_ticket last principal so that the routine can start
        // in the next heartbeat
        self.purge_old_tickets_next_principal = Some(FIRST_PRINCIPAL_BYTES.to_vec());
        self.update_derived_fields();
        self.set_lifecycle(Lifecycle::Open);

        true
    }

    /// Attempts to finalize the swap. If this function calls [`Self::finalize`],
    /// it will set `self.already_tried_to_auto_finalize` to `Some(true)`, and
    /// won't try to finalize the swap again, even if called again.
    ///
    /// The argument 'now_fn' is a function that returns the current time
    /// for bookkeeping of transfers. For easier testing, it is given
    /// an argument that is 'false' to get the timestamp when a
    /// transfer is initiated and 'true' to get the timestamp when a
    /// transfer is successful.
    pub async fn try_auto_finalize(
        &mut self,
        now_fn: fn(bool) -> u64,
        environment: &mut impl CanisterEnvironment,
    ) -> Result<FinalizeSwapResponse, String> {
        self.can_auto_finalize()?;

        // We don't want to try to finalize the swap more than once. So we'll
        // set `self.already_tried_to_auto_finalize` to true, so we don't try
        // again.
        log!(
            INFO,
            "Attempting to automatically finalize the swap at timestamp {}. (Will not automatically attempt again even if this fails.)",
            now_fn(false)
        );
        self.already_tried_to_auto_finalize = Some(true);

        // Attempt finalization
        let auto_finalize_swap_response = self.finalize(now_fn, environment).await;

        // Record the result
        if self.auto_finalize_swap_response.is_some() {
            log!(
                ERROR,
                "Somehow, auto-finalization happened twice (second time at {}). Overriding self.auto_finalize_swap_response, old value was: {:?}",
                now_fn(true),
                auto_finalize_swap_response,
            );
        }
        self.auto_finalize_swap_response = Some(auto_finalize_swap_response.clone());

        Ok(auto_finalize_swap_response)
    }

    /// Computes `amount_icp_e8s` scaled by (`total_sns_e8s` divided by
    /// `total_icp_e8s`), but perform the computation in integer space
    /// by computing `(amount_icp_e8s * total_sns_e8s) /
    /// total_icp_e8s` in 128 bit space.
    fn scale(amount_icp_e8s: u64, total_sns_e8s: u64, total_icp_e8s: NonZeroU64) -> u64 {
        assert!(amount_icp_e8s <= u64::from(total_icp_e8s));
        // Note that the multiplication cannot overflow as both factors fit in 64 bits.
        let r = (amount_icp_e8s as u128)
            .saturating_mul(total_sns_e8s as u128)
            .div(NonZeroU128::from(total_icp_e8s));
        // This follows logically from the initial assert `amount_icp_e8s <= total_icp_e8s`.
        assert!(r <= u64::MAX as u128);
        r as u64
    }

    /// Tries to transition the Swap Lifecycle to `Lifecycle::Committed`.
    /// Returns true if a transition was made, and false otherwise.
    pub fn try_commit(&mut self, now_seconds: u64) -> bool {
        if !self.can_commit(now_seconds) {
            return false;
        }

        self.set_lifecycle(Lifecycle::Committed);
        self.decentralization_swap_termination_timestamp_seconds = Some(now_seconds);

        true
    }

    /// Create the SNS Neuron recipes for direct participants and Neurons' Fund
    /// participants of the SNS token swap.
    ///
    /// This method assumes that all direct participants and neurons' fund
    /// participants have been set in the state of the Swap canister.
    ///
    /// This method is meant to be idempotent. It can be called multiple times
    /// but will only create a participant's `SnsNeuronRecipe` once. On the first
    /// call to create_sns_neuron_recipes, newly created recipes will increment
    /// the `success` field of the SweepResult. On successive calls, the
    /// `skipped` field of SweepResult will be incremented.
    pub fn create_sns_neuron_recipes(&mut self) -> SweepResult {
        let Some(params) = self.params.as_ref() else {
            log!(
                ERROR,
                "Halting create_sns_neuron_recipes(). Params is missing",
            );
            return SweepResult::new_with_global_failures(1);
        };

        let Some(neuron_basket_construction_parameters) =
            params.neuron_basket_construction_parameters.as_ref()
        else {
            log!(
                ERROR,
                "Halting create_sns_neuron_recipes(). Neuron_basket_construction_parameters is missing",
            );
            return SweepResult::new_with_global_failures(1);
        };

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting create_sns_neuron_recipes(). Init is missing or corrupted: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };
        // The following methods are safe to call since we validated Init in the above block
        let nns_governance_canister_id = init.nns_governance_or_panic();

        let mut sweep_result = SweepResult::default();

        // We are selling SNS tokens for the base token (ICP), or, in
        // general, whatever token the ledger referred to as the ICP
        // ledger holds.
        let sns_being_offered_e8s = params.sns_token_e8s;
        // Note that this value has to be > 0 as we have > 0
        // participants each with > 0 ICP contributed.
        let total_participant_icp_e8s = match NonZeroU64::try_from(
            self.current_total_participation_e8s(),
        ) {
            Ok(total_participant_icp_e8s) => total_participant_icp_e8s,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting create_sns_neuron_recipes(). Swap is finalizing with 0 total participation: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };

        // Keep track of SNS tokens sold just to check that the amount
        // is correct at the end.
        let mut total_sns_tokens_sold_e8s: u64 = 0;

        // =====================================================================
        // ===            This is where the actual swap happens              ===
        // =====================================================================
        for (buyer_principal, buyer_state) in self.buyers.iter_mut() {
            // The case that on a previous attempt at creating this neuron recipe, it was
            // successfully created and recorded. Count the number of neuron recipes that
            // would have been created.
            if buyer_state.has_created_neuron_recipes == Some(true) {
                sweep_result.skipped += neuron_basket_construction_parameters.count as u32;
                continue;
            }

            let amount_sns_e8s = Swap::scale(
                buyer_state.amount_icp_e8s(),
                sns_being_offered_e8s,
                total_participant_icp_e8s,
            );

            let Some(buyer_principal) = string_to_principal(buyer_principal) else {
                sweep_result.invalid += neuron_basket_construction_parameters.count as u32;
                continue;
            };
            match create_sns_neuron_basket_for_direct_participant(
                &buyer_principal,
                amount_sns_e8s,
                neuron_basket_construction_parameters,
                NEURON_BASKET_MEMO_RANGE_START,
            ) {
                Ok(direct_participant_sns_neuron_recipes) => {
                    self.neuron_recipes
                        .extend(direct_participant_sns_neuron_recipes);
                    total_sns_tokens_sold_e8s =
                        total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                    sweep_result.success += neuron_basket_construction_parameters.count as u32;
                    buyer_state.has_created_neuron_recipes = Some(true);
                }
                Err(error_message) => {
                    log!(
                        ERROR,
                        "Error creating a neuron basked for identity {}. Reason: {}",
                        buyer_principal,
                        error_message
                    );
                    sweep_result.failure += neuron_basket_construction_parameters.count as u32;
                    continue;
                }
            };
        }

        // Create the neuron basket for the Neuron Fund investors. The unique
        // identifier for an SNS Neuron is the SNS Ledger Subaccount, which
        // is a hash of PrincipalId and some unique memo. Since Neurons' Fund
        // investors in the swap use the NNS Governance principal_id, there can be
        // neuron id collisions, so there must be a global memo used for all baskets
        // for all NF investors.
        let mut global_neurons_fund_memo: u64 = NEURON_BASKET_MEMO_RANGE_START;
        for neurons_fund_participant in self.cf_participants.iter_mut() {
            let controller = neurons_fund_participant.try_get_controller();

            for neurons_fund_neuron in neurons_fund_participant.cf_neurons.iter_mut() {
                // Create a closure to ensure `global_neurons_fund_memo` is incremented in all cases
                let hotkeys = neurons_fund_neuron.hotkeys.clone().unwrap_or_default();
                let process_neurons_fund_neuron = || {
                    let controller = match controller.clone() {
                        Ok(nns_neuron_controller_principal) => nns_neuron_controller_principal,
                        Err(e) => {
                            log!(
                                ERROR,
                                "Error getting the controller for {neurons_fund_neuron:?} principal: {e}"
                            );
                            sweep_result.invalid +=
                                neuron_basket_construction_parameters.count as u32;
                            return;
                        }
                    };

                    // The case that on a previous attempt at creating this neuron recipe, it was
                    // successfully created and recorded. Count the number of neuron recipes that
                    // would have been created.
                    if neurons_fund_neuron.has_created_neuron_recipes == Some(true) {
                        sweep_result.skipped += neuron_basket_construction_parameters.count as u32;
                        return;
                    }

                    let amount_sns_e8s = Swap::scale(
                        neurons_fund_neuron.amount_icp_e8s,
                        sns_being_offered_e8s,
                        total_participant_icp_e8s,
                    );

                    match create_sns_neuron_basket_for_neurons_fund_participant(
                        &controller,
                        hotkeys.principals,
                        neurons_fund_neuron.nns_neuron_id,
                        amount_sns_e8s,
                        neuron_basket_construction_parameters,
                        global_neurons_fund_memo,
                        nns_governance_canister_id.get(),
                    ) {
                        Ok(cf_participants_sns_neuron_recipes) => {
                            sweep_result.success +=
                                neuron_basket_construction_parameters.count as u32;
                            self.neuron_recipes
                                .extend(cf_participants_sns_neuron_recipes);
                            total_sns_tokens_sold_e8s =
                                total_sns_tokens_sold_e8s.saturating_add(amount_sns_e8s);
                            neurons_fund_neuron.has_created_neuron_recipes = Some(true);
                        }
                        Err(error_message) => {
                            log!(
                                ERROR,
                                "Error creating a neuron basked for identity {}. Reason: {}",
                                controller,
                                error_message
                            );
                            sweep_result.failure +=
                                neuron_basket_construction_parameters.count as u32;
                        }
                    };
                };

                // Call the closure
                process_neurons_fund_neuron();

                // Increment the memo by the number neurons in a neuron basket. This means that
                // previous idempotent calls should increment global_neurons_fund_memo and handle overflow
                match global_neurons_fund_memo
                    .checked_add(neuron_basket_construction_parameters.count)
                {
                    Some(new_value) => {
                        global_neurons_fund_memo = new_value;
                    }
                    None => {
                        sweep_result.global_failures += 1;
                        // This will exit the entire function, ending all loops, but persist the data that has already been processed
                        return sweep_result;
                    }
                }
            }
        }
        log!(
            INFO,
            "SNS Neuron Recipes Created; {} successes, {} failures, {} invalids, and {} skips. Participants receive a total of {} out of {} (change {});",
            sweep_result.success,
            sweep_result.failure,
            sweep_result.invalid,
            sweep_result.skipped,
            total_sns_tokens_sold_e8s,
            sns_being_offered_e8s,
            sns_being_offered_e8s - total_sns_tokens_sold_e8s
        );

        sweep_result
    }

    /// Tries to transition the Swap Lifecycle to `Lifecycle::Aborted`.
    /// Returns true if a transition was made, and false otherwise.
    pub fn try_abort(&mut self, now_seconds: u64) -> bool {
        if !self.can_abort(now_seconds) {
            return false;
        }

        self.set_lifecycle(Lifecycle::Aborted);
        self.decentralization_swap_termination_timestamp_seconds = Some(now_seconds);

        true
    }

    //
    // --- state modifying methods ---------------------------------------------
    //

    /// Runs those tasks that should be run on canister heartbeat.
    ///
    /// The argument 'now_fn' is a function that returns the current time
    /// for bookkeeping of transfers. For easier testing, it is given
    /// an argument that is 'false' to get the timestamp when a
    /// transfer is initiated and 'true' to get the timestamp when a
    /// transfer is successful.
    pub async fn heartbeat(&mut self, now_fn: fn(bool) -> u64) {
        let heartbeat_start_seconds = now_fn(false);

        // Purge old tickets
        const NUMBER_OF_TICKETS_THRESHOLD: u64 = 100_000_000; // 100M * ~size(ticket) = ~25GB
        const TWO_DAYS_IN_NANOSECONDS: u64 = 60 * 60 * 24 * 2 * 1_000_000_000;
        const MAX_NUMBER_OF_PRINCIPALS_TO_INSPECT: u64 = 100_000;

        self.try_purge_old_tickets(
            dfn_core::api::time_nanos,
            NUMBER_OF_TICKETS_THRESHOLD,
            TWO_DAYS_IN_NANOSECONDS,
            MAX_NUMBER_OF_PRINCIPALS_TO_INSPECT,
        );

        // Automatically transition the state. Only one state transition per heartbeat.

        // Auto-open the swap
        if self.try_open(heartbeat_start_seconds) {
            log!(INFO, "Swap opened at timestamp {}", heartbeat_start_seconds);
        }
        // Auto-commit the swap
        else if self.try_commit(heartbeat_start_seconds) {
            log!(
                INFO,
                "Swap committed at timestamp {}",
                heartbeat_start_seconds
            );
        }
        // Auto-abort the swap
        else if self.try_abort(heartbeat_start_seconds) {
            log!(
                INFO,
                "Swap aborted at timestamp {}",
                heartbeat_start_seconds
            );
        }
        // Auto-finalize the swap
        // We discard the error, if there is one, because to log it would mean
        // it would be logged every heartbeat where we fall through to this
        // point (and we don't want to spam the logs).
        else if self.can_auto_finalize().is_ok() {
            // First, record when the finalization started, in case this function is
            // refactored to `await` before this point.
            let auto_finalization_start_seconds = now_fn(false);

            // Then, get the environment
            let environment = self
                .init
                .as_ref()
                .ok_or_else(|| "couldn't get `init`".to_string())
                .and_then(|init| init.environment());

            match environment {
                Err(error) => {
                    log!(
                        ERROR,
                        "Failed to get environment when attempting auto-finalization. Error: {error}"
                    );
                }
                Ok(mut environment) => {
                    // Then, attempt the auto-finalization
                    // `try_auto_finalize` will never return `Error` here
                    // because we already checked `self.can_auto_finalize()`
                    // above, and `try_auto_finalize` will only return an error
                    // if `can_auto_finalize` does.
                    // The FinalizeSwapResponse from finalization will be logged
                    // by `Self::finalize`.
                    if self
                        .try_auto_finalize(now_fn, &mut environment)
                        .await
                        .is_ok()
                    {
                        // The current time is now probably different than the time when
                        // auto-finalization began, due to the `await`.
                        let auto_finalization_finish_seconds = now_fn(true);
                        log!(INFO, "Swap auto-finalization finished at timestamp {auto_finalization_finish_seconds} (started at timestamp {auto_finalization_start_seconds})");
                    }
                }
            }
        }
    }

    /*

    Transfers IN - these transfers happen on ICP ledger canister and
    cannot be restricted based on the state of the swap
    canister. Thus, the swap canister can only be notified about
    transfers happening on these canisters.

     */

    /// In state Open, this method can be called to refresh the amount
    /// of ICP a buyer has contributed from the ICP ledger canister.
    ///
    /// It is assumed that prior to calling this method, tokens have
    /// been transfer by the buyer to a subaccount of the swap
    /// canister (this canister) on the ICP ledger.
    /// Also, deletes an existing ticket if it has been fully executed
    /// (i.e. the requested increment is >= that the ticket amount).
    /// (This allows participation to be increased later.)
    ///
    /// If the SNS had specified a swap confirmation text, the caller of this
    /// function must accept this confirmation by sending the exact same text
    /// as an argument to this function (otherwise, the call will result in
    /// an error).
    ///
    /// If a ledger transfer was successfully made, but this call
    /// fails (many reasons are possible), the owner of the ICP sent
    /// to the subaccount can reclaim their tokens using `error_refund_icp`
    /// once this swap is closed (committed or aborted).
    ///
    /// TODO(NNS1-1682): attempt to refund ICP that cannot be accepted.
    pub async fn refresh_buyer_token_e8s(
        &mut self,
        buyer: PrincipalId,
        confirmation_text: Option<String>,
        this_canister: CanisterId,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> Result<RefreshBuyerTokensResponse, String> {
        use swap_participation::*;

        // These two checks need to be repeated after awaiting the response from the ICP ledger.
        self.validate_lifecycle_is_open()
            .map_err(context_before_awaiting_icp_ledger_response)?;
        self.validate_possibility_of_direct_participation()
            .map_err(context_before_awaiting_icp_ledger_response)?;

        // User input validation doesn't expire after await, so this check doesn't need repetition.
        self.validate_confirmation_text(confirmation_text)?;

        // Look for the token balance of the specified principal's subaccount on 'this' canister.
        let e8s = {
            let account = Account {
                owner: this_canister.get().0,
                subaccount: Some(principal_to_subaccount(&buyer)),
            };
            icp_ledger
                .account_balance(account)
                .await
                .map_err(|x| x.to_string())?
                .get_e8s()
        };

        // Recheck lifecycle state and ICP target after async call because the swap could have
        // been closed (committed or aborted) while the call to get the account balance was
        // outstanding.
        self.validate_lifecycle_is_open()
            .map_err(context_after_awaiting_icp_ledger_response)?;
        self.validate_possibility_of_direct_participation()
            .map_err(context_after_awaiting_icp_ledger_response)?;

        // Once swap is OPEN, the Swap.params field is set. In light of validation performed
        // above, we should be able to `expect` this value without a panic.
        let params = &self.params.as_ref().expect("Expected params to be set");
        // Subtraction safe because of the preceding if-statement.
        let max_increment_e8s = self.available_direct_participation_e8s();

        // Check that the maximum number of participants has not been reached yet.
        {
            let num_direct_participants = self.buyers.len() as u64;
            let num_sns_neurons_per_basket = params
                .neuron_basket_construction_parameters
                .as_ref()
                .expect("neuron_basket_construction_parameters must be specified")
                .count;
            if (num_direct_participants + 1) * num_sns_neurons_per_basket
                > MAX_NEURONS_FOR_DIRECT_PARTICIPANTS
            {
                return Err(format!(
                    "The swap has reached the maximum number of direct participants ({}) and does \
                     not accept new participants; existing participants may still increase their \
                     ICP participation amount. This constraint ensures that SNS neuron baskets can \
                     be created for all existing participants (SNS neuron basket size: {}, \
                     MAX_NEURONS_FOR_DIRECT_PARTICIPANTS: {}).",
                    num_direct_participants,
                    num_sns_neurons_per_basket,
                    MAX_NEURONS_FOR_DIRECT_PARTICIPANTS,
                ));
            }
        }

        // Check that the minimum amount has been transferred before
        // actually creating an entry for the buyer.
        if e8s < params.min_participant_icp_e8s {
            return Err(format!(
                "Amount transferred: {}; minimum required to participate: {}",
                e8s, params.min_participant_icp_e8s
            ));
        }
        let max_participant_icp_e8s = params.max_participant_icp_e8s;

        let old_amount_icp_e8s = self
            .buyers
            .get(&buyer.to_string())
            .map_or(0, |buyer| buyer.amount_icp_e8s());

        if old_amount_icp_e8s >= e8s {
            // Already up-to-date. Strict inequality can happen if messages are re-ordered.
            return Ok(RefreshBuyerTokensResponse {
                icp_accepted_participation_e8s: old_amount_icp_e8s,
                icp_ledger_account_balance_e8s: e8s,
            });
        }
        // Subtraction safe because of the preceding if-statement.
        let requested_increment_e8s = e8s - old_amount_icp_e8s;
        let actual_increment_e8s = std::cmp::min(max_increment_e8s, requested_increment_e8s);
        let new_balance_e8s = old_amount_icp_e8s.saturating_add(actual_increment_e8s);
        if new_balance_e8s > max_participant_icp_e8s {
            log!(
                INFO,
                "Participant {} contributed {} e8s - the limit per participant is {}",
                buyer,
                new_balance_e8s,
                max_participant_icp_e8s
            );
        }

        // Limit the participation based on the maximum per participant.
        let new_balance_e8s = std::cmp::min(new_balance_e8s, max_participant_icp_e8s);

        // Check that the new_balance_e8s is bigger than the minimum required for
        // participating.
        if new_balance_e8s < params.min_participant_icp_e8s {
            return Err(format!(
                "Rejecting participation of effective amount {}; minimum required to participate: {}",
                new_balance_e8s, params.min_participant_icp_e8s
            ));
        }

        // Try to fetch the current ticket of the buyer
        let principal = Blob::from_bytes(buyer.as_slice().into());
        if let Some(ticket_sns_sale_canister) =
            memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal))
        {
            let amount_ticket = ticket_sns_sale_canister.amount_icp_e8s;
            // If the user has already bought tokens in this swap at a prior to the current purchase the
            // balance in the subaccount of the SNS sales canister that corresponds to the user will
            // show both the ICP balance used for the previous buy and the ICP balance used to make
            // this new purchase of SNS tokens (requested_increment_e8s + old_amount_icp_e8s).
            // If the ticket has a lower amount specified than what is the requested amount of
            // tokens according to the ICP balance in the subaccount, this check should pass
            // and the actual requested amount of tokens will be used.
            // Lower amounts than specified on the ticket are not excepted.
            if amount_ticket > requested_increment_e8s {
                return Err(format!(
                    "The available balance to be topped up ({requested_increment_e8s}) \
                    by the buyer is smaller than the amount requested ({amount_ticket})."
                ));
            }
            // The requested balance in the ticket matches the balance to be topped up in the swap
            // --> Delete fully executed ticket, if it exists and proceed with the top up
            memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow_mut().remove(&principal));
            // If there exists no ticket for the buyer, the payment flow will simply ignore the ticket
        }

        // Append to a new buyer to the BUYERS_LIST_INDEX
        let is_preexisting_buyer = self.buyers.contains_key(&buyer.to_string());
        if !is_preexisting_buyer {
            insert_buyer_into_buyers_list_index(buyer)
                .map_err(|grow_failed| {
                    format!(
                        "Failed to add buyer {} to state, the canister's stable memory could not grow: {}",
                        buyer, grow_failed
                    )
                })?;
        }

        self.buyers
            .entry(buyer.to_string())
            .or_insert_with(|| BuyerState::new(0))
            .set_amount_icp_e8s(new_balance_e8s);
        // We compute the current participation amounts once and store the result in Swap's state,
        // for efficiency reasons.
        self.update_total_participation_amounts();

        log!(
            INFO,
            "Refresh_buyer_tokens for buyer {}; old e8s {}; new e8s {}",
            buyer,
            old_amount_icp_e8s,
            new_balance_e8s,
        );
        if new_balance_e8s.saturating_sub(old_amount_icp_e8s) >= max_increment_e8s {
            log!(
                INFO,
                "Swap has reached the direct participation target of {} ICP e8s.",
                self.max_direct_participation_e8s(),
            );
        }

        Ok(RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: new_balance_e8s,
            icp_ledger_account_balance_e8s: e8s,
        })
    }

    /*

    Transfers OUT.

     */

    // Returns the ticket if a ticket was found for the caller and the ticket
    // was removed successfully. Returns None if no ticket was found for the caller.
    // Only the owner of a ticket can remove it.
    pub fn notify_payment_failure(&mut self, caller: &PrincipalId) -> NotifyPaymentFailureResponse {
        let principal = Blob::from_bytes(caller.as_slice().into());
        let ticket = match memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal)) {
            Some(ticket) => ticket,
            None => return NotifyPaymentFailureResponse { ticket: None },
        };

        // process ticket.
        memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow_mut().remove(&principal));
        log!(
            INFO,
            "{}",
            format!(
                "Ticket with ID: {} was deleted successfully. Ticket: {:?}",
                ticket.ticket_id, ticket
            )
        );
        NotifyPaymentFailureResponse {
            ticket: Some(ticket),
        }
    }

    /// Determines if the conditions have been met in order to
    /// restore the dapp canisters to the fallback controller ids.
    /// The lifecycle MUST be set to Aborted via the commit method.
    pub fn should_restore_dapp_control(&self) -> bool {
        self.lifecycle() == Lifecycle::Aborted
    }

    /// Calls SNS Root's set_dapp_controllers with the Swap canister's configured
    /// `fallback_controller_principal_ids`.
    pub async fn restore_dapp_controllers(
        &self,
        sns_root_client: &mut impl SnsRootClient,
    ) -> Result<Result<SetDappControllersResponse, CanisterCallError>, String> {
        let (controller_principal_ids, errors): (Vec<PrincipalId>, Vec<String>) = self
            .init()?
            .fallback_controller_principal_ids
            .iter()
            .map(|maybe_principal_id| PrincipalId::from_str(maybe_principal_id))
            .partition_map(|result| match result {
                Ok(p) => Either::Left(p),
                Err(msg) => Either::Right(msg.to_string()),
            });

        if !errors.is_empty() {
            return Err(format!(
                "Could not set_dapp_controllers, one or more fallback_controller_principal_ids \
                could not be parsed as a PrincipalId. {:?}",
                errors.join("\n")
            ));
        }

        Ok(sns_root_client
            .set_dapp_controllers(SetDappControllersRequest {
                canister_ids: None,
                controller_principal_ids,
            })
            .await)
    }

    /// Calls SNS Root's set_dapp_controllers with SNS Root's principal id,
    /// giving SNS Root sole control.
    pub async fn take_sole_control_of_dapp_controllers(
        &self,
        sns_root_client: &mut impl SnsRootClient,
    ) -> Result<Result<SetDappControllersResponse, CanisterCallError>, String> {
        let sns_root_principal_id = self.init()?.sns_root()?.get();
        Ok(sns_root_client
            .set_dapp_controllers(SetDappControllersRequest {
                canister_ids: None,
                controller_principal_ids: vec![sns_root_principal_id],
            })
            .await)
    }

    /// Calls restore_dapp_controllers() and handles errors for finalize
    async fn restore_dapp_controllers_for_finalize(
        &self,
        sns_root_client: &mut impl SnsRootClient,
    ) -> SetDappControllersCallResult {
        let result = self.restore_dapp_controllers(sns_root_client).await;

        match result {
            Ok(result) => result.into(),
            Err(err_message) => {
                log!(ERROR, "Halting set_dapp_controllers(), {:?}", err_message);
                SetDappControllersCallResult { possibility: None }
            }
        }
    }

    /// Calls take_sole_control_of_dapp_controllers() and handles errors for finalize
    async fn take_sole_control_of_dapp_controllers_for_finalize(
        &self,
        sns_root_client: &mut impl SnsRootClient,
    ) -> SetDappControllersCallResult {
        let result = self
            .take_sole_control_of_dapp_controllers(sns_root_client)
            .await;

        match result {
            Ok(result) => result.into(),
            Err(err_message) => {
                log!(ERROR, "Halting set_dapp_controllers(), {:?}", err_message);
                SetDappControllersCallResult { possibility: None }
            }
        }
    }

    /// Acquires the lock on `finalize_swap`.
    pub fn lock_finalize_swap(&mut self) -> Result<(), String> {
        match self.is_finalize_swap_locked() {
            true => Err("The Swap canister has finalize_swap call already in progress".to_string()),
            false => {
                self.finalize_swap_in_progress = Some(true);
                Ok(())
            }
        }
    }

    /// Releases the lock on `finalize_swap`.
    fn unlock_finalize_swap(&mut self) {
        match self.is_finalize_swap_locked() {
            true => self.finalize_swap_in_progress = Some(false),
            false => {
                log!(
                    ERROR,
                    "Unexpected condition when unlocking finalize_swap_in_progress. \
                    The lock was not held: {:?}.",
                    self.finalize_swap_in_progress
                );
            }
        }
    }

    /// Checks the internal state of `finalize_swap_in_progress` lock.
    pub fn is_finalize_swap_locked(&self) -> bool {
        match self.finalize_swap_in_progress {
            Some(true) => true,
            None | Some(false) => false,
        }
    }

    /// Distributes funds, and if the swap was successful, creates neurons. Returns
    /// a summary of (sub)actions that were performed.
    ///
    /// If the swap is not over yet, returns an error message.
    ///
    /// If swap was successful (i.e. it is in the Lifecycle::Committed phase), then
    /// ICP is sent to the SNS governance canister, and SNS tokens are sent to SNS
    /// neuron ledger accounts (i.e. subaccounts of SNS governance for the principal
    /// that funded the neuron).
    ///
    /// If the swap ended unsuccessfully (i.e. it is in the Lifecycle::Aborted
    /// phase), then ICP is send back to the buyers.
    ///
    /// The argument 'now_fn' is a function that returns the current time
    /// for bookkeeping of transfers. For easier testing, it is given
    /// an argument that is 'false' to get the timestamp when a
    /// transfer is initiated and 'true' to get the timestamp when a
    /// transfer is successful.
    ///
    /// While finalize is marked asynchronous to allow awaits across
    /// IC messages boundaries, it only allows one invocation at a time.
    /// Additional attempts to invoke finalize will return without
    /// performing any subactions.
    pub async fn finalize(
        &mut self,
        now_fn: fn(bool) -> u64,
        environment: &mut impl CanisterEnvironment,
    ) -> FinalizeSwapResponse {
        // Acquire the lock or return a FinalizeSwapResponse with an error message.
        if let Err(error_message) = self.lock_finalize_swap() {
            return FinalizeSwapResponse::with_error(error_message);
        }

        // The lock is now acquired and asynchronous calls to finalize are blocked.
        // Perform all subactions.
        let finalize_swap_response = self.finalize_inner(now_fn, environment).await;

        if finalize_swap_response.has_error_message() {
            log!(
                ERROR,
                "The swap did not finalize successfully. \n\
                finalize_swap_response: {finalize_swap_response:?}"
            );
        } else {
            log!(
                INFO,
                "The swap finalized successfully. \n\
                finalize_swap_response: {finalize_swap_response:?}"
            );
        }

        // Release the lock. Note, if there is a panic, the lock will
        // not be released. In that case, the Swap canister will need
        // to be upgraded to release the lock.
        self.unlock_finalize_swap();

        finalize_swap_response
    }

    /// Performs the subactions of finalize.
    ///
    /// IMPORTANT: As the canister awaits across message barriers to make
    /// inter-canister calls, finalize_inner and all subsequent methods MUST
    /// avoid panicking or the lock resource will not be released.
    ///
    /// In the case of an unexpected panic, the Swap canister can be upgraded
    /// and a post-upgrade hook can release the lock.
    pub async fn finalize_inner(
        &mut self,
        now_fn: fn(bool) -> u64,
        environment: &mut impl CanisterEnvironment,
    ) -> FinalizeSwapResponse {
        let mut finalize_swap_response = FinalizeSwapResponse::default();

        if let Err(e) = self.can_finalize() {
            finalize_swap_response.set_error_message(e);
            return finalize_swap_response;
        }

        // Transfer the ICP tokens from the Swap canister.
        finalize_swap_response
            .set_sweep_icp_result(self.sweep_icp(now_fn, environment.icp_ledger()).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Settle the Neurons' Fund participation in the token swap.
        finalize_swap_response.set_settle_neurons_fund_participation_result(
            self.settle_neurons_fund_participation(environment.nns_governance_mut())
                .await,
        );
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        if self.should_restore_dapp_control() {
            // Restore controllers of dapp canisters to their original
            // owners (i.e. self.init.fallback_controller_principal_ids).
            finalize_swap_response.set_set_dapp_controllers_result(
                self.restore_dapp_controllers_for_finalize(environment.sns_root_mut())
                    .await,
            );

            // In the case of returning control of the dapp(s) to the fallback
            // controllers, finalize() need not do any more work, so always return
            // and end execution.
            return finalize_swap_response;
        }

        // Create the SnsNeuronRecipes based on the contribution of direct and NF participants
        finalize_swap_response
            .set_create_sns_neuron_recipes_result(self.create_sns_neuron_recipes());
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Transfer the SNS tokens from the Swap canister.
        finalize_swap_response
            .set_sweep_sns_result(self.sweep_sns(now_fn, environment.sns_ledger()).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Once SNS tokens have been distributed to the correct accounts, claim
        // them as neurons on behalf of the Swap participants.
        finalize_swap_response.set_claim_neuron_result(
            self.claim_swap_neurons(environment.sns_governance_mut())
                .await,
        );
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        finalize_swap_response.set_set_mode_call_result(
            Self::set_sns_governance_to_normal_mode(environment.sns_governance_mut()).await,
        );

        // The following step is non-critical, so we'll do it after we set
        // governance to normal mode, but only if there were no errors.
        if !finalize_swap_response.has_error_message() {
            finalize_swap_response.set_set_dapp_controllers_result(
                self.take_sole_control_of_dapp_controllers_for_finalize(environment.sns_root_mut())
                    .await,
            );
        }

        finalize_swap_response
    }

    /// In state COMMITTED. Claims SNS Neurons on behalf of participants.
    ///
    /// Returns the following values:
    /// - the number of skipped neurons because of previous claims
    /// - the number of successful claims
    /// - the number of failed claims
    /// - the number of invalid claims due to corrupted neuron recipe state
    /// - the number of global failures due to corrupted Swap state or inconsistent API responses
    pub async fn claim_swap_neurons(
        &mut self,
        sns_governance_client: &mut impl SnsGovernanceClient,
    ) -> SweepResult {
        if self.lifecycle() != Lifecycle::Committed {
            log!(
                ERROR,
                "Halting claim_neurons(). SNS Neurons cannot be distributed if \
                Lifecycle is not COMMITTED. Current Lifecycle: {:?}",
                self.lifecycle()
            );
            return SweepResult::new_with_global_failures(1);
        }

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting claim_neurons(). State is missing or corrupted: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };

        // The following methods are safe to call since we validated Init in the above block
        let nns_governance = init.nns_governance_or_panic();
        let sns_transaction_fee_e8s = init.transaction_fee_e8s_or_panic();

        let mut sweep_result = SweepResult::default();

        // Create an index of NeuronId -> &mut SnsNeuronRecipe such that the SnsNeuronRecipe can
        // be accessed in O(1) time.
        let mut claimable_neurons_index = btreemap! {};

        // The `NeuronRecipe`s that will be used to create neurons. We are converting
        // `SnsNeuronRecipe`s to a type with a similar name, `NeuronRecipe`, as this is the type
        // expected by the SNS Governance canister.
        let mut neuron_recipes = vec![];

        for recipe in &mut self.neuron_recipes {
            // Here we convert the SnsNeuronRecipe (a Swap concept) to an SnsNeuronRecipe (an SNS
            // Governance concept).
            match recipe.to_neuron_recipe(nns_governance, sns_transaction_fee_e8s) {
                Ok(neuron_recipe) => {
                    let neuron_id = neuron_recipe.neuron_id.clone().expect(
                        "NeuronRecipe.neuron_id is always set by \
                        SnsNeuronRecipe::to_neuron_recipe",
                    );
                    claimable_neurons_index.insert(neuron_id, recipe);
                    neuron_recipes.push(neuron_recipe);
                }
                Err((error_type, error_message)) => {
                    log!(ERROR, "Error creating neuron recipe: {:?}", error_message);
                    match error_type {
                        // In the case of a bug due to programmer error, increment the invalid field.
                        ConversionError::Invalid => sweep_result.invalid += 1,
                        // If we've already processed ths neuron, increment the `skip` field.
                        ConversionError::AlreadyProcessed => sweep_result.skipped += 1,
                    }
                }
            }
        }

        // If neuron_recipes is empty, all recipes are either Invalid or Skipped and there
        // is no work to do.
        if neuron_recipes.is_empty() {
            return sweep_result;
        }

        sweep_result.consume(
            Self::batch_claim_swap_neurons(
                sns_governance_client,
                &mut neuron_recipes,
                &mut claimable_neurons_index,
            )
            .await,
        );

        sweep_result
    }

    /// A helper to batch claim the swap neurons, and process the results from SNS Governance.
    async fn batch_claim_swap_neurons(
        sns_governance_client: &mut impl SnsGovernanceClient,
        neuron_recipes: &mut Vec<NeuronRecipe>,
        claimable_neurons_index: &mut BTreeMap<NeuronId, &mut SnsNeuronRecipe>,
    ) -> SweepResult {
        log!(
            INFO,
            "Attempting to claim {} Neurons in SNS Governance. Batch size is {}",
            neuron_recipes.len(),
            CLAIM_SWAP_NEURONS_BATCH_SIZE
        );

        let mut sweep_result = SweepResult::default();

        while !neuron_recipes.is_empty() {
            let current_batch_limit =
                std::cmp::min(CLAIM_SWAP_NEURONS_BATCH_SIZE, neuron_recipes.len());

            let batch: Vec<NeuronRecipe> = neuron_recipes.drain(0..current_batch_limit).collect();
            // Used for various operations
            let batch_count = batch.len();

            log!(
                INFO,
                "Attempting to claim a batch of {} Neurons in SNS Governance.",
                batch_count,
            );

            let reply = sns_governance_client
                .claim_swap_neurons(ClaimSwapNeuronsRequest {
                    neuron_recipes: Some(NeuronRecipes::from(batch)),
                    neuron_parameters: None,
                })
                .await;

            let response = match reply {
                Ok(response) => response,
                Err(canister_call_error) => {
                    // The canister_call_error indicates a trap in the callback function, which
                    // could be the result of an unexpected panic in SNS Governance or an issue
                    // with the underlying Canister or Replica. As it is a CanisterCallError
                    // we hope that the canister being called rolls back to the appropriate checkpoint.
                    // The swap canister will mark the current batch and remaining neurons as failed
                    // and return. Calling finalize again will result in another attempt to
                    // claim those neurons.
                    log!(
                        ERROR,
                        "Encountered a CanisterCallError when claiming a batch of neurons. Err: {:?}",
                        canister_call_error,
                    );
                    sweep_result.global_failures += 1;
                    return sweep_result;
                }
            };

            let claimed_neurons = match response.claim_swap_neurons_result {
                Some(ClaimSwapNeuronsResult::Err(err_code)) => {
                    log!(
                        ERROR,
                        "claim_swap_neurons returned an error when claiming a batch of neurons. Err: {:?}",
                        ClaimSwapNeuronsError::try_from(err_code)
                    );
                    sweep_result.global_failures += 1;
                    return sweep_result;
                }
                Some(ClaimSwapNeuronsResult::Ok(claimed_neurons)) => claimed_neurons.swap_neurons,
                None => {
                    // This should not happen as it means the `claim_swap_neurons` is returning malformed
                    // input or there is a decoding problem in the Swap canister.
                    log!(
                        ERROR,
                        "ClaimSwapNeuronsResponse missing a ClaimSwapNeuronsResult. Response: {:?}",
                        response,
                    );
                    sweep_result.global_failures += 1;
                    return sweep_result;
                }
            };

            if claimed_neurons.len() != batch_count {
                log!(
                    ERROR,
                    "ClaimSwapNeuronsResponse's count of claimed_neurons is different than the count provided in the request. \
                    Request count {}. Response count {}.",
                    batch_count, claimed_neurons.len(),
                );
                sweep_result.global_failures += 1;
            }

            // Now process the actual statuses of the created neurons. Update the journal of the
            // NeuronRecipe and aggregate some stats
            for swap_neuron in claimed_neurons {
                sweep_result.consume(Self::process_swap_neuron(
                    swap_neuron,
                    claimable_neurons_index,
                ));
            }

            // TODO: Also indicate how many neurons could not be claimed in this batch.
            log!(
                INFO,
                "Successfully claimed {} SNS neurons ({} were skipped). \
                Current SweepResult progress {:?}",
                sweep_result.success,
                sweep_result.skipped,
                sweep_result,
            );
        }
        sweep_result
    }

    /// Given a SwapNeuron and an index, updates the correct SnsNeuronRecipe with the
    /// status of the SwapNeuron. Return a SweepResult to be consumed by claim_swap_neurons
    fn process_swap_neuron(
        swap_neuron: SwapNeuron,
        claimable_neurons_index: &mut BTreeMap<NeuronId, &mut SnsNeuronRecipe>,
    ) -> SweepResult {
        let mut sweep_result = SweepResult::default();

        let Some(neuron_id) = swap_neuron.id.as_ref() else {
            log!(ERROR, "Neuron must have an ID ({:?}).", swap_neuron);
            sweep_result.global_failures += 1;
            return sweep_result;
        };

        let claimed_swap_neuron_status = match ClaimedSwapNeuronStatus::try_from(swap_neuron.status)
        {
            Ok(claimed_swap_neuron_status) => claimed_swap_neuron_status,
            Err(err) => {
                log!(
                    ERROR,
                    "Could not update a ClaimStatus for ({:?}): {}",
                    swap_neuron,
                    err
                );
                sweep_result.global_failures += 1;
                return sweep_result;
            }
        };

        let Some(recipe) = claimable_neurons_index.get_mut(neuron_id) else {
            log!(
                ERROR,
                "Unable to find neuron {:?} (ID {}) in claimable_neurons_index.",
                swap_neuron,
                neuron_id,
            );
            sweep_result.global_failures += 1;
            return sweep_result;
        };

        let claim_status = ClaimedStatus::from(claimed_swap_neuron_status);

        match claim_status {
            ClaimedStatus::Success => sweep_result.success += 1,
            ClaimedStatus::Failed => sweep_result.failure += 1,
            ClaimedStatus::Invalid => sweep_result.invalid += 1,
            ClaimedStatus::Pending | ClaimedStatus::Unspecified => {
                log!(
                    ERROR,
                    "Unexpected ClaimedStatus ({:?}) resulting from \
                    ClaimedSwapNeuronStatus ({:?}) for NeuronId {}",
                    claim_status,
                    claimed_swap_neuron_status,
                    neuron_id
                );
                // Increment the SweepResult's invalid field, but the claiming could be attempted again
                sweep_result.invalid += 1;
            }
        }

        recipe.claimed_status = Some(claim_status as i32);
        sweep_result
    }

    pub async fn set_sns_governance_to_normal_mode(
        sns_governance_client: &mut impl SnsGovernanceClient,
    ) -> SetModeCallResult {
        // The SnsGovernanceClient Trait converts any errors to Err(CanisterCallError)
        // No panics should occur when issuing this message.
        sns_governance_client
            .set_mode(SetMode {
                mode: governance::Mode::Normal as i32,
            })
            .await
            .into()
    }

    /// Requests a refund of ICP tokens transferred to the Swap
    /// canister that was either never notified (via the
    /// refresh_buyer_tokens Candid method), or not fully accepted (by
    /// refresh_buyer_tokens).
    ///
    /// This method makes no changes (and instead panics) unless
    /// finalization has completed successfully (see the finalize
    /// method), which can only happen after self has entered the
    /// Aborted or Committed state.
    ///
    /// The entire balance in `subaccount(swap_canister, P)` is
    /// transferred to request.principal_id (minus the transfer fee,
    /// of course).
    ///
    /// This method is secure because it only transfers tokens from a
    /// principal's subaccount (of the Swap canister) to the
    /// principal's own account, i.e., the tokens were held in escrow
    /// for the principal (buyer) before the call and are returned to
    /// the same principal.
    pub async fn error_refund_icp(
        &self,
        self_canister_id: CanisterId,
        request: &ErrorRefundIcpRequest,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> ErrorRefundIcpResponse {
        // Fail if the request is premature.
        if !(self.lifecycle() == Lifecycle::Aborted || self.lifecycle() == Lifecycle::Committed) {
            return ErrorRefundIcpResponse::new_precondition_error(
                "Error refunds can only be performed when the swap is ABORTED or COMMITTED",
            );
        }

        // Unpack request.
        let source_principal_id = match request {
            ErrorRefundIcpRequest {
                source_principal_id: Some(source_principal_id),
            } => source_principal_id,
            _ => {
                return ErrorRefundIcpResponse::new_invalid_request_error(format!(
                    "Invalid request. Must have source_principal_id. Request:\n{:#?}",
                    request,
                ));
            }
        };

        if let Some(buyer_state) = self.buyers.get(&source_principal_id.to_string()) {
            if let Some(transfer) = &buyer_state.icp {
                if transfer.transfer_success_timestamp_seconds == 0 {
                    // This buyer has ICP not yet disbursed using the normal mechanism.
                    return ErrorRefundIcpResponse::new_precondition_error(format!(
                        "ICP cannot be refunded as principal {} has {} ICP (e8s) in escrow",
                        source_principal_id,
                        buyer_state.amount_icp_e8s()
                    ));
                }
            }
            // This buyer has participated in the swap, but all ICP
            // has already been disbursed, either back to the buyer
            // (aborted) or to the SNS Governance canister
            // (committed). Any ICP in this buyer's subaccount must
            // belong to the buyer.
        } else {
            // This buyer is not known to the swap canister. Any
            // balance in a subaccount belongs to the buyer.
        }

        let source_subaccount = principal_to_subaccount(source_principal_id);

        // Figure out how much to send back to source_principal_id based on
        // what's left in the subaccount.
        let account_balance_result = icp_ledger
            .account_balance(Account {
                owner: self_canister_id.into(),
                subaccount: Some(source_subaccount),
            })
            .await;
        let balance_e8s = match account_balance_result {
            Ok(balance) => balance.get_e8s(),
            Err(err) => {
                return ErrorRefundIcpResponse::new_external_error(format!(
                    "Unable to get the balance for the subaccount of {}: {:?}",
                    source_principal_id, err,
                ));
            }
        };

        // Make transfer.
        let amount_e8s = balance_e8s.saturating_sub(DEFAULT_TRANSFER_FEE.get_e8s());
        let dst = Account {
            owner: source_principal_id.0,
            subaccount: None,
        };
        let transfer_result = icp_ledger
            .transfer_funds(
                amount_e8s,
                DEFAULT_TRANSFER_FEE.get_e8s(),
                Some(source_subaccount),
                dst,
                0, // memo
            )
            .await;

        // Translate transfer result into return value.
        match transfer_result {
            Ok(block_height) => {
                log!(
                    INFO,
                    "Error refund - transferred {} ICP from subaccount {:#?} to {} at height {}",
                    amount_e8s,
                    source_subaccount,
                    dst,
                    block_height,
                );
                ErrorRefundIcpResponse::new_ok(block_height)
            }
            Err(err) => {
                log!(
                    ERROR,
                    "Error refund - failed to transfer {} from subaccount {:#?}: {}",
                    amount_e8s,
                    source_subaccount,
                    err,
                );
                ErrorRefundIcpResponse::new_external_error(format!(
                    "Transfer request failed: {}",
                    err,
                ))
            }
        }
    }

    /// Transfers ICP tokens from buyer's subaccounts to the SNS governance
    /// canister if COMMITTED or back to the buyer if ABORTED.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due operation already in progress
    /// - the number of successful transfers
    /// - the number of failed transfers
    /// - the number of invalid buyers due to corrupted buyer state or invalid balances
    /// - the number of global failures across the sweep such as corrupted swap state
    ///
    /// Pre-conditions:
    /// - The Swap canister's `Lifecycle` is either ABORTED or COMMITTED
    pub async fn sweep_icp(
        &mut self,
        now_fn: fn(bool) -> u64,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> SweepResult {
        let lifecycle: Lifecycle = self.lifecycle();

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting sweep_icp(). State is missing or corrupted: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };

        // The following methods are safe to call since we validated Init in the above block
        let sns_governance = init.sns_governance_or_panic();

        let mut sweep_result = SweepResult::default();

        for (principal_str, buyer_state) in self.buyers.iter_mut() {
            // principal_str should always be parseable as a PrincipalId as that is enforced
            // in `refresh_buyer_tokens`. In the case of a bug due to programmer error, increment
            // the invalid field. This will require a manual intervention via an upgrade to correct
            let principal = match string_to_principal(principal_str) {
                Some(p) => p,
                None => {
                    sweep_result.invalid += 1;
                    continue;
                }
            };

            let subaccount = principal_to_subaccount(&principal);
            let dst = if lifecycle == Lifecycle::Committed {
                // This Account should be given a name, such as SNS ICP Treasury...
                Account {
                    owner: sns_governance.get().0,
                    subaccount: None,
                }
            } else {
                Account {
                    owner: principal.0,
                    subaccount: None,
                }
            };

            let icp_transferable_amount = match buyer_state.icp.as_mut() {
                Some(transferable_amount) => transferable_amount,
                // BuyerState.icp should always be present as it is set in `refresh_buyer_tokens`.
                // In the case of a bug due to programmer error, increment the invalid field.
                // This will require a manual intervention via an upgrade to correct
                None => {
                    log!(
                        ERROR,
                        "PrincipalId {} has corrupted BuyerState: {:?}",
                        principal,
                        buyer_state
                    );
                    sweep_result.invalid += 1;
                    continue;
                }
            };

            let result = icp_transferable_amount
                .transfer_helper(
                    now_fn,
                    DEFAULT_TRANSFER_FEE,
                    Some(subaccount),
                    &dst,
                    icp_ledger,
                )
                .await;
            match result {
                // AmountToSmall should never happen as the amount contributed is checked in
                // `refresh_buyer_tokens`. In the case of a bug due to programmer error,
                // increment the invalid field. This will require a manual intervention
                // via an upgrade to correct
                TransferResult::AmountTooSmall => {
                    sweep_result.invalid += 1;
                }
                TransferResult::AlreadyStarted => {
                    sweep_result.skipped += 1;
                }
                TransferResult::Success(_) => {
                    sweep_result.success += 1;
                }
                TransferResult::Failure(_) => {
                    sweep_result.failure += 1;
                }
            }

            // Update the buyer state to indicate funds that have been successfully committed or refunded.
            if result.is_success() {
                // Record transfer fee
                icp_transferable_amount.transfer_fee_paid_e8s =
                    Some(DEFAULT_TRANSFER_FEE.get_e8s());
                // Record the amount minus transfer fee that was refunded or committed.
                let amount_transferred_e8s =
                    Some(icp_transferable_amount.amount_e8s - DEFAULT_TRANSFER_FEE.get_e8s());
                icp_transferable_amount.amount_transferred_e8s = amount_transferred_e8s;
            }
        }

        sweep_result
    }

    /// In state COMMITTED. Transfers SNS tokens from the swap
    /// canister to each buyer.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    /// - the number of invalid neuron recipes due to corrupted neuron recipe state or invalid balances
    /// - the number of global failures due to corrupted Swap state
    pub async fn sweep_sns(
        &mut self,
        now_fn: fn(bool) -> u64,
        sns_ledger: &dyn ICRC1Ledger,
    ) -> SweepResult {
        if self.lifecycle() != Lifecycle::Committed {
            log!(
                ERROR,
                "Halting sweep_sns(). SNS Tokens cannot be distributed if \
                Lifecycle is not COMMITTED. Current Lifecycle: {:?}",
                self.lifecycle()
            );
            return SweepResult::new_with_global_failures(1);
        }

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting sweep_sns(). State is missing or corrupted: {:?}",
                    error_message
                );
                return SweepResult::new_with_global_failures(1);
            }
        };

        // The following methods are safe to call since we validated Init in the above block
        let sns_governance = init.sns_governance_or_panic();
        let nns_governance = init.nns_governance_or_panic();
        let sns_transaction_fee_tokens = Tokens::from_e8s(init.transaction_fee_e8s_or_panic());

        let mut sweep_result = SweepResult::default();

        for recipe in self.neuron_recipes.iter_mut() {
            let neuron_memo = match recipe.neuron_attributes.as_ref() {
                Some(neuron_attributes) => neuron_attributes.memo,
                // SnsNeuronRecipe.neuron_attributes should always be present as it is set in `commit`.
                // In the case of a bug due to programmer error, increment the invalid field.
                // This will require a manual intervention via an upgrade to correct
                None => {
                    log!(
                        ERROR,
                        "Missing neuron attributes information for neuron recipe {:?}",
                        recipe
                    );
                    sweep_result.invalid += 1;
                    continue;
                }
            };

            let dst_subaccount = match &recipe.investor {
                Some(Investor::Direct(DirectInvestment { buyer_principal })) => {
                    match string_to_principal(buyer_principal) {
                        Some(p) => compute_neuron_staking_subaccount_bytes(p, neuron_memo),
                        // principal_str should always be parseable as a PrincipalId as that is enforced
                        // in `refresh_buyer_tokens`. In the case of a bug due to programmer error, increment
                        // the invalid field. This will require a manual intervention via an upgrade to correct
                        None => {
                            sweep_result.invalid += 1;
                            continue;
                        }
                    }
                }
                Some(Investor::CommunityFund(_)) => {
                    compute_neuron_staking_subaccount_bytes(nns_governance.into(), neuron_memo)
                }
                // SnsNeuronRecipe.investor should always be present as it is set in `commit`.
                // In the case of a bug due to programmer error, increment the invalid field.
                // This will require a manual intervention via an upgrade to correct
                None => {
                    log!(
                        ERROR,
                        "Missing investor information for neuron recipe {:?}",
                        recipe,
                    );
                    sweep_result.invalid += 1;
                    continue;
                }
            };
            let dst = Account {
                owner: sns_governance.get().0,
                subaccount: Some(dst_subaccount),
            };

            let sns_transferable_amount = match recipe.sns.as_mut() {
                Some(transferable_amount) => transferable_amount,
                // SnsNeuronRecipe.sns should always be present as it is set in `commit`.
                // In the case of a bug due to programmer error, increment the invalid field.
                // This will require a manual intervention via an upgrade to correct
                None => {
                    log!(
                        ERROR,
                        "Missing transfer information for neuron recipe {:?}",
                        recipe,
                    );
                    sweep_result.invalid += 1;
                    continue;
                }
            };

            let result = sns_transferable_amount
                .transfer_helper(
                    now_fn,
                    sns_transaction_fee_tokens,
                    /* src_subaccount= */ None,
                    &dst,
                    sns_ledger,
                )
                .await;
            match result {
                // AmountToSmall should never happen as the sns token amount is checked in
                // `commit`. In the case of a bug due to programmer error,
                // increment the invalid field. This will require a manual intervention
                // via an upgrade to correct
                TransferResult::AmountTooSmall => {
                    sweep_result.invalid += 1;
                }
                TransferResult::AlreadyStarted => {
                    sweep_result.skipped += 1;
                }
                TransferResult::Success(_) => {
                    let fee_e8s = sns_transaction_fee_tokens.get_e8s();
                    sns_transferable_amount.transfer_fee_paid_e8s = Some(fee_e8s);
                    sns_transferable_amount.amount_transferred_e8s =
                        Some(sns_transferable_amount.amount_e8s - fee_e8s);

                    sweep_result.success += 1;
                }
                TransferResult::Failure(_) => {
                    sweep_result.failure += 1;
                }
            }
        }

        sweep_result
    }

    /// Requests the NNS Governance canister to settle the Neurons' Fund
    /// participation in the Swap. If the Swap is committed, ICP will be
    /// minted to the Swap canister's ICP account, and the returned NfParticipants
    /// must have SNS neurons. If the Swap is aborted, maturity will be refunded to
    /// NNS Neurons.
    ///
    /// This method is part of the over-arching finalize_swap API. To be able to reason
    /// about the interleaving of calls and to prevent reentrancy bugs, finalize has a
    /// lock that prevents concurrent calls. As such, this method CANNOT panic as this will
    /// leave the swap canister with a held lock and no means to release it without an
    /// upgrade.
    ///
    /// Conditions for which this method will return an error:
    ///
    /// 1. There is missing or invalid state in the swap canister.
    /// 2. The replica returned a platform error to the Swap canister.
    /// 3. The NNS Gov canister returns an error to the Swap canister.
    /// 4. The NNS Gov canister's response is corrupted.
    /// 5. The NNS Gov canister's response is invalid.
    pub async fn settle_neurons_fund_participation(
        &mut self,
        nns_governance_client: &mut impl NnsGovernanceClient,
    ) -> SettleNeuronsFundParticipationResult {
        use settle_neurons_fund_participation_request::{Aborted, Committed};

        // Check if any work needs to be done.
        if !self.cf_participants.is_empty() {
            log!(
                INFO,
                "settle_neurons_fund_participation has already been called \
                successfully and cf_participants has been set. Returning successfully."
            );

            return SettleNeuronsFundParticipationResult::new_ok(
                self.current_neurons_fund_participation_e8s(),
                self.cf_participants.len() as u64,
            );
        }

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                return SettleNeuronsFundParticipationResult::new_error(error_message);
            }
        };
        // The following methods are safe to call since we validated Init in the above block
        let nns_proposal_id = init.nns_proposal_id();
        let sns_governance_canister_id = init.sns_governance_or_panic();

        // Build the NNS Governance request struct
        let swap_result = if self.lifecycle() == Lifecycle::Committed {
            settle_neurons_fund_participation_request::Result::Committed(Committed {
                sns_governance_canister_id: Some(sns_governance_canister_id.get()),
                total_direct_participation_icp_e8s: Some(self.current_direct_participation_e8s()),
                total_neurons_fund_participation_icp_e8s: Some(
                    self.current_neurons_fund_participation_e8s(),
                ),
            })
        } else {
            settle_neurons_fund_participation_request::Result::Aborted(Aborted {})
        };
        let request = SettleNeuronsFundParticipationRequest {
            nns_proposal_id: Some(nns_proposal_id),
            result: Some(swap_result),
        };

        // Issue the request to nns governance.
        let response: Result<SettleNeuronsFundParticipationResponse, CanisterCallError> =
            nns_governance_client
                .settle_neurons_fund_participation(request)
                .await;

        // Make sure no interleaved call set cf_participants while this message was waiting
        // for a response from Governance.
        if !self.cf_participants.is_empty() {
            return SettleNeuronsFundParticipationResult::new_error(format!(
                "Cf_participants is not empty. Abandoning this execution of \
                settle_neurons_fund_participation. There are currently {} cf_participants",
                self.cf_participants.len(),
            ));
        }

        // Extract the payload or return an error and halt finalization.
        let neurons_fund_neuron_portions = match response {
            Ok(settle_response) => {
                if let Some(settle_neurons_fund_participation_response::Result::Ok(ok)) =
                    settle_response.result
                {
                    ok.neurons_fund_neuron_portions
                } else if let Some(settle_neurons_fund_participation_response::Result::Err(
                    governance_error,
                )) = settle_response.result
                {
                    return SettleNeuronsFundParticipationResult::new_error(format!(
                        "NNS governance returned an error when calling \
                         settle_neurons_fund_participation. Code: {}. Message: {}",
                        governance_error.error_type, governance_error.error_message
                    ));
                } else {
                    return SettleNeuronsFundParticipationResult::new_error(
                        "NNS governance returned a SettleNeuronsFundParticipationResponse with \
                        no result. Cannot determine if request succeeded or failed."
                            .to_string(),
                    );
                }
            }
            Err(canister_call_error) => {
                return SettleNeuronsFundParticipationResult::new_error(format!(
                    "Replica returned an error when calling settle_neurons_fund_participation. \
                     Code: {:?}. Message: {}",
                    canister_call_error.code, canister_call_error.description
                ));
            }
        };

        // Process the payload.
        let mut cf_participant_map = btreemap! {};
        let mut defects = vec![];
        for np in neurons_fund_neuron_portions {
            let np = match NeuronsFundNeuron::try_from(np.clone()) {
                Ok(np) => np,
                Err(message) => {
                    defects.push(format!("NNS governance returned an invalid NeuronsFundNeuron. Struct: {:?}, Reason: {}", np, message));
                    continue;
                }
            };
            let cf_neurons: &mut Vec<CfNeuron> =
                cf_participant_map.entry(np.controller).or_insert(vec![]);

            let cf_neuron = match CfNeuron::try_new(
                np.nns_neuron_id,
                np.amount_icp_e8s,
                np.hotkeys.clone(),
            ) {
                Ok(cfn) => cfn,
                Err(message) => {
                    defects.push(format!("NNS governance returned an invalid NeuronsFundNeuron. It cannot be converted to CfNeuron. Struct: {:?}, Reason: {}", np, message));
                    continue;
                }
            };

            cf_neurons.push(cf_neuron);
        }
        // Collect all errors into an error
        if !defects.is_empty() {
            return SettleNeuronsFundParticipationResult::new_error(format!(
                "NNS Governance returned invalid NeuronsFundNeurons. Could not settle_neurons_fund_participation. Defects: {:?}", defects
            ));
        }

        // Convert the intermediate format into its final format
        #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is removed
        let cf_participants: Vec<CfParticipant> = cf_participant_map
            .into_iter()
            .map(|(nf_neuron_nns_controller, cf_neurons)| CfParticipant {
                controller: Some(nf_neuron_nns_controller),
                // TODO(NNS1-3198): Remove once hotkey_principal is removed
                hotkey_principal: nf_neuron_nns_controller.to_string(),
                cf_neurons,
            })
            .collect();

        // Persist the processed response to state
        self.cf_participants = cf_participants;
        let new_neurons_fund_participation_icp_e8s = Some(
            self.cf_participants
                .iter()
                .map(|x| x.participant_total_icp_e8s())
                .fold(0_u64, |sum, v| sum.saturating_add(v)),
        );

        if self.neurons_fund_participation_icp_e8s != new_neurons_fund_participation_icp_e8s {
            log!(
                INFO,
                "Predicted neurons_fund_participation_icp_e8s ({:?}) did not match final \
                neurons_fund_participation_icp_e8s ({:?}). Setting state to final.",
                self.neurons_fund_participation_icp_e8s,
                new_neurons_fund_participation_icp_e8s
            );
        }
        self.neurons_fund_participation_icp_e8s = new_neurons_fund_participation_icp_e8s;

        SettleNeuronsFundParticipationResult::new_ok(
            self.current_neurons_fund_participation_e8s(),
            self.cf_participants.len() as u64,
        )
    }

    // PRECONDITIONS:
    // 1. self.params must not be None
    // 2. self.params.unwrap().max_direct_participation_icp_e8s must not be None
    pub fn new_sale_ticket(
        &mut self,
        request: &NewSaleTicketRequest,
        caller: PrincipalId,
        time: u64,
    ) -> NewSaleTicketResponse {
        // Return an error if we are not in Lifecycle::Open.
        if self.lifecycle().is_before_open() {
            return NewSaleTicketResponse::err_sale_not_open();
        }
        if self.lifecycle().is_after_open() {
            return NewSaleTicketResponse::err_sale_closed();
        }
        if self.lifecycle() != Lifecycle::Open {
            // It must be that we are in Lifecycle::Unspecified, but this also
            // accounts for cases that might have been overlooked.
            log!(
                ERROR,
                "We are not in Lifecycle::Open. Swap:\n{:#?}",
                SwapDigest::new(self),
            );
            return NewSaleTicketResponse::err_sale_not_open();
        }

        if caller.is_anonymous() {
            return NewSaleTicketResponse::err_invalid_principal();
        }

        // subaccounts must be 32 bytes
        if request
            .subaccount
            .as_ref()
            .map_or(false, |subaccount| subaccount.len() != 32)
        {
            return NewSaleTicketResponse::err_invalid_subaccount();
        }
        let principal = Blob::from_bytes(caller.as_slice().into());
        if let Some(ticket) = memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal)) {
            return NewSaleTicketResponse::err_ticket_exists(ticket);
        }

        // Check that there are still available tokens
        let params = self
            .params
            .as_ref()
            .expect("Expected params to be set because lifecycle is OPEN");
        let old_balance_e8s = self
            .buyers
            .get(&caller.to_string())
            .map_or(0, |buyer_state| buyer_state.amount_icp_e8s());
        let amount_icp_e8s = match compute_participation_increment(
            self.current_direct_participation_e8s(),
            params.max_direct_participation_icp_e8s.expect(
                "`params.max_direct_participation_icp_e8s` should always be set during Swap's initialization",
            ),
            params.min_participant_icp_e8s,
            params.max_participant_icp_e8s,
            old_balance_e8s,
            request.amount_icp_e8s,
        ) {
            Ok(amount_icp_e8s) => amount_icp_e8s,
            Err((min, max)) => return NewSaleTicketResponse::err_invalid_user_amount(min, max),
        };

        let account = Some(Icrc1Account {
            owner: Some(caller),
            subaccount: request.subaccount.clone(),
        });

        let ticket_id = self.next_ticket_id.unwrap_or(0);
        self.next_ticket_id = Some(ticket_id.saturating_add(1));
        // the amount_icp_e8s is the actual_increment_e8s of the user and not necessarily was the user put in the ticket.
        // This can potentially reduce the amount of tokens to transfer/refund
        let ticket = Ticket {
            ticket_id,
            account,
            amount_icp_e8s,
            creation_time: time,
        };
        memory::OPEN_TICKETS_MEMORY.with(|m| {
            m.borrow_mut().insert(principal, ticket.clone());
        });
        NewSaleTicketResponse::ok(ticket)
    }

    /// Calls purge_old_tickets when needed.
    ///
    /// The conditions to call purge_old_tickets are the following:
    /// 1. there are more than `number_of_tickets_threshold` tickets
    /// 2. the `lifecycle` is `Open`
    /// 3. either there is an ongoing purge_old_tickets running or
    ///    10 minutes has passed since the last call
    ///
    /// Returns None if purge_old_tickets was not run, Some(false) if it was
    /// run but didn't complete, Some(true) if it was run and completed the
    /// check of all tickets.
    pub fn try_purge_old_tickets(
        &mut self,
        now_nanoseconds: impl Fn() -> u64,
        /* amount of tickets after which purge_old_tickets is executed */
        number_of_tickets_threshold: u64,
        /* minimum age of a ticket to be purged */
        max_age_in_nanoseconds: u64,
        /* max number of inspect in a single call */
        max_number_to_inspect: u64,
    ) -> Option<bool> {
        const INTERVAL_NANOSECONDS: u64 = 60 * 10 * 1_000_000_000; // 10 minutes

        if self.lifecycle() != Lifecycle::Open {
            return None;
        }

        // Do not run purge_old_tickets if the number of tickets is less than or equal
        // to the threshold. This should save cycles.
        if memory::OPEN_TICKETS_MEMORY.with(|ts| ts.borrow().len()) < number_of_tickets_threshold {
            return None;
        }

        let purge_old_tickets_last_completion_timestamp_nanoseconds = self
            .purge_old_tickets_last_completion_timestamp_nanoseconds
            .unwrap_or(0);

        let purge_old_tickets_next_principal = self.purge_old_tickets_next_principal().to_vec();
        let first_principal_bytes = FIRST_PRINCIPAL_BYTES.to_vec();

        if purge_old_tickets_next_principal != first_principal_bytes
            || purge_old_tickets_last_completion_timestamp_nanoseconds + INTERVAL_NANOSECONDS
                <= now_nanoseconds()
        {
            return match self.purge_old_tickets(
                now_nanoseconds(),
                purge_old_tickets_next_principal,
                max_age_in_nanoseconds,
                max_number_to_inspect,
            ) {
                Some(new_next_principal) => {
                    // If a principal is returned then there are some principals
                    // that haven't been checked yet by purge_old_tickets. We record
                    // the next principal so that the next heartbeat can continue the
                    // work.
                    self.purge_old_tickets_next_principal = Some(new_next_principal);
                    Some(false)
                }
                None => {
                    // If no principal is returned then purge_old_tickets has
                    // exhausted all the tickets.
                    log!(INFO, "purge_old_tickets done");
                    self.purge_old_tickets_next_principal = Some(first_principal_bytes);
                    self.purge_old_tickets_last_completion_timestamp_nanoseconds =
                        Some(now_nanoseconds());
                    Some(true)
                }
            };
        }
        None
    }

    /// Purge tickets that are older than 2 days.
    ///
    /// Because there can be many tickets, this method takes in input a starting principal,
    /// attempts to purge the first batch of MAX_NUMBER_OF_PRINCIPALS_TO_INSPECT principals and
    /// returns the last one purged so that the calling method can decide if it wants to
    /// continue with the next batch.
    fn purge_old_tickets(
        &self,
        curr_time_in_nanoseconds: u64,
        start_principal: Vec<u8>,
        /* minimum age of a ticket to be purged */
        max_age_in_nanoseconds: u64,
        /* max number of inspect in a single call */
        max_number_to_inspect: u64,
    ) -> Option<Vec<u8>> {
        if start_principal == FIRST_PRINCIPAL_BYTES.to_vec() {
            log!(
                INFO,
                "purge_old_tickets started from {}, number of tickets {}",
                hex::encode(&start_principal),
                memory::OPEN_TICKETS_MEMORY.with(|ts| ts.borrow().len()),
            );
        } else {
            log!(
                INFO,
                "purge_old_tickets resumed from {:?}",
                hex::encode(&start_principal),
            );
        }

        memory::OPEN_TICKETS_MEMORY.with(|tickets| {
            let mut to_purge = vec![];
            let last_principal = {
                let mut last_principal = None;
                let tickets = tickets.borrow();
                let min_principal = Blob::from_bytes(Cow::from(&start_principal[..]));
                let mut iter = tickets.range((Included(min_principal), Unbounded));
                for _i in 0..max_number_to_inspect {
                    match iter.next() {
                        Some((principal, ticket)) => {
                            last_principal = Some(principal.as_slice().to_vec());
                            // ticket.creation_time is in nanoseconds
                            if ticket.creation_time + max_age_in_nanoseconds
                                < curr_time_in_nanoseconds
                            {
                                to_purge.push(principal);
                            }
                        }
                        None => {
                            last_principal = None;
                            break;
                        }
                    }
                }
                last_principal
            };

            if !to_purge.is_empty() {
                log!(
                    INFO,
                    "Purging {} open tickets because they are older than {:?} (number of open tickets: {})",
                    to_purge.len(),
                    Duration::from_nanos(max_age_in_nanoseconds),
                    tickets.borrow().len(),
                );
            }

            for principal in to_purge {
                if tickets.borrow_mut().remove(&principal).is_none() {
                    log!(ERROR, "Cannot purge ticket of principal {:?} because it doesn't exist! This should not happen", principal.as_slice())
                }
            }

            last_principal
        })
    }

    //
    // --- predicates on the state ---------------------------------------------
    //

    /// Validates the state for internal consistency. This does not
    /// validate that the ledger balances correspond to what the
    /// `Swap` state thinks they are.
    pub fn validate(&self) -> Result<(), String> {
        if !Lifecycle::is_valid(self.lifecycle) {
            return Err(format!("Invalid lifecycle {}", self.lifecycle));
        }

        let init = match &self.init {
            Some(init) => init,
            None => {
                return Err("Missing 'init'.".to_string());
            }
        };
        init.validate()?;

        if let Some(params) = &self.params {
            params.validate(init)?;
        }

        for (k, b) in &self.buyers {
            if !is_valid_principal(k) {
                return Err(format!("Invalid principal {}", k));
            }
            b.validate()?;
        }
        for cfp in &self.cf_participants {
            cfp.validate()?;
        }
        for nr in &self.neuron_recipes {
            nr.validate()?;
        }

        Ok(())
    }

    /// The parameter `now_seconds` is greater than or equal to `swap_due_timestamp_seconds`.
    pub fn swap_due(&self, now_seconds: u64) -> bool {
        if let Some(params) = &self.params {
            return now_seconds >= params.swap_due_timestamp_seconds;
        }
        false
    }

    /// The minimum number of participants have been achieved, and the
    /// minimal total amount of direct participation has been reached.
    pub fn sufficient_participation(&self) -> bool {
        self.min_participation_reached() && self.min_direct_participation_icp_e8s_reached()
    }

    /// The minimum number of participants have been achieved.
    pub fn min_participation_reached(&self) -> bool {
        if let (Some(params), Some(init)) = (&self.params, &self.init) {
            if init.neurons_fund_participation.is_some() {
                // Only count direct participants for determining swap's success.
                // Note that a valid Swap Init should either have `neurons_fund_participation` or
                // `cf_participants`, but not both at the same time; here, we defensively perform
                // the check again anyway.
                if !self.cf_participants.is_empty() {
                    log!(
                        ERROR,
                        "Inconsistent Swap Init: cf_participants has {} elements (starting with \
                        {:?}) while neurons_fund_participation is set.",
                        self.cf_participants.len(),
                        self.cf_participants[0],
                    );
                }
                (self.buyers.len() as u32) >= params.min_participants
            } else {
                (self.cf_participants.len().saturating_add(self.buyers.len()) as u32)
                    >= params.min_participants
            }
        } else {
            false
        }
    }

    pub fn min_direct_participation_icp_e8s_reached(&self) -> bool {
        if let Some(params) = &self.params {
            let Some(min_direct_participation_icp_e8s) = params.min_direct_participation_icp_e8s
            else {
                return false;
            };
            return self.current_direct_participation_e8s() >= min_direct_participation_icp_e8s;
        }
        false
    }

    /// Returns the `IcpTargetProgress`, a structure summarizing the current progress in reaching
    /// the target total ICP amount (both direct and NF contributions).
    pub fn icp_target_progress(&self) -> IcpTargetProgress {
        if self.params.is_some() {
            let current_direct_participation_e8s = self.current_direct_participation_e8s();
            let max_direct_participation_e8s = self.max_direct_participation_e8s();
            match current_direct_participation_e8s.cmp(&max_direct_participation_e8s) {
                Ordering::Less => IcpTargetProgress::NotReached {
                    current_direct_participation_e8s,
                    max_direct_participation_e8s,
                },
                Ordering::Greater => IcpTargetProgress::Exceeded {
                    current_direct_participation_e8s,
                    max_direct_participation_e8s,
                },
                Ordering::Equal => IcpTargetProgress::Reached(max_direct_participation_e8s),
            }
        } else {
            IcpTargetProgress::Undefined
        }
    }

    /// Returns true if the swap can be opened at the specified
    /// timestamp, and false otherwise.
    ///
    /// Conditions:
    /// 1. The lifecycle of Swap is `Lifecycle::Adopted`
    /// 2. The current timestamp is greater than or equal to `decentralization_sale_open_timestamp_seconds`
    pub fn can_open(&self, now_seconds: u64) -> bool {
        if self.lifecycle() != Lifecycle::Adopted {
            return false;
        }

        let swap_open_timestamp_seconds = self
            .decentralization_sale_open_timestamp_seconds
            .unwrap_or(now_seconds);
        now_seconds >= swap_open_timestamp_seconds
    }

    /// Returns true if the Swap can be committed at the specified
    /// timestamp, and false otherwise.
    ///
    /// Conditions:
    /// 1. The lifecycle of Swap is `Lifecycle::Open`
    /// 2. There must be sufficient participation in the Swap
    /// 3. Either the maximum ICP target has been reached, or the Swap is due
    pub fn can_commit(&self, now_seconds: u64) -> bool {
        if self.lifecycle() != Lifecycle::Open {
            return false;
        }
        // Possible optimization: both 'sufficient_participation' and
        // 'icp_target.is_reached()' compute 'participant_total_icp_e8s', and
        // this computation could be shared (or cached).
        if !self.sufficient_participation() {
            return false;
        }

        // If swap is due, or the target ICP has been reached, return true
        self.swap_due(now_seconds) || self.icp_target_progress().is_reached_or_exceeded()
    }

    /// Returns true if the Swap can be aborted at the specified
    /// timestamp, and false otherwise.
    ///
    /// Conditions:
    /// 1. The lifecycle of Swap is `Lifecycle::Open`
    /// 2. The Swap has ended (either the Swap is due or the maximum ICP target was reached) and there
    ///    has not been sufficient participation reached.
    pub fn can_abort(&self, now_seconds: u64) -> bool {
        if self.lifecycle() != Lifecycle::Open {
            return false;
        }

        // if the swap is due or the ICP target is reached without sufficient participation, we can abort
        (self.swap_due(now_seconds) || self.icp_target_progress().is_reached_or_exceeded())
            && !self.sufficient_participation()
    }

    /// Returns Ok(()) if the swap can auto-finalize, and Err(reason) otherwise
    pub fn can_auto_finalize(&self) -> Result<(), String> {
        // Being allowed to finalize is a precondition for being allowed
        // to auto-finalize.
        self.can_finalize()?;

        let Some(init) = self.init.as_ref() else {
            return Err("unable to access swap's init".to_string());
        };

        // Fail early if `self.init.should_auto_finalize` doesn't indicate that
        // auto-finalization is enabled.
        if !init.should_auto_finalize.unwrap_or_default() {
            return Err(format!(
                "init.should_auto_finalize is {:?}, not attempting auto-finalization.",
                init.should_auto_finalize
            ));
        }

        // Fail early if we've already tried to auto-finalize the swap.
        if self.already_tried_to_auto_finalize.unwrap_or(true) {
            return Err(format!(
                "self.already_tried_to_auto_finalize is {:?}, indicating that an attempt has already been made to auto-finalize. No further attempts will be made automatically. Manually calling finalize is still allowed.",
                self.already_tried_to_auto_finalize
            ));
        }

        Ok(())
    }

    /// Returns Ok(()) if the swap can finalize, and Err(reason) otherwise
    pub fn can_finalize(&self) -> Result<(), String> {
        if !self.lifecycle_is_terminal() {
            Err(format!(
                "The Swap can only be finalized in the COMMITTED or ABORTED states. Current state is {:?}",
                self.lifecycle()
            ))
        } else {
            Ok(())
        }
    }

    //
    // --- query methods on the state  -----------------------------------------
    //

    /// Gets a copy of the Swap canister state and elides the dynamic data sources that
    /// can grow unbounded and computes the derived state of the Swap.
    pub fn get_state(&self) -> GetStateResponse {
        let swap = Swap {
            cf_participants: vec![],
            neuron_recipes: vec![],
            buyers: btreemap! {},
            ..self.clone()
        };

        GetStateResponse {
            swap: Some(swap),
            derived: Some(self.derived_state()),
        }
    }

    /// Computes the DerivedState.
    /// `sns_tokens_per_icp` will be 0 if `participant_total_icp_e8s` is 0.
    pub fn derived_state(&self) -> DerivedState {
        let participant_total_icp_e8s = self.current_total_participation_e8s();
        let direct_participant_count = Some(self.buyers.len() as u64);
        let cf_participant_count = Some(self.cf_participants.len() as u64);
        let cf_neuron_count = Some(self.cf_neuron_count());
        let tokens_available_for_swap = match self.sns_token_e8s() {
            Ok(tokens) => tokens,
            Err(err) => {
                log!(ERROR, "{}", err);
                0
            }
        };
        let sns_tokens_per_icp = i2d(tokens_available_for_swap)
            .checked_div(i2d(participant_total_icp_e8s))
            .and_then(|d| d.to_f32())
            .unwrap_or(0.0);
        let direct_participation_icp_e8s = Some(self.current_direct_participation_e8s());
        let neurons_fund_participation_icp_e8s =
            Some(self.current_neurons_fund_participation_e8s());
        DerivedState {
            buyer_total_icp_e8s: participant_total_icp_e8s,
            direct_participant_count,
            cf_participant_count,
            cf_neuron_count,
            sns_tokens_per_icp,
            direct_participation_icp_e8s,
            neurons_fund_participation_icp_e8s,
        }
    }

    pub fn get_buyer_state(&self, request: &GetBuyerStateRequest) -> GetBuyerStateResponse {
        let buyer_state = match request.principal_id {
            Some(buyer_principal_id) => self.buyers.get(&buyer_principal_id.to_string()).cloned(),
            None => panic!("GetBuyerStateRequest must provide principal_id"),
        };
        GetBuyerStateResponse { buyer_state }
    }

    /// Returns the total amount of ICP deposited by participants in the swap.
    pub fn get_buyers_total(&self) -> GetBuyersTotalResponse {
        GetBuyersTotalResponse {
            buyers_total: self.current_total_participation_e8s(),
        }
    }

    /// Returns the current lifecycle stage (e.g. Open, Committed, etc)
    pub fn get_lifecycle(&self, _request: &GetLifecycleRequest) -> GetLifecycleResponse {
        GetLifecycleResponse {
            lifecycle: Some(self.lifecycle),
            decentralization_sale_open_timestamp_seconds: self
                .decentralization_sale_open_timestamp_seconds,
            decentralization_swap_termination_timestamp_seconds: self
                .decentralization_swap_termination_timestamp_seconds,
        }
    }

    /// Returns the current lifecycle stage (e.g. Open, Committed, etc)
    pub fn get_auto_finalization_status(
        &self,
        _request: &GetAutoFinalizationStatusRequest,
    ) -> GetAutoFinalizationStatusResponse {
        GetAutoFinalizationStatusResponse {
            is_auto_finalize_enabled: self
                .init
                .as_ref()
                .and_then(|init| init.should_auto_finalize),
            has_auto_finalize_been_attempted: self.already_tried_to_auto_finalize,
            auto_finalize_swap_response: self.auto_finalize_swap_response.clone(),
        }
    }

    /// If there is an open swap ticket for the caller then it returns it;
    /// otherwise returns none.
    ///
    /// Returns an error if
    ///  - the swap is not open
    ///  - the swap is closed
    ///
    pub fn get_open_ticket(
        &self,
        _request: &GetOpenTicketRequest,
        caller: PrincipalId,
    ) -> GetOpenTicketResponse {
        if self.lifecycle() < Lifecycle::Open {
            return GetOpenTicketResponse::err_sale_not_open();
        }
        if self.lifecycle() > Lifecycle::Open {
            return GetOpenTicketResponse::err_sale_closed();
        }

        let principal = Blob::from_bytes(caller.as_slice().into());
        let maybe_ticket = memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal));
        GetOpenTicketResponse::ok(maybe_ticket)
    }

    pub fn list_direct_participants(
        &self,
        list_direct_participants_request: ListDirectParticipantsRequest,
    ) -> ListDirectParticipantsResponse {
        let ListDirectParticipantsRequest { limit, offset } = list_direct_participants_request;
        let offset = offset.unwrap_or_default() as usize;
        let limit = limit
            .unwrap_or(MAX_LIST_DIRECT_PARTICIPANTS_LIMIT)
            .min(MAX_LIST_DIRECT_PARTICIPANTS_LIMIT) as usize;

        // StableMemory Vectors do not support indexing via ranges. Instead use iters to
        // get the sub-vec
        let buyer_principals_in_page: Vec<PrincipalId> =
            memory::BUYERS_LIST_INDEX.with(|buyer_list| {
                buyer_list
                    .borrow()
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|principal| principal.into())
                    .collect()
            });

        // Look up the corresponding BuyerState for each PrincipalId in the page and construct
        // the results
        let participants = buyer_principals_in_page
            .iter()
            .map(|principal| {
                let buyer_state = self.buyers.get(&principal.to_string());
                Participant {
                    participant_id: Some(*principal),
                    participation: buyer_state.cloned(),
                }
            })
            .collect();

        ListDirectParticipantsResponse { participants }
    }

    /// Gets Params.
    pub fn get_sale_parameters(
        &self,
        _request: &GetSaleParametersRequest,
    ) -> GetSaleParametersResponse {
        let params = self.params.clone();
        GetSaleParametersResponse { params }
    }

    pub fn get_init(&self, _request: &GetInitRequest) -> GetInitResponse {
        let init = self.init.clone().expect("Swap.init must be defined");
        GetInitResponse { init: Some(init) }
    }

    /// Lists Community Fund participants.
    pub fn list_community_fund_participants(
        &self,
        request: &ListCommunityFundParticipantsRequest,
    ) -> ListCommunityFundParticipantsResponse {
        let ListCommunityFundParticipantsRequest { limit, offset } = request;
        let offset = offset.unwrap_or_default() as usize;
        let limit = limit
            .unwrap_or(DEFAULT_LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT) // use default
            .min(LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT_CAP) // cap
            as usize;

        // Disallow indexing outside of the bounds of self.cf_participants
        if offset >= self.cf_participants.len() {
            return ListCommunityFundParticipantsResponse::default();
        }

        let end = (offset + limit).min(self.cf_participants.len());
        let cf_participants = self.cf_participants[offset..end].to_vec();

        ListCommunityFundParticipantsResponse { cf_participants }
    }

    pub fn rebuild_indexes(&self) -> Result<(), String> {
        let buyers_list_index_is_empty =
            memory::BUYERS_LIST_INDEX.with(|bli| bli.borrow().is_empty());

        if !self.buyers.is_empty() && buyers_list_index_is_empty {
            log!(
                INFO,
                "Buyers state is populated but BUYERS_LIST_INDEX is not. This most likely indicates \
                that this canister was upgraded from a previous version where BUYERS_LIST_INDEX did not \
                exist. Conducting a best effort rebuild."
            );

            for key in self.buyers.keys() {
                // Try to parse the string representation of the Principal. Logging the error
                // occurs in `string_to_principal`.
                if let Some(buyer_principal) = string_to_principal(key) {
                    // If the index cannot be built due to limitations of the stable memory,
                    // return to the caller to determine how to handle the error.
                    insert_buyer_into_buyers_list_index(buyer_principal).map_err(|grow_failed| {
                        format!(
                            "Failed to add buyer {} to state, the canister's stable memory could not grow: {}",
                            buyer_principal, grow_failed
                        )
                    })?;
                }
            }
        }

        Ok(())
    }

    // List SnsNeuronRecipes with paging
    pub fn list_sns_neuron_recipes(
        &self,
        request: ListSnsNeuronRecipesRequest,
    ) -> ListSnsNeuronRecipesResponse {
        let ListSnsNeuronRecipesRequest { limit, offset } = request;
        let offset = offset.unwrap_or_default() as usize;
        let limit = limit
            .unwrap_or(DEFAULT_LIST_SNS_NEURON_RECIPES_LIMIT)
            .min(DEFAULT_LIST_SNS_NEURON_RECIPES_LIMIT) as usize;

        // Disallow indexing outside of the bounds of self.neuron_recipes
        if offset >= self.neuron_recipes.len() {
            return ListSnsNeuronRecipesResponse::default();
        }

        let end = (offset + limit).min(self.neuron_recipes.len());
        let sns_neuron_recipes = self.neuron_recipes[offset..end].to_vec();

        ListSnsNeuronRecipesResponse { sns_neuron_recipes }
    }
}

/// Computes the actual participation increment for a user
///
/// # Arguments
///
/// * `tot_direct_participation` - The current amount of tokens committed to
///                                the swap by all users.
/// * `max_tot_direct_participation` - The maximum amount of tokens that can
///                                    be committed to the swap.
/// * `min_user_participation` - The minimum amount of tokens that a
///                              user must commit to participate to the swap.
/// * `max_user_participation` - The maximum amount of tokens that a
///                              user can commit to participate to the swap.
/// * `user_participation` - The current amount of tokens committed to the
///                          swap by the user that requested the increment.
/// * `requested_increment` - The amount of tokens by which the user wants
///                           to increase its participation in the swap.
fn compute_participation_increment(
    tot_direct_participation: u64,
    max_tot_direct_participation: u64,
    min_user_participation: u64,
    max_user_participation: u64,
    user_participation: u64,
    requested_increment: u64,
) -> Result<u64, (u64, u64)> {
    // Check that there are available tokens available.
    if tot_direct_participation >= max_tot_direct_participation {
        return Err((0, 0));
    }
    // The previous check guarantees that max_available_increment > 0
    let max_available_increment = max_tot_direct_participation - tot_direct_participation;

    // Check that the user can reach min_user_participation with the next
    // ticket. We do not want users to participate less than min_user_participation
    // even if that's what's remaining in the swap.
    if user_participation.saturating_add(max_available_increment) < min_user_participation {
        return Err((0, 0));
    }

    // If we reached this point then the user can participate in the swap.
    // Next we check that the increment requested by the user is valid, that
    // is that it would put the user participation within the min and max
    // user participation (included). We also check that the increment is strictly
    // bigger than zero because zero is not a valid increment.
    let requested_user_participation = user_participation.saturating_add(requested_increment);
    if requested_increment == 0
        || requested_user_participation < min_user_participation
        || requested_user_participation > max_user_participation
    {
        let min_user_increment = min_user_participation
            .saturating_sub(user_participation)
            .clamp(1, max_available_increment);
        let max_user_increment = max_user_participation
            .saturating_sub(user_participation)
            .min(max_available_increment);
        return Err((min_user_increment, max_user_increment));
    }

    // At this point both max_available_increment and requested_increment
    // are valid increments. We take the min between the two so that the
    // user cannot participate with more tokens than what's remaining.
    Ok(max_available_increment.min(requested_increment))
}

pub fn is_valid_principal(p: &str) -> bool {
    !p.is_empty() && PrincipalId::from_str(p).is_ok()
}

pub fn principal_to_subaccount(principal_id: &PrincipalId) -> Subaccount {
    let mut subaccount = [0; std::mem::size_of::<Subaccount>()];
    let principal_id = principal_id.as_slice();
    subaccount[0] = principal_id.len().try_into().unwrap();
    subaccount[1..1 + principal_id.len()].copy_from_slice(principal_id);
    subaccount
}

/// A common pattern throughout the Swap canister is parsing the String
/// representation of a PrincipalId and logging the error if any.
pub(crate) fn string_to_principal(maybe_principal_id: &String) -> Option<PrincipalId> {
    match PrincipalId::from_str(maybe_principal_id) {
        Ok(principal_id) => Some(principal_id),
        Err(error_message) => {
            log!(
                ERROR,
                "Cannot parse principal {} for use in Swap Canister: {}",
                maybe_principal_id,
                error_message
            );
            None
        }
    }
}

/// Create the basket of SNS Neuron Recipes for a single direct participant.
fn create_sns_neuron_basket_for_direct_participant(
    buyer_principal: &PrincipalId,
    amount_sns_token_e8s: u64,
    neuron_basket_construction_parameters: &NeuronBasketConstructionParameters,
    memo_offset: u64,
) -> Result<Vec<SnsNeuronRecipe>, String> {
    let mut recipes = vec![];

    let vesting_schedule =
        neuron_basket_construction_parameters.generate_vesting_schedule(amount_sns_token_e8s)?;

    let memo_of_longest_dissolve_delay = memo_offset + (vesting_schedule.len() - 1) as u64;
    let neuron_id_with_longest_dissolve_delay = SwapNeuronId::from(
        compute_neuron_staking_subaccount_bytes(*buyer_principal, memo_of_longest_dissolve_delay),
    );

    // Create the neuron basket for the direct investors. The unique
    // identifier for an SNS Neuron is the SNS Ledger Subaccount, which
    // is a hash of PrincipalId and some unique memo. Since direct
    // investors in the swap use their own principal_id, there are no
    // neuron id collisions, and each basket can use memos starting at memo_offset.
    for (i, scheduled_vesting_event) in vesting_schedule.iter().enumerate() {
        let memo = memo_offset + i as u64;
        // The SnsNeuronRecipes are set up such that all neurons in a basket will follow
        // the neuron with the longest dissolve delay
        let largest_dissolve_delay_neuron = i == vesting_schedule.len() - 1;
        let followees = if largest_dissolve_delay_neuron {
            vec![]
        } else {
            vec![neuron_id_with_longest_dissolve_delay.clone()]
        };

        recipes.push(SnsNeuronRecipe {
            sns: Some(TransferableAmount {
                amount_e8s: scheduled_vesting_event.amount_e8s,
                transfer_start_timestamp_seconds: 0,
                transfer_success_timestamp_seconds: 0,
                amount_transferred_e8s: Some(0),
                transfer_fee_paid_e8s: Some(0),
            }),
            investor: Some(Investor::Direct(DirectInvestment {
                buyer_principal: buyer_principal.to_string(),
            })),
            neuron_attributes: Some(NeuronAttributes {
                memo,
                dissolve_delay_seconds: scheduled_vesting_event.dissolve_delay_seconds,
                followees,
            }),
            claimed_status: Some(ClaimedStatus::Pending as i32),
        });
    }

    Ok(recipes)
}

/// Create the basket of SNS Neuron Recipes for a single Neurons' Fund participant.
fn create_sns_neuron_basket_for_neurons_fund_participant(
    controller: &PrincipalId,
    hotkeys: Vec<PrincipalId>,
    nns_neuron_id: u64,
    amount_sns_token_e8s: u64,
    neuron_basket_construction_parameters: &NeuronBasketConstructionParameters,
    memo_offset: u64,
    nns_governance_canister_id: PrincipalId,
) -> Result<Vec<SnsNeuronRecipe>, String> {
    let mut recipes = vec![];

    let vesting_schedule =
        neuron_basket_construction_parameters.generate_vesting_schedule(amount_sns_token_e8s)?;

    // Since all CF Participant Neurons are controlled by NNS Governance, a global memo is used.
    // Each basket uses an offset to start its range of memos.
    let memo_of_longest_dissolve_delay = memo_offset + (vesting_schedule.len() - 1) as u64;
    let neuron_id_with_longest_dissolve_delay =
        SwapNeuronId::from(compute_neuron_staking_subaccount_bytes(
            nns_governance_canister_id,
            memo_of_longest_dissolve_delay,
        ));

    // Create the neuron basket for the Neurons' Fund investors. The unique
    // identifier for an SNS Neuron is the SNS Ledger Subaccount, which
    // is a hash of PrincipalId and some unique memo. Since Neurons' Fund
    // investors in the swap use the NNS Governance principal, there can be
    // neuron id collisions. Avoiding such collisions is handled by starting the range
    // of memos in the basket at memo_offset.
    for (i, scheduled_vesting_event) in vesting_schedule.iter().enumerate() {
        let memo = memo_offset + i as u64;

        // The SnsNeuronRecipes are set up such that all neurons in a basket will follow
        // the neuron with the longest dissolve delay
        let largest_dissolve_delay_neuron = i == vesting_schedule.len() - 1;
        let followees = if largest_dissolve_delay_neuron {
            vec![]
        } else {
            vec![neuron_id_with_longest_dissolve_delay.clone()]
        };

        #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is no longer used
        recipes.push(SnsNeuronRecipe {
            sns: Some(TransferableAmount {
                amount_e8s: scheduled_vesting_event.amount_e8s,
                transfer_start_timestamp_seconds: 0,
                transfer_success_timestamp_seconds: 0,
                amount_transferred_e8s: Some(0),
                transfer_fee_paid_e8s: Some(0),
            }),
            investor: Some(Investor::CommunityFund(CfInvestment {
                controller: Some(*controller),
                hotkeys: Some(Principals::from(hotkeys.clone())),
                nns_neuron_id,
                // TODO(NNS1-3198): Remove
                hotkey_principal: controller.to_string(),
            })),
            neuron_attributes: Some(NeuronAttributes {
                memo,
                dissolve_delay_seconds: scheduled_vesting_event.dissolve_delay_seconds,
                followees,
            }),
            claimed_status: Some(ClaimedStatus::Pending as i32),
        });
    }

    Ok(recipes)
}

#[derive(Clone, Debug)]
pub enum ConversionError {
    Invalid,
    AlreadyProcessed,
}

impl SnsNeuronRecipe {
    /// Converts a SnsNeuronRecipe (a Swap concept) to an SnsNeuronRecipe (an SNS Governance concept)
    pub fn to_neuron_recipe(
        &self,
        nns_governance: CanisterId,
        sns_transaction_fee_e8s: u64,
    ) -> Result<NeuronRecipe, (ConversionError, String)> {
        let SnsNeuronRecipe {
            sns: transferable_amount, // Mitigating a historical misnomer.
            neuron_attributes,
            claimed_status,
            investor,
        } = self;

        // SnsNeuronRecipe.investor should always be present as it is set in `commit`.
        // In the case of a bug due to programmer error, increment the invalid field.
        // This will require a manual intervention via an upgrade to correct.
        let investor = investor.as_ref().ok_or_else(|| {
            (
                ConversionError::Invalid,
                format!("Missing investor information for neuron recipe {:?}", self),
            )
        })?;

        // SnsNeuronRecipe.neuron_attributes should always be present as it is set in `commit`.
        // This will require a manual intervention via an upgrade to correct
        let neuron_attributes = neuron_attributes.as_ref().ok_or_else(|| {
            (
                ConversionError::Invalid,
                format!(
                    "Missing neuron_attributes information for neuron recipe {:?}",
                    self
                ),
            )
        })?;
        // SnsNeuronRecipe.sns should always be present as it is set in `commit`.
        // This will require a manual intervention via an upgrade to correct
        let transferable_amount = transferable_amount.as_ref().ok_or_else(|| {
            (
                ConversionError::Invalid,
                format!(
                    "Missing transferable_amount (field `sns`) for neuron recipe {:?}",
                    self
                ),
            )
        })?;

        // Claimed status is used for sanitization only, it does not affect the Ok result.
        {
            let claimed_status = claimed_status.ok_or_else(|| {
                (
                    ConversionError::Invalid,
                    format!(
                        "Missing claimed_status information for neuron recipe {:?}",
                        self
                    ),
                )
            })?;
            let claimed_status = ClaimedStatus::try_from(claimed_status).map_err(|err| {
                (
                    ConversionError::Invalid,
                    format!(
                    "Error interpreting claimed_status `{}` as ClaimedStatus for neuron recipe \
                    {:?}: {}", claimed_status, self, err
                ),
                )
            })?;
            match claimed_status {
                ClaimedStatus::Success => {
                    return Err((
                        ConversionError::AlreadyProcessed,
                        format!(
                            "Recipe {:?} was claimed in previous invocation of \
                             claim_swap_neurons(). Skipping",
                            self,
                        ),
                    ));
                }
                ClaimedStatus::Invalid | ClaimedStatus::Unspecified => {
                    // If the Recipe is marked as invalid or unspecified, intervention is needed
                    // to make valid again. As part of that intervention, the recipe must be marked
                    // as ClaimedStatus::Pending to attempt again.
                    return Err((
                        ConversionError::Invalid,
                        format!(
                        "Recipe {:?} was invalid in a previous invocation of claim_swap_neurons(). \
                        Skipping", self
                    ),
                    ));
                }
                // Remaining cases are tolerable:
                // - Pending status indicates there hasn't been a claim yet for this neuron.
                // - Failed status indicates it is okay to retry to claim a previously failed one.
                ClaimedStatus::Pending | ClaimedStatus::Failed => (),
            }
        }

        let NeuronAttributes {
            dissolve_delay_seconds,
            memo,
            followees,
            ..
        } = neuron_attributes;

        let (participant, controller) = match investor {
            Investor::Direct(DirectInvestment { buyer_principal }) => {
                let parsed_buyer_principal = match string_to_principal(buyer_principal) {
                    Some(p) => p,
                    // principal_str should always be parseable as a PrincipalId as that is enforced
                    // in `refresh_buyer_tokens`. This is the result of a bug due to programmer error
                    // and will require a manual intervention via an upgrade to correct.
                    None => {
                        return Err((
                            ConversionError::Invalid,
                            format!(
                                "Invalid principal: recipe={:?} principal={}",
                                self, buyer_principal
                            ),
                        ));
                    }
                };
                let participant = neuron_recipe::Participant::Direct(neuron_recipe::Direct {});
                (participant, parsed_buyer_principal)
            }
            Investor::CommunityFund(cf_investment) => {
                let nns_neuron_controller = match cf_investment.try_get_controller() {
                    Ok(controller) => Some(controller),
                    Err(e) => {
                        return Err((
                            ConversionError::Invalid,
                            format!(
                                "Invalid Neurons' Fund neuron: recipe={:?} error={}",
                                self, e
                            ),
                        ));
                    }
                };
                let nns_neuron_id = Some(cf_investment.nns_neuron_id);
                let nns_neuron_hotkeys = cf_investment.hotkeys.clone();
                let participant =
                    neuron_recipe::Participant::NeuronsFund(neuron_recipe::NeuronsFund {
                        nns_neuron_controller,
                        nns_neuron_id,
                        nns_neuron_hotkeys,
                    });
                (participant, PrincipalId::from(nns_governance))
            }
        };

        let neuron_id = Some(NeuronId::from(compute_neuron_staking_subaccount_bytes(
            controller, *memo,
        )));

        let followees = followees
            .iter()
            .cloned()
            .map(NeuronId::from)
            .collect::<Vec<_>>();
        let followees = Some(NeuronIds::from(followees.clone()));

        // Since claim_swap_neurons is a permission-ed API on governance, account for
        // the transfer_fee that is applied with the sns ledger transfer.
        let stake_e8s = Some(
            transferable_amount
                .amount_e8s
                .saturating_sub(sns_transaction_fee_e8s),
        );

        Ok(NeuronRecipe {
            participant: Some(participant),
            controller: Some(controller),
            neuron_id,
            dissolve_delay_seconds: Some(*dissolve_delay_seconds),
            followees,
            stake_e8s,
        })
    }
}

impl Storable for Ticket {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.encode_to_vec().into()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Cannot decode ticket")
    }

    const BOUND: Bound = Bound::Bounded {
        // [Ticket] is stored protocol-buffer encoded. The length
        // is variable but when all fields are using the max
        // number of bytes then the size is the following
        //
        //   11 + // 08 + encode_variant(u64::MAX)
        //   70 + // 12 + 44 +
        //        //    0a + encode_bytes(principal [32 bytes])
        //        //    12 + encode_bytes(subaccount [32 bytes])
        //   11 + // 18 + encode_variant(u64::MAX) +
        //   11 + // 20 + encode_variant(u64::MAX)
        //= 103 (*2 to be sure)
        max_size: 206,
        // The size is not fixed because of base 128 variants and
        // different size principals
        is_fixed_size: false,
    };
}

impl GetOpenTicketResponse {
    pub fn ok(ticket: Option<Ticket>) -> Self {
        Self {
            result: Some(get_open_ticket_response::Result::Ok(
                get_open_ticket_response::Ok { ticket },
            )),
        }
    }

    pub fn err(err: get_open_ticket_response::Err) -> Self {
        Self {
            result: Some(get_open_ticket_response::Result::Err(err)),
        }
    }

    pub fn err_sale_not_open() -> Self {
        Self::err(get_open_ticket_response::Err {
            error_type: Some(get_open_ticket_response::err::Type::SaleNotOpen as i32),
        })
    }

    pub fn err_sale_closed() -> Self {
        Self::err(get_open_ticket_response::Err {
            error_type: Some(get_open_ticket_response::err::Type::SaleClosed as i32),
        })
    }

    // panic if self.result is unset
    pub fn ticket(&self) -> Result<Option<Ticket>, i32> {
        match self.result.as_ref().unwrap() {
            get_open_ticket_response::Result::Ok(get_open_ticket_response::Ok { ticket }) => {
                Ok(ticket.to_owned())
            }
            get_open_ticket_response::Result::Err(get_open_ticket_response::Err { error_type }) => {
                Err(error_type.unwrap_or(-1))
            }
        }
    }
}

impl NewSaleTicketResponse {
    pub fn ok(ticket: Ticket) -> Self {
        Self {
            result: Some(new_sale_ticket_response::Result::Ok(
                new_sale_ticket_response::Ok {
                    ticket: Some(ticket),
                },
            )),
        }
    }

    pub fn err(err: new_sale_ticket_response::Err) -> Self {
        Self {
            result: Some(new_sale_ticket_response::Result::Err(err)),
        }
    }

    pub fn err_sale_not_open() -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::SaleNotOpen as i32,
            invalid_user_amount: None,
            existing_ticket: None,
        })
    }

    pub fn err_sale_closed() -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::SaleClosed as i32,
            invalid_user_amount: None,
            existing_ticket: None,
        })
    }

    pub fn err_invalid_principal() -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::InvalidPrincipal as i32,
            invalid_user_amount: None,
            existing_ticket: None,
        })
    }

    pub fn err_ticket_exists(ticket: Ticket) -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::TicketExists as i32,
            invalid_user_amount: None,
            existing_ticket: Some(ticket),
        })
    }

    pub fn err_invalid_subaccount() -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::InvalidSubaccount as i32,
            invalid_user_amount: None,
            existing_ticket: None,
        })
    }

    pub fn err_invalid_user_amount(
        min_amount_icp_e8s_included: u64,
        max_amount_icp_e8s_included: u64,
    ) -> Self {
        Self::err(new_sale_ticket_response::Err {
            error_type: new_sale_ticket_response::err::Type::InvalidUserAmount as i32,
            invalid_user_amount: Some(new_sale_ticket_response::err::InvalidUserAmount {
                min_amount_icp_e8s_included,
                max_amount_icp_e8s_included,
            }),
            existing_ticket: None,
        })
    }

    // panics if self.result is not set or the ticket is not set
    pub fn ticket(&self) -> Result<Ticket, new_sale_ticket_response::Err> {
        match self.result.as_ref().unwrap() {
            new_sale_ticket_response::Result::Ok(new_sale_ticket_response::Ok { ticket }) => {
                Ok(ticket.to_owned().unwrap())
            }
            new_sale_ticket_response::Result::Err(err) => Err(err.clone()),
        }
    }
}

fn insert_buyer_into_buyers_list_index(buyer_principal_id: PrincipalId) -> Result<(), GrowFailed> {
    memory::BUYERS_LIST_INDEX
        .with(|buyer_list| buyer_list.borrow_mut().push(&buyer_principal_id.into()))
}

/// A version of Swap that implements a shorter version of Debug, suitable for
/// logs. Potentially large collection fields are summarized and/or decimated.
struct SwapDigest<'a> {
    swap: &'a Swap,
}

impl<'a> SwapDigest<'a> {
    fn new(swap: &'a Swap) -> Self {
        Self { swap }
    }
}

impl<'a> fmt::Debug for SwapDigest<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let Swap {
            lifecycle,
            init,
            params,
            open_sns_token_swap_proposal_id,
            finalize_swap_in_progress,
            decentralization_sale_open_timestamp_seconds,
            decentralization_swap_termination_timestamp_seconds,
            next_ticket_id,
            purge_old_tickets_last_completion_timestamp_nanoseconds,
            purge_old_tickets_next_principal,
            already_tried_to_auto_finalize,
            auto_finalize_swap_response,

            // These are (potentially large) collections. To avoid an
            // overwhelmingly large log message, we need summarize and/or
            // decimate these.
            cf_participants,
            buyers,
            neuron_recipes,
            direct_participation_icp_e8s,
            neurons_fund_participation_icp_e8s,
        } = self.swap;

        formatter
            .debug_struct("Swap(digest)")
            .field("lifecycle", lifecycle)
            .field("init", init)
            .field("params", params)
            .field(
                "open_sns_token_swap_proposal_id",
                open_sns_token_swap_proposal_id,
            )
            .field("finalize_swap_in_progress", finalize_swap_in_progress)
            .field(
                "decentralization_sale_open_timestamp_seconds",
                decentralization_sale_open_timestamp_seconds,
            )
            .field(
                "decentralization_swap_termination_timestamp_seconds",
                decentralization_swap_termination_timestamp_seconds,
            )
            .field("next_ticket_id", next_ticket_id)
            .field(
                "purge_old_tickets_last_completion_timestamp_nanoseconds",
                purge_old_tickets_last_completion_timestamp_nanoseconds,
            )
            .field(
                "purge_old_tickets_next_principal",
                purge_old_tickets_next_principal,
            )
            .field(
                "already_tried_to_auto_finalize",
                already_tried_to_auto_finalize,
            )
            .field("auto_finalize_swap_response", auto_finalize_swap_response)
            // Summarize and/or decimate (potentially large) collection fields.
            //
            // TODO: Include some samples? E.g. the first, and last element, and
            // maybe some random elements in the middle.
            .field(
                "cf_participants",
                &format!("<len={}>", cf_participants.len()),
            )
            .field("buyers", &format!("<len={}>", buyers.len()))
            .field("neuron_recipes", &format!("<len={}>", neuron_recipes.len()))
            .field("direct_participation_icp_e8s", direct_participation_icp_e8s)
            .field(
                "neurons_fund_participation_icp_e8s",
                neurons_fund_participation_icp_e8s,
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::{
        new_sale_ticket_response::Ok, CfNeuron, CfParticipant, NeuronBasketConstructionParameters,
        Params,
    };
    use crate::swap_builder::SwapBuilder;
    use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
    use pretty_assertions::assert_eq;
    use proptest::prelude::proptest;
    use std::collections::HashSet;

    #[test]
    fn test_get_lifecycle() {
        let mut swap = Swap::default();
        let request = GetLifecycleRequest {};

        swap.lifecycle = Lifecycle::Pending as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Pending as i32)
        );

        swap.lifecycle = Lifecycle::Adopted as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Adopted as i32)
        );

        swap.lifecycle = Lifecycle::Open as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Open as i32)
        );

        swap.lifecycle = Lifecycle::Committed as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Committed as i32)
        );

        swap.lifecycle = Lifecycle::Aborted as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Aborted as i32)
        );

        swap.decentralization_sale_open_timestamp_seconds = None;
        assert_eq!(
            swap.get_lifecycle(&request)
                .decentralization_sale_open_timestamp_seconds,
            None,
        );

        swap.decentralization_sale_open_timestamp_seconds = Some(42);
        assert_eq!(
            swap.get_lifecycle(&request)
                .decentralization_sale_open_timestamp_seconds,
            Some(42),
        );

        swap.decentralization_swap_termination_timestamp_seconds = None;
        assert_eq!(
            swap.get_lifecycle(&request)
                .decentralization_swap_termination_timestamp_seconds,
            None,
        );

        swap.decentralization_swap_termination_timestamp_seconds = Some(42);
        assert_eq!(
            swap.get_lifecycle(&request)
                .decentralization_swap_termination_timestamp_seconds,
            Some(42),
        );
    }

    #[test]
    fn test_derived_state_to_get_derived_state_response() {
        let derived_state = DerivedState {
            buyer_total_icp_e8s: 400_000_000,
            sns_tokens_per_icp: 2.5f32,
            direct_participant_count: Some(1000),
            cf_participant_count: Some(100),
            cf_neuron_count: Some(200),
            direct_participation_icp_e8s: Some(500_000_000),
            neurons_fund_participation_icp_e8s: Some(300_000_000),
        };

        let response: GetDerivedStateResponse = derived_state.into();
        assert_eq!(response.sns_tokens_per_icp, Some(2.5f64));
        assert_eq!(response.buyer_total_icp_e8s, Some(400_000_000));
        assert_eq!(response.direct_participant_count, Some(1000));
        assert_eq!(response.cf_participant_count, Some(100));
        assert_eq!(response.cf_neuron_count, Some(200));
        assert_eq!(response.direct_participation_icp_e8s, Some(500_000_000));
        assert_eq!(
            response.neurons_fund_participation_icp_e8s,
            Some(300_000_000)
        );
    }

    #[test]
    fn test_process_swap_neuron_global_failures() {
        let result = Swap::process_swap_neuron(
            SwapNeuron {
                id: None, // No id to map to the index
                ..Default::default()
            },
            &mut btreemap! {},
        );

        assert_eq!(
            result,
            SweepResult {
                global_failures: 1,
                ..Default::default()
            }
        );

        let result = Swap::process_swap_neuron(
            SwapNeuron {
                id: Some(NeuronId::new_test_neuron_id(1)),
                status: 1000, // A status that is not interpretable
            },
            &mut btreemap! {},
        );

        assert_eq!(
            result,
            SweepResult {
                global_failures: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_process_swap_neuron_successful_cases() {
        let mut successful_recipe = SnsNeuronRecipe {
            claimed_status: Some(ClaimedStatus::Pending as i32),
            ..Default::default()
        };
        let mut failed_recipe = SnsNeuronRecipe {
            claimed_status: Some(ClaimedStatus::Pending as i32),
            ..Default::default()
        };
        let mut invalid_recipe = SnsNeuronRecipe {
            claimed_status: Some(ClaimedStatus::Pending as i32),
            ..Default::default()
        };

        let mut index = btreemap! {
            NeuronId::new_test_neuron_id(1) => &mut successful_recipe,
            NeuronId::new_test_neuron_id(2) => &mut failed_recipe,
            NeuronId::new_test_neuron_id(3) => &mut invalid_recipe,
        };

        // Process first to satisfy the borrow checker

        // Successful case
        let successful_sweep_result = Swap::process_swap_neuron(
            SwapNeuron {
                id: Some(NeuronId::new_test_neuron_id(1)),
                status: ClaimedSwapNeuronStatus::Success as i32,
            },
            &mut index,
        );

        // Failure case
        let failed_sweep_result = Swap::process_swap_neuron(
            SwapNeuron {
                id: Some(NeuronId::new_test_neuron_id(2)),
                status: ClaimedSwapNeuronStatus::MemoryExhausted as i32,
            },
            &mut index,
        );

        // Invalid case
        let invalid_sweep_result = Swap::process_swap_neuron(
            SwapNeuron {
                id: Some(NeuronId::new_test_neuron_id(3)),
                status: ClaimedSwapNeuronStatus::AlreadyExists as i32,
            },
            &mut index,
        );

        // Success case
        assert_eq!(
            successful_sweep_result,
            SweepResult {
                success: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            successful_recipe.claimed_status,
            Some(ClaimedStatus::Success as i32)
        );

        // Failure case
        assert_eq!(
            failed_sweep_result,
            SweepResult {
                failure: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            failed_recipe.claimed_status,
            Some(ClaimedStatus::Failed as i32)
        );

        // Invalid case
        assert_eq!(
            invalid_sweep_result,
            SweepResult {
                invalid: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            invalid_recipe.claimed_status,
            Some(ClaimedStatus::Invalid as i32),
        );
    }

    #[test]
    fn test_get_sale_parameters() {
        let swap = SwapBuilder::new().build();

        assert_eq!(
            swap.get_sale_parameters(&GetSaleParametersRequest {}),
            GetSaleParametersResponse {
                params: Some(Params {
                    min_participants: 1,
                    min_icp_e8s: 10,
                    max_icp_e8s: 100,
                    min_direct_participation_icp_e8s: Some(10,),
                    max_direct_participation_icp_e8s: Some(100,),
                    min_participant_icp_e8s: 10,
                    max_participant_icp_e8s: 20,
                    swap_due_timestamp_seconds: 1234567,
                    sns_token_e8s: 1000,
                    neuron_basket_construction_parameters: Some(
                        NeuronBasketConstructionParameters {
                            count: 2,
                            dissolve_delay_interval_seconds: 700,
                        },
                    ),
                    sale_delay_seconds: None,
                })
            },
        );
    }

    #[test]
    fn test_get_init() {
        let swap = Swap {
            init: Some(Init::default()),
            ..Default::default()
        };
        let expected_init = swap.init.clone().unwrap();
        assert_eq!(
            swap.get_init(&GetInitRequest {}),
            GetInitResponse {
                init: Some(expected_init),
            },
        );
    }

    #[test]
    fn test_list_community_fund_participants() {
        #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is removed
        let cf_participants = vec![
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(992899)),
                hotkey_principal: PrincipalId::new_user_test_id(992899).to_string(),
                cf_neurons: vec![CfNeuron::try_new(1, 698047, Vec::new()).unwrap()],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(800257)),
                hotkey_principal: PrincipalId::new_user_test_id(800257).to_string(),
                cf_neurons: vec![CfNeuron::try_new(2, 678574, Vec::new()).unwrap()],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(818371)),
                hotkey_principal: PrincipalId::new_user_test_id(818371).to_string(),
                cf_neurons: vec![CfNeuron::try_new(3, 305256, Vec::new()).unwrap()],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(657894)),
                hotkey_principal: PrincipalId::new_user_test_id(657894).to_string(),
                cf_neurons: vec![CfNeuron::try_new(4, 339747, Vec::new()).unwrap()],
            },
        ];
        let swap = Swap {
            cf_participants: cf_participants.clone(),
            ..Default::default()
        };

        assert_eq!(
            swap.list_community_fund_participants(&ListCommunityFundParticipantsRequest::default()),
            ListCommunityFundParticipantsResponse {
                cf_participants: cf_participants.clone(),
            },
        );

        assert_eq!(
            swap.list_community_fund_participants(&ListCommunityFundParticipantsRequest {
                offset: Some(2),
                ..Default::default()
            }),
            ListCommunityFundParticipantsResponse {
                cf_participants: cf_participants[2..].to_vec(),
            },
        );

        assert_eq!(
            swap.list_community_fund_participants(&ListCommunityFundParticipantsRequest {
                offset: Some(1),
                limit: Some(2),
            }),
            ListCommunityFundParticipantsResponse {
                cf_participants: cf_participants[1..3].to_vec(),
            },
        );

        assert_eq!(
            swap.list_community_fund_participants(&ListCommunityFundParticipantsRequest {
                offset: Some(2),
                limit: Some(10),
            }),
            ListCommunityFundParticipantsResponse {
                cf_participants: cf_participants[2..].to_vec(),
            },
        );

        assert_eq!(
            swap.list_community_fund_participants(&ListCommunityFundParticipantsRequest {
                offset: Some((cf_participants.len() + 1) as u64), // Give an offset outside the bounds
                limit: Some(10),                                  // Limit is irrelevant
            }),
            ListCommunityFundParticipantsResponse {
                cf_participants: vec![],
            }
        )
    }

    #[test]
    fn test_generate_vesting_schedule() {
        let neuron_basket_construction_parameters = NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 100,
        };

        assert_eq!(
            neuron_basket_construction_parameters
                .generate_vesting_schedule(/* total_amount_e8s = */ 10)
                .unwrap(),
            vec![
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 0,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 100,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 200,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 300,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 400,
                },
            ],
        );

        assert_eq!(
            neuron_basket_construction_parameters
                .generate_vesting_schedule(/* total_amount_e8s = */ 9)
                .unwrap(),
            vec![
                ScheduledVestingEvent {
                    amount_e8s: 1,
                    dissolve_delay_seconds: 0,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 100,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 200,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 300,
                },
                ScheduledVestingEvent {
                    amount_e8s: 2,
                    dissolve_delay_seconds: 400,
                },
            ],
        );
    }

    proptest! {
        #[test]
        fn test_generate_vesting_schedule_proptest(
            count in 1..25_u64,
            dissolve_delay_interval_seconds in 1..(90 * ONE_DAY_SECONDS),
            total_e8s in 1..(100 * E8),
        ) {
            let vesting_schedule = NeuronBasketConstructionParameters {
                count,
                dissolve_delay_interval_seconds,
            }
            .generate_vesting_schedule(total_e8s).unwrap();

            // Inspect overall size.
            assert_eq!(
                vesting_schedule.len() as u64,
                count,
                "{:#?}",
                vesting_schedule,
            );

            // Inspect token amounts.
            assert_eq!(
                vesting_schedule
                    .iter()
                    .map(|scheduled_vesting_event| scheduled_vesting_event.amount_e8s)
                    .sum::<u64>(),
                total_e8s,
            );
            let lower_bound_e8s = total_e8s / count;
            let upper_bound_e8s = lower_bound_e8s + 1;
            for scheduled_vesting_event in &vesting_schedule {
                assert!(
                    lower_bound_e8s <= scheduled_vesting_event.amount_e8s
                        && scheduled_vesting_event.amount_e8s <= upper_bound_e8s,
                    "{:#?}",
                    vesting_schedule,
                );
            }

            // Inspect dissolve delays.
            let mut expected_current_dissolve_delay_seconds = 0;
            for scheduled_vesting_event in &vesting_schedule {
                assert_eq!(
                    scheduled_vesting_event.dissolve_delay_seconds,
                    expected_current_dissolve_delay_seconds,
                    "{:#?}",
                    vesting_schedule,
                );
                expected_current_dissolve_delay_seconds += dissolve_delay_interval_seconds;
            }
        }
    }

    // Structure that represents the arguments of [compute_participation_increment]
    // and the expected result. See that method for a description of each argument.
    //
    // This structure exists so that it can be printed out when tests fail.
    #[derive(Debug)]
    struct ComputeParticipationIncrementScenario {
        tot_participation: u64,
        max_tot_participation: u64,
        min_user_participation: u64,
        max_user_participation: u64,
        user_participation: u64,
        requested_increment: u64,
        expected_result: Result<u64, (u64, u64)>,
    }

    #[test]
    fn test_compute_participation_increment() {
        let scenarios = vec![
            ComputeParticipationIncrementScenario {
                tot_participation: 0,
                max_tot_participation: 100,
                min_user_participation: 1,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 1,
                expected_result: Ok(1),
            },
            // happy case 1
            ComputeParticipationIncrementScenario {
                tot_participation: 40,
                max_tot_participation: 50,
                min_user_participation: 2,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 3,
                expected_result: Ok(3),
            },
            // no more tokens available in the swap
            ComputeParticipationIncrementScenario {
                tot_participation: 100,
                max_tot_participation: 100,
                min_user_participation: 1,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 1,
                expected_result: Err((0, 0)),
            },
            // requested_increment is invalid (0)
            ComputeParticipationIncrementScenario {
                tot_participation: 1,
                max_tot_participation: 100,
                min_user_participation: 1,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 0,
                expected_result: Err((1, 10)),
            },
            // requested_increment is invalid (> max_user_participation)
            ComputeParticipationIncrementScenario {
                tot_participation: 1,
                max_tot_participation: 100,
                min_user_participation: 1,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 20,
                expected_result: Err((1, 10)),
            },
            // requested_increment is invalid (< min_user_participation)
            ComputeParticipationIncrementScenario {
                tot_participation: 1,
                max_tot_participation: 100,
                min_user_participation: 2,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 1,
                expected_result: Err((2, 10)),
            },
            // The actual_increment here is 10-9 and the new participation
            // would be only 1 which is less than min_user_participation
            // required to be part of the swap.
            ComputeParticipationIncrementScenario {
                tot_participation: 9,
                max_tot_participation: 10,
                min_user_participation: 2,
                max_user_participation: 10,
                user_participation: 0,
                requested_increment: 2,
                expected_result: Err((0, 0)),
            },
        ];
        for scenario in scenarios {
            let result = compute_participation_increment(
                scenario.tot_participation,
                scenario.max_tot_participation,
                scenario.min_user_participation,
                scenario.max_user_participation,
                scenario.user_participation,
                scenario.requested_increment,
            );
            assert_eq!(
                result, scenario.expected_result,
                "Scenario {:#?} failed",
                scenario
            );
        }
    }

    #[test]
    fn test_list_sns_neuron_recipes() {
        let dummy_recipe = |investor_principal: PrincipalId| SnsNeuronRecipe {
            sns: None,
            neuron_attributes: None,
            claimed_status: None,
            investor: Some(Investor::Direct(DirectInvestment {
                buyer_principal: investor_principal.to_string(),
            })),
        };

        let neuron_recipes = vec![
            dummy_recipe(PrincipalId::new_user_test_id(0)),
            dummy_recipe(PrincipalId::new_user_test_id(1)),
            dummy_recipe(PrincipalId::new_user_test_id(2)),
            dummy_recipe(PrincipalId::new_user_test_id(3)),
        ];
        let swap = Swap {
            neuron_recipes: neuron_recipes.clone(),
            ..Default::default()
        };
        assert_eq!(
            swap.list_sns_neuron_recipes(ListSnsNeuronRecipesRequest {
                limit: None,
                offset: None
            }),
            ListSnsNeuronRecipesResponse {
                sns_neuron_recipes: neuron_recipes.clone()
            }
        );

        assert_eq!(
            swap.list_sns_neuron_recipes(ListSnsNeuronRecipesRequest {
                limit: Some(2),
                offset: None
            }),
            ListSnsNeuronRecipesResponse {
                sns_neuron_recipes: neuron_recipes[0..2].to_vec()
            }
        );

        assert_eq!(
            swap.list_sns_neuron_recipes(ListSnsNeuronRecipesRequest {
                limit: None,
                offset: Some(1)
            }),
            ListSnsNeuronRecipesResponse {
                sns_neuron_recipes: neuron_recipes[1..].to_vec()
            }
        );

        assert_eq!(
            swap.list_sns_neuron_recipes(ListSnsNeuronRecipesRequest {
                limit: Some(2),
                offset: Some(1)
            }),
            ListSnsNeuronRecipesResponse {
                sns_neuron_recipes: neuron_recipes[1..3].to_vec()
            }
        );

        assert_eq!(
            swap.list_sns_neuron_recipes(ListSnsNeuronRecipesRequest {
                limit: Some(2),                                  // Limit is irrelevant
                offset: Some((neuron_recipes.len() + 1) as u64), // Give an offset outside the bounds
            }),
            ListSnsNeuronRecipesResponse {
                sns_neuron_recipes: vec![],
            }
        )
    }

    proptest! {
        #[test]
        fn test_ticket_ids_unique(pids in proptest::collection::vec(0..u64::MAX, 0..1000)) {
            let mut swap = SwapBuilder::new()
                .with_lifecycle(Lifecycle::Open)
                .with_min_max_participant_icp(10_000, 1_000_000)
                .with_min_max_direct_participation(10_010_000, 20_000_000)
                .build();

            let mut ticket_ids = HashSet::new();
            for pid in pids {
                let principal = PrincipalId::new_user_test_id(pid);
                let request = NewSaleTicketRequest {
                    amount_icp_e8s: 10_000,
                    subaccount: None,
                };
                let ticket = match swap.new_sale_ticket(&request, principal, 0).result.unwrap() {
                    new_sale_ticket_response::Result::Ok(Ok { ticket }) => ticket.unwrap(),
                    new_sale_ticket_response::Result::Err(e) => panic!("{:?}", e),
                };
                assert_eq!(ticket_ids.replace(ticket.ticket_id), None);
            }
        }
    }

    #[test]
    fn test_try_commit_or_abort_no_buyers_with_time_remaining() {
        let sale_duration = 100;
        let time_remaining = 50;
        let now = sale_duration - time_remaining;
        let buyers = BTreeMap::new();
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .with_min_participants(1)
            .with_min_max_participant_icp(1, 20)
            .with_min_max_direct_participation(10, 100)
            .build();

        let result = swap.try_commit(now) || swap.try_abort(now);
        assert!(!result);
        assert_eq!(swap.lifecycle, Lifecycle::Open as i32);
    }

    #[test]
    fn test_try_commit_or_abort_not_enough_e8s_with_time_remaining() {
        let sale_duration = 100;
        let time_remaining = 50;
        let now = sale_duration - time_remaining;
        let buyers = btreemap! {
            PrincipalId::new_user_test_id(0).to_string() => BuyerState::new(1),
        };
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .with_min_participants(1)
            .with_min_max_participant_icp(10, 20)
            .with_min_max_direct_participation(10, 100)
            .build();

        let result = swap.try_commit(now) || swap.try_abort(now);
        assert!(!result);
        assert_eq!(swap.lifecycle, Lifecycle::Open as i32);
    }

    #[test]
    fn test_try_commit_or_abort_enough_e8s_with_time_remaining() {
        let sale_duration = 100;
        let time_remaining = 50;
        let now = sale_duration - time_remaining;
        let buyers = btreemap! {
            PrincipalId::new_user_test_id(0).to_string() => BuyerState::new(10),
        };
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .build();

        assert_eq!(
            Lifecycle::try_from(swap.lifecycle).unwrap(),
            Lifecycle::Open
        );

        let result = swap.try_commit(now) || swap.try_abort(now);
        // swap should still be open because there is time remaining and we have not
        // reached the maximum amount of ICP raised.
        assert!(!result);
        assert_eq!(
            Lifecycle::try_from(swap.lifecycle).unwrap(),
            Lifecycle::Open
        );
    }

    #[test]
    fn test_try_commit_or_abort_max_e8s_with_time_remaining() {
        let sale_duration = 100;
        let time_remaining = 50;
        let now = sale_duration - time_remaining;
        let buyers = btreemap! {
            PrincipalId::new_user_test_id(0).to_string() => BuyerState::new(20),
        };
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .with_min_participants(1)
            .with_min_max_participant_icp(10, 20)
            .with_min_max_direct_participation(10, 20)
            .build();
        swap.update_derived_fields();

        // test try_commit
        {
            let mut swap = swap.clone();
            let result = swap.try_commit(now);
            // swap should commit because there is time remaining and we have not
            // reached the maximum amount of participation
            assert!(result);
            assert_eq!(swap.lifecycle, Lifecycle::Committed as i32);
        }
        // test try_abort
        {
            let result = swap.try_abort(now);
            // swap should not have aborted, because there is time remaining
            // and we have not reached the maximum amount of participation
            assert!(!result);
            assert_eq!(swap.lifecycle, Lifecycle::Open as i32);
        }
    }

    #[test]
    fn test_try_commit_or_abort_insufficient_participation_with_no_time_remaining() {
        let sale_duration = 100;
        let time_remaining = 0;
        let now = sale_duration - time_remaining;
        let buyers = BTreeMap::new();
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .with_min_participants(1)
            .with_min_max_participant_icp(10, 20)
            .with_min_max_direct_participation(10, 20)
            .build();

        // test try_commit
        {
            let mut swap = swap.clone();
            let result = swap.try_commit(now);
            // swap should not commit because there is no time remaining and we
            // have not reached the minimum number of participants

            assert!(!result);
            assert_eq!(swap.lifecycle, Lifecycle::Open as i32);
        }
        // test try_abort
        {
            let result = swap.try_abort(now);
            // swap should abort because there is no time remaining and we
            // have not reached the minimum number of participants

            assert!(result);
            assert_eq!(swap.lifecycle, Lifecycle::Aborted as i32);
        }
    }

    #[test]
    fn test_try_commit_or_abort_insufficient_participation_with_max_icp() {
        let sale_duration = 100;
        let time_remaining = 50;
        let now = sale_duration - time_remaining;
        let buyers = btreemap! {
            PrincipalId::new_user_test_id(0).to_string() => BuyerState::new(20),
        };
        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_buyers(buyers)
            .with_swap_start_due(None, Some(sale_duration))
            .with_min_participants(2)
            .with_min_max_participant_icp(10, 20)
            .with_min_max_direct_participation(10, 20)
            .build();
        swap.update_derived_fields();

        // test try_commit
        {
            let mut swap = swap.clone();
            let result = swap.try_commit(now);
            // swap should not commit because we have reached the max icp but
            // have not reached the minimum number of participants

            assert!(!result);
            assert_eq!(swap.lifecycle, Lifecycle::Open as i32);
        }
        // test try_abort
        {
            let result = swap.try_abort(now);
            // swap should abort because we have reached the max icp but
            // have not reached the minimum number of participants

            assert!(result);
            assert_eq!(swap.lifecycle, Lifecycle::Aborted as i32);
        }
    }

    #[test]
    fn test_purge_old_tickets() {
        const TEN_MINUTES: u64 = 60 * 10 * 1_000_000_000;
        const ONE_DAY: u64 = ONE_DAY_SECONDS * 1_000_000_000;
        const NUMBER_OF_TICKETS_THRESHOLD: u64 = 10;
        const MAX_AGE_IN_NANOSECONDS: u64 = ONE_DAY * 2;
        const MAX_NUMBER_TO_INSPECT: u64 = 2;

        let min_participant_icp_e8s = 1;

        let mut swap = SwapBuilder::new()
            .with_lifecycle(Lifecycle::Open)
            .with_min_max_participant_icp(min_participant_icp_e8s, 1)
            .with_min_max_direct_participation(1, 10)
            .with_swap_start_due(None, Some(10_000_000))
            .build();

        let try_purge_old_tickets = |sale: &mut Swap, time: u64| loop {
            match sale.try_purge_old_tickets(
                || time,
                NUMBER_OF_TICKETS_THRESHOLD,
                MAX_AGE_IN_NANOSECONDS,
                MAX_NUMBER_TO_INSPECT,
            ) {
                Some(false) => continue,
                Some(true) => break,
                None => panic!("purge_old_ticket was not run"),
            }
        };

        // Check that the number_of_tickets_threshold parameter works and prevents
        // the method from being called (None == purge_old_ticket didn't run)
        assert_eq!(
            swap.try_purge_old_tickets(
                || TEN_MINUTES,
                1, /* there are 0 tickets */
                0,
                u64::MAX
            ),
            None
        );

        let principals1: Vec<PrincipalId> = (0..10).map(PrincipalId::new_user_test_id).collect();
        let principals2: Vec<PrincipalId> = (10..20).map(PrincipalId::new_user_test_id).collect();
        let principals3: Vec<PrincipalId> = (20..30).map(PrincipalId::new_user_test_id).collect();

        // add the first batch of tickets at the beginning of time
        for principal in &principals1 {
            assert!(swap
                .new_sale_ticket(
                    &NewSaleTicketRequest {
                        amount_icp_e8s: min_participant_icp_e8s,
                        subaccount: None
                    },
                    *principal,
                    0
                )
                .ticket()
                .is_ok());
        }

        // try to purge old tickets without advancing time. None of the tickets should be removed
        try_purge_old_tickets(&mut swap, TEN_MINUTES); // TEN_MINUTES in order to trigger the call

        // not purged because 0 days old
        for principal in &principals1 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // add the second batch of tickets after one day
        for principal in &principals2 {
            assert!(swap
                .new_sale_ticket(
                    &NewSaleTicketRequest {
                        amount_icp_e8s: min_participant_icp_e8s,
                        subaccount: None
                    },
                    *principal,
                    ONE_DAY
                )
                .ticket()
                .is_ok());
        }

        // try to purge old tickets after one day. None of the tickets should be removed
        try_purge_old_tickets(&mut swap, ONE_DAY);

        // not purged because 1 day old
        for principal in &principals1 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // not purged because 0 days old
        for principal in &principals2 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // try to purge old tickets after two days minus 1 second.
        // check that all the tickets are still there. This verifies
        // that the swap canister keep the tickets for the right amount of time
        try_purge_old_tickets(&mut swap, ONE_DAY * 2 - 1);

        // not purged because 2 day - 1 second old
        for principal in &principals1 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // not purged because 1 days - 1 second old
        for principal in &principals2 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // try to purge old tickets after two days.
        // All the principal1 tickets should be gone.
        // TEN_MINUTES required to trigger the method.
        try_purge_old_tickets(&mut swap, ONE_DAY * 2 + TEN_MINUTES);

        // purged because 2 days old
        for principal in &principals1 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_none());
        }

        // not purged because 1 days old
        for principal in &principals2 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // add the third batch of tickets at two days
        for principal in &principals3 {
            assert!(swap
                .new_sale_ticket(
                    &NewSaleTicketRequest {
                        amount_icp_e8s: min_participant_icp_e8s,
                        subaccount: None
                    },
                    *principal,
                    ONE_DAY * 2 + TEN_MINUTES
                )
                .ticket()
                .is_ok());
        }

        // try to purge old tickets after three days - 1 second.
        // same result
        try_purge_old_tickets(&mut swap, ONE_DAY * 3 - 1);

        // not purged because 2 days old - 1 second
        for principal in &principals2 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // try to purge old tickets after three days.
        // All the principal2 tickets should be gone.
        // TEN_MINUTES required to trigger the method.
        try_purge_old_tickets(&mut swap, ONE_DAY * 3 + TEN_MINUTES);

        // purged because 2 days old
        for principal in &principals2 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_none());
        }

        // not purged because 1 days old
        for principal in &principals3 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }

        // try to purge old tickets after 4 days but
        // with a higher threshold.
        // All the principals3 tickets should be still
        // there because of the threshold

        assert_eq!(
            swap.try_purge_old_tickets(
                || ONE_DAY * 4 + TEN_MINUTES,
                principals3.len() as u64 + 1,
                0,
                u64::MAX
            ),
            None
        );

        // not purged because threshold was not met
        for principal in &principals3 {
            assert!(swap
                .get_open_ticket(&GetOpenTicketRequest {}, *principal)
                .ticket()
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn test_cf_neuron_count() {
        #[allow(deprecated)] // TODO(NNS1-3198): Remove once hotkey_principal is removed
        let cf_participants = vec![
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(992899)),
                hotkey_principal: PrincipalId::new_user_test_id(992899).to_string(),
                cf_neurons: vec![
                    CfNeuron::try_new(1, 698047, Vec::new()).unwrap(),
                    CfNeuron::try_new(2, 303030, Vec::new()).unwrap(),
                ],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(800257)),
                hotkey_principal: PrincipalId::new_user_test_id(800257).to_string(),
                cf_neurons: vec![CfNeuron::try_new(3, 678574, Vec::new()).unwrap()],
            },
            CfParticipant {
                controller: Some(PrincipalId::new_user_test_id(818371)),
                hotkey_principal: PrincipalId::new_user_test_id(818371).to_string(),
                cf_neurons: vec![
                    CfNeuron::try_new(4, 305256, Vec::new()).unwrap(),
                    CfNeuron::try_new(5, 100000, Vec::new()).unwrap(),
                    CfNeuron::try_new(6, 1010101, Vec::new()).unwrap(),
                    CfNeuron::try_new(7, 102123, Vec::new()).unwrap(),
                ],
            },
        ];
        let swap = Swap {
            cf_participants,
            ..Default::default()
        };

        assert_eq!(7, swap.cf_neuron_count());
    }
}
