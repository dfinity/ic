use crate::clients::{NnsGovernanceClient, SnsGovernanceClient, SnsRootClient};
use crate::logs::{ERROR, INFO};
use crate::pb::v1::{
    params::NeuronBasketConstructionParameters,
    restore_dapp_controllers_response, set_dapp_controllers_call_result, set_mode_call_result,
    set_mode_call_result::SetModeResult,
    settle_community_fund_participation_result,
    sns_neuron_recipe::{ClaimedStatus, Investor, NeuronAttributes},
    BuyerState, CanisterCallError, CfInvestment, DerivedState, DirectInvestment,
    ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapResponse, GetBuyerStateRequest,
    GetBuyerStateResponse, GetBuyersTotalResponse, GetDerivedStateResponse, GetLifecycleRequest,
    GetLifecycleResponse, Init, Lifecycle, ListCommunityFundParticipantsRequest,
    ListCommunityFundParticipantsResponse, OpenRequest, OpenResponse, RefreshBuyerTokensResponse,
    RestoreDappControllersResponse, SetDappControllersCallResult, SetModeCallResult,
    SettleCommunityFundParticipationResult, SnsNeuronRecipe, Swap, SweepResult, TransferableAmount,
};
use crate::types::{ScheduledVestingEvent, TransferResult};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{i2d, ledger::compute_neuron_staking_subaccount_bytes};
use ic_sns_governance::{
    ledger::ICRC1Ledger,
    pb::v1::{
        claim_swap_neurons_request::NeuronParameters,
        claim_swap_neurons_response::ClaimSwapNeuronsResult,
        claim_swap_neurons_response::SwapNeuron, governance, ClaimSwapNeuronsError,
        ClaimSwapNeuronsRequest, ClaimedSwapNeuronStatus, NeuronId, SetMode, SetModeResponse,
    },
};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use itertools::{Either, Itertools};
use maplit::btreemap;
use rust_decimal::prelude::ToPrimitive;
use std::collections::BTreeMap;
use std::{
    mem,
    num::{NonZeroU128, NonZeroU64},
    ops::Div,
    str::FromStr,
};

// TODO(NNS1-1589): Get these from the canonical location.
use crate::pb::v1::{
    settle_community_fund_participation, GovernanceError, SetDappControllersRequest,
    SetDappControllersResponse, SettleCommunityFundParticipation,
};

// The number of bytes that the contents of a ClaimSwapNeuronsRequest can safely consume. This
// is configured to be 75% of a Xnet message size, or roughly 1.5MB. This is equivalent to
// (1024 * 1024) * 1.5
pub const CLAIM_SWAP_NEURONS_MESSAGE_SIZE_LIMIT_BYTES: usize = 1572864_usize;

const DEFAULT_LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT: u32 = 10_000;
const LIST_COMMUNITY_FUND_PARTICIPANTS_LIMIT_CAP: u32 = 10_000;

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

impl From<Result<SetDappControllersResponse, CanisterCallError>>
    for RestoreDappControllersResponse
{
    fn from(native_result: Result<SetDappControllersResponse, CanisterCallError>) -> Self {
        use restore_dapp_controllers_response::Possibility as P;
        let possibility = Some(match native_result {
            Ok(response) => P::Ok(response),
            Err(err) => P::Err(err),
        });

        Self { possibility }
    }
}

impl From<Result<Result<(), GovernanceError>, CanisterCallError>>
    for SettleCommunityFundParticipationResult
{
    fn from(original: Result<Result<(), GovernanceError>, CanisterCallError>) -> Self {
        use settle_community_fund_participation_result::{Possibility, Response};

        match original {
            Ok(inner) => Self {
                possibility: Some(Possibility::Ok(Response {
                    governance_error: match inner {
                        Ok(()) => None,
                        Err(governance_error) => Some(governance_error),
                    },
                })),
            },

            Err(err) => Self {
                possibility: Some(Possibility::Err(err)),
            },
        }
    }
}

impl From<DerivedState> for GetDerivedStateResponse {
    fn from(state: DerivedState) -> GetDerivedStateResponse {
        GetDerivedStateResponse {
            buyer_total_icp_e8s: Some(state.buyer_total_icp_e8s),
            sns_tokens_per_icp: Some(state.sns_tokens_per_icp as f64),
        }
    }
}

impl NeuronBasketConstructionParameters {
    /// Chops `total_amount_e8s` into `self.count` pieces. Each gets doled out
    /// every `self.dissolve_delay_seconds`, starting from 0.
    ///
    /// # Arguments
    /// * `total_amount_e8s` - The total amount of tokens (in e8s) to be chopped up.
    fn generate_vesting_schedule(&self, total_amount_e8s: u64) -> Vec<ScheduledVestingEvent> {
        let dissolve_delay_seconds_list = (0..(self.count))
            .map(|i| i * self.dissolve_delay_interval_seconds)
            .collect::<Vec<u64>>();

        let chunks_e8s = apportion_approximately_equally(total_amount_e8s, self.count);

        assert_eq!(dissolve_delay_seconds_list.len(), chunks_e8s.len());

        dissolve_delay_seconds_list
            .into_iter()
            .zip(chunks_e8s.into_iter())
            .map(
                |(dissolve_delay_seconds, amount_e8s)| ScheduledVestingEvent {
                    dissolve_delay_seconds,
                    amount_e8s,
                },
            )
            .collect()
    }
}

/// Chops up `total` in to `len` pieces.
///
/// More precisely, result.len() == len. result.sum() == total. Each element of
/// result is approximately equal to the others. However, unless len divides
/// total evenly, the elements of result will inevitabley be not equal.
pub fn apportion_approximately_equally(total: u64, len: u64) -> Vec<u64> {
    let quotient = total.saturating_div(len);
    let remainder = total % len;

    let mut result = vec![quotient; len as usize];
    *result.first_mut().unwrap() += remainder;

    result
}

// High level documentation in the corresponding Protobuf message.
impl Swap {
    /// Create state from an `Init` object.
    ///
    /// Requires that `init` is valid; otherwise it panics.
    pub fn new(init: Init) -> Self {
        if let Err(e) = init.validate() {
            panic!("Invalid init arg: {:#?}\nReason: {}", init, e);
        }
        Self {
            lifecycle: Lifecycle::Pending as i32,
            init: Some(init),
            params: None,
            cf_participants: vec![],
            buyers: Default::default(), // Btree map
            neuron_recipes: vec![],
            open_sns_token_swap_proposal_id: None,
            finalize_swap_in_progress: Some(false),
        }
    }

    /// Retrieve a reference to the `init` field. The `init` field
    /// is unlikely to be `None` given how `new` is implemented.
    pub fn init_or_panic(&self) -> &Init {
        self.init
            .as_ref()
            .expect("Expected the init field to be populated in the Sale canister state")
    }

    /// Retrieve a reference to the `init` field without panicking.
    pub fn init(&self) -> Result<&Init, String> {
        self.init
            .as_ref()
            .ok_or_else(|| "The Init field is not populated in the Sale canister state".to_string())
    }

    pub fn init_and_validate(&self) -> Result<&Init, String> {
        match &self.init {
            None => Err("Missing Init in the Sale canister state".to_string()),
            Some(init) => init.validate().map(|_| init),
        }
    }

    /// A Result with the number of SNS tokens for sale, or an Err if the sale hasn't
    /// been opened yet.
    pub fn sns_token_e8s(&self) -> Result<u64, String> {
        self.params
            .as_ref()
            .map(|params| params.sns_token_e8s)
            .ok_or_else(|| "Sale not open, no tokens available.".to_string())
    }

    /// The total amount of ICP contributed by direct investors and the
    /// community fund.
    pub fn participant_total_icp_e8s(&self) -> u64 {
        self.direct_investor_total_icp_e8s()
            .saturating_add(self.cf_total_icp_e8s())
    }

    /// The total amount of ICP contributed by the community fund.
    pub fn cf_total_icp_e8s(&self) -> u64 {
        self.cf_participants
            .iter()
            .map(|x| x.participant_total_icp_e8s())
            .fold(0, |sum, v| sum.saturating_add(v))
    }

    /// The total amount of ICP contributed by direct investors.
    fn direct_investor_total_icp_e8s(&self) -> u64 {
        self.buyers
            .values()
            .map(|x| x.amount_icp_e8s())
            .fold(0, |sum, v| sum.saturating_add(v))
    }

    /// Determine if the Sale is in it's terminal state
    /// based on it's lifecycle.
    fn lifecycle_is_terminal(&self) -> bool {
        self.lifecycle().is_terminal()
    }

    //
    // --- state transition functions ------------------------------------------
    //

    /// If the swap is OPEN, try to commit or abort the swap. Returns
    /// true if a transition was made and false otherwise.
    pub fn try_commit_or_abort(&mut self, now_seconds: u64) -> bool {
        if self.can_commit(now_seconds) {
            self.commit(now_seconds);
            return true;
        }
        let lifecycle = self.lifecycle();
        if lifecycle == Lifecycle::Open
            && self.swap_due(now_seconds)
            && !self.sufficient_participation()
        {
            self.abort(now_seconds);
            return true;
        }
        false
    }

    /// Precondition: lifecycle == PENDING
    ///
    /// Postcondition (on Ok): lifecycle == OPEN
    ///
    /// The parameters of the swap, specified in the request, specify
    /// the limits on total and per-participant ICP, the number of SNS
    /// tokens for sale, and the community fund participation of the
    /// swap.
    pub async fn open(
        &mut self,
        this_canister: CanisterId,
        sns_ledger: &dyn ICRC1Ledger,
        now_seconds: u64,
        req: OpenRequest,
    ) -> Result<OpenResponse, String> {
        if self.lifecycle() != Lifecycle::Pending {
            return Err("Invalid lifecycle state to OPEN the swap: must be PENDING".to_string());
        }

        req.validate(now_seconds, self.init_or_panic())?;
        let params = req.params.as_ref().expect("The params field has no value.");

        let sns_token_amount = Self::get_sns_tokens(this_canister, sns_ledger).await?;

        // Check that the SNS amount is at least the required
        // amount. We don't refuse to open the swap just because there
        // are more SNS tokens sent to the swap canister than
        // advertised, as this would lead to a dead end, because there
        // is no way to take the tokens back.
        if sns_token_amount.get_e8s() < params.sns_token_e8s {
            return Err(format!(
                "Cannot OPEN, because the expected number of SNS tokens is not \
                 available. expected={} available={}",
                params.sns_token_e8s,
                sns_token_amount.get_e8s(),
            ));
        }

        assert!(self.params.is_none());
        self.params = req.params;
        self.cf_participants = req.cf_participants;
        self.open_sns_token_swap_proposal_id = req.open_sns_token_swap_proposal_id;
        self.set_lifecycle(Lifecycle::Open);
        Ok(OpenResponse {})
    }

    /// Compute `amount_icp_e8s` scaled by (`total_sns_e8s` divided by
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

    /// Precondition: lifecycle == OPEN && sufficient_participation && (swap_due || icp_target_reached)
    ///
    /// Postcondition: lifecycle == COMMITTED
    fn commit(&mut self, now_seconds: u64) {
        assert_eq!(self.lifecycle(), Lifecycle::Open);
        assert!(self.sufficient_participation());
        assert!(self.swap_due(now_seconds) || self.icp_target_reached());
        // Safe as `params` must be specified in call to `open`.
        let params = self.params.as_ref().expect("Expected params to be set");

        let neuron_basket_construction_parameters = params
            .neuron_basket_construction_parameters
            .as_ref()
            .expect("Expected neuron_basket_construction_parameters to be set");

        // We are selling SNS tokens for the base token (ICP), or, in
        // general, whatever token the ledger referred to as the ICP
        // ledger holds.
        let sns_being_offered_e8s = params.sns_token_e8s;
        // This must hold as the swap cannot transition to state
        // OPEN without transferring tokens being offered to the swap canister.
        assert!(sns_being_offered_e8s > 0);
        // Note that this value has to be > 0 as we have > 0
        // participants each with > 0 ICP contributed.
        let total_participant_icp_e8s = NonZeroU64::try_from(self.participant_total_icp_e8s())
            .expect("participant_total_icp_e8s must be greater than 0");

        // Keep track of SNS tokens sold just to check that the amount
        // is correct at the end.
        let mut total_sns_tokens_sold: u64 = 0;
        // Vector of neuron recipes.
        let mut neurons = Vec::new();
        // =====================================================================
        // ===            This is where the actual swap happens              ===
        // =====================================================================
        for (buyer_principal, buyer_state) in self.buyers.iter() {
            let amount_sns_e8s = Swap::scale(
                buyer_state.amount_icp_e8s(),
                sns_being_offered_e8s,
                total_participant_icp_e8s,
            );

            // Create the neuron basket for the direct investors. The unique
            // identifier for an SNS Neuron is the SNS Ledger Subaccount, which
            // is a hash of PrincipalId and some unique memo. Since direct
            // investors in the swap use their own principal_id, there are no
            // neuron id collisions, and each basket can use memos starting at 0.
            for (memo, scheduled_vesting_event) in neuron_basket_construction_parameters
                .generate_vesting_schedule(amount_sns_e8s)
                .into_iter()
                .enumerate()
            {
                neurons.push(SnsNeuronRecipe {
                    sns: Some(TransferableAmount {
                        amount_e8s: scheduled_vesting_event.amount_e8s,
                        transfer_start_timestamp_seconds: 0,
                        transfer_success_timestamp_seconds: 0,
                    }),
                    investor: Some(Investor::Direct(DirectInvestment {
                        buyer_principal: buyer_principal.clone(),
                    })),
                    neuron_attributes: Some(NeuronAttributes {
                        memo: memo as u64,
                        dissolve_delay_seconds: scheduled_vesting_event.dissolve_delay_seconds,
                    }),
                    claimed_status: Some(ClaimedStatus::Pending as i32),
                });
                total_sns_tokens_sold = total_sns_tokens_sold
                    .checked_add(scheduled_vesting_event.amount_e8s)
                    .unwrap();
            }
        }

        // Create the neuron basket for the Community Fund investors. The unique
        // identifier for an SNS Neuron is the SNS Ledger Subaccount, which
        // is a hash of PrincipalId and some unique memo. Since CF
        // investors in the swap use the NNS Governance principal_id, there can be
        // neuron id collisions, so there must be a global memo used for all baskets
        // for all CF investors.
        let mut global_cf_memo = 0;
        for cf_participant in self.cf_participants.iter() {
            for cf_neuron in cf_participant.cf_neurons.iter() {
                let amount_sns_e8s = Swap::scale(
                    cf_neuron.amount_icp_e8s,
                    sns_being_offered_e8s,
                    total_participant_icp_e8s,
                );

                for scheduled_vesting_event in
                    neuron_basket_construction_parameters.generate_vesting_schedule(amount_sns_e8s)
                {
                    neurons.push(SnsNeuronRecipe {
                        sns: Some(TransferableAmount {
                            amount_e8s: scheduled_vesting_event.amount_e8s,
                            transfer_start_timestamp_seconds: 0,
                            transfer_success_timestamp_seconds: 0,
                        }),
                        investor: Some(Investor::CommunityFund(CfInvestment {
                            hotkey_principal: cf_participant.hotkey_principal.clone(),
                            nns_neuron_id: cf_neuron.nns_neuron_id,
                        })),
                        neuron_attributes: Some(NeuronAttributes {
                            memo: global_cf_memo,
                            dissolve_delay_seconds: scheduled_vesting_event.dissolve_delay_seconds,
                        }),
                        claimed_status: Some(ClaimedStatus::Pending as i32),
                    });
                    total_sns_tokens_sold = total_sns_tokens_sold
                        .checked_add(scheduled_vesting_event.amount_e8s)
                        .unwrap();
                    global_cf_memo += 1;
                }
            }
        }
        assert!(total_sns_tokens_sold <= params.sns_token_e8s);
        log!(
            INFO,
            "Token swap committed; {} direct investors and {} community fund investors receive a total of {} out of {} (change {});",
		    self.buyers.len(),
		    self.cf_participants.len(),
		    total_sns_tokens_sold,
		    params.sns_token_e8s,
		    params.sns_token_e8s - total_sns_tokens_sold
        );
        self.neuron_recipes = neurons;
        self.set_lifecycle(Lifecycle::Committed);
    }

    /// Precondition: lifecycle = OPEN && swap_due && not sufficient_participation
    ///
    /// Postcondition: lifecycle == ABORTED
    fn abort(&mut self, now_seconds: u64) {
        assert_eq!(self.lifecycle(), Lifecycle::Open);
        assert!(self.swap_due(now_seconds));
        assert!(!self.sufficient_participation());
        self.set_lifecycle(Lifecycle::Aborted);
    }

    /// Retrieve the balance of 'this' canister on the SNS token
    /// ledger.
    ///
    /// It is assumed that prior to calling this method, tokens have
    /// been transfer to the swap canister (this canister) on the
    /// ledger of `init.sns_ledger_canister_id`. This transfer is
    /// performed by the Governance canister of the SNS or
    /// pre-decentralization token holders.
    async fn get_sns_tokens(
        this_canister: CanisterId,
        sns_ledger: &dyn ICRC1Ledger,
    ) -> Result<Tokens, String> {
        // Look for the token balance of 'this' canister.
        let account = Account {
            owner: this_canister.get(),
            subaccount: None,
        };
        let e8s = sns_ledger
            .account_balance(account)
            .await
            .map_err(|x| x.to_string())?;
        Ok(e8s)
    }

    //
    // --- state modifying methods ---------------------------------------------
    //

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
    ///
    /// If a ledger transfer was successfully made, but this calls
    /// fails (many reasons are possible), the owner of the ICP sent
    /// to the subaccount can be reclaimed using `error_refund_icp`
    /// once this swap is closed (committed or aborted).
    ///
    /// TODO(NNS1-1682): attempt to refund ICP that cannot be accepted.
    pub async fn refresh_buyer_token_e8s(
        &mut self,
        buyer: PrincipalId,
        this_canister: CanisterId,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> Result<RefreshBuyerTokensResponse, String> {
        if self.lifecycle() != Lifecycle::Open {
            return Err(
                "The token amount can only be refreshed when the canister is in the OPEN state"
                    .to_string(),
            );
        }
        if self.icp_target_reached() {
            return Err("The ICP target for this token swap has already been reached.".to_string());
        }
        // Look for the token balance of the specified principal's subaccount on 'this' canister.
        let account = Account {
            owner: this_canister.get(),
            subaccount: Some(principal_to_subaccount(&buyer)),
        };
        let e8s = icp_ledger
            .account_balance(account)
            .await
            .map_err(|x| x.to_string())
            .map(|x| x.get_e8s())?;

        // Recheck lifecycle state after async call because the swap
        // could have been closed (committed or aborted) while the
        // call to get the account balance was outstanding.
        if self.lifecycle() != Lifecycle::Open {
            return Err(
                "The token amount can only be refreshed when the canister is in the OPEN state"
                    .to_string(),
            );
        }

        // Recheck total amount of ICP bought after async call.
        let participant_total_icp_e8s = self.participant_total_icp_e8s();
        let params = &self.params.as_ref().expect("Expected params to be set"); // Safe as lifecycle is OPEN.
        let max_icp_e8s = params.max_icp_e8s;
        if participant_total_icp_e8s >= max_icp_e8s {
            if participant_total_icp_e8s > max_icp_e8s {
                log!(
                    ERROR,
                    "Total amount of ICP bought {} already exceeds the target {}!",
                    participant_total_icp_e8s,
                    max_icp_e8s
                );
            }
            // Nothing we can do for this buyer.
            return Err("The swap has already reached its target".to_string());
        }
        // Subtraction safe because of the preceding if-statement.
        let max_increment_e8s = max_icp_e8s - participant_total_icp_e8s;

        // Check that the minimum amount has been transferred before
        // actually creating an entry for the buyer.
        if e8s < params.min_participant_icp_e8s {
            return Err(format!(
                "Amount transferred: {}; minimum required to participate: {}",
                e8s, params.min_participant_icp_e8s
            ));
        }
        let max_participant_icp_e8s = params.max_participant_icp_e8s;
        let buyer_state = self
            .buyers
            .entry(buyer.to_string())
            .or_insert_with(|| BuyerState {
                icp: Some(TransferableAmount {
                    amount_e8s: 0,
                    transfer_start_timestamp_seconds: 0,
                    transfer_success_timestamp_seconds: 0,
                }),
            });
        let old_amount_icp_e8s = buyer_state.amount_icp_e8s();
        if old_amount_icp_e8s >= e8s {
            // Already up-to-date. Strict inequality can happen if messages are re-ordered.
            return Ok(RefreshBuyerTokensResponse {
                icp_accepted_participation_e8s: e8s,
                icp_ledger_account_balance_e8s: e8s,
            });
        }
        // Subtraction safe because of the preceding if-statement.
        let requested_increment_e8s = e8s - old_amount_icp_e8s;
        let actual_increment_e8s = std::cmp::min(max_increment_e8s, requested_increment_e8s);
        let new_balance_e8s = buyer_state
            .amount_icp_e8s()
            .saturating_add(actual_increment_e8s);
        if new_balance_e8s > max_participant_icp_e8s {
            log!(
                INFO,
                "Participant {} contributed {} e8s - the limit per participant is {}",
                buyer,
                new_balance_e8s,
                max_participant_icp_e8s
            );
        }
        buyer_state.set_amount_icp_e8s(std::cmp::min(new_balance_e8s, max_participant_icp_e8s));
        log!(
            INFO,
            "Refresh_buyer_tokens for buyer {}; old e8s {}; new e8s {}",
            buyer,
            old_amount_icp_e8s,
            buyer_state.amount_icp_e8s()
        );
        if requested_increment_e8s >= max_increment_e8s {
            log!(INFO, "Swap has reached ICP target of {}", max_icp_e8s);
        }
        Ok(RefreshBuyerTokensResponse {
            icp_accepted_participation_e8s: buyer_state.amount_icp_e8s(),
            icp_ledger_account_balance_e8s: e8s,
        })
    }

    /*

    Transfers OUT.

     */

    /// Restores all dapp(s) canisters to te fallback controllers as specified
    /// in the SNS initialization process. `restore_dapp_controllers` is only
    /// callable by NNS Governance.
    pub async fn restore_dapp_controllers(
        &mut self,
        sns_root_client: &mut impl SnsRootClient,
        caller: PrincipalId,
    ) -> RestoreDappControllersResponse {
        // Require authorization.
        let nns_governance = self.init_or_panic().nns_governance_or_panic();
        if caller != nns_governance.get() {
            panic!(
                "This method can only be called by NNS Governance({}). Current caller is {}",
                nns_governance, caller,
            );
        }

        // With the restoration of the dapp(s) to the fallback controllers, the Sale
        // is now aborted.
        self.set_lifecycle(Lifecycle::Aborted);

        let set_dapp_controllers_result = self.set_dapp_controllers(sns_root_client).await;
        match set_dapp_controllers_result {
            Ok(set_dapp_controllers_response) => set_dapp_controllers_response.into(),
            // `restore_dapp_controllers` is called by NNS Governance which expects a
            // RestoreDappControllersResponse. Since this is after the The error response in that Response
            // object is a CanisterCallError, so transform the error_message to a
            // CanisterCallError even though this is not technically a CanisterCallError.
            //
            // TODO IC-1448: In the Single Proposal SNS Initialization, a more robust
            // response object can include errors that are not limited to CanisterCallError.
            Err(error_message) => Err(CanisterCallError {
                description: error_message,
                ..Default::default()
            })
            .into(),
        }
    }

    /// Determines if the conditions have been met in order to
    /// restore the dapp canisters to the fallback controller ids.
    /// The lifecycle MUST be set to Aborted via the commit method.
    pub fn should_restore_dapp_control(&self) -> bool {
        self.lifecycle() == Lifecycle::Aborted
    }

    /// set_dapp_controllers calls SNS Root with the Sale canister's configured
    /// `fallback_controller_principal_ids`. set_dapp_controllers is generic and
    /// used for the various Sale APIs that need to return control of the dapp(s)
    /// back to the devs.
    pub async fn set_dapp_controllers(
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

    /// Call set_dapp_controllers() and handle errors for finalize
    async fn set_dapp_controllers_for_finalize(
        &self,
        sns_root_client: &mut impl SnsRootClient,
    ) -> SetDappControllersCallResult {
        let result = self.set_dapp_controllers(sns_root_client).await;

        match result {
            Ok(result) => result.into(),
            Err(err_message) => {
                log!(ERROR, "Halting set_dapp_controllers(), {:?}", err_message);
                SetDappControllersCallResult { possibility: None }
            }
        }
    }

    /// Acquire the lock on `finalize_swap`.
    pub fn lock_finalize_swap(&mut self) -> Result<(), String> {
        match self.is_finalize_swap_locked() {
            true => Err("The Sale canister has finalize_swap call already in progress".to_string()),
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
    /// The argument 'now_fn' a function that returns the current time
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
        sns_root_client: &mut impl SnsRootClient,
        sns_governance_client: &mut impl SnsGovernanceClient,
        icp_ledger: &dyn ICRC1Ledger,
        sns_ledger: &dyn ICRC1Ledger,
        nns_governance_client: &mut impl NnsGovernanceClient,
    ) -> FinalizeSwapResponse {
        // Acquire the lock or return a FinalizeSwapResponse with an error message.
        if let Err(error_message) = self.lock_finalize_swap() {
            return FinalizeSwapResponse::with_error(error_message);
        }

        // The lock is now acquired and asynchronous calls to finalize are blocked.
        // Perform all subactions.
        let finalize_swap_response = self
            .finalize_inner(
                now_fn,
                sns_root_client,
                sns_governance_client,
                icp_ledger,
                sns_ledger,
                nns_governance_client,
            )
            .await;

        // Release the lock. Note,
        self.unlock_finalize_swap();

        finalize_swap_response
    }

    /// Perform the subactions of finalize.
    ///
    /// IMPORTANT: As the canister awaits across message barriers to make
    /// inter-canister calls, finalize_inner and all subsequent methods MUST
    /// avoid panicking or the lock resource will not be released.
    ///
    /// In the case of an unexpected panic, the Sale canister can be upgraded
    /// and a post-upgrade hook can release the lock.
    pub async fn finalize_inner(
        &mut self,
        now_fn: fn(bool) -> u64,
        sns_root_client: &mut impl SnsRootClient,
        sns_governance_client: &mut impl SnsGovernanceClient,
        icp_ledger: &dyn ICRC1Ledger,
        sns_ledger: &dyn ICRC1Ledger,
        nns_governance_client: &mut impl NnsGovernanceClient,
    ) -> FinalizeSwapResponse {
        let mut finalize_swap_response = FinalizeSwapResponse::default();

        if !self.lifecycle_is_terminal() {
            finalize_swap_response.set_error_message(format!(
                "The Sale can only be finalized in the COMMITTED or ABORTED states. Current state is {:?}",
                self.lifecycle()
            ));
            return finalize_swap_response;
        }

        // Transfer the ICP tokens from the Sale canister.
        finalize_swap_response.set_sweep_icp_result(self.sweep_icp(now_fn, icp_ledger).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Settle the CommunityFund's participation in the Sale (if any).
        finalize_swap_response.set_settle_community_fund_participation_result(
            self.settle_community_fund_participation(nns_governance_client)
                .await,
        );
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        if self.should_restore_dapp_control() {
            // Restore controllers of dapp canisters to their original
            // owners (i.e. self.init.fallback_controller_principal_ids).
            finalize_swap_response.set_set_dapp_controllers_result(
                self.set_dapp_controllers_for_finalize(sns_root_client)
                    .await,
            );

            // In the case of returning control of the dapp(s) to the fallback
            // controllers, finalize() need not do any more work, so always return
            // and end execution.
            return finalize_swap_response;
        }

        // Transfer the SNS tokens from the Sale canister.
        finalize_swap_response.set_sweep_sns_result(self.sweep_sns(now_fn, sns_ledger).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        // Once SNS tokens have been distributed to the correct accounts, claim
        // them as neurons on behalf of the Sale participants.
        finalize_swap_response
            .set_claim_neuron_result(self.claim_swap_neurons(sns_governance_client).await);
        if finalize_swap_response.has_error_message() {
            return finalize_swap_response;
        }

        finalize_swap_response.set_set_mode_call_result(
            Self::set_sns_governance_to_normal_mode(sns_governance_client).await,
        );

        finalize_swap_response
    }

    /// In state COMMITTED. Claim SNS Neurons on behalf of participants.
    ///
    /// Returns the following values:
    /// - the number of skipped neurons because of previous claims
    /// - the number of successful claims
    /// - the number of failed claims
    /// - the number of invalid claims due to corrupted neuron recipe state
    /// - the number of global failures due to corrupted Sale state or inconsistent API responses
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

        // The NeuronParameters that will be used to create neurons.
        let mut neuron_parameters = vec![];

        for recipe in &mut self.neuron_recipes {
            let (hotkey, controller, source_nns_neuron_id) = match recipe.investor.as_ref() {
                Some(Investor::Direct(DirectInvestment { buyer_principal })) => {
                    let parsed_buyer_principal = match string_to_principal(buyer_principal) {
                        Some(p) => p,
                        // principal_str should always be parseable as a PrincipalId as that is enforced
                        // in `refresh_buyer_tokens`. In the case of a bug due to programmer error, increment
                        // the invalid field. This will require a manual intervention via an upgrade to correct
                        None => {
                            sweep_result.invalid += 1;
                            continue;
                        }
                    };

                    (None, parsed_buyer_principal, None)
                }
                Some(Investor::CommunityFund(CfInvestment {
                    hotkey_principal,
                    nns_neuron_id,
                })) => {
                    let parsed_hotkey_principal = match string_to_principal(hotkey_principal) {
                        Some(p) => p,
                        // principal_str should always be parseable as a PrincipalId as that is enforced
                        // in `refresh_buyer_tokens`. In the case of a bug due to programmer error, increment
                        // the invalid field. This will require a manual intervention via an upgrade to correct
                        None => {
                            sweep_result.invalid += 1;
                            continue;
                        }
                    };

                    (
                        Some(parsed_hotkey_principal),
                        nns_governance.into(),
                        Some(*nns_neuron_id),
                    )
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

            let (dissolve_delay_seconds, memo) = match recipe.neuron_attributes.as_ref() {
                Some(neuron_attribute) => (
                    neuron_attribute.dissolve_delay_seconds,
                    neuron_attribute.memo,
                ),
                // SnsNeuronRecipe.neuron_attributes should always be present as it is set in `commit`.
                // In the case of a bug due to programmer error, increment the invalid field.
                // This will require a manual intervention via an upgrade to correct
                None => {
                    log!(
                        ERROR,
                        "Missing neuron_attributes information for neuron recipe {:?}",
                        recipe,
                    );
                    sweep_result.invalid += 1;
                    continue;
                }
            };

            let amount_e8s = match recipe.sns.as_ref() {
                Some(transferable_amount) => transferable_amount.amount_e8s,
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

            if recipe.claimed_status == Some(ClaimedStatus::Success as i32) {
                log!(
                    INFO,
                    "Recipe {:?} was claimed in previous invocation of claim_swap_neurons(). Skipping",
                    recipe,
                );
                sweep_result.skipped += 1;
                continue;
            }

            if recipe.claimed_status == Some(ClaimedStatus::Invalid as i32) {
                // If the Recipe is marked as invalid, intervention is needed to make valid again.
                // As part of that intervention, the recipe must be marked as ClaimedStatus::Pending
                // to attempt again.
                log!(INFO, "Recipe {:?} was invalid in a previous invocation of claim_swap_neurons(). Skipping", recipe);
                sweep_result.invalid += 1;
                continue;
            }

            let neuron_id =
                NeuronId::from(compute_neuron_staking_subaccount_bytes(controller, memo));

            neuron_parameters.push(NeuronParameters {
                neuron_id: Some(neuron_id.clone()),
                controller: Some(controller),
                hotkey,
                // Since claim_swap_neurons is  a permission-ed API on governance, account
                // for the transfer_fee that is applied with the sns ledger transfer
                stake_e8s: Some(amount_e8s.saturating_sub(sns_transaction_fee_e8s)),
                dissolve_delay_seconds: Some(dissolve_delay_seconds),
                source_nns_neuron_id,
            });

            claimable_neurons_index.insert(neuron_id, recipe);
        }

        // If neuron_parameters is empty, all recipes are either Invalid or Skipped and there
        // is no work to do.
        if neuron_parameters.is_empty() {
            return sweep_result;
        }

        sweep_result.consume(
            Self::batch_claim_swap_neurons(
                sns_governance_client,
                &mut neuron_parameters,
                &mut claimable_neurons_index,
            )
            .await,
        );

        sweep_result
    }

    /// A helper to batch claim the sale neurons, and process the results from SNS Governance.
    async fn batch_claim_swap_neurons(
        sns_governance_client: &mut impl SnsGovernanceClient,
        neuron_parameters: &mut Vec<NeuronParameters>,
        claimable_neurons_index: &mut BTreeMap<NeuronId, &mut SnsNeuronRecipe>,
    ) -> SweepResult {
        // Compute the number of NeuronParameters that can be packed into a xnet message.
        // In this version, the message size is 75% of its maximum size to make room for
        // any additional overhead is associated with the Request object.
        let neuron_parameters_size = mem::size_of::<NeuronParameters>();
        let batch_limit =
            CLAIM_SWAP_NEURONS_MESSAGE_SIZE_LIMIT_BYTES.saturating_div(neuron_parameters_size);

        log!(
            INFO,
            "Attempting to claim {} Neurons in SNS Governance. Batch size is {}",
            neuron_parameters.len(),
            batch_limit
        );

        let mut sweep_result = SweepResult::default();

        while !neuron_parameters.is_empty() {
            let current_batch_limit = std::cmp::min(batch_limit, neuron_parameters.len());

            let batch: Vec<NeuronParameters> =
                neuron_parameters.drain(0..current_batch_limit).collect();
            // Used for various operations
            let batch_count = batch.len();

            log!(
                INFO,
                "Attempting to claim a batch of {} Neurons in SNS Governance.",
                batch_count,
            );

            let reply = sns_governance_client
                .claim_swap_neurons(ClaimSwapNeuronsRequest {
                    neuron_parameters: batch,
                })
                .await;

            let response = match reply {
                Ok(response) => response,
                Err(canister_call_error) => {
                    // The canister_call_error indicates a trap in the callback function, which
                    // could be the result of an unexpected panic in SNS Governance or an issue
                    // with the underlying Canister or Replica. As it is a CanisterCallError
                    // we hope that the canister being called rolls back to the appropriate checkpoint.
                    // The sale canister will mark the current batch and remaining neurons as failed
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
                        ClaimSwapNeuronsError::from_i32(err_code)
                    );
                    sweep_result.global_failures += 1;
                    return sweep_result;
                }
                Some(ClaimSwapNeuronsResult::Ok(claimed_neurons)) => claimed_neurons.swap_neurons,
                None => {
                    // This should not happen as it means the `claim_swap_neurons` is returning malformed
                    // input or there is a decoding problem in the Sale canister.
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
                    claimed_neurons.len(), batch_count,
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

            log!(
                INFO,
                "Successfully claimed a batch of {} Neurons in SNS Governance. Current SweepResult progress {:?}",
                batch_count, sweep_result,
            );
        }
        sweep_result
    }

    /// Given a SwapNeuron and an index, update the correct SnsNeuronRecipe with the
    /// status of the SwapNeuron. Return a SweepResult to be consumed by claim_swap_neurons
    fn process_swap_neuron(
        swap_neuron: SwapNeuron,
        claimable_neurons_index: &mut BTreeMap<NeuronId, &mut SnsNeuronRecipe>,
    ) -> SweepResult {
        let mut sweep_result = SweepResult::default();

        if let Some(neuron_id) = swap_neuron.id.as_ref() {
            if let Some(claimed_swap_neuron_status) =
                ClaimedSwapNeuronStatus::from_i32(swap_neuron.status)
            {
                if let Some(recipe) = claimable_neurons_index.get_mut(neuron_id) {
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
                    return sweep_result;
                }
            }
        }
        log!(
            ERROR,
            "Unable to parse some part of the SwapNeuron and therefore could not update a ClaimStatus. \
            ({:?})",
            swap_neuron,
        );
        sweep_result.global_failures += 1;
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
            owner: *source_principal_id,
            subaccount: None,
        };
        let transfer_result = icp_ledger
            .transfer_funds(
                amount_e8s,
                DEFAULT_TRANSFER_FEE.get_e8s(),
                Some(source_subaccount),
                dst.clone(),
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

    /// Transfer ICP tokens from buyer's subaccounts to the SNS governance
    /// canister if COMMITTED or back to the buyer if ABORTED.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due operation already in progress
    /// - the number of successful transfers
    /// - the number of failed transfers
    /// - the number of invalid buyers due to corrupted buyer state or invalid balances
    /// - the number of global failures across the sweep such as corrupted sale state
    ///
    /// Pre-conditions:
    /// - The Sale canister's `Lifecycle` is either ABORTED or COMMITTED
    pub async fn sweep_icp(
        &mut self,
        now_fn: fn(bool) -> u64,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> SweepResult {
        let lifecycle = self.lifecycle();

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
                    owner: sns_governance.get(),
                    subaccount: None,
                }
            } else {
                Account {
                    owner: principal,
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
        }

        sweep_result
    }

    /// In state COMMITTED. Transfer SNS tokens from the swap
    /// canister to each buyer.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    /// - the number of invalid neuron recipes due to corrupted neuron recipe state or invalid balances
    /// - the number of global failures due to corrupted Sale state
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
                Some(Investor::CommunityFund(CfInvestment {
                    hotkey_principal: _,
                    nns_neuron_id: _,
                })) => compute_neuron_staking_subaccount_bytes(nns_governance.into(), neuron_memo),
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
                owner: sns_governance.get(),
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
                    sweep_result.success += 1;
                }
                TransferResult::Failure(_) => {
                    sweep_result.failure += 1;
                }
            }
        }

        sweep_result
    }

    /// Requests the NNS Governance canister to settle the CommunityFund
    /// participation in the Sale. If the Sale is committed, ICP will be
    /// minted. If the Sale is aborted, maturity will be refunded to
    /// CF Neurons.
    pub async fn settle_community_fund_participation(
        &self,
        nns_governance_client: &mut impl NnsGovernanceClient,
    ) -> SettleCommunityFundParticipationResult {
        use settle_community_fund_participation::{Aborted, Committed, Result};

        let init = match self.init_and_validate() {
            Ok(init) => init,
            Err(error_message) => {
                log!(
                    ERROR,
                    "Halting settle_community_fund_participation(). State is missing or corrupted: {:?}",
                    error_message
                );
                return SettleCommunityFundParticipationResult { possibility: None };
            }
        };

        // The following methods are safe to call since we validated Init in the above block
        let sns_governance = init.sns_governance_or_panic();

        let result = if self.lifecycle() == Lifecycle::Committed {
            Result::Committed(Committed {
                sns_governance_canister_id: Some(sns_governance.get()),
            })
        } else {
            Result::Aborted(Aborted {})
        };

        nns_governance_client
            .settle_community_fund_participation(SettleCommunityFundParticipation {
                open_sns_token_swap_proposal_id: self.open_sns_token_swap_proposal_id,
                result: Some(result),
            })
            .await
            .into()
    }

    //
    // --- predicates on the state ---------------------------------------------
    //

    /// Validate the state for internal consistency. This does not
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

    /// The parameter `now_seconds` is greater than or equal to end_timestamp_seconds.
    pub fn swap_due(&self, now_seconds: u64) -> bool {
        if let Some(params) = &self.params {
            return now_seconds >= params.swap_due_timestamp_seconds;
        }
        false
    }

    /// The minimum number of participants have been achieved, and the
    /// minimal total amount has been reached.
    pub fn sufficient_participation(&self) -> bool {
        if let Some(params) = &self.params {
            if self.cf_participants.len().saturating_add(self.buyers.len())
                < (params.min_participants as usize)
            {
                false
            } else {
                self.participant_total_icp_e8s() >= params.min_icp_e8s
            }
        } else {
            false
        }
    }

    /// The total number of ICP contributed by all buyers is at least
    /// the target ICP of the swap.
    pub fn icp_target_reached(&self) -> bool {
        if let Some(params) = &self.params {
            return self.participant_total_icp_e8s() >= params.max_icp_e8s;
        }
        false
    }

    /// Returns true if the swap can be committed at the specified
    /// timestamp, and false otherwise.
    pub fn can_commit(&self, now_seconds: u64) -> bool {
        if self.lifecycle() != Lifecycle::Open {
            return false;
        }
        // Possible optimization: both 'sufficient_participation' and
        // 'icp_target_reached' compute 'participant_total_icp_e8s', and
        // this computation could be shared (or cached).
        if !self.sufficient_participation() {
            return false;
        }
        // If swap is due, or the target ICP has been reached, return true
        self.swap_due(now_seconds) || self.icp_target_reached()
    }

    //
    // --- query methods on the state  -----------------------------------------
    //

    /// Computes the DerivedState.
    /// `sns_tokens_per_icp` will be 0 if `participant_total_icp_e8s` is 0.
    pub fn derived_state(&self) -> DerivedState {
        let participant_total_icp_e8s = self.participant_total_icp_e8s();
        let tokens_available_for_sale = match self.sns_token_e8s() {
            Ok(tokens) => tokens,
            Err(err) => {
                log!(ERROR, "{}", err);
                0
            }
        };
        DerivedState {
            buyer_total_icp_e8s: participant_total_icp_e8s,
            sns_tokens_per_icp: i2d(tokens_available_for_sale)
                .checked_div(i2d(participant_total_icp_e8s))
                .and_then(|d| d.to_f32())
                .unwrap_or(0.0),
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
            buyers_total: self.participant_total_icp_e8s(),
        }
    }

    /// Return the current lifecycle stage (e.g. Open, Committed, etc)
    pub fn get_lifecycle(&self, _request: &GetLifecycleRequest) -> GetLifecycleResponse {
        GetLifecycleResponse {
            lifecycle: Some(self.lifecycle),
        }
    }

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

        let end = (offset + limit).min(self.cf_participants.len());
        let cf_participants = self.cf_participants[offset..end].to_vec();

        ListCommunityFundParticipantsResponse { cf_participants }
    }
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

/// A common pattern throughout the Sale canister is parsing the String
/// representation of a PrincipalId and logging the error if any.
fn string_to_principal(maybe_principal_id: &String) -> Option<PrincipalId> {
    match PrincipalId::from_str(maybe_principal_id) {
        Ok(principal_id) => Some(principal_id),
        Err(error_message) => {
            log!(
                ERROR,
                "Cannot parse principal {} for use in Sale Canister: {}",
                maybe_principal_id,
                error_message
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::{CfNeuron, CfParticipant};
    use ic_nervous_system_common::{E8, SECONDS_PER_DAY};
    use pretty_assertions::assert_eq;
    use proptest::prelude::proptest;

    #[test]
    fn test_get_lifecycle() {
        let mut swap = Swap::default();
        let request = GetLifecycleRequest {};

        swap.lifecycle = Lifecycle::Pending as i32;
        assert_eq!(
            swap.get_lifecycle(&request).lifecycle,
            Some(Lifecycle::Pending as i32)
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
    }

    #[test]
    fn test_derived_state_to_get_derived_state_response() {
        let derived_state = DerivedState {
            buyer_total_icp_e8s: 400_000_000,
            sns_tokens_per_icp: 2.5f32,
        };

        let response: GetDerivedStateResponse = derived_state.into();
        assert_eq!(response.sns_tokens_per_icp, Some(2.5f64));
        assert_eq!(response.buyer_total_icp_e8s, Some(400_000_000));
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
    fn test_list_community_fund_participants() {
        let cf_participants = vec![
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(992899).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 1,
                    amount_icp_e8s: 698047,
                }],
            },
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(800257).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 2,
                    amount_icp_e8s: 678574,
                }],
            },
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(818371).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 3,
                    amount_icp_e8s: 305256,
                }],
            },
            CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(657894).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 4,
                    amount_icp_e8s: 339747,
                }],
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
    }

    #[test]
    fn test_generate_vesting_schedule() {
        let neuron_basket_construction_parameters = NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 100,
        };

        assert_eq!(
            neuron_basket_construction_parameters
                .generate_vesting_schedule(/* total_amount_e8s = */ 10),
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
                .generate_vesting_schedule(/* total_amount_e8s = */ 9),
            vec![
                ScheduledVestingEvent {
                    amount_e8s: 5,
                    dissolve_delay_seconds: 0,
                },
                ScheduledVestingEvent {
                    amount_e8s: 1,
                    dissolve_delay_seconds: 100,
                },
                ScheduledVestingEvent {
                    amount_e8s: 1,
                    dissolve_delay_seconds: 200,
                },
                ScheduledVestingEvent {
                    amount_e8s: 1,
                    dissolve_delay_seconds: 300,
                },
                ScheduledVestingEvent {
                    amount_e8s: 1,
                    dissolve_delay_seconds: 400,
                },
            ],
        );
    }

    proptest! {
        #[test]
        fn test_generate_vesting_schedule_proptest(
            count in 1..25_u64,
            dissolve_delay_interval_seconds in 1..(90 * SECONDS_PER_DAY),
            total_e8s in 1..(100 * E8),
        ) {
            let vesting_schedule = NeuronBasketConstructionParameters {
                count,
                dissolve_delay_interval_seconds,
            }
            .generate_vesting_schedule(total_e8s);

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
            for i in 1..vesting_schedule.len() {
                assert_eq!(
                    vesting_schedule.get(i).unwrap().amount_e8s,
                    total_e8s / count,
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
}
