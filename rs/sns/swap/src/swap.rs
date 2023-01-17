use crate::pb::v1::{
    error_refund_icp_response, restore_dapp_controllers_response, set_dapp_controllers_call_result,
    set_mode_call_result, settle_community_fund_participation_result, sns_neuron_recipe::Investor,
    BuyerState, CanisterCallError, CfInvestment, CfNeuron, CfParticipant, DerivedState,
    DirectInvestment, ErrorRefundIcpRequest, ErrorRefundIcpResponse, FinalizeSwapResponse,
    GetBuyerStateRequest, GetBuyerStateResponse, GetBuyersTotalResponse, Init, Lifecycle,
    OpenRequest, OpenResponse, Params, RefreshBuyerTokensResponse, RestoreDappControllersResponse,
    SetDappControllersCallResult, SetModeCallResult, SettleCommunityFundParticipationResult,
    SnsNeuronRecipe, Swap, SweepResult, TransferableAmount,
};
// TODO(NNS1-1589): Get these from authoritative source.

use crate::logs::{ERROR, INFO};
use crate::pb::v1::GovernanceError;
use async_trait::async_trait;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    i2d, ledger::compute_neuron_staking_subaccount_bytes, SECONDS_PER_DAY,
};
use ic_sns_governance::{
    ledger::ICRC1Ledger,
    pb::v1::{
        claim_swap_neurons_request::NeuronParameters, governance, ClaimSwapNeuronsRequest,
        ClaimSwapNeuronsResponse, ManageNeuron, ManageNeuronResponse, SetMode, SetModeResponse,
    },
};
use icp_ledger::DEFAULT_TRANSFER_FEE;
use itertools::{Either, Itertools};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rust_decimal::prelude::ToPrimitive;
use std::{
    num::{NonZeroU128, NonZeroU64},
    ops::Div,
    str::FromStr,
};

// TODO(NNS1-1589): Get these from the canonical location.
use crate::pb::v1::{
    settle_community_fund_participation, sns_neuron_recipe::NeuronAttributes,
    SetDappControllersRequest, SetDappControllersResponse, SettleCommunityFundParticipation,
};

pub const LOG_PREFIX: &str = "[Swap] ";

/// Result of a token transfer (commit or abort) on a ledger (ICP or
/// SNS) for a single buyer.
pub enum TransferResult {
    /// Transfer was skipped as the amount was less than the requested fee.
    AmountTooSmall,
    /// Transferred was skipped as an operation is already in progress or completed.
    AlreadyStarted,
    /// The operation was successful at the specified block height.
    Success(u64),
    /// The operation failed with the specified error message.
    Failure(String),
}

/// Intermediate struct used when generating the basket of neurons for investors.
struct ScheduledVestingEvent {
    /// The dissolve_delay of the neuron
    dissolve_delay_seconds: u64,
    /// The amount of tokens in e8s
    amount_e8s: u64,
}

impl From<(Option<i32>, String)> for CanisterCallError {
    fn from((code, description): (Option<i32>, String)) -> Self {
        Self { code, description }
    }
}

impl From<Result<SetModeResponse, CanisterCallError>> for SetModeCallResult {
    fn from(native_result: Result<SetModeResponse, CanisterCallError>) -> Self {
        let possibility = match native_result {
            Ok(_ok) => None,
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

#[async_trait]
pub trait SnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError>;

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError>;

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError>;
}

#[async_trait]
pub trait SnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError>;
}

#[async_trait]
pub trait NnsGovernanceClient {
    async fn settle_community_fund_participation(
        &mut self,
        request: SettleCommunityFundParticipation,
    ) -> Result<Result<(), GovernanceError>, CanisterCallError>;
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

    /// Creates a vector of token amounts where the `amount_tokens_e8s` is evenly distributed
    /// among `count` elements. Since this is done in integer space, the remainder is added to the
    /// last element in the vector.
    pub fn split(amount_tokens_e8s: u64, count: u64) -> Vec<u64> {
        let split_amount = amount_tokens_e8s.saturating_div(count);
        let extra = amount_tokens_e8s % split_amount;
        let mut amounts = vec![split_amount; count as usize];
        *amounts.last_mut().unwrap() += extra;

        amounts
    }

    /// Generates the vesting schedule for a given `amount_sns_tokens_e8s` based on the
    /// `Params::neuron_basket_construction_parameters`.
    fn generate_vesting_schedule(
        &self,
        amount_sns_tokens_e8s: u64,
        rng: &mut ChaCha20Rng,
    ) -> Vec<ScheduledVestingEvent> {
        let params = self.params.as_ref().expect("Expected params to be set");
        let neuron_basket = params
            .neuron_basket_construction_parameters
            .as_ref()
            .expect("Expected neuron_basket_construction_parameters to be set");

        let random_dissolve_delay_periods =
            ic_nervous_system_common::generate_random_dissolve_delay_intervals(
                neuron_basket.count,
                neuron_basket.dissolve_delay_interval_seconds,
                rng,
            );

        let split_amount_sns_tokens_e8s = Swap::split(amount_sns_tokens_e8s, neuron_basket.count);

        assert_eq!(
            random_dissolve_delay_periods.len(),
            split_amount_sns_tokens_e8s.len()
        );

        random_dissolve_delay_periods
            .into_iter()
            .zip(split_amount_sns_tokens_e8s.into_iter())
            .map(
                |(dissolve_delay_seconds, amount_e8s)| ScheduledVestingEvent {
                    dissolve_delay_seconds,
                    amount_e8s,
                },
            )
            .collect()
    }

    /// Precondition: lifecycle == OPEN && sufficient_participation && (swap_due || icp_target_reached)
    ///
    /// Postcondition: lifecycle == COMMITTED
    fn commit(&mut self, now_seconds: u64) {
        assert!(self.lifecycle() == Lifecycle::Open);
        assert!(self.sufficient_participation());
        assert!(self.swap_due(now_seconds) || self.icp_target_reached());
        // Safe as `params` must be specified in call to `open`.
        let params = self.params.as_ref().expect("Expected params to be set");
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

        let mut rng = {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&now_seconds.to_be_bytes());
            seed[8..16].copy_from_slice(&now_seconds.to_be_bytes());
            seed[16..24].copy_from_slice(&now_seconds.to_be_bytes());
            seed[24..32].copy_from_slice(&now_seconds.to_be_bytes());
            ChaCha20Rng::from_seed(seed)
        };
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
            for (memo, scheduled_vesting_event) in self
                .generate_vesting_schedule(amount_sns_e8s, &mut rng)
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

                for scheduled_vesting_event in self
                    .generate_vesting_schedule(amount_sns_e8s, &mut rng)
                    .into_iter()
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
        assert!(self.lifecycle() == Lifecycle::Open);
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
        match self.sweep_icp(now_fn, icp_ledger).await {
            Ok(sweep_result) => finalize_swap_response.set_sweep_icp(sweep_result),
            Err(error_message) => {
                finalize_swap_response.set_error_message(error_message);
                return finalize_swap_response;
            }
        };

        // Settle the CommunityFund's participation in the Sale (if any).
        match self
            .settle_community_fund_participation(nns_governance_client)
            .await
        {
            Ok(result) => {
                finalize_swap_response.set_settle_community_fund_participation_result(result)
            }
            Err(error_message) => {
                finalize_swap_response.set_error_message(error_message);
                return finalize_swap_response;
            }
        };

        if self.should_restore_dapp_control() {
            // Restore controllers of dapp canisters to their original
            // owners (i.e. self.init.fallback_controller_principal_ids).
            match self.set_dapp_controllers(sns_root_client).await {
                Ok(result) => finalize_swap_response.set_set_dapp_controllers_result(result.into()),
                Err(error_message) => finalize_swap_response.set_error_message(error_message),
            };

            // In the case of returning control of the dapp(s) to the fallback
            // controllers, finalize() need not do any more work, so always return
            // and end execution of finalize().
            return finalize_swap_response;
        }

        // Transfer the SNS tokens from the Sale canister.
        match self.sweep_sns(now_fn, sns_ledger).await {
            Ok(sweep_result) => finalize_swap_response.set_sweep_sns(sweep_result),
            Err(error_message) => {
                finalize_swap_response.set_error_message(error_message);
                return finalize_swap_response;
            }
        };

        // Once SNS tokens have been distributed to the correct accounts, claim
        // them as neurons on behalf of the Sale participants.
        match self.claim_neurons(sns_governance_client).await {
            Ok(create_neuron_result) => {
                finalize_swap_response.set_create_neuron(create_neuron_result)
            }
            Err(error_message) => {
                finalize_swap_response.set_error_message(error_message);
                return finalize_swap_response;
            }
        };

        // TODO NNS1-1715: Allow for should_set_sns_governance_to_normal_mode to succeed if
        // all non-terminally broken neurons have been claimed
        if Self::should_set_sns_governance_to_normal_mode(&finalize_swap_response) {
            let set_mode_call_result =
                Self::set_sns_governance_to_normal_mode(sns_governance_client).await;
            finalize_swap_response.set_sns_governance_normal_mode_enabled(set_mode_call_result);
        }

        finalize_swap_response
    }

    async fn claim_neurons(
        &self,
        sns_governance_client: &mut impl SnsGovernanceClient,
    ) -> Result<SweepResult, String> {
        if self.lifecycle() != Lifecycle::Committed {
            return Err(format!(
                "SNS Tokens cannot be distributed if Lifecycle \
                is not COMMITTED. Current Lifecycle: {:?}",
                self.lifecycle()
            ));
        }

        let init = self.init()?;
        let nns_governance = init.nns_governance()?;
        let sns_transaction_fee_e8s = match init.transaction_fee_e8s {
            None => {
                // This case should not be hit as the canister_init method guarantees the
                // field is populated. If through some bug or upgrade issue, this field is
                // indeed unpopulated, a post-upgrade hook can be used to repopulate this
                // field and retry finalization.
                return Err(
                    "Cannot claim SNS Neurons, SNS Ledger Transaction Fee is unknown".to_string(),
                );
            }
            Some(transaction_fee_e8s) => transaction_fee_e8s,
        };

        let (skipped, sns_neuron_recipes) = self.neuron_recipes_for_create_neuron();
        let mut result = SweepResult {
            success: 0,
            failure: 0,
            skipped,
        };

        let mut claim_swap_neuron_requests = ClaimSwapNeuronsRequest {
            neuron_parameters: vec![],
        };

        for recipe in &sns_neuron_recipes {
            let (hotkey, controller, source_nns_neuron_id) = match recipe.investor.as_ref() {
                Some(Investor::Direct(DirectInvestment { buyer_principal })) => {
                    let parsed_buyer_principal = match string_to_principal(buyer_principal) {
                        Some(p) => p,
                        None => {
                            result.failure += 1;
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
                        None => {
                            result.failure += 1;
                            continue;
                        }
                    };

                    (
                        Some(parsed_hotkey_principal),
                        nns_governance.into(),
                        Some(*nns_neuron_id),
                    )
                }
                None => {
                    log!(
                        ERROR,
                        "Missing investor information for neuron recipe {:?}",
                        recipe,
                    );
                    result.failure += 1;
                    continue;
                }
            };

            let (dissolve_delay_seconds, memo) = match recipe.neuron_attributes.as_ref() {
                Some(neuron_attribute) => (
                    neuron_attribute.dissolve_delay_seconds,
                    neuron_attribute.memo,
                ),
                None => {
                    log!(
                        ERROR,
                        "Missing neuron_attributes information for neuron recipe {:?}",
                        recipe,
                    );
                    result.failure += 1;
                    continue;
                }
            };

            claim_swap_neuron_requests
                .neuron_parameters
                .push(NeuronParameters {
                    controller: Some(controller),
                    hotkey,
                    // Since claim_swap_neurons is  a permission-ed API on governance, account
                    // for the transfer_fee that is applied with the sns ledger transfer
                    stake_e8s: Some(recipe.amount_e8s() - sns_transaction_fee_e8s),
                    memo: Some(memo),
                    dissolve_delay_seconds: Some(dissolve_delay_seconds),
                    source_nns_neuron_id,
                });
        }

        // Try to batch claim SNS neurons that were just funded.
        // The SnsGovernanceClient ensures that all errors are transformed
        // into a CanisterCallError and do not cause a panic.
        let response = sns_governance_client
            .claim_swap_neurons(claim_swap_neuron_requests)
            .await;

        if let Ok(claim_swap_neurons_response) = response {
            result.failure += claim_swap_neurons_response.failed_claims;
            result.skipped += claim_swap_neurons_response.skipped_claims;
            result.success += claim_swap_neurons_response.successful_claims;
            log!(
                INFO,
                "Successfully claimed swap neurons {:#?}",
                claim_swap_neurons_response,
            );
        } else {
            log!(ERROR, "Failed to call claim_swap_neurons: {:#?}", response,);
            result.failure += sns_neuron_recipes.len() as u32;
        }

        Ok(result)
    }

    fn should_set_sns_governance_to_normal_mode(
        finalize_swap_response: &FinalizeSwapResponse,
    ) -> bool {
        if let Some(create_neurons) = finalize_swap_response.create_neuron.as_ref() {
            if create_neurons.failure == 0 {
                return true;
            }
        }

        false
    }

    async fn set_sns_governance_to_normal_mode(
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
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    ///
    /// Pre-conditions:
    /// - The Sale canister's `Lifecycle` is either ABORTED or COMMITTED
    pub async fn sweep_icp(
        &mut self,
        now_fn: fn(bool) -> u64,
        icp_ledger: &dyn ICRC1Ledger,
    ) -> Result<SweepResult, String> {
        let lifecycle = self.lifecycle();
        let sns_governance = self.init()?.sns_governance()?;

        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;

        for (principal_str, buyer_state) in self.buyers.iter_mut() {
            let principal = match string_to_principal(principal_str) {
                Some(p) => p,
                None => {
                    failure += 1;
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
                None => {
                    log!(
                        ERROR,
                        "PrincipalId {} has corrupted BuyerState: {:?}",
                        principal,
                        buyer_state
                    );
                    failure += 1;
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
                TransferResult::AmountTooSmall | TransferResult::AlreadyStarted => {
                    skipped += 1;
                }
                TransferResult::Success(_) => {
                    success += 1;
                }
                TransferResult::Failure(_) => {
                    failure += 1;
                }
            }
        }
        Ok(SweepResult {
            success,
            failure,
            skipped,
        })
    }

    /// In state COMMITTED. Transfer SNS tokens from the swap
    /// canister to each buyer.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    pub async fn sweep_sns(
        &mut self,
        now_fn: fn(bool) -> u64,
        sns_ledger: &dyn ICRC1Ledger,
    ) -> Result<SweepResult, String> {
        if self.lifecycle() != Lifecycle::Committed {
            return Err(format!("SNS Tokens cannot be distributed if Lifecycle is not COMMITTED. Current Lifecycle: {:?}", self.lifecycle()));
        }

        let init = self.init()?;
        let sns_governance = init.sns_governance()?;
        let nns_governance = init.nns_governance()?;
        let sns_transaction_fee_tokens = match init.transaction_fee_e8s {
            None => {
                return Err(
                    "Cannot Transfer SNS Tokens, SNS Ledger Transaction Fee is unknown".to_string(),
                )
            }
            Some(transaction_fee_e8s) => Tokens::from_e8s(transaction_fee_e8s),
        };

        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;

        for recipe in self.neuron_recipes.iter_mut() {
            let neuron_memo = match recipe.neuron_attributes.as_ref() {
                None => {
                    log!(
                        ERROR,
                        "Missing neuron attributes information for neuron recipe {:?}",
                        recipe
                    );
                    failure += 1;
                    continue;
                }
                Some(neuron_attributes) => neuron_attributes.memo,
            };

            let dst_subaccount = match &recipe.investor {
                Some(Investor::Direct(DirectInvestment { buyer_principal })) => {
                    match string_to_principal(buyer_principal) {
                        Some(p) => compute_neuron_staking_subaccount_bytes(p, neuron_memo),
                        None => {
                            failure += 1;
                            continue;
                        }
                    }
                }
                Some(Investor::CommunityFund(CfInvestment {
                    hotkey_principal: _,
                    nns_neuron_id: _,
                })) => compute_neuron_staking_subaccount_bytes(nns_governance.into(), neuron_memo),
                None => {
                    log!(
                        ERROR,
                        "Missing investor information for neuron recipe {:?}",
                        recipe,
                    );
                    failure += 1;
                    continue;
                }
            };
            let dst = Account {
                owner: sns_governance.get(),
                subaccount: Some(dst_subaccount),
            };

            let sns_transferable_amount = match recipe.sns.as_mut() {
                Some(transferable_amount) => transferable_amount,
                None => {
                    log!(
                        ERROR,
                        "Missing transfer information for neuron recipe {:?}",
                        recipe,
                    );
                    failure += 1;
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
                TransferResult::AmountTooSmall | TransferResult::AlreadyStarted => {
                    skipped += 1;
                }
                TransferResult::Success(_) => {
                    success += 1;
                }
                TransferResult::Failure(_) => {
                    failure += 1;
                }
            }
        }
        Ok(SweepResult {
            success,
            failure,
            skipped,
        })
    }

    /// Returns list of neuron recipes for which an SNS neuron may need to
    /// be created (direct investment and community fund) together
    /// with the number of investors skipped.
    ///
    /// If the swap is not committed, this results in an empty vector,
    /// i.e., all investors are skipped. If the swap is committed, it
    /// returns all investors for which the SNS tokens have been
    /// disbursed.
    ///
    /// The swap does not keep track of which neurons that actually
    /// have been created; instead it relies on neuron creation being
    /// idempotent.
    pub fn neuron_recipes_for_create_neuron(&self) -> (u32, Vec<SnsNeuronRecipe>) {
        if self.lifecycle() != Lifecycle::Committed {
            return (self.neuron_recipes.len() as u32, vec![]);
        }
        let mut recipes = Vec::new();
        let mut skipped = 0;
        for recipe in self.neuron_recipes.iter() {
            if let Some(sns) = &recipe.sns {
                if sns.transfer_success_timestamp_seconds > 0 {
                    recipes.push(recipe.clone());
                    continue;
                }
            } else {
                log!(ERROR, "Missing field 'sns'");
            }
            skipped += 1;
        }
        (skipped, recipes)
    }

    /// Requests the NNS Governance canister to settle the CommunityFund
    /// participation in the Sale. If the Sale is committed, ICP will be
    /// minted. If the Sale is aborted, maturity will be refunded to
    /// CF Neurons.
    pub async fn settle_community_fund_participation(
        &self,
        nns_governance_client: &mut impl NnsGovernanceClient,
    ) -> Result<SettleCommunityFundParticipationResult, String> {
        use settle_community_fund_participation::{Aborted, Committed, Result};

        let sns_governance = self.init()?.sns_governance()?;
        let result = if self.lifecycle() == Lifecycle::Committed {
            Result::Committed(Committed {
                sns_governance_canister_id: Some(sns_governance.get()),
            })
        } else {
            Result::Aborted(Aborted {})
        };

        Ok(nns_governance_client
            .settle_community_fund_participation(SettleCommunityFundParticipation {
                open_sns_token_swap_proposal_id: self.open_sns_token_swap_proposal_id,
                result: Some(result),
            })
            .await
            .into())
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
}

pub fn is_valid_principal(p: &str) -> bool {
    !p.is_empty() && PrincipalId::from_str(p).is_ok()
}

pub fn validate_principal(p: &str) -> Result<(), String> {
    let _ = PrincipalId::from_str(p).map_err(|x| {
        format!(
            "Couldn't validate PrincipalId. String \"{}\" could not be converted to PrincipalId: {}",
            p, x
        )
    })?;
    Ok(())
}

pub fn validate_canister_id(p: &str) -> Result<(), String> {
    let pp = PrincipalId::from_str(p).map_err(|x| {
        format!(
            "Couldn't validate CanisterId. String \"{}\" could not be converted to PrincipalId: {}",
            p, x
        )
    })?;
    let _cid = CanisterId::new(pp).map_err(|x| {
        format!(
            "Couldn't validate CanisterId. PrincipalId \"{}\" could not be converted to CanisterId: {}",
            pp,
            x
        )
    })?;
    Ok(())
}

impl ErrorRefundIcpResponse {
    fn new_ok(block_height: u64) -> Self {
        use error_refund_icp_response::{Ok, Result};

        Self {
            result: Some(Result::Ok(Ok {
                block_height: Some(block_height),
            })),
        }
    }

    fn new_precondition_error(description: impl ToString) -> Self {
        Self::new_error(
            error_refund_icp_response::err::Type::Precondition,
            description,
        )
    }

    fn new_invalid_request_error(description: impl ToString) -> Self {
        Self::new_error(
            error_refund_icp_response::err::Type::InvalidRequest,
            description,
        )
    }

    fn new_external_error(description: impl ToString) -> Self {
        Self::new_error(error_refund_icp_response::err::Type::External, description)
    }

    fn new_error(
        error_type: error_refund_icp_response::err::Type,
        description: impl ToString,
    ) -> Self {
        use error_refund_icp_response::{Err, Result};

        Self {
            result: Some(Result::Err(Err {
                error_type: Some(error_type as i32),
                description: Some(description.to_string()),
            })),
        }
    }
}

impl Init {
    pub fn nns_governance_or_panic(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.nns_governance_canister_id).unwrap()).unwrap()
    }

    pub fn nns_governance(&self) -> Result<CanisterId, String> {
        let principal_id = PrincipalId::from_str(&self.nns_governance_canister_id)
            .map_err(|err| err.to_string())?;

        CanisterId::new(principal_id).map_err(|err| err.to_string())
    }

    pub fn sns_root_or_panic(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_root_canister_id).unwrap()).unwrap()
    }

    pub fn sns_governance_or_panic(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_governance_canister_id).unwrap()).unwrap()
    }

    pub fn sns_governance(&self) -> Result<CanisterId, String> {
        let principal_id = PrincipalId::from_str(&self.sns_governance_canister_id)
            .map_err(|err| err.to_string())?;

        CanisterId::new(principal_id).map_err(|err| err.to_string())
    }

    pub fn sns_ledger_or_panic(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_ledger_canister_id).unwrap()).unwrap()
    }

    pub fn icp_ledger_or_panic(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.icp_ledger_canister_id).unwrap()).unwrap()
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_canister_id(&self.nns_governance_canister_id)?;
        validate_canister_id(&self.sns_governance_canister_id)?;
        validate_canister_id(&self.sns_ledger_canister_id)?;
        validate_canister_id(&self.icp_ledger_canister_id)?;
        validate_canister_id(&self.sns_root_canister_id)?;

        if self.fallback_controller_principal_ids.is_empty() {
            return Err("at least one fallback controller required".to_string());
        }
        for fc in &self.fallback_controller_principal_ids {
            validate_principal(fc)?;
        }

        if self.transaction_fee_e8s.is_none() {
            return Err("transaction_fee_e8s is required.".to_string());
        }
        // The value itself is not checked; only that it is supplied. Needs to
        // match the value in SNS ledger though.

        if self.neuron_minimum_stake_e8s.is_none() {
            return Err("neuron_minimum_stake_e8s is required.".to_string());
        }
        // As with transaction_fee_e8s, the value itself is not checked; only
        // that it is supplied. Needs to match the value in SNS governance
        // though.

        Ok(())
    }
}

impl Params {
    pub fn validate(&self, init: &Init) -> Result<(), String> {
        if self.min_icp_e8s == 0 {
            return Err("min_icp_e8s must be > 0".to_string());
        }

        if self.min_participants == 0 {
            return Err("min_participants must be > 0".to_string());
        }

        let transaction_fee_e8s = init
            .transaction_fee_e8s
            .expect("transaction_fee_e8s was not supplied.");

        let neuron_minimum_stake_e8s = init
            .neuron_minimum_stake_e8s
            .expect("neuron_minimum_stake_e8s was not supplied");

        let neuron_basket_count = self
            .neuron_basket_construction_parameters
            .as_ref()
            .expect("participant_neuron_basket not populated.")
            .count as u128;

        let min_participant_sns_e8s = self.min_participant_icp_e8s as u128
            * self.sns_token_e8s as u128
            / self.max_icp_e8s as u128;

        let min_participant_icp_e8s_big_enough = min_participant_sns_e8s
            >= neuron_basket_count * (neuron_minimum_stake_e8s + transaction_fee_e8s) as u128;

        if !min_participant_icp_e8s_big_enough {
            return Err(format!(
                "min_participant_icp_e8s={} is too small. It needs to be \
                 large enough to ensure that participants will end up with \
                 enough SNS tokens to form {} SNS neurons, each of which \
                 require at least {} SNS e8s, plus {} e8s in transaction \
                 fees. More precisely, the following inequality must hold: \
                 min_participant_icp_e8s >= neuron_basket_count * (neuron_minimum_stake_e8s + transaction_fee_e8s) * max_icp_e8s / sns_token_e8s \
                 (where / denotes floor division).",
                self.min_participant_icp_e8s,
                neuron_basket_count,
                neuron_minimum_stake_e8s,
                transaction_fee_e8s,
            ));
        }

        if self.sns_token_e8s == 0 {
            return Err("sns_token_e8s must be > 0".to_string());
        }

        if self.max_participant_icp_e8s < self.min_participant_icp_e8s {
            return Err(format!(
                "max_participant_icp_e8s ({}) must be >= min_participant_icp_e8s ({})",
                self.max_participant_icp_e8s, self.min_participant_icp_e8s
            ));
        }

        if self.min_icp_e8s > self.max_icp_e8s {
            return Err(format!(
                "min_icp_e8s ({}) must be <= max_icp_e8s ({})",
                self.min_icp_e8s, self.max_icp_e8s
            ));
        }

        if self.max_participant_icp_e8s > self.max_icp_e8s {
            return Err(format!(
                "max_participant_icp_e8s ({}) must be <= max_icp_e8s ({})",
                self.max_participant_icp_e8s, self.max_icp_e8s
            ));
        }

        // Cap `max_icp_e8s` at 1 billion ICP
        if self.max_icp_e8s > /* 1B */ 1_000_000_000 * /* e8s per ICP */ 100_000_000 {
            return Err(format!(
                "max_icp_e8s ({}) can be at most 1B ICP",
                self.max_icp_e8s
            ));
        }

        // Cap `min_participant_icp_e8s` at 100.
        if self.min_participants > 100 {
            return Err(format!(
                "min_participants ({}) can be at most 100",
                self.min_participants
            ));
        }

        // 100 * 1B * E8S should fit in a u64.
        assert!(self
            .max_icp_e8s
            .checked_mul(self.min_participants as u64)
            .is_some());

        if self.max_icp_e8s
            < (self.min_participants as u64).saturating_mul(self.min_participant_icp_e8s)
        {
            return Err(format!(
                "max_icp_e8s ({}) must be >= min_participants ({}) * min_participant_icp_e8s ({})",
                self.max_icp_e8s, self.min_participants, self.min_participant_icp_e8s
            ));
        }

        if self.neuron_basket_construction_parameters.is_none() {
            return Err("neuron_basket_construction_parameters must be provided".to_string());
        }

        let neuron_basket = self
            .neuron_basket_construction_parameters
            .as_ref()
            .expect("Expected neuron_basket_construction_parameters to be set");

        if neuron_basket.count == 0 {
            return Err(format!(
                "neuron_basket_construction_parameters.count ({}) must be > 0",
                neuron_basket.count,
            ));
        }

        if neuron_basket.dissolve_delay_interval_seconds == 0 {
            return Err(format!(
                "neuron_basket_construction_parameters.dissolve_delay_interval_seconds ({}) must be > 0",
                neuron_basket.dissolve_delay_interval_seconds,
            ));
        }

        // The maximum dissolve delay is one dissolve_delay_interval_seconds longer than count as
        // the algorithm adds a random jitter in addition to the count * dissolve_delay_interval_seconds.
        let maximum_dissolve_delay = neuron_basket
            .count
            .saturating_add(1)
            .saturating_mul(neuron_basket.dissolve_delay_interval_seconds);

        if maximum_dissolve_delay == u64::MAX {
            return Err(
                "Chosen neuron_basket_construction_parameters will result in u64 overflow"
                    .to_string(),
            );
        }

        Ok(())
    }

    pub fn is_valid_at(&self, now_seconds: u64) -> bool {
        now_seconds.saturating_add(SECONDS_PER_DAY) <= self.swap_due_timestamp_seconds
            && self.swap_due_timestamp_seconds <= now_seconds.saturating_add(90 * SECONDS_PER_DAY)
    }
}

impl BuyerState {
    pub fn new(amount_icp_e8s: u64) -> Self {
        Self {
            icp: Some(TransferableAmount {
                amount_e8s: amount_icp_e8s,
                transfer_start_timestamp_seconds: 0,
                transfer_success_timestamp_seconds: 0,
            }),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if let Some(icp) = &self.icp {
            icp.validate()
        } else {
            Err("Field 'icp' is missing but required".to_string())
        }
    }

    pub fn amount_icp_e8s(&self) -> u64 {
        if let Some(icp) = &self.icp {
            return icp.amount_e8s;
        }
        0
    }

    pub fn set_amount_icp_e8s(&mut self, val: u64) {
        if let Some(ref mut icp) = &mut self.icp {
            icp.amount_e8s = val;
        } else {
            self.icp = Some(TransferableAmount {
                amount_e8s: val,
                transfer_start_timestamp_seconds: 0,
                transfer_success_timestamp_seconds: 0,
            });
        }
    }
}

impl TransferableAmount {
    pub fn validate(&self) -> Result<(), String> {
        if self.transfer_start_timestamp_seconds == 0 && self.transfer_success_timestamp_seconds > 0
        {
            // Successful transfer without start time.
            return Err(format!("Invariant violation: transfer_start_timestamp_seconds is zero but transfer_success_timestamp_seconds ({}) is non-zero", self.transfer_success_timestamp_seconds));
        }
        if self.transfer_start_timestamp_seconds > self.transfer_success_timestamp_seconds
            && self.transfer_success_timestamp_seconds > 0
        {
            // Successful transfer before the transfer started.
            return Err(format!("Invariant violation: transfer_start_timestamp_seconds ({}) > transfer_success_timestamp_seconds ({}) > 0", self.transfer_start_timestamp_seconds, self.transfer_success_timestamp_seconds));
        }
        Ok(())
    }

    async fn transfer_helper(
        &mut self,
        now_fn: fn(bool) -> u64,
        fee: Tokens,
        subaccount: Option<Subaccount>,
        dst: &Account,
        ledger: &dyn ICRC1Ledger,
    ) -> TransferResult {
        let amount = Tokens::from_e8s(self.amount_e8s);
        if amount <= fee {
            // Skip: amount too small...
            return TransferResult::AmountTooSmall;
        }
        if self.transfer_start_timestamp_seconds > 0 {
            // Operation in progress...
            return TransferResult::AlreadyStarted;
        }
        self.transfer_start_timestamp_seconds = now_fn(false);

        // The ICRC1Ledger Trait converts any errors to Err(NervousSystemError).
        // No panics should occur when issuing this transfer.
        let result = ledger
            .transfer_funds(
                amount.get_e8s().saturating_sub(fee.get_e8s()),
                fee.get_e8s(),
                subaccount,
                dst.clone(),
                0,
            )
            .await;
        if self.transfer_start_timestamp_seconds == 0 {
            log!(
                ERROR,
                "Token disburse logic error: expected transfer start time",
            );
        }
        match result {
            Ok(h) => {
                self.transfer_success_timestamp_seconds = now_fn(true);
                log!(
                    INFO,
                    "Transferred {} from subaccount {:?} to {} at height {} in Ledger Canister {}",
                    amount,
                    subaccount,
                    dst,
                    h,
                    ledger.canister_id()
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                self.transfer_start_timestamp_seconds = 0;
                self.transfer_success_timestamp_seconds = 0;
                log!(
                    ERROR,
                    "Failed to transfer {} from subaccount {:#?}: {}",
                    amount,
                    subaccount,
                    e
                );
                TransferResult::Failure(e.to_string())
            }
        }
    }
}

impl OpenRequest {
    pub fn validate(&self, current_timestamp_seconds: u64, init: &Init) -> Result<(), String> {
        let mut defects = vec![];

        // Inspect params.
        match self.params.as_ref() {
            None => {
                defects.push("The parameters of the swap are missing.".to_string());
            }
            Some(params) => {
                if !params.is_valid_at(current_timestamp_seconds) {
                    defects.push("The parameters of the swap are invalid.".to_string());
                } else if let Err(err) = params.validate(init) {
                    defects.push(err);
                }
            }
        }

        // Inspect open_sns_token_swap_proposal_id.
        if self.open_sns_token_swap_proposal_id.is_none() {
            defects.push("The open_sns_token_swap_proposal_id field has no value.".to_string());
        }

        // Return result.
        if defects.is_empty() {
            Ok(())
        } else {
            Err(defects.join("\n"))
        }
    }
}

impl DirectInvestment {
    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_principal(&self.buyer_principal) {
            return Err(format!("Invalid principal {}", self.buyer_principal));
        }
        Ok(())
    }
}

impl CfInvestment {
    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_principal(&self.hotkey_principal) {
            return Err(format!(
                "Invalid hotkey principal {}",
                self.hotkey_principal
            ));
        }
        if self.nns_neuron_id == 0 {
            return Err("Missing nns_neuron_id".to_string());
        }
        Ok(())
    }
}

impl SnsNeuronRecipe {
    pub fn amount_e8s(&self) -> u64 {
        if let Some(sns) = &self.sns {
            return sns.amount_e8s;
        }
        0
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(sns) = &self.sns {
            sns.validate()?;
        } else {
            return Err("Missing required field 'sns'".to_string());
        }
        match &self.investor {
            Some(Investor::Direct(di)) => di.validate()?,
            Some(Investor::CommunityFund(cf)) => cf.validate()?,
            None => return Err("Missing required field 'investor'".to_string()),
        }
        Ok(())
    }
}

impl CfParticipant {
    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_principal(&self.hotkey_principal) {
            return Err(format!(
                "Invalid hotkey principal {}",
                self.hotkey_principal
            ));
        }
        if self.cf_neurons.is_empty() {
            return Err(format!(
                "A CF participant ({}) must have at least one neuron",
                self.hotkey_principal
            ));
        }
        for n in &self.cf_neurons {
            n.validate()?;
        }
        Ok(())
    }
    pub fn participant_total_icp_e8s(&self) -> u64 {
        self.cf_neurons
            .iter()
            .map(|x| x.amount_icp_e8s)
            .fold(0, |sum, v| sum.saturating_add(v))
    }
}

impl CfNeuron {
    pub fn validate(&self) -> Result<(), String> {
        if self.nns_neuron_id == 0 {
            return Err("nns_neuron_id must be specified".to_string());
        }
        if self.amount_icp_e8s == 0 {
            return Err("amount_icp_e8s must be specified".to_string());
        }
        Ok(())
    }
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

impl Lifecycle {
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Committed | Self::Aborted => true,

            Self::Pending | Self::Open => false,
            Self::Unspecified => {
                log!(ERROR, "A wild Lifecycle::Unspecified appeared.",);
                false
            }
        }
    }
}

impl FinalizeSwapResponse {
    pub fn with_error(error_message: String) -> Self {
        FinalizeSwapResponse {
            error_message: Some(error_message),
            ..Default::default()
        }
    }

    pub fn set_error_message(&mut self, error_message: String) {
        self.error_message = Some(error_message)
    }

    pub fn set_sweep_icp(&mut self, sweep_icp: SweepResult) {
        self.sweep_icp = Some(sweep_icp)
    }

    pub fn set_settle_community_fund_participation_result(
        &mut self,
        result: SettleCommunityFundParticipationResult,
    ) {
        self.settle_community_fund_participation_result = Some(result)
    }

    pub fn set_set_dapp_controllers_result(&mut self, result: SetDappControllersCallResult) {
        self.set_dapp_controllers_result = Some(result)
    }

    pub fn set_sweep_sns(&mut self, sweep_sns: SweepResult) {
        self.sweep_sns = Some(sweep_sns)
    }

    pub fn set_create_neuron(&mut self, create_neuron: SweepResult) {
        self.create_neuron = Some(create_neuron)
    }

    pub fn set_sns_governance_normal_mode_enabled(
        &mut self,
        set_mode_call_result: SetModeCallResult,
    ) {
        self.sns_governance_normal_mode_enabled = Some(set_mode_call_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::params::NeuronBasketConstructionParameters;
    use ic_nervous_system_common::{
        assert_is_err, assert_is_ok, E8, SECONDS_PER_DAY, START_OF_2022_TIMESTAMP_SECONDS,
    };
    use lazy_static::lazy_static;
    use prost::Message;

    const OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID: u64 = 489102;

    const PARAMS: Params = Params {
        max_icp_e8s: 1_000 * E8,
        max_participant_icp_e8s: 1_000 * E8,
        min_icp_e8s: 10 * E8,
        min_participant_icp_e8s: 5 * E8,
        sns_token_e8s: 5_000 * E8,
        min_participants: 10,
        swap_due_timestamp_seconds: START_OF_2022_TIMESTAMP_SECONDS + 14 * SECONDS_PER_DAY,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 3,
            dissolve_delay_interval_seconds: 7890000, // 3 months
        }),
    };

    lazy_static! {
        static ref OPEN_REQUEST: OpenRequest = OpenRequest {
            params: Some(PARAMS),
            cf_participants: vec![CfParticipant {
                hotkey_principal: PrincipalId::new_user_test_id(423939).to_string(),
                cf_neurons: vec![CfNeuron {
                    nns_neuron_id: 42,
                    amount_icp_e8s: 99,
                }],
            },],
            open_sns_token_swap_proposal_id: Some(OPEN_SNS_TOKEN_SWAP_PROPOSAL_ID),
        };

        // Fill out Init just enough to test Params validation. These values are
        // similar to, but not the same analogous values in NNS.
        static ref INIT: Init = Init {
            transaction_fee_e8s: Some(12_345),
            neuron_minimum_stake_e8s: Some(123_456_789),
            ..Default::default()
        };
    }

    #[test]
    fn accept_iff_can_form_sns_neuron_in_the_worst_case() {
        let mut init = INIT.clone();

        let sns_token_e8s = PARAMS.min_participant_icp_e8s as u128 * PARAMS.sns_token_e8s as u128
            / PARAMS.max_icp_e8s as u128;
        let neuron_basket_count = PARAMS
            .neuron_basket_construction_parameters
            .as_ref()
            .expect("participant_neuron_basket not populated.")
            .count as u128;
        let available_sns_token_e8s_per_neuron =
            sns_token_e8s / neuron_basket_count as u128 - init.transaction_fee_e8s.unwrap() as u128;
        assert!(available_sns_token_e8s_per_neuron < u64::MAX as u128);
        let available_sns_token_e8s_per_neuron = available_sns_token_e8s_per_neuron as u64;
        assert!(init.neuron_minimum_stake_e8s.unwrap() <= available_sns_token_e8s_per_neuron);

        // Set the bar as high as min_participant_icp_e8s can "jump".
        init.neuron_minimum_stake_e8s = Some(available_sns_token_e8s_per_neuron);
        assert_is_ok!(PARAMS.validate(&init));

        // The bar can still be cleared if lowered.
        init.neuron_minimum_stake_e8s = Some(available_sns_token_e8s_per_neuron - 1);
        assert_is_ok!(PARAMS.validate(&init));

        // Raise the bar so that it can no longer be cleared.
        init.neuron_minimum_stake_e8s = Some(available_sns_token_e8s_per_neuron + 1);
        assert_is_err!(PARAMS.validate(&init));
    }

    #[test]
    fn open_request_validate_ok() {
        assert_is_ok!(OPEN_REQUEST.validate(START_OF_2022_TIMESTAMP_SECONDS, &INIT));
    }

    #[test]
    fn open_request_validate_invalid_params() {
        let request = OpenRequest {
            params: Some(Params {
                swap_due_timestamp_seconds: 42,
                ..PARAMS.clone()
            }),
            ..OPEN_REQUEST.clone()
        };

        assert_is_err!(request.validate(START_OF_2022_TIMESTAMP_SECONDS, &INIT));
    }

    #[test]
    fn open_request_validate_no_proposal_id() {
        let request = OpenRequest {
            open_sns_token_swap_proposal_id: None,
            ..OPEN_REQUEST.clone()
        };

        assert_is_err!(request.validate(START_OF_2022_TIMESTAMP_SECONDS, &INIT));
    }

    #[test]
    fn participant_total_icp_e8s_no_overflow() {
        let participant = CfParticipant {
            hotkey_principal: "".to_string(),
            cf_neurons: vec![
                CfNeuron {
                    nns_neuron_id: 0,
                    amount_icp_e8s: u64::MAX,
                },
                CfNeuron {
                    nns_neuron_id: 0,
                    amount_icp_e8s: u64::MAX,
                },
            ],
        };
        let total = participant.participant_total_icp_e8s();
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn large_community_fund_does_not_result_in_oversized_open_request() {
        const MAX_SIZE_BYTES: usize = 1 << 21; // 2 Mi

        let neurons_per_principal = 3;

        let cf_participant = CfParticipant {
            hotkey_principal: PrincipalId::new_user_test_id(789362).to_string(),
            cf_neurons: (0..neurons_per_principal)
                .map(|_| CfNeuron {
                    nns_neuron_id: 592523,
                    amount_icp_e8s: 1_000 * E8,
                })
                .collect(),
        };

        let mut open_request = OpenRequest {
            cf_participants: vec![cf_participant],
            ..Default::default()
        };

        // Crescendo
        loop {
            let mut buffer: Vec<u8> = vec![];
            open_request.encode(&mut buffer).unwrap();
            if buffer.len() > MAX_SIZE_BYTES {
                break;
            }

            // Double size of cf_participants.
            open_request
                .cf_participants
                .append(&mut open_request.cf_participants.clone());
        }

        // TODO: Get more precise using our favorite algo: binary search!
        let safe_len = open_request.cf_participants.len() / 2;
        assert!(safe_len > 10_000);
        println!(
            "Looks like we can support at least {} Community Fund neurons (among {} principals).",
            safe_len * neurons_per_principal,
            safe_len,
        );
    }
}
