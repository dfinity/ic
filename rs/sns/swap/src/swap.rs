use crate::pb::v1::{
    set_dapp_controllers_call_result, set_mode_call_result, sns_neuron_recipe::Investor,
    BuyerState, CanisterCallError, CfInvestment, CfNeuron, CfParticipant, DerivedState,
    DirectInvestment, FinalizeSwapResponse, GetBuyerStateRequest, GetBuyerStateResponse,
    GetBuyersTotalResponse, Init, Lifecycle, OpenRequest, OpenResponse, Params,
    RefreshBuyerTokensResponse, SetDappControllersCallResult, SetModeCallResult, SnsNeuronRecipe,
    Swap, SweepResult, TransferableAmount,
};
use async_trait::async_trait;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes;
use ic_sns_governance::{
    ledger::Ledger,
    pb::v1::{
        governance, manage_neuron, manage_neuron_response, ManageNeuron, ManageNeuronResponse,
        SetMode, SetModeResponse,
    },
    types::DEFAULT_TRANSFER_FEE,
};
use std::str::FromStr;

use crate::pb::v1::{SetDappControllersRequest, SetDappControllersResponse};

// TODO: remove when not used.
pub const START_OF_2022_TIMESTAMP_SECONDS: u64 = 1640995200;

pub const LOG_PREFIX: &str = "[Swap] ";
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

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

#[async_trait]
pub trait SnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError>;

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError>;
}

#[async_trait]
pub trait SnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError>;
}

// High level documentation in the corresponding Protobuf message.
impl Swap {
    /// Create state from an `Init` object.
    ///
    /// Requires that `init` is valid; otherwise it panics.
    pub fn new(init: Init) -> Self {
        if let Err(e) = init.validate() {
            panic!("{}", e);
        }
        Self {
            lifecycle: Lifecycle::Pending as i32,
            init: Some(init),
            params: None,
            cf_participants: vec![],
            buyers: Default::default(), // Btree map
            neuron_recipes: vec![],
            cf_minting: None,
        }
    }

    /// Retrieve a reference to the `init` field. The `init` field
    /// must always be not-`None` given how `new` is implemented.
    pub fn init(&self) -> &Init {
        (&self.init).as_ref().unwrap()
    }

    /// The number of SNS tokens for sale, or zero if the sale hasn't
    /// been opened yet.
    pub fn sns_token_e8s(&self) -> u64 {
        if let Some(params) = &self.params {
            params.sns_token_e8s
        } else {
            0
        }
    }

    // The total amount of ICP contributed by direct investors and the
    // community fund.
    pub fn participant_total_icp_e8s(&self) -> u64 {
        self.direct_investor_total_icp_e8s()
            .saturating_add(self.cf_total_icp_e8s())
    }

    // The total amount of ICP contributed by the community fund.
    pub fn cf_total_icp_e8s(&self) -> u64 {
        // TODO: use saturating add...
        self.cf_participants
            .iter()
            .map(|x| x.participant_total_icp_e8s())
            .sum()
    }

    // The total amount of ICP contributed by direct investors.
    fn direct_investor_total_icp_e8s(&self) -> u64 {
        self.buyers.values().map(|x| x.amount_icp_e8s()).sum()
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
        sns_ledger: &dyn Ledger,
        now_seconds: u64,
        req: OpenRequest,
    ) -> Result<OpenResponse, String> {
        if self.lifecycle() != Lifecycle::Pending {
            return Err("Invalid lifecycle state to OPEN the swap: must be PENDING".to_string());
        }

        let params = req
            .params
            .as_ref()
            .ok_or("The parameters of the swap are missing.")?;
        if !params.is_valid_at(now_seconds) {
            return Err("The parameters of the swap are invalid.".to_string());
        }
        params.validate()?;

        let sns_token_amount = Self::get_sns_tokens(this_canister, sns_ledger).await?;

        // Check that the SNS amount is at least the required
        // amount. We don't refuse to open the swap just because there
        // are more SNS tokens sent to the swap canister than
        // advertised, as this would lead to a dead end, because there
        // is no way to take the tokens back.
        if sns_token_amount.get_e8s() < params.sns_token_e8s {
            return Err(
                "Cannot OPEN, because the expected number of SNS tokens is not available"
                    .to_string(),
            );
        }

        assert!(self.params.is_none());
        self.params = req.params;
        self.cf_participants = req.cf_participants;
        self.set_lifecycle(Lifecycle::Open);
        Ok(OpenResponse {})
    }

    /// Compute `amount_icp_e8s` scaled by (`total_sns_e8s` divided by
    /// `total_icp_e8s`), but perform the computation in integer space
    /// by computing `(amount_icp_e8s * total_sns_e8s) /
    /// total_icp_e8s` in 128 bit space.
    fn scale(amount_icp_e8s: u64, total_sns_e8s: u64, total_icp_e8s: u64) -> u64 {
        assert!(amount_icp_e8s <= total_icp_e8s);
        // Note that the multiplication cannot overflow as both factors fit in 64 bits.
        let r = ((amount_icp_e8s as u128) * (total_sns_e8s as u128)) / (total_icp_e8s as u128);
        // This follows logically from the initial assert `amount_icp_e8s <= total_icp_e8s`.
        assert!(r <= u64::MAX as u128);
        r as u64
    }

    /// Precondition: lifecycle == OPEN && sufficient_participation && (swap_due || icp_target_reached)
    ///
    /// Postcondition: lifecycle == COMMITTED
    fn commit(&mut self, now_seconds: u64) {
        assert!(self.lifecycle() == Lifecycle::Open);
        assert!(self.sufficient_participation());
        assert!(self.swap_due(now_seconds) || self.icp_target_reached());
        // Safe as `params` must be specified in call to `open`.
        let params = self.params.as_ref().unwrap();
        // We are selling SNS tokens for the base token (ICP), or, in
        // general, whatever token the ledger referred to as the ICP
        // ledger holds.
        let sns_being_offered_e8s = params.sns_token_e8s;
        // This must hold as the swap cannot transition to state
        // OPEN without transferring tokens being offered to the swap canister.
        assert!(sns_being_offered_e8s > 0);
        // Note that this value has to be > 0 as we have > 0
        // participants each with > 0 ICP contributed.
        let total_participant_icp_e8s = self.participant_total_icp_e8s();
        assert!(total_participant_icp_e8s > 0);
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
            neurons.push(SnsNeuronRecipe {
                sns: Some(TransferableAmount {
                    amount_e8s: amount_sns_e8s,
                    transfer_start_timestamp_seconds: 0,
                    transfer_success_timestamp_seconds: 0,
                }),
                investor: Some(Investor::Direct(DirectInvestment {
                    buyer_principal: buyer_principal.clone(),
                })),
            });
            total_sns_tokens_sold = total_sns_tokens_sold.checked_add(amount_sns_e8s).unwrap();
        }
        for cf_participant in self.cf_participants.iter() {
            for cf_neuron in cf_participant.cf_neurons.iter() {
                let amount_sns_e8s = Swap::scale(
                    cf_neuron.amount_icp_e8s,
                    sns_being_offered_e8s,
                    total_participant_icp_e8s,
                );
                neurons.push(SnsNeuronRecipe {
                    sns: Some(TransferableAmount {
                        amount_e8s: amount_sns_e8s,
                        transfer_start_timestamp_seconds: 0,
                        transfer_success_timestamp_seconds: 0,
                    }),
                    investor: Some(Investor::CommunityFund(CfInvestment {
                        hotkey_principal: cf_participant.hotkey_principal.clone(),
                        nns_neuron_id: cf_neuron.nns_neuron_id,
                    })),
                });
                total_sns_tokens_sold = total_sns_tokens_sold.checked_add(amount_sns_e8s).unwrap();
            }
        }
        assert!(total_sns_tokens_sold <= params.sns_token_e8s);
        println!("{}INFO: token swap committed; {} direct investors and {} communtify fund investors receive a total of {} out of {} (change {});",
		 LOG_PREFIX,
		 self.buyers.len(),
		 self.cf_participants.len(),
		 total_sns_tokens_sold,
		 params.sns_token_e8s,
		 params.sns_token_e8s - total_sns_tokens_sold);
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
    /// been transfer to the swap canister (this cansiter) on the
    /// ledger of `init.sns_ledger_canister_id`. This transfer is
    /// performed by the Governance cansiter of the SNS or
    /// pre-decentralization token holders.
    async fn get_sns_tokens(
        this_canister: CanisterId,
        sns_ledger: &dyn Ledger,
    ) -> Result<Tokens, String> {
        // Look for the token balanace of 'this' canister.
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
    canister. Thus, the swap cansiter can only be notified about
    transfers happening on these canisters.

     */

    /// In state Open, this method can be called to refresh the amount
    /// of ICP a buyer has contributed from the ICP ledger canister.
    ///
    /// It is assumed that prior to calling this method, tokens have
    /// been transfer by the buyer to a subaccount of the swap
    /// canister (this cansiter) on the ICP ledger.
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
        icp_ledger: &dyn Ledger,
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
        // Look for the token balanace of the specified principal's subaccount on 'this' canister.
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
        let params = &self.params.as_ref().unwrap(); // Safe as lifecycle is OPEN.
        let max_icp_e8s = params.max_icp_e8s;
        if participant_total_icp_e8s >= max_icp_e8s {
            if participant_total_icp_e8s > max_icp_e8s {
                println!(
                    "{}WARNING: total amount of ICP bought {} already exceeds the target {}!",
                    LOG_PREFIX, participant_total_icp_e8s, max_icp_e8s
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
                icp_accepted_partipation_e8s: e8s,
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
            println!(
                "{}INFO: participant {} contributed {} e8s - the limit per participant is {}",
                LOG_PREFIX, buyer, new_balance_e8s, max_participant_icp_e8s
            );
        }
        buyer_state.set_amount_icp_e8s(std::cmp::min(new_balance_e8s, max_participant_icp_e8s));
        println!(
            "{}INFO: refresh_buyer_tokens for buyer {}; old e8s {}; new e8s {}",
            LOG_PREFIX,
            buyer,
            old_amount_icp_e8s,
            buyer_state.amount_icp_e8s()
        );
        if requested_increment_e8s >= max_increment_e8s {
            println!(
                "{}LOG: swap has reached ICP target of {}",
                LOG_PREFIX, max_icp_e8s
            );
        }
        Ok(RefreshBuyerTokensResponse {
            icp_accepted_partipation_e8s: buyer_state.amount_icp_e8s(),
            icp_ledger_account_balance_e8s: e8s,
        })
    }

    /*

    Transfers OUT.

     */

    /// Distributes funds, and if the swap was successful, creates neurons. Returns
    /// a summary of (sub)actions that were performed.
    ///
    /// If the swap is not over yet, panics.
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
    pub async fn finalize(
        &mut self,
        now_fn: fn(bool) -> u64,
        sns_root_client: &mut impl SnsRootClient,
        sns_governance_client: &mut impl SnsGovernanceClient,
        icp_ledger: &dyn Ledger,
        sns_ledger: &dyn Ledger,
    ) -> FinalizeSwapResponse {
        let lifecycle = self.lifecycle();
        assert!(
            lifecycle == Lifecycle::Committed || lifecycle == Lifecycle::Aborted,
            "Swap can only be finalized in the COMMITTED or ABORTED states - was {:?}",
            lifecycle
        );

        let sweep_icp = self
            .sweep_icp(now_fn, DEFAULT_TRANSFER_FEE, icp_ledger)
            .await;
        if lifecycle != Lifecycle::Committed {
            // Restore controllers of dapp canisters to their original owners (i.e. self.init.fallback_controller_principal_ids).
            let set_dapp_controllers_result = sns_root_client.set_dapp_controllers(
                SetDappControllersRequest {
                    controller_principal_ids: self
                        .init()
                        .fallback_controller_principal_ids
                        .iter()
                        .map(|s| PrincipalId::from_str(s)
                             .expect("Unable to parse element in fallback_controller_principal_ids as a PrincipalId.")
                        )
                        .collect(),
                }
            )
            .await;

            return FinalizeSwapResponse {
                sweep_icp: Some(sweep_icp),
                sweep_sns: None,
                create_neuron: None,
                sns_governance_normal_mode_enabled: None,
                set_dapp_controllers_result: Some(set_dapp_controllers_result.into()),
            };
        }

        let sweep_sns = self
            .sweep_sns(now_fn, DEFAULT_TRANSFER_FEE, sns_ledger)
            .await;

        let create_neuron = self.claim_neurons(sns_governance_client).await;

        let sns_governance_normal_mode_enabled =
            Self::set_sns_governance_to_normal_mode_if_all_neurons_claimed(
                sns_governance_client,
                &create_neuron,
            )
            .await;

        // TODO(NNS1-1664): this also needs to pass the community fund
        // participation back to the NNS so the NNS can mint ICP and
        // send to the SNS Governance canister.

        FinalizeSwapResponse {
            sweep_icp: Some(sweep_icp),
            sweep_sns: Some(sweep_sns),
            create_neuron: Some(create_neuron),
            sns_governance_normal_mode_enabled,
            set_dapp_controllers_result: None,
        }
    }

    async fn claim_neurons(
        &self,
        sns_governance_client: &mut impl SnsGovernanceClient,
    ) -> SweepResult {
        let (skipped, investors) = self.investors_for_create_neuron();
        let mut result = SweepResult {
            success: 0,
            failure: 0,
            skipped,
        };
        let nns_governance = self.init().nns_governance();
        // TODO: for a community fund neuron, the hotkey needs to make
        // its way into the neuron creation call somehow...
        for inv in &investors {
            let (_hotkey, controller, memo) = match &inv {
                Investor::Direct(DirectInvestment { buyer_principal: p }) => {
                    (None, PrincipalId::from_str(p).unwrap(), 0)
                }
                Investor::CommunityFund(CfInvestment {
                    hotkey_principal,
                    nns_neuron_id,
                }) => (
                    Some(hotkey_principal),
                    nns_governance.into(),
                    *nns_neuron_id,
                ),
            };
            // Claim SNS neuron that we just funded (or at least tried to).
            let request = ManageNeuron {
                subaccount: vec![],
                command: Some(manage_neuron::Command::ClaimOrRefresh(
                    manage_neuron::ClaimOrRefresh {
                        by: Some(manage_neuron::claim_or_refresh::By::MemoAndController(
                            manage_neuron::claim_or_refresh::MemoAndController {
                                controller: Some(controller),
                                memo,
                            },
                        )),
                    },
                )),
            };

            let response = sns_governance_client.manage_neuron(request).await;

            if let Ok(ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::ClaimOrRefresh(claim)),
            }) = response
            {
                println!(
                    "{}INFO: Neuron successfully claimed for investor {:#?}: {:#?}",
                    LOG_PREFIX, inv, claim,
                );
                result.success += 1;
                continue;
            }

            println!(
                "{}ERROR: Unable to claim neuron for investor {:#?}: {:#?}",
                LOG_PREFIX, inv, response,
            );
            result.failure += 1;
        }
        result
    }

    async fn set_sns_governance_to_normal_mode_if_all_neurons_claimed(
        sns_governance_client: &mut impl SnsGovernanceClient,
        create_neuron: &SweepResult,
    ) -> Option<SetModeCallResult> {
        let all_neurons_created = create_neuron.failure == 0;

        if !all_neurons_created {
            return None;
        }

        Some(
            sns_governance_client
                .set_mode(SetMode {
                    mode: governance::Mode::Normal as i32,
                })
                .await
                .into(),
        )
    }

    /// Requests a refund of ICP tokens transferred to the Swap
    /// cansiter in error. This method only works if this
    /// canister is in the COMMITTED or ABORTED state.
    ///
    /// The request is to refund `amount` tokens for `principal`
    /// (using `fee` as fee) on the ICP ledger. The specified amount
    /// of tokens is transferred from `subaccount(swap_canister, P)`
    /// to `P`, where `P` is the specified principal.
    ///
    /// Note that this function cannot mutate `self` - it only
    /// initiates a ledger transfer, which may fail. It is up to the
    /// caller to ensure the correctness of the parameters.
    ///
    /// This method is secure because it only transfers tokens from a
    /// principal's subaccount (of the Swap canister) to the
    /// principal's own account, i.e., the tokens were held in escrow
    /// for the principal (buyer) before the call and are returned to
    /// the same principal. Moreover, this method can only be called
    /// by the principal; this serves two purposes: first, that third
    /// parties cannot make many small transfers to drain the
    /// principal's tokens by multiple fees, and, second, so a third
    /// party cannot return the buyer's token that they intended to
    /// use to join the swap.
    pub async fn error_refund_icp(
        &self,
        principal: PrincipalId,
        amount: Tokens,
        fee: Tokens,
        icp_ledger: &dyn Ledger,
    ) -> TransferResult {
        if !(self.lifecycle() == Lifecycle::Aborted || self.lifecycle() == Lifecycle::Committed) {
            return TransferResult::Failure(
                "Error refunds can only be performed when the swap is ABORTED or COMMITTED"
                    .to_string(),
            );
        }
        if let Some(buyer_state) = self.buyers.get(&principal.to_string()) {
            if let Some(transfer) = &buyer_state.icp {
                if transfer.transfer_success_timestamp_seconds == 0 {
                    // This buyer has ICP not yet disbursed using the normal mechanism.
                    return TransferResult::Failure(format!(
                        "ICP cannot be refunded as principal {} has {} ICP (e8s) in escrow",
                        principal,
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
        let subaccount = principal_to_subaccount(&principal);
        let dst = Account {
            owner: principal,
            subaccount: None,
        };
        let result = icp_ledger
            .transfer_funds(
                amount.get_e8s().saturating_sub(fee.get_e8s()),
                fee.get_e8s(),
                Some(subaccount),
                dst.clone(),
                0,
            )
            .await;
        match result {
            Ok(h) => {
                println!(
                    "{}INFO: error refund - transferred {} ICP from subaccount {:#?} to {} at height {}",
                    LOG_PREFIX, amount, subaccount, dst, h
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                println!(
                    "{}ERROR: error refund - failed to transfer {} from subaccount {:#?}: {}",
                    LOG_PREFIX, amount, subaccount, e
                );
                TransferResult::Failure(e.to_string())
            }
        }
    }

    /// In state COMMITTED or ABORTED. Transfer ICP tokens from
    /// buyer's subaccounts to the SNS governance canister if
    /// COMMITTED or back to the buyer if ABORTED.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    pub async fn sweep_icp(
        &mut self,
        now_fn: fn(bool) -> u64,
        fee: Tokens,
        icp_ledger: &dyn Ledger,
    ) -> SweepResult {
        let lifecycle = self.lifecycle();
        assert!(lifecycle == Lifecycle::Committed || lifecycle == Lifecycle::Aborted);
        let sns_governance = self.init().sns_governance();
        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;
        for (principal_str, buyer_state) in self.buyers.iter_mut() {
            let principal = match PrincipalId::from_str(principal_str) {
                Ok(p) => p,
                Err(msg) => {
                    println!(
                        "{}ERROR: cannot parse principal {} for disbursal: {}",
                        LOG_PREFIX, principal_str, msg
                    );
                    failure += 1;
                    continue;
                }
            };
            let subaccount = principal_to_subaccount(&principal);
            let dst = if lifecycle == Lifecycle::Committed {
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
            let result = buyer_state
                .icp
                .as_mut()
                .unwrap()
                .transfer_helper(now_fn, fee, Some(subaccount), &dst, icp_ledger)
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
        SweepResult {
            success,
            failure,
            skipped,
        }
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
        fee: Tokens,
        sns_ledger: &dyn Ledger,
    ) -> SweepResult {
        assert!(self.lifecycle() == Lifecycle::Committed);
        let sns_governance = self.init().sns_governance();
        let nns_governance = self.init().nns_governance();
        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;
        for recipe in self.neuron_recipes.iter_mut() {
            let dst_subaccount = match &recipe.investor {
                Some(Investor::Direct(DirectInvestment { buyer_principal })) => {
                    match PrincipalId::from_str(buyer_principal) {
                        Ok(p) => compute_neuron_staking_subaccount_bytes(p, 0),
                        Err(msg) => {
                            println!(
                                "{}ERROR: cannot parse principal {} for disbursal: {}",
                                LOG_PREFIX, buyer_principal, msg
                            );
                            failure += 1;
                            continue;
                        }
                    }
                }
                Some(Investor::CommunityFund(CfInvestment {
                    hotkey_principal: _,
                    nns_neuron_id,
                })) => {
                    compute_neuron_staking_subaccount_bytes(nns_governance.into(), *nns_neuron_id)
                }
                None => {
                    println!(
                        "{}ERROR: missing investor information for neuron",
                        LOG_PREFIX
                    );
                    skipped += 1;
                    continue;
                }
            };
            let dst = Account {
                owner: sns_governance.get(),
                subaccount: Some(dst_subaccount),
            };
            let result = recipe
                .sns
                .as_mut()
                .unwrap()
                .transfer_helper(
                    now_fn, fee, /* src_subaccount= */ None, &dst, sns_ledger,
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
        SweepResult {
            success,
            failure,
            skipped,
        }
    }

    /// Returns list of investors for which an SNS neuron may need to
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
    pub fn investors_for_create_neuron(&self) -> (u32, Vec<Investor>) {
        if self.lifecycle() != Lifecycle::Committed {
            return (self.neuron_recipes.len() as u32, vec![]);
        }
        let mut investors = Vec::new();
        let mut skipped = 0;
        for recipe in self.neuron_recipes.iter() {
            if let Some(sns) = &recipe.sns {
                if sns.transfer_success_timestamp_seconds > 0 {
                    if let Some(investor) = &recipe.investor {
                        investors.push(investor.clone());
                        continue;
                    } else {
                        println!("{}WARNING: missing field 'investor'", LOG_PREFIX);
                    }
                }
            } else {
                println!("{}WARNING: missing field 'sns'", LOG_PREFIX);
            }
            skipped += 1;
        }
        (skipped, investors)
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
        if let Some(init) = &self.init {
            init.validate()?;
        } else {
            return Err("Missing 'init'.".to_string());
        }
        if let Some(params) = &self.params {
            params.validate()?;
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

    /// The paramter `now_seconds` is greater than or equal to end_timestamp_seconds.
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
            if self.cf_participants.len() + self.buyers.len() < (params.min_participants as usize) {
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
        if !(self.swap_due(now_seconds) || self.icp_target_reached()) {
            return false;
        }
        true
    }

    //
    // --- query methods on the state  -----------------------------------------
    //

    pub fn derived_state(&self) -> DerivedState {
        let participant_total_icp_e8s = self.participant_total_icp_e8s();
        DerivedState {
            buyer_total_icp_e8s: participant_total_icp_e8s,
            sns_tokens_per_icp: ((self.sns_token_e8s() as f64) / (participant_total_icp_e8s as f64))
                as f32,
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
    let _ = PrincipalId::from_str(p).map_err(|x| x.to_string())?;
    Ok(())
}

pub fn validate_canister_id(p: &str) -> Result<(), String> {
    let pp = PrincipalId::from_str(p).map_err(|x| x.to_string())?;
    let _cid = CanisterId::new(pp).map_err(|x| x.to_string())?;
    Ok(())
}

impl Init {
    pub fn nns_governance(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.nns_governance_canister_id).unwrap()).unwrap()
    }
    pub fn sns_root(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_root_canister_id).unwrap()).unwrap()
    }
    pub fn sns_governance(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_governance_canister_id).unwrap()).unwrap()
    }
    pub fn sns_ledger(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.sns_ledger_canister_id).unwrap()).unwrap()
    }
    pub fn icp_ledger(&self) -> CanisterId {
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
        Ok(())
    }
}

impl Params {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_icp_e8s == 0 {
            return Err("min_icp_e8s must be > 0".to_string());
        }
        if self.min_participants == 0 {
            return Err("min_participants must be > 0".to_string());
        }
        if self.min_participant_icp_e8s == 0 {
            return Err("min_participant_icp_e8s must be > 0".to_string());
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
        ledger: &dyn Ledger,
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
        // Memo = 0
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
            println!(
                "{}ERROR: token disburse logic error: expected transfer start time",
                LOG_PREFIX
            );
        }
        match result {
            Ok(h) => {
                self.transfer_success_timestamp_seconds = now_fn(true);
                println!(
                    "{}INFO: transferred {} ICP from subaccount {:?} to {} at height {}",
                    LOG_PREFIX, amount, subaccount, dst, h
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                self.transfer_start_timestamp_seconds = 0;
                self.transfer_success_timestamp_seconds = 0;
                println!(
                    "{}ERROR: failed to transfer {} from subaccount {:#?}: {}",
                    LOG_PREFIX, amount, subaccount, e
                );
                TransferResult::Failure(e.to_string())
            }
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
        // TODO: use saturating add...
        self.cf_neurons.iter().map(|x| x.amount_icp_e8s).sum()
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
