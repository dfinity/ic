use crate::pb::v1::{
    set_mode_call_result, BuyerState, CanisterCallError, DerivedState, FinalizeSaleResponse, Init,
    Lifecycle, Sale, SetModeCallResult, State, SweepResult,
};
use async_trait::async_trait;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;

use ic_nervous_system_common::ledger::{self, Ledger};
use ic_sns_governance::pb::v1::{
    governance, manage_neuron, ManageNeuron, ManageNeuronResponse, SetMode, SetModeResponse,
};

use std::str::FromStr;

use ledger_canister::{AccountIdentifier, Subaccount, DEFAULT_TRANSFER_FEE};

use ledger_canister::Tokens;

pub const LOG_PREFIX: &str = "[Sale] ";

/// Result of a token transfer (commit or abort) on a ledger (ICP or SNS) for a single buyer.
pub enum TransferResult {
    /// Transfer was skipped as the amount was less than the requested fee.
    AmountTooSmall,
    /// Transferred was skipped as an operation is already in progress.
    AlreadyInProgress,
    /// The operation was successful at the specified block height.
    Success(u64),
    /// The operation failed with an error message.
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

#[async_trait]
pub trait SnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError>;

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError>;
}

/**

State diagram for the sale canister's state.

```text
           has_sns_amount                  sufficient_participation && (sale_due || icp_target_reached)
PENDING -------------------------> OPEN ------------------------------------------------------------> COMMITTED
 |                                  |                                                                     |
 |                                  | sale_due && not sufficient_participation                             |
 |                                  v                                                                     v
 |                                 ABORTED ---------------------------------------------------------> <DELETED>
 |                                  ^
 |                                  |
 +--------------------- sale_due  --+
```

Here `sufficient_participation` means that the minimum number of
participants `min_participants` has been reached, each contributing
between `min_participant_icp_e8s` and `max_participant_icp_e8s`, and
their total contributions add up to at least `min_icp_e8s`.

The 'sale' canister smart contract is used to perform a type of
single-price auction (SNS/ICP) of one token type SNS for another token
type ICP (this is typically ICP, but can be treatd as a variable) at a
specific date/time in the future.

Such a single-price auction is typically used to decentralize an SNS,
i.e., to ensure that a sufficient number of governance tokens of the
SNS are distributed among different participants.

The dramatis personae of the 'sale' canister are as follows:

- The sale canister itself.

- The NNS governance canister - which is the only principal that can open the sale.

- The governance canister of the SNS to be decentralized.

- The ledger canister of the SNS, i.e., the ledger of the token type
  being auctioned off.

- The ICP ledger cansiter, or more generally of the base currency of
  the auction.

When the sale canister is initialized, it must be configured with
the canister IDs of the other four participant canisters, the date/time
at which the token swap will take place, and configuration parmeters
for the amount of SNS tokens for sale, the minimal number of
participants, the minimum number of base tokens (ICP) of each
paricipant, as well as the target number of base tokens (ICP) of the
sale.

Step 0. The canister is created, specifying all initalization
parameters, which are henceforth fixed for the lifetime of the
canister.

Step 1 (State 'pending'). The sale canister is loaded with the right
amount of SNS tokens.

Step 2. (State 'open'). The sale is open for paricipants who can enter
into the auction with a number of ICP tokens until either the target
amount has been reached or the auction is due, i.e., the date/time of
the auction has been reached. .

Step 3a. (State 'committed'). Tokens are allocated to partcipants at a
single clearing price, i.e., the number of SNS tokens for sale divided
by the number of ICP tokens entered into the auction. In this state,
participants can withdraw their tokens to form a neuron in the
governance canister of the SNS.

Step 3b. (State 'aborted'). If the minimum number of base tokens have
not been reached before the due date/time, the sale is aborted. .

The 'sale' canister can be deleted when all tokens registered with the
'sale' canister have been disbursed to their rightful owners.
*/
impl Sale {
    /// Create state from an `Init` object. If `init` is valid, the
    /// sale is created in the 'pending' lifecycle state; otherwise,
    /// it is created in the 'aborted' lifecycle state.
    pub fn new(init: Init) -> Self {
        let lifecycle = if init.is_valid() {
            Lifecycle::Pending
        } else {
            Lifecycle::Aborted
        } as i32;
        Self {
            init: Some(init),
            state: Some(State {
                sns_token_e8s: 0,
                buyers: Default::default(),
                lifecycle,
            }),
        }
    }

    pub fn init(&self) -> &Init {
        (&self.init).as_ref().unwrap()
    }

    pub fn state(&self) -> &State {
        (&self.state).as_ref().unwrap()
    }

    pub fn state_mut(&mut self) -> &mut State {
        (&mut self.state).as_mut().unwrap()
    }

    //
    // --- state transition functions ------------------------------------------
    //

    /// If the sale is 'open', try to commit or abort the
    /// sale. Returns true if a transition was made and false
    /// otherwise.
    pub fn try_commit_or_abort(&mut self, now_seconds: u64) -> bool {
        if self.can_commit(now_seconds) {
            self.commit(now_seconds);
            return true;
        }
        let lifecycle = self.state().lifecycle();
        if (lifecycle == Lifecycle::Open || lifecycle == Lifecycle::Pending)
            && self.sale_due(now_seconds)
            && !self.sufficient_participation()
        {
            self.abort(now_seconds);
            return true;
        }
        false
    }

    /// Precondition: lifecycle == Pending && sns_amount_available
    ///
    /// Postcondition (on Ok): lifecycle == Open
    pub fn open(&mut self) -> Result<(), String> {
        if self.state().lifecycle() != Lifecycle::Pending {
            return Err(
                "Invalid lifecycle state to 'open' the sale; must be 'pending'".to_string(),
            );
        }
        if !self.sns_amount_available() {
            return Err("Cannot 'open' the tokens for sale have not yet been received".to_string());
        }
        self.state_mut().set_lifecycle(Lifecycle::Open);
        Ok(())
    }

    /// Precondition: lifecycle == Open && sufficient_participation && (sale_due || icp_target_reached)
    ///
    /// Postcondition: lifecycle == Committed
    fn commit(&mut self, now_seconds: u64) {
        assert!(self.state().lifecycle() == Lifecycle::Open);
        assert!(self.sufficient_participation());
        assert!(self.sale_due(now_seconds) || self.icp_target_reached());
        // We are selling SNS tokens for the base token (ICP), or, in
        // general, whatever token the ledger referred to as the ICP
        // ledger holds.
        let sns_for_sale_e8s = self.state().sns_token_e8s as u128;
        // This must hold as the sale cannot transition to state
        // 'Open' without tokens for sale.
        assert!(sns_for_sale_e8s > 0);
        // Note that this value has to be > 0 as we have > 0
        // participants each with > 0 ICP contributed.
        let total_buyer_icp_e8s = self.state().buyer_total_icp_e8s() as u128;
        assert!(total_buyer_icp_e8s > 0);
        let state_mut = self.state_mut();
        // Keep track of SNS tokens sold just to check that the amount
        // is correct at the end.
        let mut total_sns_tokens_sold: u64 = 0;
        // =====================================================================
        // ===            This is where the actual swap happens              ===
        // =====================================================================
        for (_, state) in state_mut.buyers.iter_mut() {
            // If we divide SNS (sns_for_sale_e8s) with ICP
            // (total_buyer_icp_e8s), we get the price of SNS tokens in
            // ICP tokens for the sale, i.e., the fractional number of
            // SNS token the buyer get for one ICP token.
            //
            // The amount of token received by a buyer is the amount
            // of ICP entered times SNS/ICP.
            //
            // But instead of representing this as the amount of ICP
            // entered times the price SNS/ICP, we first multiply and
            // then divide, to avoid loss of precision. Also, we
            // perform the operation in u128 to prevent loss of precision.
            let amount_sns_e8s_u128 = sns_for_sale_e8s
                .saturating_mul(state.amount_icp_e8s as u128)
                .saturating_div(total_buyer_icp_e8s as u128);
            // Note that state.amount_icp_e8s <= total_buyer_icp_e8s,
            // whence amount_sns_e8s <= sns_for_sale_e8s <=
            // u64::MAX.
            assert!(amount_sns_e8s_u128 <= u64::MAX as u128);
            let x = amount_sns_e8s_u128 as u64;
            state.amount_sns_e8s = x;
            total_sns_tokens_sold = total_sns_tokens_sold.saturating_add(x);
        }
        assert!(total_sns_tokens_sold <= sns_for_sale_e8s as u64);
        println!("{}INFO: token sale committed; {} participants receive a total of {} out of {} (change {});",
		 LOG_PREFIX,
		 state_mut.buyers.len(),
		 total_sns_tokens_sold,
		 state_mut.sns_token_e8s,
		 state_mut.sns_token_e8s - total_sns_tokens_sold);
        // Note: we set 'sns_token_e8s' to zero when the sale is
        // concluded even if there is some change to spare due to
        // accumulated rounding errors.
        state_mut.sns_token_e8s = 0;
        state_mut.set_lifecycle(Lifecycle::Committed);
    }

    /// Precondition: lifecycle IN {Open, Pending} && sale_due && not sufficient_participation
    ///
    /// Postcondition: lifecycle == Aborted
    fn abort(&mut self, now_seconds: u64) {
        assert!(
            self.state().lifecycle() == Lifecycle::Open
                || self.state().lifecycle() == Lifecycle::Pending
        );
        assert!(self.sale_due(now_seconds));
        assert!(!self.sufficient_participation());
        self.state_mut().sns_token_e8s = 0;
        self.state_mut().set_lifecycle(Lifecycle::Aborted);
    }

    //
    // --- state modifying methods ---------------------------------------------
    //

    /*

    Transfers IN - these transfers happen on ledger canisters (ICP or
    SNS tokens) and cannot be restricted based on the state of the
    sale canister. Thus, the sale cansiter can only be notified about
    transfers happening on these canisters.

     */

    /// In state Pending, this method can be called to refresh the
    /// amount "for sale" from the relevant ledger canister.
    ///
    /// It is assumed that prior to calling this method, tokens have
    /// been transfer to the sale canister (this cansiter) on the
    /// ledger of `init.sns_ledger_canister_id`. This transfer is
    /// performed by the Governance cansiter of the SNS or
    /// pre-decentralization token holders.
    pub async fn refresh_sns_token_e8s(
        &mut self,
        this_canister: CanisterId,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> Result<(), String> {
        if self.state().lifecycle() != Lifecycle::Pending {
            return Err(
                "The token amount 'for sale' can only be refreshed in the 'pending' state"
                    .to_string(),
            );
        }
        // Look for the token balanace of 'this' canister.
        let account = AccountIdentifier::new(this_canister.get(), None);
        // Look on the 'for sale' ledger.
        let e8s = ledger_stub(self.init().sns_ledger())
            .account_balance(account)
            .await
            .map_err(|x| x.to_string())
            .map(|x| x.get_e8s())?;
        // Recheck lifecycle state after await.
        if self.state().lifecycle() != Lifecycle::Pending {
            return Err(
                "The token amount 'for sale' can only be refreshed in the 'pending' state"
                    .to_string(),
            );
        }
        let old_sns_tokens_e8s = self.state().sns_token_e8s;
        println!(
            "{}INFO: refresh_sns_token old e8s: {}; new e8s: {}",
            LOG_PREFIX, old_sns_tokens_e8s, e8s
        );
        // Note that we allow any number of outstanding
        // requests, and responses may arrive in any
        // order. To be safe, we take the max of the old
        // and the new value.
        self.state_mut().sns_token_e8s = std::cmp::max(old_sns_tokens_e8s, e8s);
        Ok(())
    }

    /// In state Open, this method can be called to refresh the amount
    /// of ICP a buyer has contributed from the ICP ledger canister.
    ///
    /// It is assumed that prior to calling this method, tokens have
    /// been transfer by the buyer to a subaccount of the sale
    /// canister (this cansiter) on the ICP ledger.
    pub async fn refresh_buyer_token_e8s(
        &mut self,
        buyer: PrincipalId,
        this_canister: CanisterId,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> Result<(), String> {
        if self.state().lifecycle() != Lifecycle::Open {
            return Err(
                "The token amount can only be refreshed when the canister is in the 'open' state"
                    .to_string(),
            );
        }
        if self.icp_target_reached() {
            return Err("The ICP target for this token sale has already been reached.".to_string());
        }
        // Look for the token balanace of the specified principal's subaccount on 'this' canister.
        let account = AccountIdentifier::new(this_canister.get(), Some(Subaccount::from(&buyer)));
        let e8s = ledger_stub(self.init().icp_ledger())
            .account_balance(account)
            .await
            .map_err(|x| x.to_string())
            .map(|x| x.get_e8s())?;

        // Recheck lifecycle state after async call.
        if self.state().lifecycle() != Lifecycle::Open {
            return Err(
                "The token amount can only be refreshed when the canister is in the 'open' state"
                    .to_string(),
            );
        }

        // Recheck total amount of ICP bought after async call.
        let buyer_total_icp_e8s = self.state().buyer_total_icp_e8s();
        let max_icp_e8s = self.init().max_icp_e8s;
        if buyer_total_icp_e8s >= max_icp_e8s {
            if buyer_total_icp_e8s > max_icp_e8s {
                println!(
                    "{}WARNING: total amount of ICP bought {} already exceeds the target {}!",
                    LOG_PREFIX, buyer_total_icp_e8s, max_icp_e8s
                );
            }
            // Nothing we can do for this buyer.
            return Ok(());
        }
        // Subtraction safe because of the preceding if-statement.
        let max_increment_e8s = max_icp_e8s - buyer_total_icp_e8s;

        // Check that the minimum amount has been transferred before
        // actually creating an entry for the buyer.
        if e8s < self.init().min_participant_icp_e8s {
            return Err(format!(
                "Amount transferred: {}; minimum required to participate: {}",
                e8s,
                self.init().min_participant_icp_e8s
            ));
        }
        // Extract init parameter before mutable borrow of state.
        let max_participant_icp_e8s = self.init().max_participant_icp_e8s;
        let buyer_state = self
            .state_mut()
            .buyers
            .entry(buyer.to_string())
            .or_insert_with(|| BuyerState {
                amount_icp_e8s: 0,
                amount_sns_e8s: 0,
                icp_disbursing: false,
                sns_disbursing: false,
            });
        let old_amount_icp_e8s = buyer_state.amount_icp_e8s;
        if old_amount_icp_e8s >= e8s {
            // Already up-to-date. Strict inequality can happen if messages are re-ordered.
            return Ok(());
        }
        // Subtraction safe because of the preceding if-statement.
        let requested_increment_e8s = e8s - old_amount_icp_e8s;
        let actual_increment_e8s = std::cmp::min(max_increment_e8s, requested_increment_e8s);
        let new_balance_e8s = buyer_state
            .amount_icp_e8s
            .saturating_add(actual_increment_e8s);
        buyer_state.amount_icp_e8s = std::cmp::min(new_balance_e8s, max_participant_icp_e8s);
        println!(
            "{}INFO: refresh_buyer_tokens for buyer {}; old e8s {}; new e8s {}",
            LOG_PREFIX, buyer, old_amount_icp_e8s, buyer_state.amount_icp_e8s
        );
        if requested_increment_e8s >= max_increment_e8s {
            println!(
                "{}LOG: sale has reached ICP target of {}",
                LOG_PREFIX, max_icp_e8s
            );
        }
        if new_balance_e8s > max_participant_icp_e8s {
            println!(
                "{}INFO: participant {} contributed {} e8s - the limit per participant is {}",
                LOG_PREFIX, buyer, new_balance_e8s, max_participant_icp_e8s
            );
        }
        // TODO: Consider returning information about the amount accepted.
        Ok(())
    }

    /*

    Transfers OUT.

     */

    /// In state 'committed'. Transfer tokens from this canister to
    /// the neuron staking subaccount of the SNS governance canister.
    pub async fn claim_tokens(
        &mut self,
        principal: PrincipalId,
        fee: Tokens,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> TransferResult {
        if self.state().lifecycle() != Lifecycle::Committed {
            return TransferResult::Failure(
                "Tokens can only be claimed when the sale is 'committed'".to_string(),
            );
        }
        // TODO: get rid of logically unneccessary clone
        let init = self.init().clone();
        if let Some(buyer_state) = self.state_mut().buyers.get_mut(&principal.to_string()) {
            // Observe: memo == 0. Could be specified as an argument instead.
            let dst_subaccount = ledger::compute_neuron_staking_subaccount(principal, 0);
            let dst = AccountIdentifier::new(init.sns_governance().get(), Some(dst_subaccount));
            let result = buyer_state
                .sns_transfer_helper(&init, fee, dst, &ledger_stub)
                .await;
            result
        } else {
            TransferResult::Failure(format!("Principal {} not found", principal))
        }
    }

    /// In state 'aborted'. Refund tokens on the ICP ledger from
    /// buyer's subaccount of this canister to the buyer's own
    /// account.
    pub async fn refund_tokens(
        &mut self,
        principal: PrincipalId,
        fee: Tokens,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> TransferResult {
        if self.state().lifecycle() != Lifecycle::Aborted {
            return TransferResult::Failure(
                "Tokens can only be refunded when the sale is 'aborted'".to_string(),
            );
        }
        // TODO: get rid of logically unneccessary clone
        let init = self.init().clone();
        if let Some(buyer_state) = self.state_mut().buyers.get_mut(&principal.to_string()) {
            let subaccount = Subaccount::from(&principal);
            let dst = AccountIdentifier::new(principal, None);
            buyer_state
                .icp_transfer_helper(&init, fee, subaccount, dst, &ledger_stub)
                .await
        } else {
            TransferResult::Failure(format!("Principal {} not found", principal))
        }
    }

    /// Distributes funds, and if the sale was successful, creates neurons. Returns
    /// a summary of (sub)actions that were performed.
    ///
    /// If the sale is not over yet, panics.
    ///
    /// If sale was successful (i.e. it is in the Lifecycle::Committed phase), then
    /// ICP is sent to the SNS governance canister, and SNS tokens are sent to SNS
    /// neuron ledger accounts (i.e. subaccounts of SNS governance for the principal
    /// that funded the neuron).
    ///
    /// If the sale ended unsuccessfully (i.e. it is in the Lifecycle::Aborted
    /// phase), then ICP is send back to the buyers.
    pub async fn finalize(
        &mut self,
        sns_governance_client: &mut impl SnsGovernanceClient,
        ledger_factory: impl Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> FinalizeSaleResponse {
        let lifecycle = self.state().lifecycle();
        assert!(
            lifecycle == Lifecycle::Committed || lifecycle == Lifecycle::Aborted,
            "Sale can only be finalized in the committed or aborted states - was {:?}",
            lifecycle
        );

        let sweep_icp = self.sweep_icp(DEFAULT_TRANSFER_FEE, &ledger_factory).await;
        if lifecycle != Lifecycle::Committed {
            return FinalizeSaleResponse {
                sweep_icp: Some(sweep_icp),
                sweep_sns: None,
                create_neuron: None,
                sns_governance_normal_mode_enabled: None,
            };
        }

        let sweep_sns = self.sweep_sns(DEFAULT_TRANSFER_FEE, &ledger_factory).await;

        let create_neuron = self.claim_neurons(sns_governance_client).await;

        let sns_governance_normal_mode_enabled =
            Self::set_sns_governance_to_normal_mode_if_all_neurons_claimed(
                sns_governance_client,
                &create_neuron,
            )
            .await;

        FinalizeSaleResponse {
            sweep_icp: Some(sweep_icp),
            sweep_sns: Some(sweep_sns),
            create_neuron: Some(create_neuron),
            sns_governance_normal_mode_enabled,
        }
    }

    async fn claim_neurons(
        &self,
        sns_governance_client: &mut impl SnsGovernanceClient,
    ) -> SweepResult {
        let (skipped, princpal_ids) = self.principals_for_create_neuron();
        let mut result = SweepResult {
            success: 0,
            failure: 0,
            skipped,
        };

        for p in princpal_ids {
            // Claim SNS neuron that we just funded (or at least tried to).
            let request = ManageNeuron {
                subaccount: vec![],
                command: Some(manage_neuron::Command::ClaimOrRefresh(
                    manage_neuron::ClaimOrRefresh {
                        by: Some(manage_neuron::claim_or_refresh::By::MemoAndController(
                            manage_neuron::claim_or_refresh::MemoAndController {
                                controller: Some(p),
                                memo: 0,
                            },
                        )),
                    },
                )),
            };
            match sns_governance_client.manage_neuron(request).await {
                Ok(_response) => result.success += 1,
                Err(_err) => result.failure += 1,
            }
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

    /// Requests a refund of ICP tokens transferred to the Sale
    /// cansiter in error. This method only works if this
    /// canister is in the 'committed' or 'aborted' state.
    ///
    /// The request is to refund `amount` tokens for `principal`
    /// (using `fee` as fee) on the ICP ledger. The specified amount
    /// of tokens is transferred from `subaccount(sale_canister, P)`
    /// to `P`, where `P` is the specified principal.
    ///
    /// Note that this function cannot mutate `self` - it only
    /// initiates a ledger transfer, which may fail. It is up to the
    /// caller to ensure the correctness of the parameters.
    ///
    /// This method is secure because it only transfers tokens from a
    /// principal's subaccount (of the Sale canister) to the
    /// principal's own account, i.e., the tokens were held in escrow
    /// for the principal (buyer) before the call and are returned to
    /// the same principal. Moreover, this method can only be called
    /// by the principal; this serves two purposes: first, that third
    /// parties cannot make many small transfers to drain the
    /// principal's tokens by multiple fees, and, second, so a third
    /// party cannot return the buyer's token that they intended to
    /// use to join the sale.
    pub async fn error_refund_icp(
        &self,
        principal: PrincipalId,
        amount: Tokens,
        fee: Tokens,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> TransferResult {
        if !(self.state().lifecycle() == Lifecycle::Aborted
            || self.state().lifecycle() == Lifecycle::Committed)
        {
            return TransferResult::Failure(
                "Error refunds can only be performed when the sale is 'aborted' or 'committed'"
                    .to_string(),
            );
        }
        if let Some(buyer_state) = self.state().buyers.get(&principal.to_string()) {
            // This buyer has participated in the sale, but all ICP
            // has already been disbursed, either back to the buyer
            // (aborted) or to the SNS Governance canister
            // (committed). Any ICP in this buyer's subaccount must
            // belong to the buyer.
            if buyer_state.amount_icp_e8s != 0 || buyer_state.icp_disbursing {
                return TransferResult::Failure(format!(
                    "ICP cannot be refunded as principal {} has {} ICP (e8s) in escrow",
                    principal, buyer_state.amount_icp_e8s
                ));
            }
        }
        let subaccount = Subaccount::from(&principal);
        let dst = AccountIdentifier::new(principal, None);
        let result = ledger_stub(self.init().icp_ledger())
            .transfer_funds(
                amount.get_e8s().saturating_sub(fee.get_e8s()),
                fee.get_e8s(),
                Some(subaccount),
                dst,
                0,
            )
            .await;
        match result {
            Ok(h) => {
                println!(
                    "{}INFO: error refund - transferred {} ICP from subaccount {} to {} at height {}",
                    LOG_PREFIX, amount, subaccount, dst, h
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                println!(
                    "{}ERROR: error refund - failed to transfer {} from subaccount {}: {}",
                    LOG_PREFIX, amount, subaccount, e
                );
                TransferResult::Failure(e.to_string())
            }
        }
    }

    /// In state 'committed' or 'aborted'. Transfer ICP tokens from
    /// buyer's subaccounts to the SNS governance canister if
    /// 'committed' or back to the buyer if 'aborted'.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    pub async fn sweep_icp(
        &mut self,
        fee: Tokens,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> SweepResult {
        let lifecycle = self.state().lifecycle();
        assert!(lifecycle == Lifecycle::Committed || lifecycle == Lifecycle::Aborted);
        // TODO: get rid of logically unneccessary clone
        let init = self.init().clone();
        let sns_governance = init.sns_governance();
        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;
        for (principal_str, buyer_state) in self.state_mut().buyers.iter_mut() {
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
            let subaccount = Subaccount::from(&principal);
            let dst = if lifecycle == Lifecycle::Committed {
                AccountIdentifier::new(sns_governance.get(), None)
            } else {
                AccountIdentifier::new(principal, None)
            };
            let result = buyer_state
                .icp_transfer_helper(&init, fee, subaccount, dst, &ledger_stub)
                .await;
            match result {
                TransferResult::AmountTooSmall | TransferResult::AlreadyInProgress => {
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

    /// In state 'committed'. Transfer SNS tokens from the sale
    /// canister to each buyer.
    ///
    /// Returns the following values:
    /// - the number of skipped buyers due balance less than fee or operation already in progress
    /// - the number of successful transfers
    /// - the number of errors
    pub async fn sweep_sns(
        &mut self,
        fee: Tokens,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> SweepResult {
        assert!(self.state().lifecycle() == Lifecycle::Committed);
        // TODO: get rid of logically unneccessary clone
        let init = self.init().clone();
        let sns_governance = init.sns_governance();
        let mut skipped: u32 = 0;
        let mut success: u32 = 0;
        let mut failure: u32 = 0;
        for (principal_str, buyer_state) in self.state_mut().buyers.iter_mut() {
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
            // Observe: memo == 0. Could be specified as an argument instead.
            let dst_subaccount = ledger::compute_neuron_staking_subaccount(principal, 0);
            let dst = AccountIdentifier::new(sns_governance.get(), Some(dst_subaccount));
            let result = buyer_state
                .sns_transfer_helper(&init, fee, dst, &ledger_stub)
                .await;
            match result {
                TransferResult::AmountTooSmall | TransferResult::AlreadyInProgress => {
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

    /// Returns the set of principals for which a neuron may need to be
    /// created together with the number of principals skipped.
    ///
    /// If the sale is not committed, this results in an empty vector,
    /// i.e., all principals are skipped. If the sale is committed, it
    /// returns all principals for which the SNS tokens have been
    /// disbursed.
    ///
    /// The sale does not keep track of which neurons that actually
    /// have been created; instead it relies on neuron creation being
    /// idempotent.
    pub fn principals_for_create_neuron(&self) -> (u32, Vec<PrincipalId>) {
        if self.state().lifecycle() != Lifecycle::Committed {
            return (self.state().buyers.len() as u32, vec![]);
        }
        let mut principal_ids = Vec::new();
        let mut skipped = 0;
        for (x, y) in self.state().buyers.iter() {
            if y.amount_sns_e8s == 0 {
                match PrincipalId::from_str(x).ok() {
                    None => {
                        skipped += 1;
                    }
                    Some(xx) => principal_ids.push(xx),
                }
            } else {
                skipped += 1;
            }
        }
        (skipped, principal_ids)
    }

    //
    // --- predicates on the state ---------------------------------------------
    //

    pub fn is_valid(&self) -> bool {
        if let Some(init) = &self.init {
            if let Some(state) = &self.state {
                return init.is_valid() && state.is_valid();
            }
        }
        false
    }

    /// The amount of tokens for sale (`state.sns_token_e8s`) is
    /// greater than zero.
    pub fn sns_amount_available(&self) -> bool {
        if let Some(state) = &self.state {
            return state.sns_token_e8s > 0;
        }
        false
    }

    /// The paramter `now_seconds` is greater than or equal to the
    /// initialization parameter for the token sale timestamp.
    pub fn sale_due(&self, now_seconds: u64) -> bool {
        self.init
            .as_ref()
            .map(|x| x.sale_due(now_seconds))
            .unwrap_or(false)
    }

    /// The minimum number of participants have been achieved, and the
    /// minimal total amount has been reached.
    pub fn sufficient_participation(&self) -> bool {
        if let Some(init) = &self.init {
            if let Some(state) = &self.state {
                return state.buyers.len() >= (init.min_participants as usize)
                    && state.buyer_total_icp_e8s() >= init.min_icp_e8s;
            }
        }
        false
    }

    /// The total number of ICP contributed by all buyers is at least
    /// the target ICP of the sale.
    pub fn icp_target_reached(&self) -> bool {
        if let Some(init) = &self.init {
            if let Some(state) = &self.state {
                return state.buyer_total_icp_e8s() >= init.max_icp_e8s;
            }
        }
        false
    }

    /// Returns true if the sale can be committed at the specified
    /// timestamp, and false otherwise.
    pub fn can_commit(&self, now_seconds: u64) -> bool {
        if self.state().lifecycle() != Lifecycle::Open {
            return false;
        }
        // Possible optimization: both 'sufficient_participation' and
        // 'icp_target_reached' compute 'buyer_total_icp_e8s', and
        // this computation could be shared (or cached).
        if !self.sufficient_participation() {
            return false;
        }
        if !(self.sale_due(now_seconds) || self.icp_target_reached()) {
            return false;
        }
        true
    }

    //
    // --- query methods on the state  -----------------------------------------
    //

    pub fn derived_state(&self) -> DerivedState {
        let buyer_total_icp_e8s = self.state().buyer_total_icp_e8s();
        DerivedState {
            buyer_total_icp_e8s,
            sns_tokens_per_icp: ((self.state().sns_token_e8s as f64) / (buyer_total_icp_e8s as f64))
                as f32,
        }
    }
}

impl Init {
    // TODO: validate these 'principals'.
    pub fn nns_governance(&self) -> CanisterId {
        CanisterId::new(PrincipalId::from_str(&self.nns_governance_canister_id).unwrap()).unwrap()
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

    pub fn sale_due(&self, now_seconds: u64) -> bool {
        now_seconds >= self.token_sale_timestamp_seconds
    }

    pub fn is_valid(&self) -> bool {
        // Sale date in the future, or at least past
        // '2022-01-01T00:00:00 GMT+0000' to prevent initialisation
        // errors.
        self.token_sale_timestamp_seconds >= 1640995200
        // TODO: check that the canister IDs are valid.
        //
            && !self.nns_governance_canister_id.is_empty()
            && !self.sns_governance_canister_id.is_empty()
            && !self.sns_ledger_canister_id.is_empty()
            && !self.icp_ledger_canister_id.is_empty()
            && self.min_participants > 0
            && self.min_participant_icp_e8s > 0
            && self.max_participant_icp_e8s >= self.min_participant_icp_e8s
            && self.max_participant_icp_e8s <= self.max_icp_e8s
	    // Check that the numbers make sense, i.e., don't overflow
	    && (self.min_participants as u64).checked_mul(self.max_participant_icp_e8s).is_some()
            && self.max_icp_e8s >= (self.min_participants as u64).saturating_mul(self.min_participant_icp_e8s)
	    && self.min_icp_e8s <= self.max_icp_e8s
    }
}

impl State {
    pub fn buyer_total_icp_e8s(&self) -> u64 {
        self.buyers.values().map(|x| x.amount_icp_e8s).sum()
    }
    pub fn all_zeroed(&self) -> bool {
        self.buyers.values().all(|x| x.zeroed())
    }
    pub fn is_valid(&self) -> bool {
        true
    }
}

impl BuyerState {
    pub fn zeroed(&self) -> bool {
        self.amount_icp_e8s == 0
            && self.amount_sns_e8s == 0
            && !self.icp_disbursing
            && !self.sns_disbursing
    }

    async fn icp_transfer_helper(
        &mut self,
        init: &Init,
        fee: Tokens,
        subaccount: Subaccount,
        dst: AccountIdentifier,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> TransferResult {
        let amount = Tokens::from_e8s(self.amount_icp_e8s);
        if amount <= fee {
            // Skip: amount too small...
            return TransferResult::AmountTooSmall;
        }
        if self.icp_disbursing {
            // Operation in progress...
            return TransferResult::AlreadyInProgress;
        }
        self.icp_disbursing = true;
        let result = ledger_stub(init.icp_ledger())
            .transfer_funds(
                amount.get_e8s().saturating_sub(fee.get_e8s()),
                fee.get_e8s(),
                Some(subaccount),
                dst,
                0,
            )
            .await;
        if !self.icp_disbursing {
            println!("{}ERROR: ICP disburse logic error", LOG_PREFIX);
        }
        self.icp_disbursing = false;
        match result {
            Ok(h) => {
                self.amount_icp_e8s = 0;
                println!(
                    "{}INFO: transferred {} ICP from subaccount {} to {} at height {}",
                    LOG_PREFIX, amount, subaccount, dst, h
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                println!(
                    "{}ERROR: failed to transfer {} from subaccount {}: {}",
                    LOG_PREFIX, amount, subaccount, e
                );
                TransferResult::Failure(e.to_string())
            }
        }
    }

    async fn sns_transfer_helper(
        &mut self,
        init: &Init,
        fee: Tokens,
        dst: AccountIdentifier,
        ledger_stub: &'_ dyn Fn(CanisterId) -> Box<dyn Ledger>,
    ) -> TransferResult {
        let sns_ledger = init.sns_ledger();
        let amount = Tokens::from_e8s(self.amount_sns_e8s);
        if amount <= fee {
            // Skip: amount too small...
            return TransferResult::AmountTooSmall;
        }
        if self.sns_disbursing {
            // Operation in progress...
            return TransferResult::AlreadyInProgress;
        }
        self.sns_disbursing = true;
        let result = ledger_stub(sns_ledger)
            .transfer_funds(
                amount.get_e8s().saturating_sub(fee.get_e8s()),
                fee.get_e8s(),
                None,
                dst,
                0,
            )
            .await;
        if !self.sns_disbursing {
            println!("{}ERROR: SNS disburse logic error", LOG_PREFIX);
        }
        self.sns_disbursing = false;
        match result {
            Ok(h) => {
                self.amount_sns_e8s = 0;
                println!(
                    "{}INFO: transferred {} SNS tokens to {} at height {}",
                    LOG_PREFIX, amount, dst, h
                );
                TransferResult::Success(h)
            }
            Err(e) => {
                println!("{}ERROR: failed to transfer {}: {}", LOG_PREFIX, amount, e);
                TransferResult::Failure(e.to_string())
            }
        }
    }
}

// Tools needed (Pete):
//
// - Compute subaccount(S, P) for a given buyer P once the canister S is installed.
//
// - P = dfx get-principal
