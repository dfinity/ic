//! Keeping the dedicated sweeper address funded with gas, per
//! `rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing". ckETH is burned from the minter's fee subaccount *before* the ETH moves, which is
//! what makes "cumulative burned >= cumulative spent" hold at every instant and not just once things
//! settle.

#[cfg(test)]
mod tests;

use crate::CKETH_FEE_SUBACCOUNT;
use crate::eth_logs::LedgerSubaccount;
use crate::guard::TimerGuard;
use crate::ledger_client::LedgerClient;
use crate::logs::{DEBUG, INFO};
use crate::memo::BurnMemo;
use crate::numeric::{LedgerBurnIndex, Wei};
use crate::state::audit::{EventType, process_event};
use crate::state::transactions::EthWithdrawalRequest;
use crate::state::{State, TaskType, mutate_state, read_state};
use crate::time::TimeProvider;
use ic_canister_log::log;
use ic_cdk::api::canister_self;

/// Tops the sweeper address up when the balance the minter can vouch for has fallen below the
/// configured low-water mark. Reads state, decides, burns, records — no chain read, because the
/// minter already knows a lower bound on that balance from its own events.
pub async fn fund_sweeper_address<T: TimeProvider>(time_provider: &T) {
    let _guard = match TimerGuard::new(TaskType::SweeperFunding) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let Some(sweeper) = read_state(State::sweeper_address) else {
        log!(
            DEBUG,
            "[fund_sweeper]: SKIPPING: the ECDSA public key is not available yet"
        );
        return;
    };

    // One snapshot for both: the decision reads the balance bound itself, and the log lines below
    // report the same figure it decided on.
    let (decision, sweeper_balance) = read_state(|s| {
        (
            plan_funding(s),
            s.sweeper_funding.sweeper_balance_lower_bound(),
        )
    });

    let amount = match decision {
        FundingDecision::Fund(amount) => amount,
        FundingDecision::NotDue => {
            log!(
                DEBUG,
                "[fund_sweeper]: SKIPPING: {sweeper} holds at least {sweeper_balance}, at or above \
                 the low-water mark"
            );
            return;
        }
        FundingDecision::InsufficientBalance {
            available,
            required,
        } => {
            log!(
                INFO,
                "[fund_sweeper]: SKIPPING: funding {sweeper} needs {required} but only {available} \
                 of the minter's ETH is backed by deposits"
            );
            return;
        }
        FundingDecision::AlreadyInFlight {
            ledger_burn_index,
            amount,
        } => {
            log!(
                INFO,
                "[fund_sweeper]: SKIPPING: funding {ledger_burn_index} of {amount} is still in \
                 flight; one funding at a time"
            );
            return;
        }
    };

    log!(
        INFO,
        "[fund_sweeper]: {sweeper} holds at least {sweeper_balance}; funding it with {amount}, \
         burning as much ckETH"
    );

    let client = read_state(LedgerClient::cketh_ledger_from_state);
    let ledger_burn_index = match client
        .burn_from_own_subaccount(
            CKETH_FEE_SUBACCOUNT,
            amount,
            BurnMemo::Convert {
                to_address: sweeper,
            },
        )
        .await
    {
        Ok(index) => index,
        Err(e) => {
            log!(
                INFO,
                "[fund_sweeper]: SKIPPING: failed to burn {amount} ckETH from the fee \
                 account: {e:?}"
            );
            return;
        }
    };

    let request = EthWithdrawalRequest {
        withdrawal_amount: amount,
        destination: sweeper,
        ledger_burn_index,
        from: canister_self(),
        from_subaccount: LedgerSubaccount::from_bytes(CKETH_FEE_SUBACCOUNT),
        created_at: Some(time_provider.time()),
    };
    mutate_state(|s| {
        process_event(
            s,
            EventType::AcceptedSweeperFundingRequest(request),
            time_provider,
        );
    });
}

/// Why a funding is or is not due at `sweeper_balance`.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum FundingDecision {
    /// Move this much ETH to the sweeper address, burning as much ckETH for it.
    Fund(Wei),
    /// A previous funding is still between its burn and its finalized transfer.
    AlreadyInFlight {
        ledger_burn_index: LedgerBurnIndex,
        amount: Wei,
    },
    /// The minter's deposit-backed ETH does not cover the funding.
    InsufficientBalance {
        available: Wei,
        required: Wei,
    },
    NotDue,
}

/// Decides against the lower bound the minter tracks on the sweeper address' balance, read from the
/// state rather than passed in, so the decision cannot be made against a balance the state
/// contradicts. Erring low can only make a funding look due sooner than it is, never hide one that
/// is due.
///
/// Refuses while an earlier funding is still somewhere in the withdrawal pipeline, i.e. between its
/// burn and its finalized transfer. That is prudence rather than a correctness requirement: each
/// funding burns for its own transfer, so two in flight are still each covered by their own burn.
/// One at a time keeps a single funding on the withdrawal nonce lane and the accounting easy to
/// follow. A stuck funding therefore blocks later ones, which is the safe direction but needs its
/// own metric to be visible.
pub fn plan_funding(state: &State) -> FundingDecision {
    let sweeper_balance = state.sweeper_funding.sweeper_balance_lower_bound();
    let Some(amount) = state.sweeper_funding_config().amount_due(sweeper_balance) else {
        return FundingDecision::NotDue;
    };
    if let Some(outstanding) = state.withdrawal_transactions.outstanding_sweeper_funding() {
        return FundingDecision::AlreadyInFlight {
            ledger_burn_index: outstanding.ledger_burn_index,
            amount: outstanding.withdrawal_amount,
        };
    }
    // A tripwire rather than a live constraint. In any state the accounting can reach, the ETH
    // counter is at least the ckETH supply — every debit is covered by its own burn, and every mint
    // by a deposit that credited the counter — and a funding burns ckETH out of that same supply, so
    // `amount` is covered whenever the burn can succeed. What this catches is ckETH that exists
    // without ETH behind it: the funding would then debit ETH the minter never received, and
    // underflow at finalization inside the withdrawal timer, which head-of-line blocks every user
    // withdrawal behind it. Refusing costs a delay.
    let available = state.eth_balance().eth_balance();
    if available < amount {
        return FundingDecision::InsufficientBalance {
            available,
            required: amount,
        };
    }
    // The burn is the amount: a funding carves its fee out of what it burns, exactly like a user
    // withdrawal. It always clears the ledger's minimum, since `amount_due` is at least the
    // configured headroom and `validate` keeps that at or above the minimum withdrawal amount — and
    // a real burn is what gives a funding the ledger index its withdrawal pipeline is keyed by.
    FundingDecision::Fund(amount)
}
