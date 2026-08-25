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
use ic_canister_log::log;
use ic_cdk::api::{canister_self, time};

/// Tops the sweeper address up when the balance the minter can vouch for has fallen below the
/// configured low-water mark. Reads state, decides, burns, records — no chain read, because the
/// minter already knows a lower bound on that balance from its own events.
pub async fn fund_sweeper_address() {
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

    // What the minter's own records say reached the sweeper address, rather than a chain read: the
    // bound errs low, so it can only delay a funding, never authorise one against gas that is not
    // there.
    let sweeper_balance = read_state(|s| s.sweeper_funding.sweeper_balance_lower_bound());

    let amount = match read_state(|s| plan_funding(s, sweeper_balance)) {
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
        created_at: Some(time()),
    };
    mutate_state(|s| {
        process_event(s, EventType::AcceptedSweeperFundingRequest(request));
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

/// Decides whether a funding is due at `sweeper_balance`, which callers supply as a *lower* bound on
/// the sweeper address' real balance. Erring low can only make a funding look due when it is not,
/// which over-provisions gas the minter has burned for; the reverse would spend ETH against gas that
/// is not there.
///
/// Asks whether anything is due before asking what stands in the way, so that the quiet case — the
/// sweeper is topped up and the hourly check has nothing to do — is [`FundingDecision::NotDue`] and
/// not a report about an in-flight funding that happens to also be pending.
///
/// Refuses while an earlier funding is still somewhere in the withdrawal pipeline, i.e. between its
/// burn and its finalized transfer. That is prudence rather than a correctness requirement: each
/// funding burns for its own transfer, so two in flight are still each covered by their own burn.
/// One at a time keeps a single funding on the withdrawal nonce lane and the accounting easy to
/// follow. A stuck funding therefore blocks later ones, which is the safe direction but needs its
/// own metric to be visible.
pub fn plan_funding(state: &State, sweeper_balance: Wei) -> FundingDecision {
    let Some(amount) = state.sweeper_funding_config().amount_due(sweeper_balance) else {
        return FundingDecision::NotDue;
    };
    if let Some(outstanding) = state.withdrawal_transactions.outstanding_sweeper_funding() {
        return FundingDecision::AlreadyInFlight {
            ledger_burn_index: outstanding.ledger_burn_index,
            amount: outstanding.withdrawal_amount,
        };
    }
    // Funding debits `eth_balance`, which counts only ETH received through deposits, so a funding
    // above it would spend ETH the accounting knows nothing about. Solvency does not rest on this
    // check — it rests on every debit being covered by its own burn, which is what keeps the
    // counter from going negative even with user withdrawals in flight against the same balance.
    // What the check does buy is the fresh deployment, where the minter may hold ETH it has not yet
    // seen a deposit for: refusing keeps that ETH out of a funding, and waiting is free.
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
