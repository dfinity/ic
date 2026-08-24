//! Keeping the dedicated sweeper address funded with gas, per
//! `rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing". ckETH is burned from the minter's fee subaccount *before* the ETH moves, which is
//! what makes "cumulative burned >= cumulative spent" hold at every instant and not just once things
//! settle.

#[cfg(test)]
mod tests;

use crate::CKETH_FEE_SUBACCOUNT;
use crate::eth_rpc_client::{NoReduction, ToReducedWithStrategy};
use crate::guard::TimerGuard;
use crate::ledger_client::LedgerClient;
use crate::logs::{DEBUG, INFO};
use crate::memo::BurnMemo;
use crate::numeric::{LedgerBurnIndex, Wei};
use crate::state::audit::{EventType, process_event};
use crate::state::transactions::EthWithdrawalRequest;
use crate::state::{State, TaskType, mutate_state, read_state};
use ic_canister_log::log;

/// Tops the sweeper address up when its balance has fallen below the configured low-water mark.
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

    let block_height = read_state(|s| s.ethereum_block_height.clone()).into();
    let sweeper_balance =
        match crate::eth_rpc_client::get_balance::eth_get_balance(&sweeper, block_height)
            .await
            // No client-side reduction: the balance is whatever the EVM RPC canister's own
            // consensus agreed on — a threshold of the providers — and a result it reports as
            // inconsistent stays an error. Settling for fewer providers than the threshold demands
            // is not a trade worth making on the number that decides whether ckETH gets burned.
            .reduce_with_strategy(NoReduction)
        {
            Ok(balance) => balance,
            Err(e) => {
                // Not treated as a zero balance: that would burn ckETH for gas already in place.
                log!(
                    INFO,
                    "[fund_sweeper]: SKIPPING: failed to read the balance of {sweeper}: {e:?}"
                );
                return;
            }
        };

    let amount = match read_state(|s| plan_funding(s, sweeper_balance)) {
        FundingDecision::Fund(amount) => amount,
        FundingDecision::NotDue => {
            log!(
                DEBUG,
                "[fund_sweeper]: SKIPPING: {sweeper} holds {sweeper_balance}, at or above the low-water mark"
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
        "[fund_sweeper]: {sweeper} holds {sweeper_balance}; funding it with {amount}, \
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
        from: ic_cdk::api::canister_self(),
        from_subaccount: crate::eth_logs::LedgerSubaccount::from_bytes(CKETH_FEE_SUBACCOUNT),
        created_at: Some(ic_cdk::api::time()),
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

/// Decides whether a funding is due at `sweeper_balance`.
///
/// Refuses while an earlier funding is still somewhere in the withdrawal pipeline, i.e. between its
/// burn and its finalized transfer. That is prudence rather than a correctness requirement: each
/// funding burns for its own transfer, so two in flight are still each covered by their own burn.
/// One at a time keeps a single funding on the withdrawal nonce lane and the accounting easy to
/// follow. A stuck funding therefore blocks later ones, which is the safe direction but needs its
/// own metric to be visible.
pub fn plan_funding(state: &State, sweeper_balance: Wei) -> FundingDecision {
    if let Some(outstanding) = state.withdrawal_transactions.outstanding_sweeper_funding() {
        return FundingDecision::AlreadyInFlight {
            ledger_burn_index: outstanding.ledger_burn_index,
            amount: outstanding.withdrawal_amount,
        };
    }
    match state.sweeper_funding_config().amount_due(sweeper_balance) {
        None => FundingDecision::NotDue,
        Some(amount) => {
            // Funding debits `eth_balance`, which counts only ETH received through deposits, so
            // moving more than that would spend ETH the accounting knows nothing about — and the
            // debit at finalization would underflow and trap the withdrawal timer, head-of-line
            // blocking every user withdrawal behind it. Waiting is the safe direction.
            let available = state.eth_balance().eth_balance();
            if available < amount {
                return FundingDecision::InsufficientBalance {
                    available,
                    required: amount,
                };
            }
            // The burn is the amount: a funding carves its fee out of what it burns, exactly
            // like a user withdrawal. It always clears the ledger's minimum, since `amount_due` is
            // at least the configured headroom and `validate` keeps that at or above the minimum
            // withdrawal amount — and a real burn is what gives a funding the ledger index its
            // withdrawal pipeline is keyed by.
            FundingDecision::Fund(amount)
        }
    }
}
