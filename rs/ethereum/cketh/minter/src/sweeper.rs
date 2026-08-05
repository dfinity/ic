//! Keeping the dedicated sweeper address funded with gas, per
//! `rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing". ckETH is burned from the minter's fee subaccount *before* the ETH moves, which is
//! what makes "cumulative burned >= cumulative spent" hold at every instant and not just once things
//! settle.

#[cfg(test)]
mod tests;

use crate::guard::TimerGuard;
use crate::ledger_client::LedgerClient;
use crate::logs::{DEBUG, INFO};
use crate::memo::BurnMemo;
use crate::numeric::Wei;
use crate::state::audit::{EventType, process_event};
use crate::state::sweeper_funding::{InFlightFunding, SweeperFundingAccounting};
use crate::state::transactions::SweeperFundingRequest;
use crate::state::{State, TaskType, mutate_state, read_state};
use crate::{CKETH_FEE_SUBACCOUNT, deposit_address::sweeper_address};
use ic_canister_log::log;
use ic_ethereum_types::Address;

/// Tops the sweeper address up when its balance has fallen below the configured low-water mark.
pub async fn fund_sweeper_address() {
    let _guard = match TimerGuard::new(TaskType::SweeperFunding) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let Some(sweeper) = read_state(sweeper_address_from_state) else {
        log!(
            DEBUG,
            "[fund_sweeper]: SKIPPING: the ECDSA public key is not available yet"
        );
        return;
    };

    let block_height = read_state(|s| s.ethereum_block_height.clone()).into();
    let sweeper_balance =
        match crate::eth_rpc_client::get_balance::eth_get_balance(&sweeper, block_height).await {
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

    let plan = match read_state(|s| plan_funding(s, sweeper_balance)) {
        FundingDecision::Fund(plan) => plan,
        FundingDecision::NotDue => {
            log!(
                DEBUG,
                "[fund_sweeper]: SKIPPING: {sweeper} holds {sweeper_balance}, at or above the low-water mark"
            );
            return;
        }
        FundingDecision::AlreadyInFlight(in_flight) => {
            log!(
                INFO,
                "[fund_sweeper]: SKIPPING: funding {} of {} is still in flight; \
                 starting another would spend more than has been burned",
                in_flight.ledger_burn_index,
                in_flight.amount,
            );
            return;
        }
    };

    log!(
        INFO,
        "[fund_sweeper]: {sweeper} holds {sweeper_balance}; funding it with {} \
         (burning {} ckETH, {} covered by earlier unspent burns)",
        plan.amount,
        plan.burn,
        plan.amount.checked_sub(plan.burn).unwrap_or(Wei::ZERO),
    );

    let client = read_state(LedgerClient::cketh_ledger_from_state);
    let ledger_burn_index = match client
        .burn_from_own_subaccount(
            CKETH_FEE_SUBACCOUNT,
            plan.burn,
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
                "[fund_sweeper]: SKIPPING: failed to burn {} ckETH from the fee account: {e:?}",
                plan.burn
            );
            return;
        }
    };

    let request = SweeperFundingRequest {
        withdrawal_amount: plan.amount,
        destination: sweeper,
        ledger_burn_index,
        from: ic_cdk::api::canister_self(),
        from_subaccount: crate::eth_logs::LedgerSubaccount::from_bytes(CKETH_FEE_SUBACCOUNT),
        created_at: ic_cdk::api::time(),
        cketh_burned: plan.burn,
    };
    mutate_state(|s| {
        process_event(s, EventType::AcceptedSweeperFundingRequest(request));
    });
}

/// The minter's dedicated sweeper address, or `None` while the master public key is still unknown.
///
/// Reads the cached key rather than fetching it: a second concurrent `ecdsa_public_key` call traps
/// the canister, so the first run is delayed until the install-time fetch has cached it.
pub fn sweeper_address_from_state(state: &State) -> Option<Address> {
    let (master_public_key, chain_code) = state.public_key_and_chain_code()?;
    Some(sweeper_address(&master_public_key, &chain_code))
}

/// How much ETH to move, and how much ckETH that costs. `burn` is at most `amount`, the remainder
/// being covered by earlier burns that were never spent.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct FundingPlan {
    pub amount: Wei,
    pub burn: Wei,
}

/// Why a funding is or is not due at `sweeper_balance`.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum FundingDecision {
    Fund(FundingPlan),
    /// A previous funding is still between its burn and its finalized transfer.
    AlreadyInFlight(InFlightFunding),
    NotDue,
}

/// Decides whether a funding is due at `sweeper_balance`, and what it costs.
///
/// The in-flight refusal is load-bearing: an earmarked burn is indistinguishable from spare credit,
/// so a second funding would offset against the first one's burn and the two transfers together
/// would outspend it. A stuck funding therefore blocks later ones, which is the safe direction but
/// needs its own metric to be visible.
pub fn plan_funding(state: &State, sweeper_balance: Wei) -> FundingDecision {
    if let Some(in_flight) = state.sweeper_funding.in_flight_funding() {
        return FundingDecision::AlreadyInFlight(in_flight);
    }
    match state.sweeper_funding_config.amount_due(sweeper_balance) {
        None => FundingDecision::NotDue,
        Some(amount) => FundingDecision::Fund(FundingPlan {
            amount,
            burn: burn_for(&state.sweeper_funding, amount, minimum_burn(state)),
        }),
    }
}

/// The burn a funding of `amount` costs, given the credit from earlier burns that were never spent.
///
/// Floored at `minimum_burn`: every funding needs a real burn, since its ledger index keys the
/// withdrawal pipeline, and the floor also draws the credit down rather than stranding funding when
/// the credit exceeds the amount due.
fn burn_for(accounting: &SweeperFundingAccounting, amount: Wei, minimum_burn: Wei) -> Wei {
    std::cmp::max(accounting.burn_required_for(amount), minimum_burn)
}

/// The smallest burn a funding will make: the minter's minimum withdrawal amount, reused rather
/// than adding a second knob, since `validate_config` already guarantees it covers the ledger fee.
fn minimum_burn(state: &State) -> Wei {
    state.cketh_minimum_withdrawal_amount
}
