//! Burn-first accounting for sweeper fee funding, "Fund the transaction fees without touching the
//! ckETH backing": ckETH is burned from the minter's fee subaccount *before* the ETH moves, so that
//! at every instant
//!
//! ```text
//! cumulative ckETH burned for sweeping >= cumulative ETH debited from the main address for sweeping
//! ```
//!
//! The surplus is never re-minted and never discounted from a later burn. It sits at the *main*
//! address, not the sweeper's, so it is tracked here rather than read back on chain.

#[cfg(test)]
mod tests;

use crate::numeric::Wei;
use crate::tx::{Finalized, SweepTransaction};

/// How much ckETH has been burned for sweeping and how much of it has actually been spent — the two
/// sides of the invariant above — along with the sweeper address' own ETH balance, which the
/// spending side maintains.
///
/// The sweeper's balance is kept like [`EthBalance`] keeps the main address' but differs in *when*
/// it debits: the main address debits what a transaction actually cost once it finalizes, while
/// the sweeper debits an accepted sweep's whole possible cost — its fee ceiling, a sweep sending
/// no ETH — up front, and is credited back at finalization whatever the sweep turned out not to
/// spend. Holding the whole cost early is what keeps the balance a lower bound while sweeps are in
/// flight, and the sweep pipeline only accepts a sweep the balance covers, so an uncovered debit
/// is a bug, exactly as on the main address. There is no unspent-fee counter either: an unspent
/// fee returns into the balance and is spent by a later sweep, unlike on the main address where it
/// accrues as surplus. ETH anyone else sends to the sweeper is not tracked and only pushes its
/// true balance above this record.
///
/// [`EthBalance`]: crate::state::EthBalance
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SweeperFundingAccounting {
    /// Grows when a funding is accepted, by the whole amount that funding may spend.
    cumulative_burned: Wei,
    /// Grows when that funding's transaction finalizes, by the ETH the sweeper received — nothing
    /// if it failed.
    cumulative_transferred: Wei,
    /// Grows at the same point by the fee the transaction paid, which it does either way. Together
    /// with the amount transferred it is the spend, which never overtakes the burn.
    cumulative_transaction_fees: Wei,
    sweeper_balance: SweeperBalance,
}

impl Default for SweeperFundingAccounting {
    fn default() -> Self {
        Self {
            cumulative_burned: Wei::ZERO,
            cumulative_transferred: Wei::ZERO,
            cumulative_transaction_fees: Wei::ZERO,
            sweeper_balance: SweeperBalance::default(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct SweeperBalance {
    eth_balance: Wei,
    total_effective_tx_fees: Wei,
}

impl Default for SweeperBalance {
    fn default() -> Self {
        Self {
            eth_balance: Wei::ZERO,
            total_effective_tx_fees: Wei::ZERO,
        }
    }
}

impl SweeperBalance {
    fn credit(&mut self, amount: Wei) {
        self.eth_balance = self
            .eth_balance
            .checked_add(amount)
            .expect("BUG: overflow in the sweeper balance");
    }

    fn debit(&mut self, amount: Wei) {
        self.eth_balance = self.eth_balance.checked_sub(amount).unwrap_or_else(|| {
            panic!(
                "BUG: the sweeper balance {} cannot cover a debit of {amount}",
                self.eth_balance
            )
        });
    }

    fn add_effective_tx_fee(&mut self, fee: Wei) {
        self.total_effective_tx_fees = self
            .total_effective_tx_fees
            .checked_add(fee)
            .expect("BUG: overflow in the sweeper's effective transaction fees");
    }
}

impl SweeperFundingAccounting {
    /// Records a burn from the fee subaccount, before any ETH moves.
    pub fn record_burn(&mut self, amount: Wei) {
        self.cumulative_burned = self
            .cumulative_burned
            .checked_add(amount)
            .expect("BUG: overflow in cumulative burned for sweeping");
    }

    /// Records a finalized funding transaction: `transferred` reached the sweeper address (zero if
    /// the transaction failed) and `transaction_fee` was spent on gas either way.
    pub fn record_finalized_funding(&mut self, transferred: Wei, transaction_fee: Wei) {
        self.cumulative_transferred = self
            .cumulative_transferred
            .checked_add(transferred)
            .expect("BUG: overflow in cumulative transferred to the sweeper");
        self.cumulative_transaction_fees = self
            .cumulative_transaction_fees
            .checked_add(transaction_fee)
            .expect("BUG: overflow in cumulative sweeper funding fees");
        self.sweeper_balance.credit(transferred);
        // Checked eagerly so a violation surfaces at the transition that caused it.
        let _ = self.burned_not_yet_spent();
    }

    /// Debits the whole cost an accepted sweep can put on the sweeper address: the ceiling on its
    /// transaction fee, which caps every resubmission too — so a sweep is debited once however
    /// many times the pipeline resubmits it.
    ///
    /// Deliberately not added to [`Self::cumulative_spent`]: that counter is the minter's own ETH,
    /// and this ETH was counted there once already, when the funding that delivered it to the
    /// sweeper finalized. Counting it twice would make spend overtake burn and trip the invariant.
    pub fn record_accepted_sweep(&mut self, max_transaction_fee: Wei) {
        self.sweeper_balance.debit(max_transaction_fee);
    }

    /// Settles a finalized sweep against the hold its acceptance took, reading what actually
    /// happened off the transaction and its receipt: the part of `max_transaction_fee` the sweep
    /// did not pay comes back into the balance, and the fee it paid is recorded. The fee is a
    /// sweep's whole cost whether it succeeded or reverted — its acceptance held nothing else, so
    /// a sweep that sent ETH is a bug.
    pub fn record_finalized_sweep(
        &mut self,
        max_transaction_fee: Wei,
        sweep: &Finalized<SweepTransaction>,
    ) {
        assert_eq!(
            *sweep.transaction_amount(),
            Wei::ZERO,
            "BUG: a sweep must not send ETH, its acceptance held only the transaction fee"
        );
        let effective_fee = sweep.effective_transaction_fee();
        let unspent_fee = max_transaction_fee
            .checked_sub(effective_fee)
            .expect("BUG: a sweep may not pay more than its fee ceiling");
        self.sweeper_balance.credit(unspent_fee);
        self.sweeper_balance.add_effective_tx_fee(effective_fee);
    }

    /// Total transaction fees finalized sweeps actually paid out of the sweeper address.
    pub fn total_effective_sweep_fees(&self) -> Wei {
        self.sweeper_balance.total_effective_tx_fees
    }

    /// Total ETH debited from the main address on account of sweeping.
    pub fn cumulative_spent(&self) -> Wei {
        self.cumulative_transferred
            .checked_add(self.cumulative_transaction_fees)
            .expect("BUG: overflow in cumulative spent on sweeping")
    }

    pub fn cumulative_burned(&self) -> Wei {
        self.cumulative_burned
    }

    /// A lower bound on the sweeper address' ETH balance: what finalized fundings delivered, less
    /// the gas held for every sweep in flight and the fees finalized sweeps actually paid.
    ///
    /// Holding at acceptance rather than at spend is what keeps this a bound while sweeps are in
    /// flight: gas a committed sweep will pay stops counting as available immediately, and a sweep
    /// whose finalization is never observed leaves the bound too *low* — which brings a funding
    /// forward and makes it larger, since [`SweeperFundingConfig::amount_due`] tops up to the target
    /// from wherever the bound sits — rather than too high, which would let the minter believe in
    /// gas that is gone.
    pub fn sweeper_balance_lower_bound(&self) -> Wei {
        self.sweeper_balance.eth_balance
    }

    /// ckETH burned for sweeping that has not been spent yet: the burn of a funding in flight, plus
    /// the fees earlier fundings provisioned but did not pay. Panics rather than saturating if spend
    /// ever exceeds burn, which would mean ckETH is under-backed.
    pub fn burned_not_yet_spent(&self) -> Wei {
        self.cumulative_burned
            .checked_sub(self.cumulative_spent())
            .expect(
                "BUG: more ETH spent on sweeping than ckETH burned for it, \
                 meaning ckETH is under-backed",
            )
    }
}

/// When to top the sweeper address up, and to what. Derived from the minimum withdrawal amount, so
/// that the gap between the two — the smallest amount a funding moves — clears the ledger minimum by
/// construction.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct SweeperFundingConfig {
    /// Fund the sweeper address once its ETH balance falls below this.
    pub low_water_mark: Wei,
    /// Top the sweeper address up to this balance.
    pub target: Wei,
}

/// The target in minimum withdrawal amounts: 0.3 ETH against mainnet's 0.03. Provisional, to be
/// calibrated during the Sepolia rollout.
pub const SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS: u8 = 10;

impl SweeperFundingConfig {
    /// Refilling starts at half the target, so a funding moves at least five minimum withdrawal
    /// amounts. `None` if the target would overflow, which [`State::validate_config`] rejects.
    ///
    /// [`State::validate_config`]: crate::state::State::validate_config
    pub fn for_minimum_withdrawal_amount(minimum_withdrawal_amount: Wei) -> Option<Self> {
        let target = minimum_withdrawal_amount
            .checked_mul(SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS)?;
        Some(Self {
            low_water_mark: target
                .checked_div_floor(2_u8)
                .expect("BUG: dividing by a non-zero constant"),
            target,
        })
    }

    /// How much ETH to move to bring `sweeper_balance` up to the target, or `None` when the
    /// balance is still above the low-water mark and no funding is due.
    pub fn amount_due(&self, sweeper_balance: Wei) -> Option<Wei> {
        if sweeper_balance >= self.low_water_mark {
            return None;
        }
        Some(
            self.target
                .checked_sub(sweeper_balance)
                .expect("BUG: the low-water mark must not exceed the target"),
        )
    }
}
