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

/// How much ckETH has been burned for sweeping and how much of it has actually been spent: the two
/// sides of the invariant above.
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
    /// Grows when a sweep is accepted, by the most that sweep can cost the sweeper address: the ETH
    /// it moves plus the ceiling on its transaction fee, which caps every resubmission too. Not part
    /// of the invariant above — this ETH was already counted as spent when the funding that
    /// delivered it finalized — but subtracted from the balance bound, so that gas a committed sweep
    /// will consume stops counting as available the moment it is committed.
    cumulative_sweep_provisioned: Wei,
    /// Grows when a sweep finalizes, by the part of that provision it turned out not to need: the
    /// fee it did not pay, plus the value it did not move if it failed.
    cumulative_sweep_refunded: Wei,
}

impl Default for SweeperFundingAccounting {
    fn default() -> Self {
        Self {
            cumulative_burned: Wei::ZERO,
            cumulative_transferred: Wei::ZERO,
            cumulative_transaction_fees: Wei::ZERO,
            cumulative_sweep_provisioned: Wei::ZERO,
            cumulative_sweep_refunded: Wei::ZERO,
        }
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
        // Checked eagerly so a violation surfaces at the transition that caused it.
        let _ = self.burned_not_yet_spent();
    }

    /// Records the most an accepted sweep can cost the sweeper address, taking it out of the balance
    /// bound up front. Recorded when the sweep is accepted rather than when its transaction is
    /// signed, so that a sweep provisions once however many times the pipeline resubmits it — every
    /// attempt is capped by the same fee ceiling.
    ///
    /// Deliberately not added to [`Self::cumulative_spent`]: that counter is the minter's own ETH,
    /// and this ETH was counted there once already, when the funding that delivered it to the
    /// sweeper finalized. Counting it twice would make spend overtake burn and trip the invariant.
    pub fn record_accepted_sweep(&mut self, provisioned: Wei) {
        self.cumulative_sweep_provisioned = self
            .cumulative_sweep_provisioned
            .checked_add(provisioned)
            .expect("BUG: overflow in cumulative sweep provisioned");
    }

    /// Records the part of a finalized sweep's provision it did not need, putting it back into the
    /// balance bound.
    pub fn record_finalized_sweep(&mut self, refunded: Wei) {
        self.cumulative_sweep_refunded = self
            .cumulative_sweep_refunded
            .checked_add(refunded)
            .expect("BUG: overflow in cumulative sweep refunded");
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
    /// what accepted sweeps have provisioned, plus what finalized sweeps handed back.
    ///
    /// Provisioning at acceptance rather than at spend is what keeps this a bound while sweeps are in
    /// flight: gas a committed sweep will pay stops counting as available immediately, and a sweep
    /// whose finalization is never observed leaves the bound too *low* — which delays a funding —
    /// rather than too high, which would let the minter believe in gas that is gone. ETH sent to the
    /// address by anyone else only pushes the true balance further above the bound.
    ///
    /// Saturating rather than checked: these counters are the minter's own record, and after an
    /// upgrade that starts them from zero — or a sweeper address funded before the minter tracked it
    /// — provisioning can legitimately exceed the deliveries. Trapping here would trap the replay of
    /// every event after it, so it floors at zero, which reads as "assume nothing is prepaid".
    pub fn sweeper_balance_lower_bound(&self) -> Wei {
        self.cumulative_transferred
            .checked_add(self.cumulative_sweep_refunded)
            .expect("BUG: overflow in the sweeper balance bound")
            .checked_sub(self.cumulative_sweep_provisioned)
            .unwrap_or(Wei::ZERO)
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
