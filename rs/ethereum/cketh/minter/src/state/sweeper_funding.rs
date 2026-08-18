//! Burn-first accounting for sweeper fee funding, per
//! `rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
//! ckETH backing". Sweep gas is prepaid: ckETH is burned from the minter's fee subaccount *before*
//! the ETH moves, so that at every instant
//!
//! ```text
//! cumulative ckETH burned for sweeping >= cumulative ETH debited from the main address for sweeping
//! ```
//!
//! The burn runs ahead of the spend, since a funding provisions the maximum fee its transaction may
//! pay and usually pays less — and a failed one moves no ETH at all. That surplus is never re-minted
//! and never discounted from a later burn: it simply stays as backing, exactly like the unspent gas
//! of a user withdrawal. Each funding therefore burns for its own transfer alone, and this module
//! only has to observe the surplus, which it does for the invariant above and for the dashboard. It
//! sits at the *main* address, not the sweeper's, so it cannot be read back on chain.
//!
//! A fold over events the minter already persists, so replay reconstructs it exactly.

#[cfg(test)]
mod tests;

use crate::numeric::Wei;

/// How much ckETH has been burned for sweeping and how much of it has actually been spent.
///
/// Not CBOR-serializable: rebuilt from the audit events on every upgrade, never persisted.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SweeperFundingAccounting {
    /// Total ckETH burned from the fee subaccount to fund sweeping.
    cumulative_burned: Wei,
    /// Total ETH delivered to the sweeper address by finalized funding transactions.
    cumulative_transferred: Wei,
    /// Total effective fees paid by finalized funding transactions, successful or not.
    cumulative_transaction_fees: Wei,
}

impl Default for SweeperFundingAccounting {
    fn default() -> Self {
        Self {
            cumulative_burned: Wei::ZERO,
            cumulative_transferred: Wei::ZERO,
            cumulative_transaction_fees: Wei::ZERO,
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

    /// Total ETH debited from the main address on account of sweeping.
    pub fn cumulative_spent(&self) -> Wei {
        self.cumulative_transferred
            .checked_add(self.cumulative_transaction_fees)
            .expect("BUG: overflow in cumulative spent on sweeping")
    }

    pub fn cumulative_burned(&self) -> Wei {
        self.cumulative_burned
    }

    /// ckETH burned for sweeping that has not been spent yet: the burn of a funding still in
    /// flight, plus the fees earlier fundings provisioned but did not pay. A gauge rather than a
    /// running total — it jumps by the whole amount when a funding burns and falls back when that
    /// transaction finalizes. Panics rather than saturating if spend ever exceeds burn, since that
    /// means ckETH is under-backed and is not a recoverable state.
    pub fn burned_not_yet_spent(&self) -> Wei {
        self.cumulative_burned
            .checked_sub(self.cumulative_spent())
            .expect(
                "BUG: more ETH spent on sweeping than ckETH burned for it, \
                 meaning ckETH is under-backed",
            )
    }
}

/// When to top the sweeper address up, and to what. Proposal-configurable; the defaults below are
/// provisional, to be calibrated during the Sepolia rollout.
///
/// Not CBOR-serializable: replayed from the `Upgrade` events that set it, never persisted.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SweeperFundingConfig {
    /// Fund the sweeper address once its ETH balance falls below this.
    pub low_water_mark: Wei,
    /// Top the sweeper address up to this balance.
    pub target: Wei,
}

/// 0.02 ETH: roughly 24 solo sweeps at 10 gwei, so refilling starts well before running dry.
pub const DEFAULT_SWEEPER_FUNDING_LOW_WATER_MARK: Wei = Wei::new(20_000_000_000_000_000);
/// 0.1 ETH, so a funding covers many sweeps and its own fee stays a small fraction of the amount
/// moved.
///
/// Coupled to the check in [`SweeperFundingConfig::validate`]: the pair leaves 0.08 ETH of headroom,
/// which is therefore the largest `minimum_withdrawal_amount` a fresh install can accept, since
/// `InitArg` cannot express the bounds. Widen these defaults rather than relaxing the check.
pub const DEFAULT_SWEEPER_FUNDING_TARGET: Wei = Wei::new(100_000_000_000_000_000);

impl Default for SweeperFundingConfig {
    fn default() -> Self {
        Self {
            low_water_mark: DEFAULT_SWEEPER_FUNDING_LOW_WATER_MARK,
            target: DEFAULT_SWEEPER_FUNDING_TARGET,
        }
    }
}

/// Why a proposed [`SweeperFundingConfig`] is not usable.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum InvalidSweeperFundingConfig {
    /// Without headroom every funding would immediately be due again, funding in a tight loop.
    TargetNotAboveLowWaterMark { low_water_mark: Wei, target: Wei },
    /// The headroom is the smallest amount a funding ever moves, so below the minimum burn every
    /// cycle would burn more ckETH than it moves ETH.
    HeadroomBelowMinimumBurn { headroom: Wei, minimum_burn: Wei },
}

impl SweeperFundingConfig {
    /// Validates the pair against the smallest burn a funding will make. Takes `minimum_burn`
    /// rather than checking the bounds alone because this is what an NNS proposal leans on.
    pub fn validate(&self, minimum_burn: Wei) -> Result<(), InvalidSweeperFundingConfig> {
        if self.target <= self.low_water_mark {
            return Err(InvalidSweeperFundingConfig::TargetNotAboveLowWaterMark {
                low_water_mark: self.low_water_mark,
                target: self.target,
            });
        }
        let headroom = self
            .target
            .checked_sub(self.low_water_mark)
            .expect("BUG: target is above the low-water mark");
        if headroom < minimum_burn {
            return Err(InvalidSweeperFundingConfig::HeadroomBelowMinimumBurn {
                headroom,
                minimum_burn,
            });
        }
        Ok(())
    }

    /// How much ETH to move to bring `sweeper_balance` up to the target, or `None` when the
    /// balance is still above the low-water mark and no funding is due.
    pub fn amount_due(&self, sweeper_balance: Wei) -> Option<Wei> {
        if sweeper_balance >= self.low_water_mark {
            return None;
        }
        // Non-zero: the balance is below the low-water mark, which `validate` keeps below the target.
        self.target.checked_sub(sweeper_balance)
    }
}
