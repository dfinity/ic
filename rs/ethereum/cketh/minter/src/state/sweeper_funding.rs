//! Burn-first accounting for sweeper fee funding, per
//! `rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without touching the
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

/// How much ckETH has been burned for sweeping and how much of it has actually been spent.
///
/// Not CBOR-serializable: rebuilt from the audit events on every upgrade, never persisted.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SweeperFundingAccounting {
    cumulative_burned: Wei,
    cumulative_transferred: Wei,
    /// Fees of finalized funding transactions, successful or not.
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
        // Non-zero: the balance is below the low-water mark, which is half the target.
        self.target.checked_sub(sweeper_balance)
    }
}
