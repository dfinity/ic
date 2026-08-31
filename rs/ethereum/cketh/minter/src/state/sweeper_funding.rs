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

use crate::eth_rpc_client::responses::TransactionStatus;
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
    /// How many funding transactions finalized, by outcome. Failures are expected to stay at zero:
    /// a bare transfer to an address derived from the minter's own key has no code to revert in.
    successful_fundings: u64,
    failed_fundings: u64,
}

impl Default for SweeperFundingAccounting {
    fn default() -> Self {
        Self {
            cumulative_burned: Wei::ZERO,
            cumulative_transferred: Wei::ZERO,
            cumulative_transaction_fees: Wei::ZERO,
            successful_fundings: 0,
            failed_fundings: 0,
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

    /// Records a finalized funding transaction: `amount` is what its transfer carried and
    /// `transaction_fee` what it paid for gas, which it did either way.
    ///
    /// The outcome decides both the count and whether the transfer landed, so it is one call.
    /// A failure is counted rather than trapped: the burn simply goes unspent, and the count is the
    /// only signal that something believed impossible has happened.
    pub fn record_finalized_funding(
        &mut self,
        status: &TransactionStatus,
        amount: Wei,
        transaction_fee: Wei,
    ) {
        let transferred = match status {
            TransactionStatus::Success => {
                self.successful_fundings = self.successful_fundings.saturating_add(1);
                amount
            }
            TransactionStatus::Failure => {
                self.failed_fundings = self.failed_fundings.saturating_add(1);
                Wei::ZERO
            }
        };
        self.cumulative_transferred = self
            .cumulative_transferred
            .checked_add(transferred)
            .expect("BUG: overflow in cumulative transferred to the sweeper");
        self.cumulative_transaction_fees = self
            .cumulative_transaction_fees
            .checked_add(transaction_fee)
            .expect("BUG: overflow in cumulative sweeper funding fees");
        // The checked helper, not the saturating getter: a violation traps at the transition that
        // caused it rather than being smoothed over on the next scrape.
        self.checked_burned_not_yet_spent().expect(
            "BUG: more ETH spent on sweeping than ckETH burned for it, \
             meaning ckETH is under-backed",
        );
    }

    pub fn successful_fundings(&self) -> u64 {
        self.successful_fundings
    }

    pub fn failed_fundings(&self) -> u64 {
        self.failed_fundings
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

    /// A lower bound on the sweeper address' ETH balance: what finalized fundings delivered. Nothing
    /// debits it yet; when sweeping lands it will subtract the gas submitted sweeps provisioned, so
    /// the bound stays conservative. ETH sent to the address by anyone else only pushes the true
    /// balance above it.
    pub fn sweeper_balance_lower_bound(&self) -> Wei {
        self.cumulative_transferred
    }

    /// ckETH burned for sweeping that has not been spent yet: the burn of a funding in flight, plus
    /// the fees earlier fundings provisioned but did not pay. The in-flight part is drawn down when
    /// that funding finalizes; what is left of it never is, so the floor only ever rises.
    ///
    /// Saturates: the metrics and the dashboard read it from a query, and an under-backed minter is
    /// exactly when those surfaces must stay up. The state transition traps instead.
    pub fn burned_not_yet_spent(&self) -> Wei {
        self.checked_burned_not_yet_spent().unwrap_or(Wei::ZERO)
    }

    /// `None` if more ETH has been spent on sweeping than ckETH was burned for it, which would mean
    /// ckETH is under-backed.
    fn checked_burned_not_yet_spent(&self) -> Option<Wei> {
        self.cumulative_burned.checked_sub(self.cumulative_spent())
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
