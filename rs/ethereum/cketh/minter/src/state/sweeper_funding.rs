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

/// The sweeper address' ETH balance as last observed on chain: the prepaid sweep gas, cached because
/// reading it costs an outcall.
///
/// Not CBOR-serializable, and deliberately absent after an upgrade: an observation from before one
/// should not authorise spending after it, and [`check_prepaid_sweep_gas`] refuses on absent.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct ObservedSweeperBalance {
    pub balance: Wei,
    /// IC time of the reading, in nanoseconds.
    pub observed_at_nanos: u64,
}

/// How long an observation is trusted for a spending decision.
///
/// Two days against a 24-hour [`crate::SWEEPER_FUNDING_INTERVAL`] leaves exactly one tick of slack:
/// one missed refresh is tolerated, two consecutive misses stop sweeping.
pub const MAX_SWEEPER_BALANCE_AGE_NANOS: u64 = 2 * 24 * 60 * 60 * 1_000_000_000;

/// Why sweeping is not currently allowed to spend gas.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum PrepaidGasUnavailable {
    NeverObserved,
    Stale { age_nanos: u64 },
    Insufficient { available: Wei, required: Wei },
}

impl ObservedSweeperBalance {
    fn age_nanos(&self, now_nanos: u64) -> u64 {
        now_nanos.saturating_sub(self.observed_at_nanos)
    }
}

/// Whether the sweeper's last observed balance covers `required` wei of gas for *one* sweep.
///
/// Fails closed: an unknown or stale observation is an error, since a sweep the sweeper cannot pay
/// for is wasted work, while a wrongly withheld sweep costs only delay.
///
/// A precondition on a snapshot, not an allowance: it neither reserves nor deducts, so a caller
/// issuing several sweeps between two observations has to subtract what it has already committed.
/// Two 6-wei sweeps both pass against a 10-wei observation, as does one whose gas the queried block
/// had not yet accounted for. The backing invariant does not rest on this: funding counts the whole
/// transfer as spent once it finalizes, so every wei at the sweeper address is already covered by a
/// burn that preceded it, and drawing it down cannot make spend outrun burn.
pub fn check_prepaid_sweep_gas(
    observed: Option<ObservedSweeperBalance>,
    required: Wei,
    now_nanos: u64,
) -> Result<Wei, PrepaidGasUnavailable> {
    let observed = observed.ok_or(PrepaidGasUnavailable::NeverObserved)?;
    let age_nanos = observed.age_nanos(now_nanos);
    if age_nanos > MAX_SWEEPER_BALANCE_AGE_NANOS {
        return Err(PrepaidGasUnavailable::Stale { age_nanos });
    }
    if observed.balance < required {
        return Err(PrepaidGasUnavailable::Insufficient {
            available: observed.balance,
            required,
        });
    }
    Ok(observed.balance)
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
