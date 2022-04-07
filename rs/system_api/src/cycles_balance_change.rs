use std::{cmp::Ordering, ops::Add};

use ic_types::Cycles;
use serde::{Deserialize, Serialize};

/// Represents a change in the cycles balance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CyclesBalanceChange {
    Added(Cycles),
    Removed(Cycles),
}

impl CyclesBalanceChange {
    /// Returns the change from the first cycles balance to the second.
    pub fn new(old_balance: Cycles, new_balance: Cycles) -> Self {
        let result = if old_balance <= new_balance {
            Self::Added(new_balance - old_balance)
        } else {
            Self::Removed(old_balance - new_balance)
        };
        result.canonical()
    }

    /// Returns the change representing added cycles.
    pub fn added(value: Cycles) -> Self {
        Self::Added(value).canonical()
    }

    /// Returns the change representing removed cycles.
    pub fn removed(value: Cycles) -> Self {
        Self::Removed(value).canonical()
    }

    /// Returns the zero change.
    pub fn zero() -> Self {
        Self::Added(Cycles::new(0)).canonical()
    }

    /// Applies the change to the given cycles balance and returns the result.
    pub fn apply(self, balance: Cycles) -> Cycles {
        match self {
            Self::Added(added) => balance + added,
            Self::Removed(removed) => balance - removed,
        }
    }

    /// The same as `apply()` but works on references.
    pub fn apply_ref(&self, balance: &mut Cycles) {
        match self {
            Self::Added(added) => *balance += *added,
            Self::Removed(removed) => *balance -= *removed,
        }
    }

    // Replaces `Removed(0)` with `Added(0)` to avoid -0.
    fn canonical(&self) -> Self {
        match self {
            Self::Added(value) => Self::Added(*value),
            Self::Removed(value) => {
                if value.get() == 0 {
                    Self::Added(*value)
                } else {
                    Self::Removed(*value)
                }
            }
        }
    }
}

impl PartialEq for CyclesBalanceChange {
    fn eq(&self, other: &Self) -> bool {
        match (self.canonical(), other.canonical()) {
            (Self::Added(lhs), Self::Added(rhs)) | (Self::Removed(lhs), Self::Removed(rhs)) => {
                lhs == rhs
            }
            (Self::Added(_), Self::Removed(_)) | (Self::Removed(_), Self::Added(_)) => false,
        }
    }
}

impl PartialOrd for CyclesBalanceChange {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self.canonical(), other.canonical()) {
            (Self::Added(lhs), Self::Added(rhs)) => PartialOrd::partial_cmp(&lhs, &rhs),
            (Self::Removed(lhs), Self::Removed(rhs)) => {
                // Swap the order of `rhs` and `lhs`.
                PartialOrd::partial_cmp(&rhs, &lhs)
            }
            (Self::Added(_), Self::Removed(_)) => Some(Ordering::Greater),
            (Self::Removed(_), Self::Added(_)) => Some(Ordering::Less),
        }
    }
}

impl Add for CyclesBalanceChange {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let result = match (self, rhs) {
            (Self::Added(added1), Self::Added(added2)) => Self::Added(added1 + added2),
            (Self::Added(added), Self::Removed(removed))
            | (Self::Removed(removed), Self::Added(added)) => {
                if added >= removed {
                    Self::Added(added - removed)
                } else {
                    Self::Removed(removed - added)
                }
            }
            (Self::Removed(removed1), Self::Removed(removed2)) => {
                Self::Removed(removed1 + removed2)
            }
        };
        result.canonical()
    }
}

#[cfg(test)]
mod tests {
    use ic_types::Cycles;

    use crate::cycles_balance_change::CyclesBalanceChange;

    fn cc(value: u128) -> Cycles {
        Cycles::from(value)
    }

    #[test]
    fn test_comparison() {
        assert_eq!(
            CyclesBalanceChange::added(cc(0)),
            CyclesBalanceChange::removed(cc(0))
        );
        assert!(CyclesBalanceChange::removed(cc(0)) >= CyclesBalanceChange::added(cc(0)));
        assert!(CyclesBalanceChange::removed(cc(0)) <= CyclesBalanceChange::added(cc(0)));
        assert!(CyclesBalanceChange::added(cc(42)) > CyclesBalanceChange::removed(cc(42)));
        assert!(CyclesBalanceChange::removed(cc(42)) < CyclesBalanceChange::added(cc(42)));
        assert!(
            CyclesBalanceChange::added(cc(u128::MAX))
                > CyclesBalanceChange::added(cc(u128::MAX - 1))
        );
        assert!(
            CyclesBalanceChange::removed(cc(u128::MAX))
                < CyclesBalanceChange::removed(cc(u128::MAX - 1))
        );
    }

    #[test]
    fn test_addition() {
        assert_eq!(
            CyclesBalanceChange::zero(),
            CyclesBalanceChange::added(cc(0)) + CyclesBalanceChange::removed(cc(0))
        );
        assert_eq!(
            CyclesBalanceChange::added(cc(42)),
            CyclesBalanceChange::added(cc(42)) + CyclesBalanceChange::removed(cc(0))
        );
        assert_eq!(
            CyclesBalanceChange::added(cc(42)),
            CyclesBalanceChange::removed(cc(42)) + CyclesBalanceChange::added(cc(84))
        );
        assert_eq!(
            CyclesBalanceChange::removed(cc(42)),
            CyclesBalanceChange::removed(cc(84)) + CyclesBalanceChange::added(cc(42))
        );
        assert_eq!(
            CyclesBalanceChange::zero(),
            CyclesBalanceChange::removed(cc(u128::MAX)) + CyclesBalanceChange::added(cc(u128::MAX))
        );
        assert_eq!(
            CyclesBalanceChange::zero(),
            CyclesBalanceChange::added(cc(u128::MAX)) + CyclesBalanceChange::removed(cc(u128::MAX))
        );
        // Saturating operation.
        assert_eq!(
            CyclesBalanceChange::added(cc(u128::MAX)),
            CyclesBalanceChange::added(cc(u128::MAX)) + CyclesBalanceChange::added(cc(u128::MAX))
        );
        // Saturating operation.
        assert_eq!(
            CyclesBalanceChange::removed(cc(u128::MAX)),
            CyclesBalanceChange::removed(cc(u128::MAX))
                + CyclesBalanceChange::removed(cc(u128::MAX))
        );
    }

    #[test]
    fn test_apply() {
        assert_eq!(cc(58), CyclesBalanceChange::removed(cc(42)).apply(cc(100)));
        assert_eq!(cc(42), CyclesBalanceChange::added(cc(20)).apply(cc(22)));
        // Saturating operation.
        assert_eq!(cc(0), CyclesBalanceChange::removed(cc(100)).apply(cc(99)));
        // Saturating operation.
        assert_eq!(
            cc(u128::MAX),
            CyclesBalanceChange::added(cc(u128::MAX)).apply(cc(u128::MAX))
        );
        // Saturating operation.
        assert_eq!(
            cc(0),
            CyclesBalanceChange::removed(cc(u128::MAX)).apply(cc(0))
        );
    }

    #[test]
    fn test_apply_ref() {
        let mut balance = cc(100);
        let change = CyclesBalanceChange::removed(cc(42));
        change.apply_ref(&mut balance);
        assert_eq!(cc(58), balance);
    }

    #[test]
    fn test_new() {
        assert_eq!(
            CyclesBalanceChange::added(cc(100)),
            CyclesBalanceChange::new(cc(50), cc(150))
        );
        assert_eq!(
            CyclesBalanceChange::removed(cc(100)),
            CyclesBalanceChange::new(cc(150), cc(50))
        );
    }
}
