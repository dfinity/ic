// TODO(EXC-240): The following module is deprecated and should be removed.

use serde::{Deserialize, Serialize};

/// ICP represents the ICP tokens on the IC.
///
/// Since ICP tokens are a method of payment, they are designed with the
/// following constraints:
///
/// 1) ICP cannot be minted outside of this module. This is enforced by
///    making its constructor private.
///
/// 2) ICP can only be minted by a `Tap`. If a component in the IC mints
///    ICP, it will need to be passed a `Tap` for it to mint them. This
///    makes it very clear which components are responsible for issuing ICP.
///
/// 3) ICP can only be burned by a `Sink`. If a component burns ICP, it
///    must use a `Sink` in order to burn those ICP. If ICP are dropped without
///    being burned by a `Sink`, the destructor of ICP panics.
///
///    In other words:
///
///      * Only a component with a `Tap` can mint ICP.
///      * Only a component with a `Sink` can burn ICP.
///      * A component without a `Tap` or a `Sink` is guaranteed to not mint nor
///        burn any ICP.
///
/// The `must_use` attributes offers additional compile-time warnings if ICP
/// are accidentally dropped out of scope.
///
/// For now, cloning is enabled to not make the change too disruptive.
/// Disallowing cloning will also make imply that one cannot directly clone a
/// `SystemState` or a `CanisterState`. The `clone` implementation of these
/// components will need to be modified such that cloning them results in a copy
/// of them, but with zero ICP.
#[must_use]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct ICP(u64);

#[derive(Debug, Clone, PartialEq)]
pub enum ICPError {
    OutOfICP { available: u64, requested: u64 },
}

impl ICP {
    /// Returns a new object with zero ICP.
    pub const fn zero() -> Self {
        ICP(0)
    }

    /// Returns the current balance.
    pub fn balance(&self) -> u64 {
        self.0
    }

    /// Adds the requested number of ICP to the current object.
    ///
    /// Panics if the icp to be added would result in a balance overflow. This
    /// should be fine as we don't expect we'll hit this limit soon.
    pub fn add(&mut self, mut icp: ICP) {
        let amount = icp.balance();
        // burn the amount to be added.
        icp.0 = 0;
        match self.0.checked_add(amount) {
            Some(res) => {
                self.0 = res;
            }
            None => {
                // burn the current object before panic'ing. This way we won't panic inside the
                // panic when the current object is dropped.
                self.0 = 0;
                panic!("ICP balance overflow");
            }
        }
    }

    /// Returns the entire amount contained in the current object.
    pub fn take(&mut self) -> ICP {
        self.withdraw(self.balance()).unwrap()
    }

    /// Withdraws the requested number of ICP from the current object.
    pub fn withdraw(&mut self, amount: u64) -> Result<ICP, ICPError> {
        self.withdraw_with_threshold(amount, 0)
    }

    /// Withdraws the requested number of ICP from the current object, while
    /// guaranteeing that the balance after the withdrawal remains above the
    /// given threshold.
    pub fn withdraw_with_threshold(
        &mut self,
        amount: u64,
        threshold: u64,
    ) -> Result<ICP, ICPError> {
        let available_balance = self.balance().saturating_sub(threshold);

        if available_balance < amount {
            Err(ICPError::OutOfICP {
                available: available_balance,
                requested: amount,
            })
        } else {
            self.0 -= amount;
            Ok(ICP(amount))
        }
    }
}

impl std::fmt::Display for ICP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ICP({})", self.0)
    }
}

impl Drop for ICP {
    fn drop(&mut self) {
        // if self.0 != 0 {
        //     panic!("ICP leakage detected!");
        // }
    }
}

/// A tap is used for minting ICP. In the future, this could be a trait
/// where we have different implementations of a Tap, each offering different
/// constraints or be implemented for different types of tokens.
pub struct Tap;

impl Tap {
    pub fn mint(amount: u64) -> ICP {
        ICP(amount)
    }
}

/// A sink is used for burning ICP. In the future, this could be a trait
/// where we have different implementations, each offering different
/// constraints or be implemented for different types of tokens.
pub struct Sink;

impl Sink {
    pub fn burn(mut icp: ICP) {
        icp.0 = 0;
        // icp is dropped at the end of this function.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    #[should_panic(expected = "leakage detected")]
    fn non_zero_icp_panic_when_dropped() {
        let _ = Tap::mint(100);

        // ICP have been created but not destroyed.
        // The destructor should panic.
    }

    #[test]
    fn icp_can_be_created_and_destroyed() {
        let c = Tap::mint(100);
        Sink::burn(c);
    }

    #[test]
    fn icp_are_not_copyable() {
        let c = Tap::mint(100);
        let a = c;

        // If icp were copied from `c` to `a`, then `c` would still be
        // present and it would panic once it is dropped.
        Sink::burn(a);
    }

    #[test]
    fn zero_icp_can_be_dropped() {
        let _ = Tap::mint(0);
    }

    #[test]
    fn can_withdraw_icp_if_enough_balance() {
        let mut icp = Tap::mint(100);
        let amount = 50;

        let res = icp.withdraw(amount).unwrap();
        assert_eq!(res.balance(), amount);

        Sink::burn(icp);
        Sink::burn(res);
    }

    #[test]
    fn withdraw_icp_fails_if_not_enough_balance() {
        let mut icp = Tap::mint(100);
        let amount = 200;

        let res = icp.withdraw(amount);
        assert_eq!(
            res,
            Err(ICPError::OutOfICP {
                available: icp.balance(),
                requested: amount
            })
        );

        Sink::burn(icp);
    }

    #[test]
    fn can_withdraw_icp_with_threshold_if_enough_balance() {
        let mut icp = Tap::mint(100);
        let amount = 50;
        let threshold = 20;

        let res = icp.withdraw_with_threshold(amount, threshold).unwrap();
        assert_eq!(res.balance(), amount);

        Sink::burn(icp);
        Sink::burn(res);
    }

    #[test]
    fn withdraw_icp_with_threshold_fails_if_not_enough_balance() {
        let mut icp = Tap::mint(100);
        let amount = 50;
        let threshold = 60;

        let res = icp.withdraw_with_threshold(amount, threshold);
        assert_eq!(
            res,
            Err(ICPError::OutOfICP {
                available: icp.balance() - threshold,
                requested: amount
            })
        );

        Sink::burn(icp);
    }

    #[test]
    fn can_add_icp() {
        let mut icp = Tap::mint(100);
        let extra_icp = Tap::mint(20);

        icp.add(extra_icp);
        assert_eq!(icp.balance(), 120);

        Sink::burn(icp);
    }

    #[test]
    #[should_panic(expected = "ICP balance overflow")]
    fn add_icp_with_overlflow() {
        let mut icp = Tap::mint(std::u64::MAX);
        let extra_icp = Tap::mint(20);

        icp.add(extra_icp);
    }
}
