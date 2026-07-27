#[cfg(test)]
mod tests;

use crate::endpoints::DepositErc20Error;
use crate::state::event::{DepositAddressRegistration, DepositAddressRegistry};
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::num::NonZeroUsize;
use std::time::Duration;

/// Time window during which a registered ckERC20 deposit address is kept armed.
pub const DEPOSIT_ADDRESS_SCAN_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

// Ethereum blocktime is 12s (on average), so that there are 7_200 blocks per day.
// Use 1 transaction per block to a minter-controlled address as a crude upper-bound.
const MAX_ACTIVE_DEPOSIT_ADDRESSES: NonZeroUsize = NonZeroUsize::new(7_000).unwrap();

/// Registry of minter-controlled ckERC20 deposit addresses, each derived
/// individually for a user's account. This in particular enables deposits from
/// central exchanges (CEX), which send from an address the user does not
/// control.
///
/// A `deposit_erc20` request arms the user-derived address by adding it to a
/// bounded, time-expiring watchlist. Scanning those addresses and minting the
/// corresponding ckERC20 is future work (DEFI-2927).
#[derive(Clone, PartialEq, Debug)]
pub struct AutomaticDeposits {
    watchlist: TimedSizedMap<Account, DepositRequest>,
}

impl AutomaticDeposits {
    /// Add the deposit `address` derived for `account` to the watchlist.
    ///
    /// Returns the watched address together with the timestamp until which a
    /// deposit to it is guaranteed to be noticed. Re-registering an account that
    /// is still armed returns the already-stored address and its original
    /// validity window without re-arming it, and fails with
    /// [`DepositErc20Error::TooManyActiveAddresses`] when the watchlist is full
    /// of live entries.
    pub fn watch_address_for_account(
        &mut self,
        now: Timestamp,
        account: Account,
        address: Address,
    ) -> Result<Entry<DepositRequest>, DepositErc20Error> {
        match self
            .watchlist
            .insert(now, account, DepositRequest::from(address))
        {
            Ok(_) | Err(InsertError::AlreadyPresent { .. }) => {
                let entry = self
                    .watchlist
                    .get_entry(now, &account)
                    .expect("BUG: the entry is live right after insert or AlreadyPresent");
                Ok(entry.clone())
            }
            Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveAddresses),
        }
    }

    /// Rebuild the watchlist exactly from a registry previously produced by
    /// [`Self::watchlist_snapshot`], replacing any existing content.
    ///
    /// The watchlist is restored verbatim under the limits recorded in the
    /// registry (`scan_window_nanos`, `capacity`), not the current code
    /// constants: entries keep their stored expiry (no clamping), expired
    /// entries are preserved (no eviction), and the entry count may exceed
    /// `capacity` (no admission check). This makes the restored state equal to
    /// the one that produced the registry, which the event-log equivalence
    /// check relies on. Changing the limits across versions is future work.
    pub fn rebuild_watchlist(&mut self, registry: &DepositAddressRegistry) {
        let ttl = Duration::from_nanos(registry.scan_window_nanos);
        let capacity = NonZeroUsize::new(usize::try_from(registry.capacity).unwrap_or(usize::MAX))
            .expect("BUG: deposit address registry capacity must be non-zero");
        let entries = registry.registrations.iter().map(|deposit| {
            (
                Account {
                    owner: deposit.owner,
                    subaccount: deposit.subaccount,
                },
                Entry {
                    value: DepositRequest::from(deposit.address),
                    expires_at: deposit.expires_at_nanos,
                },
            )
        });
        self.watchlist = TimedSizedMap::from_ordered_entries(ttl, capacity, entries);
    }

    /// The live watchlist entry for `account`, or `None` if the account is not
    /// currently armed (absent or expired as of `now`).
    pub fn get_entry(&self, now: Timestamp, account: &Account) -> Option<&Entry<DepositRequest>> {
        self.watchlist.get_entry(now, account)
    }

    /// Full snapshot of the watchlist, faithful enough to reconstruct it exactly
    /// via [`Self::rebuild_watchlist`]: it records the current limits and lists
    /// every entry (live and expired-but-unevicted) in time-index order.
    pub fn watchlist_snapshot(&self) -> DepositAddressRegistry {
        let registrations = self
            .watchlist
            .iter_by_expiry()
            .map(|(account, deposit)| DepositAddressRegistration {
                owner: account.owner,
                subaccount: account.subaccount,
                address: deposit.value.address,
                expires_at_nanos: deposit.expires_at,
            })
            .collect();
        DepositAddressRegistry {
            scan_window_nanos: u64::try_from(self.watchlist.ttl().as_nanos()).unwrap_or(u64::MAX),
            capacity: self.watchlist.capacity().get() as u64,
            registrations,
        }
    }
}

impl Default for AutomaticDeposits {
    fn default() -> Self {
        Self {
            watchlist: TimedSizedMap::new(
                DEPOSIT_ADDRESS_SCAN_WINDOW,
                MAX_ACTIVE_DEPOSIT_ADDRESSES,
            ),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DepositRequest {
    pub address: Address,
}

impl From<Address> for DepositRequest {
    fn from(address: Address) -> Self {
        Self { address }
    }
}
