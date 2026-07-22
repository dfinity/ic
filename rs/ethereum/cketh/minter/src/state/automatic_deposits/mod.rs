use crate::endpoints::DepositErc20Error;
use crate::state::event::DepositAddressRegistration;
use crate::timed_sized_map::{Entry, InsertError, TimedSizedMap, Timestamp};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::cmp::Reverse;
use std::num::NonZeroUsize;
use std::time::Duration;

/// Time window during which a registered ckERC20 deposit address is kept armed.
pub const DEPOSIT_ADDRESS_SCAN_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

// Ethereum blocktime is 12s (on average), so that there are 7_200 blocks per day.
// Use 1 transaction per block to a minter-controlled address as a crude upper-bound.
const MAX_ACTIVE_DEPOSIT_ADDRESSES: NonZeroUsize = NonZeroUsize::new(7_000).unwrap();

/// State machine to handle deposits made to addresses controlled by the minter individually-derived for each user.
/// This is in particular allows deposits from central exchanges (CEX).
/// Overall the deposit lifecycle is as follows:
/// 1. The user deposit request adds the corresponding user-derived address to the watchlist.
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

    /// Rebuild the watchlist from a snapshot previously produced by
    /// [`Self::watchlist_snapshot`], replacing any existing content.
    ///
    /// Entries are re-admitted under *this* version's limits rather than the
    /// ones in effect when the snapshot was taken: entries already expired as of
    /// `now` are dropped, each entry's validity is clamped to the current scan
    /// window, and the current capacity is enforced. Since the snapshot lists
    /// entries longest-lived first, the soonest-to-expire are the ones dropped
    /// when the snapshot exceeds the current capacity.
    pub fn rebuild_watchlist(&mut self, now: Timestamp, snapshot: &[DepositAddressRegistration]) {
        self.watchlist.clear();
        for deposit in snapshot {
            let account = Account {
                owner: deposit.owner,
                subaccount: deposit.subaccount,
            };
            let entry = Entry {
                value: DepositRequest::from(deposit.address),
                expires_at: deposit.expires_at_nanos,
            };
            let _ = self.watchlist.insert_entry(now, account, entry);
        }
    }

    pub fn watchlist_iter(&self) -> impl Iterator<Item = (&Account, &Entry<DepositRequest>)> {
        self.watchlist.iter()
    }

    pub fn watchlist_snapshot(&self) -> Vec<DepositAddressRegistration> {
        let mut snapshot: Vec<_> = self
            .watchlist
            .iter()
            .map(|(account, deposit)| DepositAddressRegistration {
                owner: account.owner,
                subaccount: account.subaccount,
                address: deposit.value.address,
                expires_at_nanos: deposit.expires_at,
            })
            .collect();
        snapshot.sort_unstable_by_key(|deposit| Reverse(deposit.expires_at_nanos));

        snapshot
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
