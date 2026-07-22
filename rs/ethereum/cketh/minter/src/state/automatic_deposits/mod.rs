use crate::endpoints::DepositErc20Error;
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
    ) -> Result<(Address, Timestamp), DepositErc20Error> {
        match self
            .watchlist
            .insert(now, account, DepositRequest::from(address))
        {
            Ok(_) => Ok((address, valid_until(now))),
            Err(InsertError::AlreadyPresent { .. }) => {
                let entry = self
                    .watchlist
                    .get_entry(now, &account)
                    .expect("BUG: AlreadyPresent implies a live stored entry");
                Ok((entry.value.address, valid_until(entry.inserted_at)))
            }
            Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveAddresses),
        }
    }

    pub fn watchlist_iter(&self) -> impl Iterator<Item = (&Account, &Entry<DepositRequest>)> {
        self.watchlist.iter()
    }

    /// The watched address for `account`, or `None` if absent or expired as of `now`.
    pub fn get(&self, now: Timestamp, account: &Account) -> Option<&Address> {
        self.watchlist
            .get(now, account)
            .map(|request| &request.address)
    }

    /// Rebuild the watchlist from a previously captured snapshot, preserving each entry's original
    /// registration time. This is a trusted restore of an already-valid snapshot.
    pub fn from_entries(entries: impl IntoIterator<Item = (Timestamp, Account, Address)>) -> Self {
        Self {
            watchlist: TimedSizedMap::from_entries(
                DEPOSIT_ADDRESS_SCAN_WINDOW,
                MAX_ACTIVE_DEPOSIT_ADDRESSES,
                entries
                    .into_iter()
                    .map(|(registered_at, account, address)| {
                        (registered_at, account, DepositRequest::from(address))
                    }),
            ),
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

/// The timestamp until which a deposit address registered at `registered_at` is
/// kept armed, i.e. `registered_at + DEPOSIT_ADDRESS_SCAN_WINDOW`.
fn valid_until(registered_at: Timestamp) -> Timestamp {
    Timestamp::from_nanos(
        registered_at
            .as_nanos()
            .saturating_add(DEPOSIT_ADDRESS_SCAN_WINDOW.as_nanos() as u64),
    )
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
