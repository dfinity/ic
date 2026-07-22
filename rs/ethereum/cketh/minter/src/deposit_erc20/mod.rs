use crate::deposit_address::{DepositAddressSchema, deposit_address};
use crate::endpoints::DepositErc20Error;
use crate::state::State;
use crate::timed_sized_map::Timestamp;
use ic_ethereum_types::Address;
use ic_secp256k1::PublicKey;
use icrc_ledger_types::icrc1::account::Account;

#[cfg(test)]
mod tests;

/// Derive the ckERC20 deposit address for `account` and register the
/// (account -> address) mapping in the bounded, time-expiring watchlist.
///
/// Returns the deposit address together with the timestamp until which a
/// deposit to it is guaranteed to be noticed. Re-registering an already-armed
/// account returns the same address and validity window without re-arming it.
pub fn register_deposit_address(
    state: &mut State,
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    now: Timestamp,
    account: Account,
) -> Result<(Address, Timestamp), DepositErc20Error> {
    let address = deposit_address(
        master_public_key,
        chain_code,
        DepositAddressSchema::CkErc20,
        &account,
    );
    state
        .automatic_deposits
        .watch_address_for_account(now, account, address)
}
