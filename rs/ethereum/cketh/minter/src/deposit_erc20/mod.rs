use crate::deposit_address::{DepositAddressSchema, deposit_address};
use crate::endpoints::{DepositErc20Error, DepositMode};
use crate::state::State;
use crate::timed_sized_map::{InsertError, Timestamp};
use ic_secp256k1::PublicKey;
use icrc_ledger_types::icrc1::account::Account;

#[cfg(test)]
mod tests;

/// Derive the ckERC20 deposit address for `account` and register the
/// (account -> address) mapping in the bounded, time-expiring registry.
///
/// Returns the EIP-55 checksummed deposit address. Re-registering an
/// already-armed account returns the same address without re-arming it.
pub fn register_deposit_address(
    state: &mut State,
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    now: Timestamp,
    account: Account,
    mode: DepositMode,
) -> Result<String, DepositErc20Error> {
    match mode {
        DepositMode::Sponsored { .. } => {
            return Err(DepositErc20Error::TemporarilyUnavailable(
                "sponsored deposits are not yet supported".to_string(),
            ));
        }
        DepositMode::DeductFromDeposit => {}
    }

    let address = deposit_address(
        master_public_key,
        chain_code,
        DepositAddressSchema::CkErc20,
        &account,
    );
    let derived_address = address.to_string();

    match state.deposit_addresses.insert(now, account, address) {
        Ok(_) => Ok(derived_address),
        Err(InsertError::AlreadyPresent { .. }) => Ok(state
            .deposit_addresses
            .get(now, &account)
            .expect("BUG: AlreadyPresent implies a live stored entry")
            .to_string()),
        Err(InsertError::AtCapacity { .. }) => Err(DepositErc20Error::TooManyActiveAddresses),
    }
}
