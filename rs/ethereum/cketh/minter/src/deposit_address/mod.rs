use crate::address::ecdsa_public_key_to_address;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PublicKey};
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode};
use serde_bytes::ByteBuf;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// An Ethereum address the minter controls and derived for a single IC account, to which that
/// account's deposits are sent.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug, Decode, Encode)]
#[cbor(transparent)]
pub struct DepositAddress(#[n(0)] Address);

impl DepositAddress {
    /// Tag an [`Address`] as a deposit address. [`deposit_address`] is the only caller that
    /// derives one; everything else reconstructs an address the minter derived earlier (event
    /// replay, tests), so this asserts provenance rather than establishing it.
    pub const fn new(address: Address) -> Self {
        Self(address)
    }

    /// The underlying Ethereum address, for the boundaries that need the raw value (ABI encoding,
    /// the Candid layer). Deliberately explicit: every use is a place the distinction is dropped.
    pub const fn as_address(&self) -> &Address {
        &self.0
    }
}

impl Display for DepositAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FromStr for DepositAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).map(Self)
    }
}

const CKERC20_DEPOSIT_SCHEMA_TAG: u8 = 1;
const CKETH_DEPOSIT_SCHEMA_TAG: u8 = 2;
const SWEEPER_SCHEMA_TAG: u8 = 3;

/// Schema tag distinguishing the families of per-account deposit addresses
/// derived by the minter.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum DepositAddressSchema {
    CkErc20,
    CkEth,
}

impl DepositAddressSchema {
    fn tag(self) -> u8 {
        match self {
            DepositAddressSchema::CkErc20 => CKERC20_DEPOSIT_SCHEMA_TAG,
            DepositAddressSchema::CkEth => CKETH_DEPOSIT_SCHEMA_TAG,
        }
    }
}

/// Derive the deposit address of an IC account for the given schema from the
/// minter's master threshold-ECDSA public key.
pub fn deposit_address(
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    schema: DepositAddressSchema,
    account: &Account,
) -> DepositAddress {
    DepositAddress::new(derive_address(
        master_public_key,
        chain_code,
        deposit_derivation_path(schema, account),
    ))
}

/// Derive the minter's dedicated sweeper address from its master
/// threshold-ECDSA public key.
pub fn sweeper_address(master_public_key: &PublicKey, chain_code: &[u8; 32]) -> Address {
    derive_address(master_public_key, chain_code, sweeper_derivation_path())
}

pub fn deposit_derivation_path(schema: DepositAddressSchema, account: &Account) -> Vec<ByteBuf> {
    vec![
        ByteBuf::from(vec![schema.tag()]),
        ByteBuf::from(account.owner.as_slice().to_vec()),
        ByteBuf::from(account.effective_subaccount().to_vec()),
    ]
}

pub(crate) fn sweeper_derivation_path() -> Vec<ByteBuf> {
    vec![ByteBuf::from(vec![SWEEPER_SCHEMA_TAG])]
}

fn derive_address(
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    derivation_path: Vec<ByteBuf>,
) -> Address {
    ecdsa_public_key_to_address(&derive_public_key(
        master_public_key,
        chain_code,
        &derivation_path,
    ))
}

/// The public key the minter signs with under `derivation_path`, derived non-hardened from its
/// master threshold-ECDSA key.
///
/// Every address in the derivation tree is this key's address, and every signature the minter makes
/// under that path verifies against it — which is why recovering a signature's parity must use it
/// and not the master key (an empty path derives to the master key itself, so the main address is
/// the one case where the two coincide).
pub fn derive_public_key(
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    derivation_path: &[ByteBuf],
) -> PublicKey {
    let derivation_path = DerivationPath::new(
        derivation_path
            .iter()
            .map(|index| DerivationIndex(index.to_vec()))
            .collect(),
    );
    master_public_key
        .derive_subkey_with_chain_code(&derivation_path, chain_code)
        .0
}
