use crate::address::ecdsa_public_key_to_address;
use crate::eth_logs::{LedgerSubaccount, principal_to_bytes32};
use candid::Principal;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PublicKey};
use serde_bytes::ByteBuf;

#[cfg(test)]
mod tests;

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
    owner: &Principal,
    subaccount: Option<&LedgerSubaccount>,
) -> Address {
    derive_address(
        master_public_key,
        chain_code,
        deposit_derivation_path(schema, owner, subaccount),
    )
}

/// Derive the minter's dedicated sweeper address from its master
/// threshold-ECDSA public key.
pub fn sweeper_address(master_public_key: &PublicKey, chain_code: &[u8; 32]) -> Address {
    derive_address(master_public_key, chain_code, sweeper_derivation_path())
}

/// Derivation path of an IC account's deposit address for the given schema.
///
/// The path is non-empty and therefore never collides with the empty
/// [`crate::MAIN_DERIVATION_PATH`] used for the minter's main address.
pub fn deposit_derivation_path(
    schema: DepositAddressSchema,
    owner: &Principal,
    subaccount: Option<&LedgerSubaccount>,
) -> Vec<ByteBuf> {
    vec![
        ByteBuf::from(vec![schema.tag()]),
        ByteBuf::from(principal_to_bytes32(owner).to_vec()),
        ByteBuf::from(subaccount_to_bytes32(subaccount).to_vec()),
    ]
}

/// Derivation path of the minter's dedicated sweeper address.
pub fn sweeper_derivation_path() -> Vec<ByteBuf> {
    vec![ByteBuf::from(vec![SWEEPER_SCHEMA_TAG])]
}

fn derive_address(
    master_public_key: &PublicKey,
    chain_code: &[u8; 32],
    derivation_path: Vec<ByteBuf>,
) -> Address {
    let derivation_path = DerivationPath::new(
        derivation_path
            .into_iter()
            .map(|index| DerivationIndex(index.into_vec()))
            .collect(),
    );
    let (derived_public_key, _derived_chain_code) =
        master_public_key.derive_subkey_with_chain_code(&derivation_path, chain_code);
    ecdsa_public_key_to_address(&derived_public_key)
}

fn subaccount_to_bytes32(subaccount: Option<&LedgerSubaccount>) -> [u8; 32] {
    subaccount
        .cloned()
        .map(LedgerSubaccount::to_bytes)
        .unwrap_or([0_u8; 32])
}
