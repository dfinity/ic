use crate::address::ecdsa_public_key_to_address;
use ic_ethereum_types::Address;
use ic_secp256k1::{DerivationIndex, DerivationPath, PublicKey};
use icrc_ledger_types::icrc1::account::Account;
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
    account: &Account,
) -> Address {
    derive_address(
        master_public_key,
        chain_code,
        deposit_derivation_path(schema, account),
    )
}

/// Derive the minter's dedicated sweeper address from its master
/// threshold-ECDSA public key.
pub fn sweeper_address(master_public_key: &PublicKey, chain_code: &[u8; 32]) -> Address {
    derive_address(master_public_key, chain_code, sweeper_derivation_path())
}

fn deposit_derivation_path(schema: DepositAddressSchema, account: &Account) -> Vec<ByteBuf> {
    vec![
        ByteBuf::from(vec![schema.tag()]),
        ByteBuf::from(account.owner.as_slice().to_vec()),
        ByteBuf::from(account.effective_subaccount().to_vec()),
    ]
}

fn sweeper_derivation_path() -> Vec<ByteBuf> {
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
