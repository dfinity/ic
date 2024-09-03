use ic_crypto_secp256k1::PublicKey;
use ic_ethereum_types::Address;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(test)]
mod tests;

pub fn ecdsa_public_key_to_address(pubkey: &PublicKey) -> ic_ethereum_types::Address {
    let key_bytes = pubkey.serialize_sec1(/*compressed=*/ false);
    debug_assert_eq!(key_bytes[0], 0x04);
    let hash = keccak(&key_bytes[1..]);
    let mut addr = [0u8; 20];
    addr[..].copy_from_slice(&hash[12..32]);
    ic_ethereum_types::Address::new(addr)
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    ic_crypto_sha3::Keccak256::hash(bytes)
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum AddressValidationError {
    Invalid { error: String },
    NotSupported(Address),
    Blocked(Address),
}

impl Display for AddressValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AddressValidationError::Invalid { error } => {
                write!(f, "Invalid address: {}", error)
            }
            AddressValidationError::NotSupported(address) => {
                write!(f, "Address {} is not supported", address)
            }
            AddressValidationError::Blocked(address) => {
                write!(f, "address {} is blocked", address)
            }
        }
    }
}

/// Validate whether the given address can be used as the destination of an Ethereum transaction.
pub fn validate_address_as_destination(address: &str) -> Result<Address, AddressValidationError> {
    let address =
        Address::from_str(address).map_err(|e| AddressValidationError::Invalid { error: e })?;
    if address == Address::ZERO {
        return Err(AddressValidationError::NotSupported(address));
    }
    if crate::blocklist::is_blocked(&address) {
        return Err(AddressValidationError::Blocked(address));
    }
    Ok(address)
}
