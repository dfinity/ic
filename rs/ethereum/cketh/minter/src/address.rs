use candid::CandidType;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter, LowerHex, UpperHex};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// An Ethereum account address.
#[derive(
    Clone,
    Copy,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    CandidType,
)]
#[serde(transparent)]
#[cbor(transparent)]
pub struct Address(
    #[serde(with = "crate::serde_data")]
    #[cbor(n(0), with = "minicbor::bytes")]
    [u8; 20],
);

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Address {
    pub const ZERO: Self = Self([0u8; 20]);

    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        let key_bytes = pubkey.serialize_sec1(/*compressed=*/ false);
        debug_assert_eq!(key_bytes[0], 0x04);
        let hash = keccak(&key_bytes[1..]);
        let mut addr = [0u8; 20];
        addr[..].copy_from_slice(&hash[12..32]);
        Self(addr)
    }
}

impl LowerHex for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

impl TryFrom<&[u8; 32]> for Address {
    type Error = String;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        let (leading_zeroes, address_bytes) = value.split_at(12);
        if !leading_zeroes.iter().all(|leading_zero| *leading_zero == 0) {
            return Err(format!(
                "address has leading non-zero bytes: {:?}",
                leading_zeroes
            ));
        }
        Ok(Address::new(
            <[u8; 20]>::try_from(address_bytes).expect("vector has correct length"),
        ))
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("address doesn't start with '0x'".to_string());
        }
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("address is not hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display address using EIP-55
        // https://eips.ethereum.org/EIPS/eip-55
        let mut addr_chars = [0u8; 20 * 2];
        hex::encode_to_slice(self.0, &mut addr_chars)
            .expect("bug: failed to encode an address as hex");

        let checksum = keccak(&addr_chars[..]);
        let mut cs_nibbles = [0u8; 32 * 2];
        for i in 0..32 {
            cs_nibbles[2 * i] = checksum[i] >> 4;
            cs_nibbles[2 * i + 1] = checksum[i] & 0x0f;
        }
        write!(f, "0x")?;
        for (a, cs) in addr_chars.iter().zip(cs_nibbles.iter()) {
            let ascii_byte = if *cs >= 0x08 {
                a.to_ascii_uppercase()
            } else {
                *a
            };
            write!(f, "{}", char::from(ascii_byte))?;
        }
        Ok(())
    }
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    ic_crypto_sha3::Keccak256::hash(bytes)
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressValidationError {
    ContractCreation,
}

impl Display for AddressValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AddressValidationError::ContractCreation => {
                write!(
                    f,
                    "contract creation address {} is not supported",
                    Address::ZERO
                )
            }
        }
    }
}

/// Validate whether the given address can be used as the destination of an Ethereum transaction.
// TODO FI-902: add blocklist check
pub fn validate_address_as_destination(
    address: Address,
) -> Result<Address, AddressValidationError> {
    if address == Address::ZERO {
        return Err(AddressValidationError::ContractCreation);
    }
    Ok(address)
}
