//! Utilities to derive, display, and parse bitcoin addresses.

use crate::ECDSAPublicKey;
use ic_btc_types::Network;
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath, ExtendedBip32DerivationOutput};
use ic_icrc1::Account;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinAddress {
    WitnessV0([u8; 20]),
}

impl BitcoinAddress {
    /// Converts the address to the textual representation.
    pub fn display(&self, network: Network) -> String {
        match self {
            Self::WitnessV0(pkhash) => network_and_pkhash_to_p2wpkh(network, pkhash),
        }
    }
}

/// Returns the derivation path that should be used to sign a message from a
/// specified account.
pub fn derivation_path(account: &Account) -> Vec<Vec<u8>> {
    const SCHEMA_V1: u8 = 1;
    vec![
        vec![SCHEMA_V1],
        account.owner.as_slice().to_vec(),
        account.effective_subaccount().to_vec(),
    ]
}

/// Returns a valid extended BIP-32 derivation path from an Account (Principal + subaccount)
pub fn derive_public_key(ecdsa_public_key: &ECDSAPublicKey, account: &Account) -> ECDSAPublicKey {
    let ExtendedBip32DerivationOutput {
        derived_public_key,
        derived_chain_code,
    } = DerivationPath::new(
        derivation_path(account)
            .into_iter()
            .map(DerivationIndex)
            .collect(),
    )
    .key_derivation(&ecdsa_public_key.public_key, &ecdsa_public_key.chain_code)
    .unwrap(); // the derivation should always be possible
    ECDSAPublicKey {
        public_key: derived_public_key,
        chain_code: derived_chain_code,
    }
}

/// Derives a Bitcoin address for the specified account and converts it into
/// bech32 textual representation.
pub fn account_to_p2wpkh_address(
    network: Network,
    ecdsa_public_key: &ECDSAPublicKey,
    account: &Account,
) -> String {
    network_and_public_key_to_p2wpkh(
        network,
        &derive_public_key(ecdsa_public_key, account).public_key,
    )
}

/// Constructs the bitcoin address corresponding to the specified account.
pub fn account_to_bitcoin_address(
    ecdsa_public_key: &ECDSAPublicKey,
    account: &Account,
) -> BitcoinAddress {
    let pk = derive_public_key(ecdsa_public_key, account).public_key;
    BitcoinAddress::WitnessV0(crate::tx::hash160(&pk))
}

pub fn network_and_pkhash_to_p2wpkh(network: Network, pkhash: &[u8; 20]) -> String {
    use bech32::u5;

    let witness_version: u5 = u5::try_from_u8(0).unwrap();
    let data: Vec<u5> = std::iter::once(witness_version)
        .chain(
            bech32::convert_bits(&pkhash[..], 8, 5, true)
                .unwrap()
                .into_iter()
                .map(|b| u5::try_from_u8(b).unwrap()),
        )
        .collect();
    let hrp = hrp(network);
    bech32::encode(hrp, data, bech32::Variant::Bech32).unwrap()
}

/// Calculates the p2wpkh address as described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
///
/// # Panics
///
/// This function panics if the public key in not compressed.
pub fn network_and_public_key_to_p2wpkh(network: Network, public_key: &[u8]) -> String {
    assert_eq!(public_key.len(), 33);
    assert!(public_key[0] == 0x02 || public_key[0] == 0x03);

    network_and_pkhash_to_p2wpkh(network, &crate::tx::hash160(public_key))
}

/// Returns the human-readable part of a bech32 address
pub fn hrp(network: Network) -> &'static str {
    match network {
        ic_btc_types::Network::Mainnet => "bc",
        ic_btc_types::Network::Testnet => "tb",
        ic_btc_types::Network::Regtest => "bcrt",
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseAddressError {
    MalformedAddress(String),
    UnsupportedWitnessVersion(u8),
    UnexpectedHumanReadablePart { expected: String, actual: String },
    BadWitnessLength { expected: usize, actual: usize },
    NoData,
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedAddress(msg) => write!(fmt, "{}", msg),
            Self::UnsupportedWitnessVersion(v) => write!(fmt, "unsupported witness version {}", v),
            Self::UnexpectedHumanReadablePart { expected, actual } => {
                write!(fmt, "expected address HRP {}, got {}", expected, actual)
            }
            Self::BadWitnessLength { expected, actual } => write!(
                fmt,
                "expected witness program of length {}, got {}",
                expected, actual
            ),
            Self::NoData => write!(fmt, "the address contains no data"),
        }
    }
}

/// Parses a BIP-0173 address.
pub fn parse_address(address: &str, network: Network) -> Result<BitcoinAddress, ParseAddressError> {
    let (found_hrp, five_bit_groups, _) =
        bech32::decode(address).map_err(|e| ParseAddressError::MalformedAddress(e.to_string()))?;
    let expected_hrp = hrp(network);

    if found_hrp.to_lowercase() != expected_hrp {
        return Err(ParseAddressError::UnexpectedHumanReadablePart {
            expected: expected_hrp.to_string(),
            actual: found_hrp,
        });
    }

    if five_bit_groups.is_empty() {
        return Err(ParseAddressError::NoData);
    }

    let witness_version = five_bit_groups[0].to_u8();

    if witness_version != 0 {
        return Err(ParseAddressError::UnsupportedWitnessVersion(
            witness_version,
        ));
    }

    let data = bech32::convert_bits(
        &five_bit_groups[1..],
        /*from=*/ 5,
        /*to=*/ 8,
        /*pad=*/ false,
    )
    .map_err(|e| {
        ParseAddressError::MalformedAddress(format!(
            "failed to decode witness from address {}: {}",
            address, e
        ))
    })?;

    if data.len() != 20 {
        return Err(ParseAddressError::BadWitnessLength {
            expected: 20,
            actual: data.len(),
        });
    }

    let mut pkhash = [0u8; 20];
    pkhash[..].copy_from_slice(&data[..]);

    Ok(BitcoinAddress::WitnessV0(pkhash))
}

#[cfg(test)]
mod tests {
    use super::{hrp, parse_address, BitcoinAddress, ParseAddressError};
    use bech32::u5;
    use ic_btc_types::Network;

    fn generate_address(witness_version: Option<u8>, data: &[u8], network: Network) -> String {
        let data: Vec<u5> = witness_version
            .iter()
            .map(|n| u5::try_from_u8(*n).unwrap())
            .chain(
                bech32::convert_bits(data, 8, 5, true)
                    .unwrap()
                    .into_iter()
                    .map(|b| u5::try_from_u8(b).unwrap()),
            )
            .collect();
        let hrp = hrp(network);
        bech32::encode(hrp, data, bech32::Variant::Bech32).unwrap()
    }

    #[test]
    fn test_check_address() {
        assert_eq!(
            Ok(BitcoinAddress::WitnessV0([
                117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67,
                59, 214
            ])),
            parse_address(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                Network::Mainnet
            )
        );
        assert_eq!(
            Ok(BitcoinAddress::WitnessV0([
                117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67,
                59, 214
            ])),
            parse_address(
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                Network::Mainnet
            )
        );

        // Invalid checksum.
        parse_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            Network::Mainnet,
        )
        .unwrap_err();

        assert_eq!(
            ParseAddressError::UnsupportedWitnessVersion(1),
            parse_address(
                &generate_address(Some(1), &[0u8; 20], Network::Mainnet),
                Network::Mainnet,
            )
            .unwrap_err()
        );

        assert_eq!(
            ParseAddressError::NoData,
            parse_address(
                &generate_address(None, b"", Network::Mainnet),
                Network::Mainnet,
            )
            .unwrap_err()
        );

        assert_eq!(
            ParseAddressError::UnexpectedHumanReadablePart {
                expected: "bc".to_string(),
                actual: "tb".to_string()
            },
            parse_address(
                &generate_address(Some(0), &[0; 20], Network::Testnet),
                Network::Mainnet,
            )
            .unwrap_err()
        );

        assert_eq!(
            ParseAddressError::BadWitnessLength {
                expected: 20,
                actual: 32,
            },
            parse_address(
                &generate_address(Some(0), &[0; 32], Network::Mainnet),
                Network::Mainnet,
            )
            .unwrap_err()
        );
    }
}
