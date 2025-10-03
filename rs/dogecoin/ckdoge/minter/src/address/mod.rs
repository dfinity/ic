#[cfg(test)]
mod tests;

use crate::lifecycle::init::Network;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L167
const DOGE_MAINNET_PREFIX: u8 = 30;
const DOGE_MAINNET_P2SH_PREFIX: u8 = 22;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L327
const DOGE_TESTNET_PREFIX: u8 = 113;
const DOGE_TESTNET_P2SH_PREFIX: u8 = 196;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L472
const DOGE_REGTEST_PREFIX: u8 = 111;
const DOGE_REGTEST_P2SH_PREFIX: u8 = 196;

#[derive(Eq, PartialEq, Debug)]
pub enum DogecoinAddress {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
}

#[derive(Eq, PartialEq, Debug)]
pub enum ParseAddressError {
    UnsupportedAddressType,
    WrongNetwork { expected: Network, actual: Network },
    MalformedAddress(String),
    UnexpectedHumanReadablePart { expected: String, actual: String },
    NoData,
}

impl DogecoinAddress {
    pub fn parse(address: &str, network: &Network) -> Result<Self, ParseAddressError> {
        if address.len() > 125 {
            // 1 byte requires at most 5 base-58 characters
            // Decoded address must be 25 bytes.
            return Err(ParseAddressError::MalformedAddress(format!(
                "Expected an address with at most 125 base-58 characters, got {}",
                address.len()
            )));
        }

        let bytes = bs58::decode(address)
            .into_vec()
            .map_err(|e| ParseAddressError::MalformedAddress(e.to_string()))?;

        if bytes.is_empty() {
            return Err(ParseAddressError::NoData);
        }

        // P2PKH or P2SH address
        // 1 byte address type + 20 bytes of PK hash + 4 bytes of checksum
        if bytes.len() != 25 {
            return Err(ParseAddressError::MalformedAddress(format!(
                "Expected the address to be 25 bytes, got {}",
                bytes.len(),
            )));
        }

        let checksum = sha256(&sha256(&bytes[0..21]));
        if checksum[0..4] != bytes[21..25] {
            return Err(ParseAddressError::MalformedAddress(format!(
                "checksum mismatch expected {}, got {}",
                hex::encode(&checksum[0..4]),
                hex::encode(&bytes[21..25]),
            )));
        }

        let mut data: [u8; 20] = [0; 20];
        data.copy_from_slice(&bytes[1..21]);

        match (bytes[0], network) {
            (DOGE_MAINNET_PREFIX, Network::Mainnet)
            | (DOGE_TESTNET_PREFIX, Network::Testnet)
            | (DOGE_REGTEST_PREFIX, Network::Regtest) => Ok(Self::P2pkh(data)),
            (DOGE_MAINNET_P2SH_PREFIX, Network::Mainnet)
            | (DOGE_TESTNET_P2SH_PREFIX, Network::Testnet)
            | (DOGE_REGTEST_P2SH_PREFIX, Network::Regtest) => Ok(Self::P2sh(data)),
            (DOGE_MAINNET_PREFIX, _) | (DOGE_MAINNET_P2SH_PREFIX, _) => {
                Err(ParseAddressError::WrongNetwork {
                    actual: Network::Mainnet,
                    expected: *network,
                })
            }
            (DOGE_TESTNET_PREFIX, _) | (DOGE_TESTNET_P2SH_PREFIX, _) => {
                Err(ParseAddressError::WrongNetwork {
                    actual: Network::Testnet,
                    expected: *network,
                })
            }
            (DOGE_REGTEST_PREFIX, _) => Err(ParseAddressError::WrongNetwork {
                actual: Network::Regtest,
                expected: *network,
            }),
            _ => Err(ParseAddressError::UnsupportedAddressType),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DogecoinAddress::P2pkh(data) => data.as_slice(),
            DogecoinAddress::P2sh(data) => data.as_slice(),
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().into()
}
