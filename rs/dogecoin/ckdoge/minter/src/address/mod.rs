#[cfg(test)]
mod tests;

use crate::lifecycle::init::Network;
use std::fmt;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L167
const DOGE_MAINNET_P2PKH_PREFIX: u8 = 30;
const DOGE_MAINNET_P2SH_PREFIX: u8 = 22;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L327
const DOGE_TESTNET_P2PKH_PREFIX: u8 = 113;
const DOGE_TESTNET_P2SH_PREFIX: u8 = 196;

// See https://github.com/dogecoin/dogecoin/blob/7237da74b8c356568644cbe4fba19d994704355b/src/chainparams.cpp#L472
const DOGE_REGTEST_P2PKH_PREFIX: u8 = 111;
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
    NoData,
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAddressType => {
                write!(fmt, "ckDOGE supports only P2PKH and P2SH addresses")
            }
            Self::WrongNetwork { expected, actual } => {
                write!(
                    fmt,
                    "expected an address from network {expected}, got an address from network {actual}"
                )
            }
            Self::MalformedAddress(msg) => write!(fmt, "{msg}"),
            Self::NoData => write!(fmt, "the address contains no data"),
        }
    }
}

impl DogecoinAddress {
    pub fn parse(address: &str, network: &Network) -> Result<Self, ParseAddressError> {
        // Same limit as
        // https://github.com/dfinity/rust-dogecoin/blob/b24563ead9c61522e05b144d527c4b114befc301/bitcoin/src/dogecoin/address/mod.rs#L534
        if address.len() > 50 {
            return Err(ParseAddressError::MalformedAddress(format!(
                "Expected an address with at most 50 base-58 characters, got {}",
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
            (DOGE_MAINNET_P2PKH_PREFIX, Network::Mainnet)
            | (DOGE_TESTNET_P2PKH_PREFIX, Network::Testnet)
            | (DOGE_REGTEST_P2PKH_PREFIX, Network::Regtest) => Ok(Self::P2pkh(data)),
            (DOGE_MAINNET_P2SH_PREFIX, Network::Mainnet)
            | (DOGE_TESTNET_P2SH_PREFIX, Network::Testnet)
            | (DOGE_REGTEST_P2SH_PREFIX, Network::Regtest) => Ok(Self::P2sh(data)),
            (DOGE_MAINNET_P2PKH_PREFIX, _) | (DOGE_MAINNET_P2SH_PREFIX, _) => {
                Err(ParseAddressError::WrongNetwork {
                    actual: Network::Mainnet,
                    expected: *network,
                })
            }
            (DOGE_TESTNET_P2PKH_PREFIX, _) | (DOGE_TESTNET_P2SH_PREFIX, _) => {
                Err(ParseAddressError::WrongNetwork {
                    actual: Network::Testnet,
                    expected: *network,
                })
            }
            (DOGE_REGTEST_P2PKH_PREFIX, _) => Err(ParseAddressError::WrongNetwork {
                actual: Network::Regtest,
                expected: *network,
            }),
            _ => Err(ParseAddressError::UnsupportedAddressType),
        }
    }

    pub fn display(&self, network: &Network) -> String {
        let prefix = match (self, network) {
            (DogecoinAddress::P2pkh(_), Network::Mainnet) => DOGE_MAINNET_P2PKH_PREFIX,
            (DogecoinAddress::P2sh(_), Network::Mainnet) => DOGE_MAINNET_P2SH_PREFIX,
            (DogecoinAddress::P2pkh(_), Network::Testnet) => DOGE_TESTNET_P2PKH_PREFIX,
            (DogecoinAddress::P2sh(_), Network::Testnet) => DOGE_TESTNET_P2SH_PREFIX,
            (DogecoinAddress::P2pkh(_), Network::Regtest) => DOGE_REGTEST_P2PKH_PREFIX,
            (DogecoinAddress::P2sh(_), Network::Regtest) => DOGE_REGTEST_P2SH_PREFIX,
        };
        version_and_hash_to_address(prefix, self.as_array())
    }

    fn as_array(&self) -> &[u8; 20] {
        match self {
            DogecoinAddress::P2pkh(data) => data,
            DogecoinAddress::P2sh(data) => data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DogecoinAddress::P2pkh(data) => data.as_slice(),
            DogecoinAddress::P2sh(data) => data.as_slice(),
        }
    }

    pub fn from_compressed_public_key(public_key: &[u8; 33]) -> Self {
        assert!(public_key[0] == 0x02 || public_key[0] == 0x03);
        DogecoinAddress::P2pkh(ic_ckbtc_minter::tx::hash160(public_key))
    }
}

pub fn version_and_hash_to_address(version: u8, hash: &[u8; 20]) -> String {
    let mut buf = Vec::with_capacity(25);
    buf.push(version);
    buf.extend_from_slice(hash);
    let sha256d = sha256(&sha256(&buf));
    buf.extend_from_slice(&sha256d[0..4]);
    bs58::encode(&buf).into_string()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().into()
}
