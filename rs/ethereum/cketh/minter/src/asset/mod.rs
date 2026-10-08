use ic_ethereum_types::Address;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// An asset depositable at a minter-controlled deposit address: native ETH or an ERC-20 token
/// identified by its Ethereum contract address. Explicit rather than a sentinel address, so the
/// ETH asset can never be confused with a token whose contract address is zero.
///
/// The CBOR encoding lives in [`crate::cbor`], next to the other custom codecs.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum Asset {
    Eth,
    Erc20(Address),
}

impl Asset {
    pub fn erc20_contract_address(&self) -> Option<Address> {
        match self {
            Asset::Erc20(address) => Some(*address),
            Asset::Eth => None,
        }
    }
}

impl From<Address> for Asset {
    fn from(address: Address) -> Self {
        Asset::Erc20(address)
    }
}

/// The ETH asset, as a type: code generic over the asset kind uses this and [`Erc20Asset`]
/// where mixing the kinds up must not compile, and [`Asset`] where both are handled alike.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct EthAsset;

/// An ERC-20 token, as a type: the compile-time counterpart of [`Asset::Erc20`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Erc20Asset(Address);

impl Erc20Asset {
    pub fn new(contract_address: Address) -> Self {
        Self(contract_address)
    }

    pub fn contract_address(&self) -> Address {
        self.0
    }
}

impl From<EthAsset> for Asset {
    fn from(_: EthAsset) -> Self {
        Asset::Eth
    }
}

impl From<Erc20Asset> for Asset {
    fn from(token: Erc20Asset) -> Self {
        Asset::Erc20(token.contract_address())
    }
}

impl Display for Asset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Asset::Eth => write!(f, "ETH"),
            Asset::Erc20(address) => Display::fmt(address, f),
        }
    }
}

impl FromStr for Asset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "ETH" {
            return Ok(Asset::Eth);
        }
        Address::from_str(s).map(Asset::Erc20)
    }
}
