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
