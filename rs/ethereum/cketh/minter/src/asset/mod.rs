use ic_ethereum_types::Address;
use minicbor::data::Type;
use minicbor::decode::Decoder;
use minicbor::encode::{Encoder, Write};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg(test)]
mod tests;

/// An asset depositable at a minter-controlled deposit address: native ETH or an ERC-20 token
/// identified by its Ethereum contract address. Explicit rather than a sentinel address, so the
/// ETH asset can never be confused with a token whose contract address is zero.
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

/// Encoded as the bare [`Address`] for [`Asset::Erc20`] — byte-identical to the address the
/// audit-log events held before this enum existed, so those events decode unchanged — and as
/// CBOR null for [`Asset::Eth`], which no address encoding ever produces.
impl<C> minicbor::Encode<C> for Asset {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Asset::Erc20(address) => address.encode(e, ctx),
            Asset::Eth => {
                e.null()?;
                Ok(())
            }
        }
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Asset {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        if d.datatype()? == Type::Null {
            d.null()?;
            return Ok(Asset::Eth);
        }
        Address::decode(d, ctx).map(Asset::Erc20)
    }
}
