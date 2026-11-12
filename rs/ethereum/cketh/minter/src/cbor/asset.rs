use crate::asset::Asset;
use ic_ethereum_types::Address;
use minicbor::data::Type;
use minicbor::decode::Decoder;
use minicbor::encode::{Encoder, Write};

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
