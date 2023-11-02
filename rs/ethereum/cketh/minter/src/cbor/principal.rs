use candid::Principal;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};

pub fn decode<Ctx>(d: &mut Decoder<'_>, _ctx: &mut Ctx) -> Result<Principal, Error> {
    let bytes = d.bytes()?;
    Principal::try_from_slice(bytes).map_err(|e| Error::message(e.to_string()))
}

pub fn encode<Ctx, W: Write>(
    v: &Principal,
    e: &mut Encoder<W>,
    _ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.bytes(v.as_slice())?;
    Ok(())
}
