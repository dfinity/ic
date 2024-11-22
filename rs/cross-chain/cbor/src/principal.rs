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

pub mod option {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Decode, Encode)]
    #[cbor(transparent)]
    struct CborPrincipal(#[cbor(n(0), with = "crate::cbor::principal")] pub Principal);

    pub fn decode<Ctx>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Option<Principal>, Error> {
        Ok(Option::<CborPrincipal>::decode(d, ctx)?.map(|n| n.0))
    }

    pub fn encode<Ctx, W: Write>(
        v: &Option<Principal>,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        (*v).map(CborPrincipal).encode(e, ctx)
    }
}
