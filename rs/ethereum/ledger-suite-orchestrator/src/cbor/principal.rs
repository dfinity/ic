use candid::Principal;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};

//TODO: extract to separate crate since also used in ckETH
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

pub mod vec {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Encode, Decode)]
    #[cbor(transparent)]
    struct CborPrincipal(#[cbor(n(0), with = "crate::cbor::principal")] Principal);

    pub fn decode<Ctx>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Vec<Principal>, Error> {
        Ok(Vec::<CborPrincipal>::decode(d, ctx)?
            .into_iter()
            .map(|p| p.0)
            .collect())
    }

    pub fn encode<Ctx, W: Write>(
        v: &[Principal],
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        v.iter()
            .map(|p| CborPrincipal(*p))
            .collect::<Vec<_>>()
            .encode(e, ctx)
    }
}
