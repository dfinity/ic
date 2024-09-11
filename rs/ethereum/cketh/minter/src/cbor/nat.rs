use candid::Nat;
use minicbor::data::Tag;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

pub fn decode<Ctx>(d: &mut Decoder<'_>, _ctx: &mut Ctx) -> Result<Nat, Error> {
    let pos = d.position();
    match d.u64() {
        Ok(n) => return Ok(Nat::from(n)),
        Err(e) if e.is_type_mismatch() => {
            d.set_position(pos);
        }
        Err(e) => return Err(e),
    }
    let tag: Tag = d.tag()?;
    if tag != Tag::PosBignum {
        return Err(Error::message(
            "failed to parse Nat: expected the PosBignum tag",
        ));
    }
    let be_bytes = d.bytes()?;
    Ok(Nat(BigUint::from_bytes_be(be_bytes)))
}

pub fn encode<Ctx, W: Write>(
    v: &Nat,
    e: &mut Encoder<W>,
    _ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    if let Some(n) = v.0.to_u32() {
        return e.u32(n)?.ok();
    }
    match v.0.to_u64() {
        Some(n) => e.u64(n)?.ok(),
        None => e.tag(Tag::PosBignum)?.bytes(&v.0.to_bytes_be())?.ok(),
    }
}

pub mod option {
    use super::*;
    use minicbor::{Decode, Encode};

    #[derive(Decode, Encode)]
    #[cbor(transparent)]
    struct CborNat(#[cbor(n(0), with = "crate::cbor::nat")] pub Nat);

    pub fn decode<Ctx>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Option<Nat>, Error> {
        Ok(Option::<CborNat>::decode(d, ctx)?.map(|n| n.0))
    }

    pub fn encode<Ctx, W: Write>(
        v: &Option<Nat>,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        v.clone().map(CborNat).encode(e, ctx)
    }
}
