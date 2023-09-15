use ethnum::u256;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};
use phantom_newtype::Id;

pub fn decode<Ctx, Tag>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Id<Tag, u256>, Error> {
    Ok(Id::new(super::u256::decode(d, ctx)?))
}

pub fn encode<Ctx, Tag, W: Write>(
    v: &Id<Tag, u256>,
    e: &mut Encoder<W>,
    ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    super::u256::encode(v.get_ref(), e, ctx)
}
