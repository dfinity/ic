use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};
use minicbor::{Decode, Encode};
use phantom_newtype::Id;

pub fn decode<'b, Ctx, Repr, Tag>(
    d: &mut Decoder<'b>,
    ctx: &mut Ctx,
) -> Result<Id<Tag, Repr>, Error>
where
    Repr: Decode<'b, Ctx>,
{
    Ok(Id::new(Repr::decode(d, ctx)?))
}

pub fn encode<Ctx, Repr, Tag, W: Write>(
    v: &Id<Tag, Repr>,
    e: &mut Encoder<W>,
    ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    Repr: Encode<Ctx>,
{
    v.get_ref().encode(e, ctx)
}
