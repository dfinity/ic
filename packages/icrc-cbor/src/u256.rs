use ethnum::u256;
use minicbor::data::Tag;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};

const U32_MAX: u256 = u256::new(u32::MAX as u128);
const U64_MAX: u256 = u256::new(u64::MAX as u128);

pub fn decode<Ctx>(d: &mut Decoder<'_>, _ctx: &mut Ctx) -> Result<u256, Error> {
    let pos = d.position();
    match d.u64() {
        Ok(n) => return Ok(u256::from(n)),
        Err(e) if e.is_type_mismatch() => {
            d.set_position(pos);
        }
        Err(e) => return Err(e),
    }

    let tag: Tag = d.tag()?;
    if tag != Tag::PosBignum {
        return Err(Error::message(
            "failed to parse u256: expected a PosBignum tag",
        ));
    }
    let bytes = d.bytes()?;
    if bytes.len() > 32 {
        return Err(Error::message(format!(
            "failed to parse u256: expected at most 32 bytes, got: {}",
            bytes.len()
        )));
    }
    let mut be_bytes = [0u8; 32];
    be_bytes[32 - bytes.len()..32].copy_from_slice(bytes);
    Ok(u256::from_be_bytes(be_bytes))
}

pub fn encode<Ctx, W: Write>(
    v: &u256,
    e: &mut Encoder<W>,
    _ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    if v <= &U32_MAX {
        e.u32(v.as_u32())?;
    } else if v <= &U64_MAX {
        e.u64(v.as_u64())?;
    } else {
        let be_bytes = v.to_be_bytes();
        let non_zero_pos = be_bytes
            .iter()
            .position(|x| *x != 0)
            .unwrap_or(be_bytes.len());
        e.tag(Tag::PosBignum)?.bytes(&be_bytes[non_zero_pos..])?;
    }
    Ok(())
}
