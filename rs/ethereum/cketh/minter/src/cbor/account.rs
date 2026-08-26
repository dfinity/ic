use candid::Principal;
use icrc_ledger_types::icrc1::account::Account;
use minicbor::decode::{Decoder, Error};
use minicbor::encode::{Encoder, Write};
use minicbor::{Decode, Encode};

/// An [`Account`] split the way the minter's events carry one: an owner and an optional 32-byte
/// subaccount, rather than the ICRC-1 type itself.
#[derive(Decode, Encode)]
struct CborAccount {
    #[cbor(n(0), with = "icrc_cbor::principal")]
    owner: Principal,
    #[cbor(n(1), with = "minicbor::bytes")]
    subaccount: Option<[u8; 32]>,
}

pub fn decode<Ctx>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Account, Error> {
    let CborAccount { owner, subaccount } = CborAccount::decode(d, ctx)?;
    Ok(Account { owner, subaccount })
}

pub fn encode<Ctx, W: Write>(
    v: &Account,
    e: &mut Encoder<W>,
    ctx: &mut Ctx,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    CborAccount {
        owner: v.owner,
        subaccount: v.subaccount,
    }
    .encode(e, ctx)
}
