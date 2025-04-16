use crate::checked_amount::CheckedAmountOf;
use minicbor::{Decode, Encode};
use phantom_newtype::Id;
use proptest::prelude::*;

pub fn check_roundtrip<T>(v: &T) -> Result<(), TestCaseError>
where
    for<'a> T: PartialEq + std::fmt::Debug + Encode<()> + Decode<'a, ()>,
{
    let mut buf = vec![];
    minicbor::encode(v, &mut buf).expect("encoding should succeed");
    let decoded = minicbor::decode(&buf).expect("decoding should succeed");
    prop_assert_eq!(v, &decoded);
    Ok(())
}

enum IdTag {}
type U256Newtype = CheckedAmountOf<IdTag>;
type U64Newtype = Id<IdTag, u64>;

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct U256NewtypeContainer {
    #[cbor(n(0))]
    pub value: U256Newtype,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct U64NewtypeContainer {
    #[cbor(n(0), with = "crate::cbor::id")]
    pub value: U64Newtype,
}

proptest! {
    #[test]
    fn checked_amount_of_encoding_roundtrip((hi, lo) in (any::<u128>(), any::<u128>())) {
        check_roundtrip(&U256NewtypeContainer {
            value: U256Newtype::from_words(hi, lo),
        })?;
    }

    #[test]
    fn u64_id_encoding_roundtrip(n in any::<u64>()) {
        check_roundtrip(&U64NewtypeContainer {
            value: U64Newtype::new(n),
        })?;
    }
}
