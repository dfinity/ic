use candid::Nat;
use ic_icrc1_tokens_u256::U256;
use ic_stable_structures::storable::Storable;
use proptest::prelude::*;

fn arb_u256() -> impl Strategy<Value = U256> {
    (any::<u128>(), any::<u128>()).prop_map(|(x, y)| U256::from_words(x, y))
}

proptest! {
    #[test]
    fn nat_round_trip(v in arb_u256()) {
        prop_assert_eq!(Ok(v), Nat::from(v).try_into());
    }

    #[test]
    fn storable_round_trip(v in arb_u256()) {
        let encoded_v = v.to_bytes();
        prop_assert_eq!(U256::BOUND.max_size() as usize, encoded_v.len());
        prop_assert_eq!(v, U256::from_bytes(encoded_v));
    }

    #[test]
    fn cbor_roundtrip(v in arb_u256()) {
        let mut buf = vec![];
        ciborium::into_writer(&v, &mut buf).unwrap();
        let n: U256 = ciborium::from_reader(&buf[..]).unwrap();
        prop_assert_eq!(v, n);
    }

    #[test]
    fn cbor_u64_compact(v in any::<u64>()) {
        let mut buf = vec![];
        ciborium::into_writer(&v, &mut buf).unwrap();
        let n: U256 = ciborium::from_reader(&buf[..]).unwrap();
        prop_assert_eq!(Some(v), n.try_as_u64());
    }
}

#[test]
fn cbor_bignum_encoding() {
    let bignum = U256::from_words(0, u64::MAX as u128 + 1);
    let mut buf = vec![];
    ciborium::into_writer(&bignum, &mut buf).unwrap();
    // See: https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums
    assert_eq!(hex::encode(&buf), "c249010000000000000000");
}
