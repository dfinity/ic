use candid::{Nat, Principal};
#[cfg(feature = "u256")]
use ethnum::{U256, u256};
use minicbor::{Decode, Encode};
use proptest::collection::vec as pvec;
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

#[cfg(feature = "u256")]
#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct U256Container {
    #[cbor(n(0), with = "crate::u256")]
    pub value: u256,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct NatContainer {
    #[cbor(n(0), with = "crate::nat")]
    pub value: Nat,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct OptNatContainer {
    #[cbor(n(0), with = "crate::nat::option")]
    pub value: Option<Nat>,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct PrincipalContainer {
    #[cbor(n(0), with = "crate::principal")]
    pub value: Principal,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
struct OptPrincipalContainer {
    #[cbor(n(0), with = "crate::principal::option")]
    pub value: Option<Principal>,
}

proptest! {
    #[cfg(feature = "u256")]
    #[test]
    fn u256_encoding_roundtrip((hi, lo) in (any::<u128>(), any::<u128>())) {
        check_roundtrip(&U256Container {
            value: U256([hi, lo]),
        })?;
    }

    #[cfg(feature = "u256")]
    #[test]
    fn u256_small_value_encoding_roundtrip(n in any::<u64>()) {
        check_roundtrip(&U256Container {
            value: u256::from(n),
        })?;
    }

    #[test]
    fn nat_encoding_roundtrip(n in any::<u128>()) {
        check_roundtrip(&NatContainer {
            value: Nat::from(n),
        })?;
    }

    #[test]
    fn opt_nat_encoding_roundtrip(n in proptest::option::of(any::<u128>())) {
        check_roundtrip(&OptNatContainer {
            value: n.map(Nat::from),
        })?;
    }

    #[test]
    fn principal_encoding_roundtrip(p in pvec(any::<u8>(), 0..30)) {
        check_roundtrip(&PrincipalContainer {
            value: Principal::from_slice(&p),
        })?;
    }

    #[test]
    fn opt_principal_encoding_roundtrip(p in proptest::option::of(pvec(any::<u8>(), 0..30))) {
        check_roundtrip(&OptPrincipalContainer {
            value: p.map(|principal| Principal::from_slice(&principal)),
        })?;
    }
}
