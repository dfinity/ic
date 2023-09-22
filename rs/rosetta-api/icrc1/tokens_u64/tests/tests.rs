use ic_icrc1_tokens_u64::U64;
use ic_ledger_core::tokens::Tokens;
use proptest::prelude::*;

proptest! {
    #[test]
    fn decode_u64_amounts(value in any::<u64>()) {
        let mut buf = vec![];
        ciborium::into_writer(&value, &mut buf).unwrap();
        let amount: U64 = ciborium::de::from_reader(&buf[..]).expect("failed to decode U64");
        prop_assert_eq!(U64::new(value), amount);
    }

    #[test]
    fn decode_legacy_token_amounts(value in any::<u64>()) {
        let mut buf = vec![];
        ciborium::into_writer(&Tokens::from_e8s(value), &mut buf).unwrap();
        let amount: U64 = ciborium::de::from_reader(&buf[..]).expect("failed to decode U64");
        prop_assert_eq!(U64::new(value), amount);
    }
}
