mod transaction_nonce {
    use crate::numeric::TransactionNonce;
    use assert_matches::assert_matches;
    use candid::Nat;
    use num_bigint::BigUint;
    use proptest::{array::uniform32, prelude::any, prop_assert_eq, proptest};

    #[test]
    fn should_overflow() {
        let nonce = TransactionNonce(ethnum::u256::MAX);
        assert_eq!(nonce.checked_increment(), None);
    }

    #[test]
    fn should_not_overflow() {
        let nonce = TransactionNonce(ethnum::u256::MAX - 1);
        assert_eq!(
            nonce.checked_increment(),
            Some(TransactionNonce(ethnum::u256::MAX))
        );
    }

    proptest! {
        #[test]
        fn should_convert_from_nat(u256_bytes in uniform32(any::<u8>())) {
            let u256 = Nat(BigUint::from_bytes_be(&u256_bytes));

            assert_eq!(
                TransactionNonce::try_from(u256),
                Ok(TransactionNonce(ethnum::u256::from_be_bytes(u256_bytes)))
            );
        }

        #[test]
        fn biguint_to_u256_conversion(value in any::<u128>()) {
            use crate::numeric::Wei;
            use ethnum::U256;

            let nat_value: Nat = value.into();
            let expected_wei_value = Wei(U256::from(value));

            let converted_wei: Wei = nat_value.try_into().unwrap();
            prop_assert_eq!(converted_wei, expected_wei_value);
        }
    }

    #[test]
    fn should_fail_when_nat_too_big() {
        const U256_MAX: &[u8; 64] =
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

        assert_eq!(
            TransactionNonce::try_from(Nat(
                BigUint::parse_bytes(U256_MAX, 16).expect("Failed to parse u256 max")
            )),
            Ok(TransactionNonce(ethnum::u256::MAX))
        );

        let u256_max_plus_one: Nat =
            Nat(BigUint::parse_bytes(U256_MAX, 16).expect("Failed to parse u256 max")) + 1;
        assert_matches!(
            TransactionNonce::try_from(u256_max_plus_one),
            Err(e) if e.contains("Nat does not fit in a U256")
        );
    }
}
