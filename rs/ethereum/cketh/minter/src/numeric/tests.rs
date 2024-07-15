mod transaction_nonce {
    use crate::numeric::TransactionNonce;
    use assert_matches::assert_matches;
    use candid::Nat;
    use num_bigint::BigUint;
    use proptest::{array::uniform32, prelude::any, prop_assert_eq, proptest};

    #[test]
    fn should_overflow() {
        let nonce = TransactionNonce::MAX;
        assert_eq!(nonce.checked_increment(), None);
    }

    #[test]
    fn should_not_overflow() {
        let nonce = TransactionNonce::MAX
            .checked_sub(TransactionNonce::ONE)
            .unwrap();
        assert_eq!(nonce.checked_increment(), Some(TransactionNonce::MAX));
    }

    proptest! {
        #[test]
        fn should_convert_from_nat(u256_bytes in uniform32(any::<u8>())) {
            let u256 = Nat(BigUint::from_bytes_be(&u256_bytes));

            assert_eq!(
                TransactionNonce::try_from(u256),
                Ok(TransactionNonce::from_be_bytes(u256_bytes))
            );
        }

        #[test]
        fn biguint_to_u256_conversion(value in any::<u128>()) {
            use crate::numeric::Wei;

            let nat_value: Nat = value.into();
            let expected_wei_value = Wei::from(value);

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
            Ok(TransactionNonce::MAX)
        );

        let u256_max_plus_one: Nat =
            Nat(BigUint::parse_bytes(U256_MAX, 16).expect("Failed to parse u256 max"))
                + Nat::from(1_u8);
        assert_matches!(
            TransactionNonce::try_from(u256_max_plus_one),
            Err(e) if e.contains("Nat does not fit in a U256")
        );
    }
}

mod wei {
    use crate::numeric::{wei_from_milli_ether, Wei};

    #[test]
    fn should_not_overflow_when_converting_from_milli_ether() {
        assert_eq!(
            wei_from_milli_ether(u128::MAX),
            Wei::from_str_hex("0xDE0B6B3A763FFFFFFFFFFFFFFFFFFFFF21F494C589C0000").unwrap()
        );
    }
}

mod cbor {
    use crate::checked_amount::CheckedAmountOf;
    use proptest::{array::uniform32, prelude::any, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_preserve_value_but_not_tag_during_deser(bytes in uniform32(any::<u8>())) {
            let amount_a = AmountA::from_be_bytes(bytes);
            let amount_b = AmountB::from_be_bytes(bytes);

            let mut encoded_amount_a = vec![];
            minicbor::encode(amount_a, &mut encoded_amount_a).unwrap();
            let mut encoded_amount_b = vec![];
            minicbor::encode(amount_b, &mut encoded_amount_b).unwrap();
            prop_assert_eq!(&encoded_amount_a, &encoded_amount_b);

            let decoded_amount_b_from_a: AmountB = minicbor::decode(&encoded_amount_a).unwrap();
            prop_assert_eq!(
                amount_a.to_be_bytes(),
                decoded_amount_b_from_a.to_be_bytes()
            );

            let decoded_amount_a_from_b: AmountA = minicbor::decode(&encoded_amount_b).unwrap();
            prop_assert_eq!(
                amount_b.to_be_bytes(),
                decoded_amount_a_from_b.to_be_bytes()
            );
        }
    }

    enum AmountATag {}
    type AmountA = CheckedAmountOf<AmountATag>;

    enum AmountBTag {}
    type AmountB = CheckedAmountOf<AmountBTag>;
}
