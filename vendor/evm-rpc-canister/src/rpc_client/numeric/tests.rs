mod transaction_nonce {
    use crate::rpc_client::numeric::TransactionCount;
    use evm_rpc_types::Nat256;
    use proptest::{array::uniform32, prelude::any, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_convert_from_nat(u256_bytes in uniform32(any::<u8>())) {
            let u256 = Nat256::from_be_bytes(u256_bytes);

            prop_assert_eq!(
                TransactionCount::from(u256.clone()),
                TransactionCount::from_be_bytes(u256_bytes)
            );

            prop_assert_eq!(
                u256,
                TransactionCount::from_be_bytes(u256_bytes).into()
            )
        }
    }
}
