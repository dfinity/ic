use crate::checked_amount::CheckedAmountOf;
use proptest::strategy::Strategy;

mod transaction_price {
    mod increase_by_10_percent {
        use crate::numeric::WeiPerGas;
        use crate::tx::tests::arb_checked_amount_of;
        use crate::tx::TransactionPrice;
        use proptest::{prelude::any, prop_assert_eq, proptest};

        proptest! {
            #[test]
            fn should_saturate(gas_limit in arb_checked_amount_of()) {
                let unreasonable_price = TransactionPrice {
                    gas_limit,
                    max_fee_per_gas: WeiPerGas::MAX,
                    max_priority_fee_per_gas: WeiPerGas::MAX,
                };
                let increased_price = unreasonable_price.clone().increase_by_10_percent();

                prop_assert_eq!(increased_price, unreasonable_price);
            }
        }

        proptest! {
            #[test]
            fn should_have_at_least_10_percent_difference(gas_limit in arb_checked_amount_of(), max_fee_per_gas in any::<u128>(), max_priority_fee_per_gas in any::<u128>()) {
                let price = TransactionPrice {
                    gas_limit,
                    max_fee_per_gas: WeiPerGas::from(max_fee_per_gas),
                    max_priority_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas),
                };
                let bumped_price = price.clone().increase_by_10_percent();
                let max_fee_per_gas_diff = bumped_price.max_fee_per_gas.checked_sub(price.max_fee_per_gas).expect("bumped max fee per gas should be greater than original");
                let max_priority_fee_per_gas_diff = bumped_price.max_priority_fee_per_gas.checked_sub(price.max_priority_fee_per_gas).expect("bumped max priority fee per gas should be greater than original");

                prop_assert_eq!(price.gas_limit, bumped_price.gas_limit);
                prop_assert_eq!(max_fee_per_gas_diff, price.max_fee_per_gas.checked_div_ceil(10_u8).unwrap());
                prop_assert_eq!(max_priority_fee_per_gas_diff, price.max_priority_fee_per_gas.checked_div_ceil(10_u8).unwrap());
            }
        }
    }
}

fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
    use proptest::arbitrary::any;
    use proptest::array::uniform32;
    uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
}
