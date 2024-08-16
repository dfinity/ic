use crate::tx::{GasFeeEstimate, TransactionPrice};
use proptest::strategy::Strategy;

mod estimate_transaction_price {
    use crate::eth_rpc::FeeHistory;
    use crate::numeric::{BlockNumber, WeiPerGas};
    use crate::tx::{estimate_transaction_fee, GasFeeEstimate, TransactionFeeEstimationError};
    use assert_matches::assert_matches;
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};
    use std::cmp::max;

    proptest! {
        #[test]
        fn should_estimate_transaction_price(
            base_fee_per_gas in vec(any::<u64>(), 6),
            reward in vec(any::<u64>(), 5)
        ) {
            let expected_base_fee_per_gas = base_fee_per_gas[5];
            let expected_max_priority_fee_per_gas = {
                let mut sorted_reward = reward.clone();
                sorted_reward.sort();
                let median = sorted_reward[2];
                max(median, 1_500_000_000_u64)
            };
            let fee_history = fee_history(base_fee_per_gas, reward);

            let result = estimate_transaction_fee(&fee_history);

            prop_assert_eq!(
                result,
                Ok(GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(expected_base_fee_per_gas),
                    max_priority_fee_per_gas: WeiPerGas::from(expected_max_priority_fee_per_gas),
                })
            )
        }
    }

    #[test]
    fn should_fail_when_base_fee_per_gas_overflows() {
        let fee_history = fee_history(
            vec![
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::MAX,
            ],
            vec![0_u8, 0, 0, 0, 0],
        );

        let result = estimate_transaction_fee(&fee_history);

        assert_matches!(result, Err(TransactionFeeEstimationError::Overflow(_)));
    }

    #[test]
    fn should_fail_when_max_priority_fee_per_gas_overflows() {
        let fee_history = fee_history(vec![0_u8, 0, 0, 0, 0, 1], [WeiPerGas::MAX; 5].to_vec());
        let result = estimate_transaction_fee(&fee_history);
        assert_matches!(result, Err(TransactionFeeEstimationError::Overflow(_)));
    }

    fn fee_history<U: Into<WeiPerGas>, V: Into<WeiPerGas>>(
        base_fee_per_gas: Vec<U>,
        reward: Vec<V>,
    ) -> FeeHistory {
        assert_eq!(
            base_fee_per_gas.len(),
            reward.len() + 1,
            "base_fee_per_gas must contain a value for the next block"
        );
        FeeHistory {
            oldest_block: BlockNumber::new(0x10f73fc),
            base_fee_per_gas: base_fee_per_gas.into_iter().map(|x| x.into()).collect(),
            reward: reward.into_iter().map(|x| vec![x.into()]).collect(),
        }
    }
}

mod resubmit_transaction_price {
    use crate::numeric::WeiPerGas;
    use crate::tx::tests::{arb_gas_fee_estimate, arb_transaction_price};
    use crate::tx::GasFeeEstimate;
    use proptest::{prop_assert, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_be_the_same_when_base_fee_per_gas_covered(initial_price in arb_transaction_price()) {
            let max_base_fee_per_gas = initial_price
                .max_fee_per_gas
                .checked_sub(initial_price.max_priority_fee_per_gas)
                .expect("BUG: max fee per gas should be greater or equal than max priority fee per gas");
            let mut base_fee_per_gas = max_base_fee_per_gas;
            while base_fee_per_gas > WeiPerGas::ZERO {
                let new_gas_fee = GasFeeEstimate {
                    base_fee_per_gas,
                    max_priority_fee_per_gas: initial_price.max_priority_fee_per_gas,
                };

                let updated_price = initial_price
                    .clone()
                    .resubmit_transaction_price(new_gas_fee);

                prop_assert_eq!(&updated_price, &initial_price);

                base_fee_per_gas = base_fee_per_gas.div_by_two();
            }
        }
    }

    proptest! {
        #[test]
        fn should_increase_by_at_least_10_percent_when_base_fee_not_covered(initial_price in arb_transaction_price()) {
            let max_base_fee_per_gas = initial_price
                .max_fee_per_gas
                .checked_sub(initial_price.max_priority_fee_per_gas)
                .expect(
                    "BUG: max fee per gas should be greater or equal than max priority fee per gas",
                );
            let mut base_fee_per_gas = max_base_fee_per_gas
                .checked_add(WeiPerGas::ONE)
                .unwrap_or(WeiPerGas::MAX);
            while base_fee_per_gas < WeiPerGas::MAX {
                let new_gas_fee = GasFeeEstimate {
                    base_fee_per_gas,
                    max_priority_fee_per_gas: initial_price.max_priority_fee_per_gas,
                };

                let updated_price = initial_price
                    .clone()
                    .resubmit_transaction_price(new_gas_fee);
                let max_priority_fee_per_gas_diff = updated_price.max_priority_fee_per_gas.checked_sub(initial_price.max_priority_fee_per_gas).expect("updated max priority fee per gas should be greater than original");

                prop_assert_eq!(updated_price.gas_limit, initial_price.gas_limit);
                prop_assert!(updated_price.max_fee_per_gas >= initial_price.max_fee_per_gas);
                prop_assert_eq!(max_priority_fee_per_gas_diff, initial_price.max_priority_fee_per_gas.checked_div_ceil(10_u8).unwrap());

                base_fee_per_gas = base_fee_per_gas.checked_mul(2_u8).unwrap_or(WeiPerGas::MAX);
            }
        }
    }

    proptest! {
        #[test]
        fn should_always_increase_or_be_the_same(initial_price in arb_transaction_price(), new_gas_fee in arb_gas_fee_estimate()) {
            let updated_price = initial_price
                .clone()
                .resubmit_transaction_price(new_gas_fee);

            prop_assert_eq!(updated_price.gas_limit, initial_price.gas_limit);
            prop_assert!(updated_price.max_fee_per_gas >= initial_price.max_fee_per_gas);
            prop_assert!(updated_price.max_priority_fee_per_gas >= initial_price.max_priority_fee_per_gas);
        }
    }
}

#[test]
fn should_cbor_encoding_be_stable() {
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    };
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    // see https://sepolia.etherscan.io/getRawTx?tx=0x66a9a218ea720ac6d2c9e56f7e44836c1541c186b7627bda220857ce34e2df7f
    let signature = Eip1559Signature {
        signature_y_parity: true,
        r: u256::from_str_hex("0x7d097b81dc8bf5ad313f8d6656146d4723d0e6bb3fb35f1a709e6a3d4426c0f3")
            .unwrap(),
        s: u256::from_str_hex("0x4f8a618d959e7d96e19156f0f5f2ed321b34e2004a0c8fdb7f02bc7d08b74441")
            .unwrap(),
    };
    let transaction = Eip1559TransactionRequest {
        chain_id: 11155111,
        nonce: TransactionNonce::from(6_u8),
        max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
        max_fee_per_gas: WeiPerGas::new(0x598653cd),
        gas_limit: GasAmount::new(56_511),
        destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
        amount: Wei::new(1_000_000_000_000_000),
        data: hex::decode(
            "b214faa51d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000",
        )
        .unwrap(),
        access_list: AccessList::new(),
    };
    let signed_tx = SignedEip1559TransactionRequest::from((transaction, signature));
    let mut encoded_signed_tx: Vec<u8> = Vec::new();

    minicbor::encode(&signed_tx, &mut encoded_signed_tx).unwrap();

    assert_eq!(
        encoded_signed_tx,
        [
            130, 137, 26, 0, 170, 54, 167, 6, 26, 89, 104, 47, 0, 26, 89, 134, 83, 205, 25, 220,
            191, 84, 180, 75, 94, 117, 106, 137, 71, 117, 252, 50, 237, 223, 51, 20, 187, 27, 25,
            68, 220, 52, 27, 0, 3, 141, 126, 164, 198, 128, 0, 88, 36, 178, 20, 250, 165, 29, 136,
            45, 21, 176, 159, 142, 129, 226, 150, 6, 48, 95, 95, 239, 197, 239, 243, 226, 48, 150,
            32, 163, 85, 126, 202, 227, 157, 98, 2, 0, 0, 128, 131, 245, 194, 88, 32, 125, 9, 123,
            129, 220, 139, 245, 173, 49, 63, 141, 102, 86, 20, 109, 71, 35, 208, 230, 187, 63, 179,
            95, 26, 112, 158, 106, 61, 68, 38, 192, 243, 194, 88, 32, 79, 138, 97, 141, 149, 158,
            125, 150, 225, 145, 86, 240, 245, 242, 237, 50, 27, 52, 226, 0, 74, 12, 143, 219, 127,
            2, 188, 125, 8, 183, 68, 65
        ]
    );

    let decoded_signed_tx: SignedEip1559TransactionRequest =
        minicbor::decode(&encoded_signed_tx).unwrap();

    assert_eq!(decoded_signed_tx, signed_tx);
}

fn arb_transaction_price() -> impl Strategy<Value = TransactionPrice> {
    use crate::numeric::WeiPerGas;
    use crate::test_fixtures::arb::arb_checked_amount_of;
    use proptest::prelude::any;
    (arb_checked_amount_of(), any::<u128>(), any::<u128>()).prop_map(
        |(gas_limit, delta_to_max_fee_per_gas, max_priority_fee_per_gas)| TransactionPrice {
            gas_limit,
            // max_fee_per_gas is always greater or equal to max_priority_fee_per_gas
            max_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas)
                .checked_add(WeiPerGas::from(delta_to_max_fee_per_gas))
                .expect("BUG: addition of 2 u128 should not overflow a u256"),
            max_priority_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas),
        },
    )
}

fn arb_gas_fee_estimate() -> impl Strategy<Value = GasFeeEstimate> {
    use crate::numeric::WeiPerGas;
    use proptest::prelude::any;
    (any::<u64>(), any::<u64>()).prop_map(|(base_fee_per_gas, max_priority_fee_per_gas)| {
        GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(base_fee_per_gas),
            max_priority_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas),
        }
    })
}
