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

#[test]
fn should_cbor_encoding_be_stable() {
    use crate::address::Address;
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    };
    use ethnum::u256;
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

fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
    use proptest::arbitrary::any;
    use proptest::array::uniform32;
    uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
}
