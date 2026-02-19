use crate::{Hex, Hex20, Hex256, Hex32, HexByte, Nat256, TransactionReceipt};
use candid::{CandidType, Decode, Deserialize, Encode, Nat};
use num_bigint::BigUint;
use proptest::{
    prelude::{any, Strategy, TestCaseError},
    prop_assert, prop_assert_eq, proptest,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{ops::RangeInclusive, str::FromStr};

mod nat256 {
    use super::*;

    proptest! {
        #[test]
        fn should_encode_decode(u256 in arb_u256()) {
            encode_decode_roundtrip(u256);
        }

        #[test]
        fn should_fail_to_decode_nat_overflowing_a_u256(offset in any::<u64>()) {
            let u256_max: BigUint = BigUint::from_bytes_be(&[0xff; 32]);
            encode_decode_roundtrip(u256_max.clone());

            let offset = BigUint::from(offset);
            let overflow_u256 = Nat::from(u256_max + offset);
            let encoded_overflow_u256 = Encode!(&overflow_u256).unwrap();

            let decoded_overflow_nat256: Result<Nat256, _> = Decode!(&encoded_overflow_u256, Nat256);
            let error_msg = format!("{:?}", decoded_overflow_nat256.unwrap_err());

            assert!(
                error_msg.contains("Deserialize error: Nat does not fit in a U256"),
                "Unexpected error message: {}",
                error_msg
            );
        }

        #[test]
        fn should_convert_to_bytes_and_back(u256 in arb_u256()) {
            let value = Nat256::try_from(Nat::from(u256)).unwrap();
            let bytes = value.clone().into_be_bytes();

            let value_from_bytes = Nat256::from_be_bytes(bytes);

            assert_eq!(value, value_from_bytes);
        }
    }

    #[test]
    fn should_have_transparent_debug_and_display_representation() {
        let number = Nat256::from(0x68802B_u32);

        assert_eq!(format!("{:?}", number), "6848555");
        assert_eq!(format!("{}", number), "6848555");
    }

    fn encode_decode_roundtrip(value: BigUint) {
        let nat = Nat::from(value);
        let encoded_nat = Encode!(&nat).unwrap();

        let nat256 = Nat256::try_from(nat.clone()).unwrap();
        let encoded_nat256 = Encode!(&nat256).unwrap();

        assert_eq!(encoded_nat, encoded_nat256);

        let decoded_nat256: Nat256 = Decode!(&encoded_nat, Nat256).unwrap();
        assert_eq!(decoded_nat256.0, nat);
    }

    fn arb_u256() -> impl Strategy<Value = BigUint> {
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(|value| BigUint::from_bytes_be(&value))
    }
}

mod hex_string {
    use super::*;

    proptest! {
        #[test]
        fn should_encode_decode(
            hex1 in arb_var_len_hex_string(1..=1_usize),
            hex20 in arb_var_len_hex_string(20..=20_usize),
            hex32 in arb_var_len_hex_string(32..=32_usize),
            hex256 in arb_var_len_hex_string(256..=256_usize),
            hex in arb_var_len_hex_string(0..=100_usize)
        ) {
            encode_decode_roundtrip::<HexByte>(&hex1)?;
            encode_decode_roundtrip::<Hex20>(&hex20)?;
            encode_decode_roundtrip::<Hex32>(&hex32)?;
            encode_decode_roundtrip::<Hex256>(&hex256)?;
            encode_decode_roundtrip::<Hex>(&hex)?;
        }

        #[test]
        fn should_fail_to_decode_strings_with_wrong_length(
            short_hex1 in arb_var_len_hex_string(0..=0_usize),
            long_hex1 in arb_var_len_hex_string(2..=100_usize),
            short_hex20 in arb_var_len_hex_string(0..=19_usize),
            long_hex20 in arb_var_len_hex_string(21..=100_usize),
            short_hex32 in arb_var_len_hex_string(0..=31_usize),
            long_hex32 in arb_var_len_hex_string(33..=100_usize),
            short_hex256 in arb_var_len_hex_string(0..=255_usize),
            long_hex256 in arb_var_len_hex_string(257..=500_usize),
        ) {
            expect_decoding_error::<HexByte>(&short_hex1)?;
            expect_decoding_error::<HexByte>(&long_hex1)?;
            expect_decoding_error::<Hex20>(&short_hex20)?;
            expect_decoding_error::<Hex20>(&long_hex20)?;
            expect_decoding_error::<Hex32>(&short_hex32)?;
            expect_decoding_error::<Hex32>(&long_hex32)?;
            expect_decoding_error::<Hex256>(&short_hex256)?;
            expect_decoding_error::<Hex256>(&long_hex256)?;
        }
    }

    #[test]
    fn should_have_ethereum_style_debug_format() {
        let hex = Hex32::from([
            115, 166, 64, 150, 180, 39, 93, 36, 71, 160, 156, 224, 104, 32, 54, 11, 239, 30, 208,
            187, 226, 23, 212, 37, 216, 38, 46, 98, 221, 154, 234, 158,
        ]);
        let hex_debug = format!("{:?}", hex);

        assert_eq!(
            hex_debug,
            "0x73a64096b4275d2447a09ce06820360bef1ed0bbe217d425d8262e62dd9aea9e"
        )
    }

    #[test]
    fn should_decode_single_hex_char_into_hex_byte() {
        for single_hex in "0123456789abcdefABCDEF".chars() {
            let expected_value =
                HexByte::from(u8::from_str_radix(&single_hex.to_string(), 16).unwrap());

            let single_digit_hex = format!("0x{}", single_hex);
            let single_digit_hex_parsed: HexByte = single_digit_hex.parse().unwrap();
            assert_eq!(single_digit_hex_parsed, expected_value);

            let double_digit_hex = format!("0x0{}", single_hex);
            let double_digit_hex_parsed: HexByte = double_digit_hex.parse().unwrap();
            assert_eq!(double_digit_hex_parsed, expected_value);
        }
    }

    fn encode_decode_roundtrip<T>(value: &str) -> Result<(), TestCaseError>
    where
        T: FromStr + CandidType + DeserializeOwned + PartialEq + std::fmt::Debug,
        <T as FromStr>::Err: std::fmt::Debug,
    {
        let hex: T = value.parse().unwrap();

        let encoded_text_value = Encode!(&value.to_lowercase()).unwrap();
        let encoded_hex = Encode!(&hex).unwrap();
        prop_assert_eq!(
            &encoded_text_value,
            &encoded_hex,
            "Encode value differ for {}",
            value
        );

        let decoded_hex = Decode!(&encoded_text_value, T).unwrap();
        prop_assert_eq!(&decoded_hex, &hex, "Decode value differ for {}", value);
        Ok(())
    }

    fn expect_decoding_error<T>(wrong_hex: &str) -> Result<(), TestCaseError>
    where
        T: FromStr + CandidType + DeserializeOwned + PartialEq + std::fmt::Debug,
        <T as FromStr>::Err: std::fmt::Debug,
    {
        let result = Decode!(&Encode!(&wrong_hex).unwrap(), T);
        prop_assert!(
            result.is_err(),
            "Expected error decoding {}, got: {:?}",
            wrong_hex,
            result
        );
        Ok(())
    }
}

#[test]
fn should_decode_renamed_field() {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
    pub struct Struct {
        #[serde(rename = "fieldName")]
        pub field_name: u64,
    }
    let value = Struct { field_name: 123 };
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Struct).unwrap(), value);
}

#[test]
fn should_decode_checked_amount() {
    let value = Nat256::from(123_u32);
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Nat256).unwrap(), value);
}

#[test]
fn should_decode_address() {
    let value = Hex20::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Hex20).unwrap(), value);
}

#[test]
fn should_decode_transaction_receipt() {
    let value = crate::TransactionReceipt {
        status: Some(0x1_u8.into()),
        root: None,
        transaction_hash: "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
            .parse()
            .unwrap(),
        contract_address: None,
        block_number: 18_515_371_u64.into(),
        block_hash: "0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be"
            .parse()
            .unwrap(),
        effective_gas_price: 26_776_497_782_u64.into(),
        gas_used: 32_137_u32.into(),
        from: "0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667"
            .parse()
            .unwrap(),
        logs: vec![],
        logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
        to: Some("0x356cfd6e6d0000400000003900b415f80669009e"
            .parse()
            .unwrap()),
        transaction_index: 0xd9_u16.into(),
        tx_type: "0x2".parse().unwrap(),
        cumulative_gas_used: 0xf02aed_u64.into(),
    };
    assert_eq!(
        Decode!(&Encode!(&value).unwrap(), TransactionReceipt).unwrap(),
        value
    );
}

#[cfg(feature = "alloy")]
mod alloy_conversion_tests {
    use super::*;
    use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};

    proptest! {
        #[test]
        fn should_convert_to_and_from_alloy(
            hex20 in arb_hex20(),
            hex32 in arb_hex32(),
            hex256 in arb_hex256(),
            hex in arb_hex(),
            wrapped_u64 in arb_u64(),
            nat256 in arb_nat256(),
        ) {
            prop_assert_eq!(hex20.clone(), Hex20::from(Address::from(hex20)));
            prop_assert_eq!(hex32.clone(), Hex32::from(B256::from(hex32)));
            prop_assert_eq!(hex256.clone(), Hex256::from(Bloom::from(hex256)));
            prop_assert_eq!(hex.clone(), Hex::from(Bytes::from(hex)));
            prop_assert_eq!(wrapped_u64.clone(), Nat256::from(B64::try_from(wrapped_u64).unwrap()));
            prop_assert_eq!(nat256.clone(), Nat256::from(U256::from(nat256)));
        }
    }

    fn arb_hex20() -> impl Strategy<Value = Hex20> {
        arb_var_len_hex_string(20..=20_usize).prop_map(|s| Hex20::from_str(s.as_str()).unwrap())
    }

    fn arb_hex32() -> impl Strategy<Value = Hex32> {
        arb_var_len_hex_string(32..=32_usize).prop_map(|s| Hex32::from_str(s.as_str()).unwrap())
    }

    fn arb_hex256() -> impl Strategy<Value = Hex256> {
        arb_var_len_hex_string(256..=256_usize).prop_map(|s| Hex256::from_str(s.as_str()).unwrap())
    }

    fn arb_hex() -> impl Strategy<Value = Hex> {
        arb_var_len_hex_string(0..=100_usize).prop_map(|s| Hex::from_str(s.as_str()).unwrap())
    }

    fn arb_u64() -> impl Strategy<Value = Nat256> {
        any::<u64>().prop_map(Nat256::from)
    }

    fn arb_nat256() -> impl Strategy<Value = Nat256> {
        any::<[u8; 32]>().prop_map(Nat256::from_be_bytes)
    }
}

fn arb_var_len_hex_string(num_bytes_range: RangeInclusive<usize>) -> impl Strategy<Value = String> {
    num_bytes_range.prop_flat_map(|num_bytes| {
        proptest::string::string_regex(&format!("0x[0-9a-fA-F]{{{}}}", 2 * num_bytes)).unwrap()
    })
}
