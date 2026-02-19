use crate::{Block, FeeHistory, Hex, Hex20, Hex256, Hex32, LogEntry, Nat256};
use num_bigint::BigUint;
use proptest::{
    arbitrary::any,
    collection::vec,
    option,
    prelude::{Just, Strategy},
    prop_assert_eq, prop_compose, proptest,
};
use serde_json::Value;
use std::{ops::RangeInclusive, str::FromStr};

// To check conversion from `evm_rpc_types` to `alloy_rpc_types`, these tests generate an arbitrary
// (valid) type from the `evm_rpc_types` crate, convert it to the corresponding `alloy_rpc_types`
// type, and compare both serialized values.
// This is done so that we can check conversion for randomly generated values and not just a few
// hardcoded instances.
#[cfg(feature = "alloy")]
mod alloy_conversion_tests {
    use super::*;

    const PARIS_BLOCK: u64 = 15_537_394;

    proptest! {
        #[test]
        fn should_convert_log_to_alloy(entry in arb_log_entry()) {
            let serialized = serde_json::to_value(&entry).unwrap();

            let alloy_log = alloy_rpc_types::Log::try_from(entry.clone()).unwrap();
            let alloy_serialized = serde_json::to_value(&alloy_log).unwrap();

            prop_assert_eq!(serialized, canonicalize_log(alloy_serialized));
        }

        #[test]
        fn should_convert_pre_paris_block_to_alloy(block in arb_pre_paris_block()) {
            let serialized = serde_json::to_value(&block).unwrap();

            let alloy_block = alloy_rpc_types::Block::try_from(block.clone()).unwrap();
            let alloy_serialized = serde_json::to_value(&alloy_block).unwrap();

            prop_assert_eq!(serialized, canonicalize_block(alloy_serialized));
        }

        #[test]
        fn should_convert_post_paris_block_to_alloy(block in arb_post_paris_block()) {
            // For post-Paris blocks, the difficulty field is optional. However, the `difficulty` field
            // is mandatory in the `alloy_rpc_types::Block` type. Therefore, convert `null` values to 0.
            fn canonicalize_difficulty (mut serialized_block: Value) -> Value {
                if let Some(Value::Null) = serialized_block.get("difficulty") {
                    serialized_block["difficulty"] = Value::from(Vec::<Value>::new());
                }
                serialized_block
            }

            let serialized = serde_json::to_value(&block).unwrap();

            let alloy_block = alloy_rpc_types::Block::try_from(block.clone()).unwrap();
            let alloy_serialized = serde_json::to_value(&alloy_block).unwrap();

            prop_assert_eq!(canonicalize_difficulty(serialized), canonicalize_block(alloy_serialized));
        }

        #[test]
        fn should_convert_fee_history_to_alloy(fee_history in arb_fee_history()) {
            let serialized = serde_json::to_value(&fee_history).unwrap();

            let alloy_fee_history = alloy_rpc_types::FeeHistory::try_from(fee_history.clone()).unwrap();
            let alloy_serialized = serde_json::to_value(&alloy_fee_history).unwrap();

            prop_assert_eq!(serialized, canonicalize_fee_history(alloy_serialized));
        }
    }

    fn canonicalize_log(mut serialized_log: Value) -> Value {
        // Convert hex-encoded numerical values to arrays of `u32` digits.
        hex_to_u32_digits(&mut serialized_log, "transactionIndex");
        hex_to_u32_digits(&mut serialized_log, "logIndex");
        hex_to_u32_digits(&mut serialized_log, "blockNumber");
        serialized_log
    }

    fn canonicalize_fee_history(mut serialized_fee_history: Value) -> Value {
        // Convert hex-encoded numerical values to arrays of `u32` digits.
        hex_to_u32_digits(&mut serialized_fee_history, "oldestBlock");
        // Convert hex-encoded arrays of numerical values to contain arrays of `u32` digits.
        fn f(v: &mut Value) {
            if let Value::String(hex) = v {
                let hex = hex.strip_prefix("0x").unwrap_or(hex);
                *v = BigUint::parse_bytes(hex.as_bytes(), 16)
                    .unwrap()
                    .to_u32_digits()
                    .into();
            }
        }
        traverse_nested_array(serialized_fee_history.get_mut("baseFeePerGas"), &f);
        traverse_nested_array(serialized_fee_history.get_mut("reward"), &f);
        // Add `[]` for values that alloy skips during serialization when they are empty.
        add_empty_if_absent(&mut serialized_fee_history, "baseFeePerGas");
        add_empty_if_absent(&mut serialized_fee_history, "gasUsedRatio");
        add_empty_if_absent(&mut serialized_fee_history, "reward");
        serialized_fee_history
    }

    fn canonicalize_block(mut serialized_block: Value) -> Value {
        // Convert hex-encoded numerical values to arrays of `u32` digits.
        hex_to_u32_digits(&mut serialized_block, "baseFeePerGas");
        hex_to_u32_digits(&mut serialized_block, "number");
        hex_to_u32_digits(&mut serialized_block, "difficulty");
        hex_to_u32_digits(&mut serialized_block, "gasLimit");
        hex_to_u32_digits(&mut serialized_block, "gasUsed");
        hex_to_u32_digits(&mut serialized_block, "nonce");
        hex_to_u32_digits(&mut serialized_block, "size");
        hex_to_u32_digits(&mut serialized_block, "timestamp");
        hex_to_u32_digits(&mut serialized_block, "totalDifficulty");
        // Add `null` for values that alloy skips during serialization when they are absent.
        add_null_if_absent(&mut serialized_block, "baseFeePerGas");
        add_null_if_absent(&mut serialized_block, "totalDifficulty");
        serialized_block
    }

    fn arb_pre_paris_block() -> impl Strategy<Value = Block> {
        arb_block(
            (0..PARIS_BLOCK).prop_map(Nat256::from),
            arb_nat256().prop_map(Some),
        )
    }

    fn arb_post_paris_block() -> impl Strategy<Value = Block> {
        arb_block(
            (PARIS_BLOCK..).prop_map(Nat256::from),
            option::of(Just(Nat256::ZERO)),
        )
    }

    prop_compose! {
        fn arb_fee_history()(
            oldest_block in arb_u64(),
            base_fee_per_gas in vec(arb_u128(), 0..10),
            gas_used_ratio in vec(any::<f64>(), 0..10),
            reward in vec(vec(arb_u128(), 0..10), 0..10),
        ) -> FeeHistory {
            FeeHistory {
                oldest_block,
                base_fee_per_gas,
                gas_used_ratio,
                reward,
            }
        }
    }

    prop_compose! {
        fn arb_block(
            number_strategy: impl Strategy<Value = Nat256>,
            difficulty_strategy: impl Strategy<Value = Option<Nat256>>
        )
        (
            base_fee_per_gas in option::of(arb_u64()),
            number in number_strategy,
            difficulty in difficulty_strategy,
            extra_data in arb_hex(),
            gas_limit in arb_u64(),
            gas_used in arb_u64(),
            hash in arb_hex32(),
            logs_bloom in arb_hex256(),
            miner in  arb_hex20(),
            mix_hash in arb_hex32(),
            nonce in arb_u64(),
            parent_hash in arb_hex32(),
            receipts_root in arb_hex32(),
            sha3_uncles in arb_hex32(),
            size in arb_u64(),
            state_root in arb_hex32(),
            timestamp in arb_u64(),
            total_difficulty in option::of(arb_nat256()),
            transactions in vec(arb_hex32(), 0..100),
            transactions_root in arb_hex32(),
            uncles in vec(arb_hex32(), 0..100),
        ) -> Block {
            Block {
                base_fee_per_gas,
                number,
                difficulty,
                extra_data,
                gas_limit,
                gas_used,
                hash,
                logs_bloom,
                miner,
                mix_hash,
                nonce,
                parent_hash,
                receipts_root,
                sha3_uncles,
                size,
                state_root,
                timestamp,
                total_difficulty,
                transactions,
                // The `transactionsRoot` field is mandatory as per the Ethereum JSON-RPC API.
                // See: https://ethereum.github.io/execution-apis/api-documentation/
                transactions_root: Some(transactions_root),
                uncles,
            }
        }
    }

    prop_compose! {
        fn arb_log_entry()
        (
            address in arb_hex20(),
            topics in  vec(arb_hex32(), 0..=4),
            data in arb_hex(),
            block_number in option::of(arb_u64()),
            transaction_hash in option::of(arb_hex32()),
            transaction_index in option::of(arb_u64()),
            block_hash in option::of(arb_hex32()),
            log_index in option::of(arb_u64()),
            removed in any::<bool>(),
        ) -> LogEntry {
            LogEntry {
                address,
                topics,
                data,
                block_number,
                transaction_hash,
                transaction_index,
                block_hash,
                log_index,
                removed,
            }
        }
    }

    // `u64` wrapped in a `Nat256`
    fn arb_u64() -> impl Strategy<Value = Nat256> {
        any::<u64>().prop_map(Nat256::from)
    }

    // `u128` wrapped in a `Nat256`
    fn arb_u128() -> impl Strategy<Value = Nat256> {
        any::<u128>().prop_map(Nat256::from)
    }

    fn arb_nat256() -> impl Strategy<Value = Nat256> {
        any::<[u8; 32]>().prop_map(Nat256::from_be_bytes)
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

    // This method checks if the given `serde_json::Value` contains the given field, and if so,
    // it parses its value as a hexadecimal string and converts it to an array of u32 digits.
    // This is needed to compare serialized values between `alloy_rpc_types` and `evm_rpc_types`
    // since the former serialized integers as hex strings, but the latter as arrays of u32 digits.
    fn hex_to_u32_digits(serialized: &mut Value, field: &str) {
        if let Some(Value::String(hex)) = serialized.get(field) {
            let hex = hex.strip_prefix("0x").unwrap_or(hex);
            let digits = BigUint::parse_bytes(hex.as_bytes(), 16)
                .unwrap()
                .to_u32_digits();
            serialized[field] = digits.into();
        }
    }

    // This method checks if the given `serde_json` contains the given field, and if not, sets its
    // value to `serde_json::Value::Null`.
    // This is needed to compare serialized values because some fields are skipped during
    // serialization in `alloy_rpc_types` but not `evm_rpc_types`
    fn add_null_if_absent(serialized: &mut Value, field: &str) {
        if serialized.get(field).is_none() {
            serialized[field] = Value::Null;
        }
    }

    // This method checks if the given `serde_json` contains the given field, and if not, sets its
    // value to `serde_json::Value::Array([])`.
    // This is needed to compare serialized values because some fields are skipped during
    // serialization in `alloy_rpc_types` but not `evm_rpc_types`
    fn add_empty_if_absent(serialized: &mut Value, field: &str) {
        if serialized.get(field).is_none() {
            serialized[field] = Value::Array(Vec::<Value>::new());
        }
    }

    fn traverse_nested_array(v: Option<&mut Value>, f: &impl Fn(&mut Value)) {
        if let Some(Value::Array(ref mut values)) = v {
            for value in values.iter_mut() {
                if let Value::Array(_) = value {
                    traverse_nested_array(Some(value), f)
                } else {
                    f(value);
                }
            }
        }
    }
}

fn arb_var_len_hex_string(num_bytes_range: RangeInclusive<usize>) -> impl Strategy<Value = String> {
    num_bytes_range.prop_flat_map(|num_bytes| {
        proptest::string::string_regex(&format!("0x[0-9a-fA-F]{{{}}}", 2 * num_bytes)).unwrap()
    })
}
