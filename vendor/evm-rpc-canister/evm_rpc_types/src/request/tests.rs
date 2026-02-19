#[cfg(feature = "alloy")]
mod alloy_conversion_tests {
    use crate::TransactionRequest;
    use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
    use alloy_rpc_types::{AccessList, AccessListItem, TransactionInput};
    use proptest::{
        collection::vec,
        option,
        prelude::{any, Just, Strategy},
        prop_compose, prop_oneof, proptest,
    };
    use serde_json::Value;

    proptest! {
        #[test]
        fn should_convert_tx_request_from_alloy(alloy_tx_request in arb_tx_request()) {
            fn canonicalize (mut serialized: Value) -> Value {
                // Remove null entries
                if let Value::Object(ref mut v) = &mut serialized {
                    v.retain(|_, val| !val.is_null());
                }

                // Convert arrays of u32 digits to hex strings
                fn convert_field_to_hex(v: &mut Value, field: &str) {
                    if let Some(Value::Array(arr)) = v.get_mut(field) {
                        let hex_str: String = arr
                            .into_iter()
                            .rev()
                            .map(|x| {
                                let n = x.as_u64().unwrap() as u32;
                                hex::encode(n.to_be_bytes())
                            })
                            .collect();

                        let hex_str = hex_str.trim_start_matches("0");
                        let hex_str = if hex_str.is_empty() { "0" } else { hex_str };

                        *v.get_mut(field).unwrap() = Value::String(format!("0x{}", hex_str));
                    }
                }

                // Convert e.g. 0x00 to 0x0 or 0x01 to 0x1
                fn trim_leading_zeroes(v: &mut Value, field: &str) {
                    if let Value::Object(map) = v {
                        if let Some(Value::String(value)) = map.get_mut(field) {
                            if value.starts_with("0x0") {
                                *value = format!("0x{}", value.trim_start_matches("0x").trim_start_matches("0"));
                            }
                        }
                    }
                }

                trim_leading_zeroes(&mut serialized, "type");

                convert_field_to_hex(&mut serialized, "gasPrice");
                convert_field_to_hex(&mut serialized, "maxFeePerGas");
                convert_field_to_hex(&mut serialized, "maxPriorityFeePerGas");
                convert_field_to_hex(&mut serialized, "maxFeePerBlobGas");
                convert_field_to_hex(&mut serialized, "gas");
                convert_field_to_hex(&mut serialized, "value");
                convert_field_to_hex(&mut serialized, "nonce");
                convert_field_to_hex(&mut serialized, "chainId");

                serialized
            }


            let tx_request = TransactionRequest::try_from(alloy_tx_request.clone()).unwrap();
            let serialized_tx_request = serde_json::to_value(&tx_request).unwrap();

            let serialized_alloy_tx_request = serde_json::to_value(&alloy_tx_request.normalized_input()).unwrap();

            assert_eq!(canonicalize(serialized_tx_request), canonicalize(serialized_alloy_tx_request));
        }
    }

    prop_compose! {
        fn arb_tx_request()(
            from in option::of(arb_address()),
            to in option::of(arb_tx_kind()),
            gas_price in option::of(any::<u128>()),
            max_fee_per_gas in option::of(any::<u128>()),
            max_priority_fee_per_gas in option::of(any::<u128>()),
            max_fee_per_blob_gas in option::of(any::<u128>()),
            gas in option::of(any::<u64>()),
            value in option::of(any::<u128>().prop_map(U256::from)),
            input in arb_tx_input(),
            nonce in option::of(any::<u64>()),
            chain_id in option::of(any::<u64>()),
            access_list in option::of(arb_access_list()),
            transaction_type in option::of(any::<u8>()),
            blob_versioned_hashes in option::of(arb_b256_vec()),
        ) -> alloy_rpc_types::TransactionRequest {
            alloy_rpc_types::TransactionRequest {
                from,
                to,
                gas_price,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                max_fee_per_blob_gas,
                gas,
                value,
                input,
                nonce,
                chain_id,
                access_list,
                transaction_type,
                blob_versioned_hashes,
                // Blobs are too big and cause a stack overflow error when running proptests.
                sidecar: None,
                // No corresponding field in `evm_rpc_types::TransactionRequest`
                authorization_list: None,
            }
        }
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        any::<[u8; 20]>().prop_map(Address::from)
    }

    fn arb_bytes() -> impl Strategy<Value = Bytes> {
        vec(any::<u8>(), 0..20).prop_map(|b| Bytes::from(b))
    }

    fn arb_tx_kind() -> impl Strategy<Value = TxKind> {
        prop_oneof![Just(TxKind::Create), arb_address().prop_map(TxKind::Call)]
    }

    fn arb_tx_input() -> impl Strategy<Value = TransactionInput> {
        prop_oneof![
            Just(TransactionInput::default()),
            arb_bytes().prop_map(|bytes| TransactionInput::new(bytes).normalized_input()),
            arb_bytes().prop_map(|bytes| TransactionInput::new(bytes).normalized_data()),
            arb_bytes().prop_map(|bytes| TransactionInput::new(bytes).with_both()),
        ]
    }

    fn arb_access_list() -> impl Strategy<Value = AccessList> {
        vec(arb_access_list_item(), 0..10).prop_map(AccessList::from)
    }

    prop_compose! {
        fn arb_access_list_item()(
            address in arb_address(),
            storage_keys in arb_b256_vec(),
        ) -> AccessListItem {
            AccessListItem { address, storage_keys }
        }
    }

    fn arb_b256_vec() -> impl Strategy<Value = Vec<B256>> {
        vec(any::<[u8; 32]>().prop_map(B256::from), 0..10)
    }
}
