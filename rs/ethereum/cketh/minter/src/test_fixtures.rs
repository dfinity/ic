use crate::lifecycle::init::InitArg;
use crate::state::State;
use candid::{Nat, Principal};

pub fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(
    f: F,
    expected_message: &str,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.expect_err(&format!(
        "Expected panic with message containing: {}",
        expected_message
    ));
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{:?}", error)
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {}, but got: {}",
        expected_message,
        panic_message
    );
}

pub fn initial_state() -> State {
    State::try_from(valid_init_arg()).expect("BUG: invalid init arg")
}

pub fn valid_init_arg() -> InitArg {
    InitArg {
        ethereum_network: Default::default(),
        ecdsa_key_name: "test_key_1".to_string(),
        ethereum_contract_address: None,
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ethereum_block_height: Default::default(),
        minimum_withdrawal_amount: Nat::from(10_000_000_000_000_000_u64),
        next_transaction_nonce: Default::default(),
        last_scraped_block_number: Default::default(),
    }
}

pub mod arb {
    use crate::checked_amount::CheckedAmountOf;
    use crate::eth_logs::LedgerSubaccount;
    use crate::eth_rpc::{Block, Data, FeeHistory, FixedSizeData, Hash, LogEntry};
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::BlockRangeInclusive;
    use candid::Principal;
    use evm_rpc_client::{
        Hex, Hex20, Hex256, Hex32, HexByte, HttpOutcallError as EvmHttpOutcallError,
        JsonRpcError as EvmJsonRpcError, Nat256, ProviderError as EvmProviderError,
        RpcError as EvmRpcError, ValidationError as EvmValidationError,
    };
    use ic_cdk::api::call::RejectionCode;
    use ic_ethereum_types::Address;
    use proptest::{
        array::{uniform20, uniform32},
        collection::vec,
        option,
        prelude::{any, Just, Strategy},
        prop_oneof,
    };

    pub fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
    }

    pub fn arb_block_range_inclusive() -> impl Strategy<Value = BlockRangeInclusive> {
        (arb_checked_amount_of(), arb_checked_amount_of())
            .prop_map(|(start, end)| BlockRangeInclusive::new(start, end))
    }

    pub fn arb_nat_256() -> impl Strategy<Value = Nat256> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(Nat256::from_be_bytes)
    }

    pub fn arb_principal() -> impl Strategy<Value = Principal> {
        vec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
    }

    pub fn arb_ledger_subaccount() -> impl Strategy<Value = Option<LedgerSubaccount>> {
        uniform32(any::<u8>()).prop_map(LedgerSubaccount::from_bytes)
    }

    pub fn arb_hex_byte() -> impl Strategy<Value = HexByte> {
        use proptest::arbitrary::any;
        any::<u8>().prop_map(HexByte::from)
    }

    pub fn arb_hex20() -> impl Strategy<Value = Hex20> {
        use proptest::arbitrary::any;
        use proptest::array::uniform20;
        uniform20(any::<u8>()).prop_map(Hex20::from)
    }

    pub fn arb_hex32() -> impl Strategy<Value = Hex32> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(Hex32::from)
    }

    pub fn arb_hex256() -> impl Strategy<Value = Hex256> {
        use proptest::arbitrary::any;
        vec(any::<u8>(), 256..=256).prop_map(|bytes| {
            let array: [u8; 256] = bytes.try_into().unwrap();
            Hex256::from(array)
        })
    }

    pub fn arb_hex() -> impl Strategy<Value = Hex> {
        use proptest::arbitrary::any;
        vec(any::<u8>(), 0..100).prop_map(Hex::from)
    }

    pub fn arb_address() -> impl Strategy<Value = Address> {
        uniform20(any::<u8>()).prop_map(Address::new)
    }

    pub fn arb_hash() -> impl Strategy<Value = Hash> {
        uniform32(any::<u8>()).prop_map(Hash)
    }

    pub fn arb_fixed_size_data() -> impl Strategy<Value = FixedSizeData> {
        uniform32(any::<u8>()).prop_map(FixedSizeData)
    }

    pub fn arb_data() -> impl Strategy<Value = Data> {
        vec(any::<u8>(), 1..1000).prop_map(Data)
    }

    pub fn arb_block() -> impl Strategy<Value = Block> {
        (arb_checked_amount_of(), arb_checked_amount_of()).prop_map(|(number, base_fee_per_gas)| {
            Block {
                number,
                base_fee_per_gas,
            }
        })
    }

    pub fn arb_log_entry() -> impl Strategy<Value = LogEntry> {
        (
            arb_address(),
            vec(arb_fixed_size_data(), 1..=10),
            arb_data(),
            option::of(arb_checked_amount_of()),
            option::of(arb_hash()),
            option::of(arb_checked_amount_of::<()>()),
            option::of(arb_hash()),
            option::of(arb_checked_amount_of()),
            any::<bool>(),
        )
            .prop_map(
                |(
                    address,
                    topics,
                    data,
                    block_number,
                    transaction_hash,
                    transaction_index,
                    block_hash,
                    log_index,
                    removed,
                )| LogEntry {
                    address,
                    topics,
                    data,
                    block_number,
                    transaction_hash,
                    transaction_index: transaction_index.map(CheckedAmountOf::into_inner),
                    block_hash,
                    log_index,
                    removed,
                },
            )
    }

    pub fn arb_fee_history() -> impl Strategy<Value = FeeHistory> {
        (
            arb_checked_amount_of(),
            vec(arb_checked_amount_of(), 1..=10),
            vec(vec(arb_checked_amount_of(), 1..=10), 1..=10),
        )
            .prop_map(|(oldest_block, base_fee_per_gas, reward)| FeeHistory {
                oldest_block,
                base_fee_per_gas,
                reward,
            })
    }

    pub fn arb_gas_used_ratio() -> impl Strategy<Value = Vec<f64>> {
        vec(any::<f64>(), 1..=10)
    }

    fn arb_transaction_status() -> impl Strategy<Value = TransactionStatus> {
        prop_oneof![
            Just(TransactionStatus::Success),
            Just(TransactionStatus::Failure)
        ]
    }

    pub fn arb_transaction_receipt() -> impl Strategy<Value = TransactionReceipt> {
        (
            arb_hash(),
            arb_checked_amount_of(),
            arb_checked_amount_of(),
            arb_checked_amount_of(),
            arb_transaction_status(),
            arb_hash(),
        )
            .prop_map(
                |(
                    block_hash,
                    block_number,
                    effective_gas_price,
                    gas_used,
                    status,
                    transaction_hash,
                )| {
                    TransactionReceipt {
                        block_hash,
                        block_number,
                        effective_gas_price,
                        gas_used,
                        status,
                        transaction_hash,
                    }
                },
            )
    }

    pub fn arb_evm_rpc_error() -> impl Strategy<Value = EvmRpcError> {
        prop_oneof![
            arb_evm_provider_error().prop_map(EvmRpcError::ProviderError),
            arb_evm_http_outcall_error().prop_map(EvmRpcError::HttpOutcallError),
            arb_evm_json_rpc_error().prop_map(EvmRpcError::JsonRpcError),
            arb_evm_validation_error().prop_map(EvmRpcError::ValidationError),
        ]
    }

    fn arb_evm_provider_error() -> impl Strategy<Value = EvmProviderError> {
        prop_oneof![
            Just(EvmProviderError::NoPermission),
            (any::<u128>(), any::<u128>()).prop_map(|(expected, received)| {
                EvmProviderError::TooFewCycles { expected, received }
            }),
            Just(EvmProviderError::ProviderNotFound),
            Just(EvmProviderError::MissingRequiredProvider),
        ]
    }

    fn arb_evm_http_outcall_error() -> impl Strategy<Value = EvmHttpOutcallError> {
        prop_oneof![
            (arb_rejection_code(), ".*")
                .prop_map(|(code, message)| EvmHttpOutcallError::IcError { code, message }),
            (any::<u16>(), ".*", proptest::option::of(".*")).prop_map(
                |(status, body, parsing_error)| {
                    EvmHttpOutcallError::InvalidHttpJsonRpcResponse {
                        status,
                        body,
                        parsing_error,
                    }
                }
            )
        ]
    }

    fn arb_evm_json_rpc_error() -> impl Strategy<Value = EvmJsonRpcError> {
        (any::<i64>(), ".*").prop_map(|(code, message)| EvmJsonRpcError { code, message })
    }

    fn arb_rejection_code() -> impl Strategy<Value = RejectionCode> {
        (0..=6).prop_map(RejectionCode::from)
    }

    fn arb_evm_validation_error() -> impl Strategy<Value = EvmValidationError> {
        prop_oneof![
            ".*".prop_map(EvmValidationError::Custom),
            ".*".prop_map(EvmValidationError::InvalidHex),
        ]
    }
}
