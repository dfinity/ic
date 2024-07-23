pub mod arb {
    use evm_rpc_client::types::candid::{
        HttpOutcallError as EvmHttpOutcallError, JsonRpcError as EvmJsonRpcError,
        ProviderError as EvmProviderError, RpcError as EvmRpcError,
        ValidationError as EvmValidationError,
    };
    use ic_cdk::api::call::RejectionCode;
    use proptest::{
        prelude::{any, Just, Strategy},
        prop_oneof,
    };

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
            ".*".prop_map(EvmValidationError::UrlParseError),
            ".*".prop_map(EvmValidationError::HostNotAllowed),
            Just(EvmValidationError::CredentialPathNotAllowed),
            Just(EvmValidationError::CredentialHeaderNotAllowed)
        ]
    }
}
