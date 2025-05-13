use evm_rpc_client::{EthMainnetService, RpcService as EvmRpcService};

const BLOCK_PI: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::BlockPi);
const PUBLIC_NODE: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::PublicNode);
const LLAMA_NODES: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::Llama);

mod multi_call_results {

    mod reduce_with_equality {
        use crate::eth_rpc::HttpOutcallError;
        use crate::eth_rpc_client::tests::{BLOCK_PI, PUBLIC_NODE};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults, SingleCallError};
        use ic_cdk::api::call::RejectionCode;

        #[test]
        #[should_panic(expected = "MultiCallResults cannot be empty")]
        fn should_panic_when_empty() {
            let _panic = MultiCallResults::<String>::from_non_empty_iter(vec![]);
        }

        #[test]
        fn should_be_inconsistent_when_different_call_errors() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    BLOCK_PI,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }
                    .into()),
                ),
                (
                    PUBLIC_NODE,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::SysTransient,
                        message: "transient".to_string(),
                    }
                    .into()),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_inconsistent_when_different_rpc_errors() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    BLOCK_PI,
                    Err(SingleCallError::JsonRpcError {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Err(SingleCallError::JsonRpcError {
                        code: -32000,
                        message: "nonce too low".to_string(),
                    }),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_inconsistent_when_different_ok_results() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (BLOCK_PI, Ok("hello".to_string())),
                (PUBLIC_NODE, Ok("world".to_string())),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_consistent_http_outcall_error() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    BLOCK_PI,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }
                    .into()),
                ),
                (
                    PUBLIC_NODE,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }
                    .into()),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(
                reduced,
                Err(MultiCallError::ConsistentHttpOutcallError(
                    HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }
                ))
            );
        }

        #[test]
        fn should_be_consistent_rpc_error() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    BLOCK_PI,
                    Err(SingleCallError::JsonRpcError {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Err(SingleCallError::JsonRpcError {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(
                reduced,
                Err(MultiCallError::ConsistentJsonRpcError {
                    code: -32700,
                    message: "insufficient funds for gas * price + value".to_string(),
                })
            );
        }

        #[test]
        fn should_be_consistent_ok_result() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (BLOCK_PI, Ok("0x01".to_string())),
                (PUBLIC_NODE, Ok("0x01".to_string())),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Ok("0x01".to_string()));
        }
    }

    mod reduce_with_stable_majority_by_key {
        use crate::eth_rpc::{FeeHistory, HttpOutcallError};
        use crate::eth_rpc_client::tests::{BLOCK_PI, LLAMA_NODES, PUBLIC_NODE};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults, SingleCallError};
        use crate::numeric::{BlockNumber, WeiPerGas};
        use ic_cdk::api::call::RejectionCode;

        #[test]
        fn should_get_unanimous_fee_history() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(fee_history())),
                    (PUBLIC_NODE, Ok(fee_history())),
                    (LLAMA_NODES, Ok(fee_history())),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(reduced, Ok(fee_history()));
        }

        #[test]
        fn should_get_fee_history_with_2_out_of_3() {
            for index_non_majority in 0..3_usize {
                let index_majority = (index_non_majority + 1) % 3;
                let mut fees = [fee_history(), fee_history(), fee_history()];
                fees[index_non_majority].oldest_block = BlockNumber::new(0x10f73fd);
                assert_ne!(
                    fees[index_non_majority].oldest_block,
                    fees[index_majority].oldest_block
                );
                let majority_fee = fees[index_majority].clone();
                let [block_pi_fee_history, llama_nodes_fee_history, public_node_fee_history] = fees;
                let results: MultiCallResults<FeeHistory> =
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history)),
                        (LLAMA_NODES, Ok(llama_nodes_fee_history)),
                        (PUBLIC_NODE, Ok(public_node_fee_history)),
                    ]);

                let reduced = results
                    .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

                assert_eq!(reduced, Ok(majority_fee));
            }
        }

        #[test]
        fn should_get_fee_history_with_2_out_of_3_when_third_is_error() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(fee_history())),
                    (
                        PUBLIC_NODE,
                        Err(HttpOutcallError::IcError {
                            code: RejectionCode::SysTransient,
                            message: "no consensus".to_string(),
                        }
                        .into()),
                    ),
                    (LLAMA_NODES, Ok(fee_history())),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(reduced, Ok(fee_history()));
        }

        #[test]
        fn should_fail_when_no_strict_majority() {
            let block_pi_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fd),
                ..fee_history()
            };
            let llama_nodes_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fc),
                ..fee_history()
            };
            let public_node_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fe),
                ..fee_history()
            };
            let three_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (PUBLIC_NODE, Ok(public_node_fee_history.clone())),
                ]);

            let reduced = three_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                        (PUBLIC_NODE, Ok(public_node_fee_history)),
                    ])
                ))
            );

            let two_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                ]);

            let reduced = two_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                        (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                    ])
                ))
            );

            let two_distinct_results_and_error: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (
                        PUBLIC_NODE,
                        Err(SingleCallError::JsonRpcError {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                    (LLAMA_NODES, Ok(llama_nodes_fee_history.clone())),
                ]);

            let reduced = two_distinct_results_and_error
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history)),
                        (LLAMA_NODES, Ok(llama_nodes_fee_history)),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_when_fee_history_inconsistent_for_same_oldest_block() {
            let (fee, inconsistent_fee) = {
                let fee = fee_history();
                let mut inconsistent_fee = fee.clone();
                inconsistent_fee.base_fee_per_gas[0] = WeiPerGas::new(0x729d3f3b4);
                assert_ne!(fee, inconsistent_fee);
                (fee, inconsistent_fee)
            };

            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(fee.clone())),
                    (PUBLIC_NODE, Ok(inconsistent_fee.clone())),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(fee.clone())),
                        (PUBLIC_NODE, Ok(inconsistent_fee)),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_when_no_sufficient_ok_responses() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(fee_history())),
                    (
                        PUBLIC_NODE,
                        Err(SingleCallError::JsonRpcError {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                ]);

            let reduced = results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)));
        }

        fn fee_history() -> FeeHistory {
            FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fc),
                base_fee_per_gas: vec![
                    WeiPerGas::new(0x729d3f3b3),
                    WeiPerGas::new(0x766e503ea),
                    WeiPerGas::new(0x75b51b620),
                    WeiPerGas::new(0x74094f2b4),
                    WeiPerGas::new(0x716724f03),
                    WeiPerGas::new(0x73b467f76),
                ],
                reward: vec![
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x55d4a80)],
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x5f5e100)],
                ],
            }
        }
    }

    mod has_http_outcall_error_matching {
        use crate::eth_rpc::HttpOutcallError;
        use crate::eth_rpc_client::tests::{BLOCK_PI, LLAMA_NODES, PUBLIC_NODE};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults, SingleCallError};
        use ic_cdk::api::call::RejectionCode;
        use proptest::prelude::any;
        use proptest::proptest;

        proptest! {
            #[test]
            fn should_not_match_when_consistent_json_rpc_error(code in any::<i64>(), message in ".*") {
                let error: MultiCallError<String> = MultiCallError::ConsistentJsonRpcError {
                    code,
                    message,
                };
                let always_true = |_outcall_error: &HttpOutcallError| true;

                assert!(!error.has_http_outcall_error_matching(always_true));
            }
        }

        #[test]
        fn should_match_when_consistent_http_outcall_error() {
            let error: MultiCallError<String> =
                MultiCallError::ConsistentHttpOutcallError(HttpOutcallError::IcError {
                    code: RejectionCode::SysTransient,
                    message: "message".to_string(),
                });
            let always_true = |_outcall_error: &HttpOutcallError| true;
            let always_false = |_outcall_error: &HttpOutcallError| false;

            assert!(error.has_http_outcall_error_matching(always_true));
            assert!(!error.has_http_outcall_error_matching(always_false));
        }

        #[test]
        fn should_match_on_single_inconsistent_result_with_outcall_error() {
            let always_true = |_outcall_error: &HttpOutcallError| true;
            let error_with_no_outcall_error =
                MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(1)),
                    (
                        LLAMA_NODES,
                        Err(SingleCallError::JsonRpcError {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                    (PUBLIC_NODE, Ok(1)),
                ]));
            assert!(!error_with_no_outcall_error.has_http_outcall_error_matching(always_true));

            let error_with_outcall_error =
                MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(vec![
                    (BLOCK_PI, Ok(1)),
                    (
                        LLAMA_NODES,
                        Err(HttpOutcallError::IcError {
                            code: RejectionCode::SysTransient,
                            message: "message".to_string(),
                        }
                        .into()),
                    ),
                    (PUBLIC_NODE, Ok(1)),
                ]));
            assert!(error_with_outcall_error.has_http_outcall_error_matching(always_true));
        }
    }
}

mod eth_get_transaction_receipt {
    use crate::eth_rpc::Hash;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::{BlockNumber, GasAmount, WeiPerGas};
    use assert_matches::assert_matches;
    use proptest::proptest;
    use std::str::FromStr;

    #[test]
    fn should_deserialize_transaction_receipt() {
        const RECEIPT: &str = r#"{
        "transactionHash": "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
        "blockHash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
        "blockNumber": "0x4132ec",
        "logs": [],
        "contractAddress": null,
        "effectiveGasPrice": "0xfefbee3e",
        "cumulativeGasUsed": "0x8b2e10",
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x01",
        "to": "0xdd2851cdd40ae6536831558dd46db62fac7a844d",
        "transactionIndex": "0x32",
        "type": "0x2"
    }"#;

        let receipt: TransactionReceipt = serde_json::from_str(RECEIPT).unwrap();

        assert_eq!(
            receipt,
            TransactionReceipt {
                block_hash: Hash::from_str(
                    "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4"
                )
                .unwrap(),
                block_number: BlockNumber::new(0x4132ec),
                effective_gas_price: WeiPerGas::new(0xfefbee3e),
                gas_used: GasAmount::new(0x5208),
                status: TransactionStatus::Success,
                transaction_hash: Hash::from_str(
                    "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"
                )
                .unwrap(),
            }
        )
    }

    #[test]
    fn should_deserialize_transaction_status() {
        let status: TransactionStatus = serde_json::from_str("\"0x01\"").unwrap();
        assert_eq!(status, TransactionStatus::Success);

        // some providers do not return a full byte (2 hex digits) for the status
        let status: TransactionStatus = serde_json::from_str("\"0x1\"").unwrap();
        assert_eq!(status, TransactionStatus::Success);

        let status: TransactionStatus = serde_json::from_str("\"0x0\"").unwrap();
        assert_eq!(status, TransactionStatus::Failure);

        let status: TransactionStatus = serde_json::from_str("\"0x00\"").unwrap();
        assert_eq!(status, TransactionStatus::Failure);
    }

    #[test]
    fn should_deserialize_serialized_transaction_status() {
        let status: TransactionStatus =
            serde_json::from_str(&serde_json::to_string(&TransactionStatus::Success).unwrap())
                .unwrap();
        assert_eq!(status, TransactionStatus::Success);

        let status: TransactionStatus =
            serde_json::from_str(&serde_json::to_string(&TransactionStatus::Failure).unwrap())
                .unwrap();
        assert_eq!(status, TransactionStatus::Failure);
    }

    proptest! {
        #[test]
        fn should_fail_deserializing_wrong_transaction_status(wrong_status in 2_u32..u32::MAX) {
            let status = format!("\"0x{:x}\"", wrong_status);
            let error = serde_json::from_str::<TransactionStatus>(&status);
            assert_matches!(error, Err(e) if e.to_string().contains("invalid transaction status"));
        }
    }
}

mod eth_get_transaction_count {
    use crate::numeric::TransactionCount;

    #[test]
    fn should_deserialize_transaction_count() {
        let count: TransactionCount = serde_json::from_str("\"0x3d8\"").unwrap();
        assert_eq!(count, TransactionCount::from(0x3d8_u32));
    }
}

mod evm_rpc_conversion {
    use crate::eth_rpc::SendRawTransactionResult;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::eth_rpc_client::tests::{BLOCK_PI, LLAMA_NODES, PUBLIC_NODE};
    use crate::eth_rpc_client::{
        FeeHistory, HttpOutcallError, LogEntry, MultiCallError, MultiCallResults, Reduce,
        SingleCallError,
    };
    use crate::test_fixtures::arb::{
        arb_evm_rpc_error, arb_fee_history, arb_gas_used_ratio, arb_hex20, arb_hex256, arb_hex32,
        arb_hex_byte, arb_log_entry, arb_nat_256, arb_transaction_receipt,
    };
    use evm_rpc_client::{
        FeeHistory as EvmFeeHistory, Hex, Hex20, Hex32, HttpOutcallError as EvmHttpOutcallError,
        LogEntry as EvmLogEntry, MultiRpcResult as EvmMultiRpcResult, Nat256, RpcApi as EvmRpcApi,
        RpcError as EvmRpcError, RpcService as EvmRpcService,
        SendRawTransactionStatus as EvmSendRawTransactionStatus,
        TransactionReceipt as EvmTransactionReceipt,
    };
    use proptest::{prelude::Strategy, prop_assert_eq, proptest};
    use std::collections::BTreeSet;
    use std::fmt::Debug;

    proptest! {
        #[test]
        fn should_preserve_http_outcall_errors(evm_error in arb_evm_rpc_error()) {
            let minter_error = SingleCallError::from(evm_error.clone());

            match (evm_error, minter_error) {
                (EvmRpcError::HttpOutcallError(e), SingleCallError::HttpOutcallError(m)) => match e {
                    EvmHttpOutcallError::IcError { code, message } => {
                        assert_eq!(m, HttpOutcallError::IcError { code, message })
                    }
                    EvmHttpOutcallError::InvalidHttpJsonRpcResponse {
                        status,
                        body,
                        parsing_error,
                    } => {
                        assert_eq!(
                            m,
                            HttpOutcallError::InvalidHttpJsonRpcResponse {
                                status,
                                body,
                                parsing_error
                            }
                        )
                    }
                },
                (EvmRpcError::HttpOutcallError(e), _) => {
                    panic!("EVM-RPC HTTP outcall error not preserved: {:?}", e)
                }
                (_, SingleCallError::HttpOutcallError(e)) => {
                    panic!("Unexpected Minter HTTP outcall error: {:?}", e)
                }
                _ => (),
            };
        }
    }

    proptest! {
        #[test]
        fn should_have_consistent_fee_history_between_minter_and_evm_rpc(
            minter_fee_history in arb_fee_history(),
            gas_used_ratio in arb_gas_used_ratio(),
            first_error in arb_evm_rpc_error(),
            second_error in arb_evm_rpc_error(),
            third_error in arb_evm_rpc_error(),
        ) {
            let evm_fee_history = evm_rpc_fee_history(minter_fee_history.clone(), gas_used_ratio);
            test_consistency_between_minter_and_evm_rpc(minter_fee_history, Some(evm_fee_history), first_error, second_error, third_error)?;
        }
    }

    proptest! {
        #[test]
        fn should_have_consistent_transaction_receipts_between_minter_and_evm_rpc
        (
            transaction_receipts in minter_and_evm_rpc_transaction_receipts(),
            first_error in arb_evm_rpc_error(),
            second_error in arb_evm_rpc_error(),
            third_error in arb_evm_rpc_error(),
        ) {
            let (minter_tx_receipt, evm_rpc_tx_receipt) = transaction_receipts;
            test_consistency_between_minter_and_evm_rpc(minter_tx_receipt, evm_rpc_tx_receipt, first_error, second_error, third_error)?;
        }
    }

    proptest! {
        #[test]
        fn should_have_consistent_send_raw_transaction_result_between_minter_and_evm_rpc
        (
            evm_tx_status in arb_evm_rpc_send_raw_transaction_status(),
            first_error in arb_evm_rpc_error(),
            second_error in arb_evm_rpc_error(),
            third_error in arb_evm_rpc_error(),
        ) {
            let minter_tx_result = SendRawTransactionResult::from(evm_tx_status.clone());
            test_consistency_between_minter_and_evm_rpc(minter_tx_result, evm_tx_status, first_error, second_error, third_error)?;
        }
    }

    fn test_consistency_between_minter_and_evm_rpc<R, M, E>(
        minter_ok: M,
        evm_rpc_ok: E,
        first_error: EvmRpcError,
        second_error: EvmRpcError,
        third_error: EvmRpcError,
    ) -> Result<(), proptest::prelude::TestCaseError>
    where
        R: Debug + PartialEq + serde::Serialize,
        M: Clone,
        E: Clone,
        MultiCallResults<M>: Reduce<Item = R>,
        EvmMultiRpcResult<E>: Reduce<Item = R>,
    {
        let (block_pi_evm_rpc_provider, public_node_evm_rpc_provider, llama_nodes_evm_rpc_provider) =
            evm_rpc_providers();

        // 0 error
        let evm_result = EvmMultiRpcResult::Consistent(Ok(evm_rpc_ok.clone()));
        let minter_result: MultiCallResults<M> = MultiCallResults::from_non_empty_iter(vec![
            (BLOCK_PI, Ok(minter_ok.clone())),
            (PUBLIC_NODE, Ok(minter_ok.clone())),
            (LLAMA_NODES, Ok(minter_ok.clone())),
        ]);
        prop_assert_eq!(evm_result.reduce(), minter_result.reduce());

        // 1 error
        for first_error_index in 0..3_usize {
            let mut evm_results = vec![
                (block_pi_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
                (public_node_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
                (llama_nodes_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
            ];
            evm_results.get_mut(first_error_index).unwrap().1 = Err(first_error.clone());
            let evm_result = EvmMultiRpcResult::Inconsistent(evm_results);

            let mut minter_results = vec![
                (BLOCK_PI, Ok(minter_ok.clone())),
                (PUBLIC_NODE, Ok(minter_ok.clone())),
                (LLAMA_NODES, Ok(minter_ok.clone())),
            ];
            minter_results.get_mut(first_error_index).unwrap().1 =
                Err(SingleCallError::from(first_error.clone()));
            let minter_result: MultiCallResults<M> =
                MultiCallResults::from_non_empty_iter(minter_results);

            prop_assert_eq!(evm_result.reduce(), minter_result.reduce());
        }

        // 2 errors
        for ok_index in 0..3_usize {
            let mut evm_results = vec![
                (block_pi_evm_rpc_provider.clone(), Err(first_error.clone())),
                (
                    public_node_evm_rpc_provider.clone(),
                    Err(second_error.clone()),
                ),
                (
                    llama_nodes_evm_rpc_provider.clone(),
                    Err(third_error.clone()),
                ),
            ];
            evm_results.get_mut(ok_index).unwrap().1 = Ok(evm_rpc_ok.clone());
            let evm_result = EvmMultiRpcResult::Inconsistent(evm_results);

            let mut minter_results = vec![
                (BLOCK_PI, Err(SingleCallError::from(first_error.clone()))),
                (
                    PUBLIC_NODE,
                    Err(SingleCallError::from(second_error.clone())),
                ),
                (LLAMA_NODES, Err(SingleCallError::from(third_error.clone()))),
            ];
            minter_results.get_mut(ok_index).unwrap().1 = Ok(minter_ok.clone());
            let minter_result: MultiCallResults<M> =
                MultiCallResults::from_non_empty_iter(minter_results);

            prop_assert_eq_ignoring_provider(evm_result.reduce(), minter_result.reduce())?;
        }

        // 3 errors
        let evm_result: EvmMultiRpcResult<E> = EvmMultiRpcResult::Inconsistent(vec![
            (block_pi_evm_rpc_provider.clone(), Err(first_error.clone())),
            (
                public_node_evm_rpc_provider.clone(),
                Err(second_error.clone()),
            ),
            (
                llama_nodes_evm_rpc_provider.clone(),
                Err(third_error.clone()),
            ),
        ]);
        let minter_result: MultiCallResults<M> = MultiCallResults::from_non_empty_iter(vec![
            (BLOCK_PI, Err(SingleCallError::from(first_error.clone()))),
            (
                PUBLIC_NODE,
                Err(SingleCallError::from(second_error.clone())),
            ),
            (LLAMA_NODES, Err(SingleCallError::from(third_error.clone()))),
        ]);
        prop_assert_eq_ignoring_provider(evm_result.reduce(), minter_result.reduce())?;

        Ok(())
    }

    fn evm_rpc_providers() -> (EvmRpcService, EvmRpcService, EvmRpcService) {
        let block_pi_evm_rpc_provider = EvmRpcService::Custom(EvmRpcApi {
            url: "block_pi".to_string(),
            headers: None,
        });
        let public_node_evm_rpc_provider = EvmRpcService::Custom(EvmRpcApi {
            url: "public_node".to_string(),
            headers: None,
        });
        let llama_nodes_evm_rpc_provider = EvmRpcService::Custom(EvmRpcApi {
            url: "llama".to_string(),
            headers: None,
        });
        (
            block_pi_evm_rpc_provider,
            public_node_evm_rpc_provider,
            llama_nodes_evm_rpc_provider,
        )
    }

    fn prop_assert_eq_ignoring_provider<
        R: AsRef<Result<T, MultiCallError<T>>>,
        T: PartialEq + Debug + serde::Serialize,
    >(
        left: R,
        right: R,
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let left = left.as_ref();
        let right = right.as_ref();
        match left {
            Ok(_) => {
                prop_assert_eq!(left, right)
            }
            Err(e) => match e {
                MultiCallError::ConsistentHttpOutcallError(_)
                | MultiCallError::ConsistentJsonRpcError { .. }
                | MultiCallError::ConsistentEvmRpcCanisterError(_) => {
                    prop_assert_eq!(left, right)
                }
                MultiCallError::InconsistentResults(left_inconsistent_results) => {
                    let right_inconsistent_results = match right {
                        Err(MultiCallError::InconsistentResults(results)) => results,
                        _ => panic!("Expected inconsistent results"),
                    };
                    // Providers are used as keys for MultiCallResults::ok_results and MultiCallResults::errors,
                    // so since we want to ignore them, it makes sense to also ignore the order of the values,
                    // since different providers have different orderings.
                    prop_assert_eq!(
                        left_inconsistent_results
                            .ok_results
                            .values()
                            // It generally doesn't make sense for `T` to implement `Ord`,
                            // but in this context it can always be serialized to JSON,
                            // which we use for comparison purposes.
                            .map(|v| serde_json::to_string(v).unwrap())
                            .collect::<BTreeSet<_>>(),
                        right_inconsistent_results
                            .ok_results
                            .values()
                            .map(|v| serde_json::to_string(v).unwrap())
                            .collect::<BTreeSet<_>>()
                    );
                    prop_assert_eq!(
                        left_inconsistent_results
                            .errors
                            .values()
                            .collect::<BTreeSet<_>>(),
                        right_inconsistent_results
                            .errors
                            .values()
                            .collect::<BTreeSet<_>>()
                    );
                }
            },
        }
        Ok(())
    }

    fn evm_rpc_log_entry(minter_log_entry: LogEntry) -> EvmLogEntry {
        EvmLogEntry {
            address: Hex20::from(minter_log_entry.address.into_bytes()),
            topics: minter_log_entry
                .topics
                .into_iter()
                .map(|topic| Hex32::from(topic.0))
                .collect(),
            data: Hex::from(minter_log_entry.data.0),
            block_number: minter_log_entry.block_number.map(Nat256::from),
            transaction_hash: minter_log_entry
                .transaction_hash
                .map(|hash| Hex32::from(hash.0)),
            transaction_index: minter_log_entry
                .transaction_index
                .map(|q| Nat256::from_be_bytes(q.to_be_bytes())),
            block_hash: minter_log_entry.block_hash.map(|hash| Hex32::from(hash.0)),
            log_index: minter_log_entry.log_index.map(Nat256::from),
            removed: minter_log_entry.removed,
        }
    }

    pub fn evm_rpc_fee_history(
        minter_fee_history: FeeHistory,
        gas_used_ratio: Vec<f64>,
    ) -> EvmFeeHistory {
        EvmFeeHistory {
            oldest_block: minter_fee_history.oldest_block.into(),
            base_fee_per_gas: minter_fee_history
                .base_fee_per_gas
                .into_iter()
                .map(Nat256::from)
                .collect(),
            gas_used_ratio,
            reward: minter_fee_history
                .reward
                .into_iter()
                .map(|rewards| rewards.into_iter().map(Nat256::from).collect())
                .collect(),
        }
    }

    fn minter_and_evm_rpc_transaction_receipts(
    ) -> impl Strategy<Value = (Option<TransactionReceipt>, Option<EvmTransactionReceipt>)> {
        use proptest::{option, prelude::Just};
        option::of(arb_transaction_receipt()).prop_flat_map(|minter_tx_receipt| {
            (
                Just(minter_tx_receipt.clone()),
                arb_evm_rpc_transaction_receipt(minter_tx_receipt),
            )
        })
    }

    fn arb_evm_rpc_transaction_receipt(
        minter_tx_receipt: Option<TransactionReceipt>,
    ) -> impl Strategy<Value = Option<EvmTransactionReceipt>> {
        use proptest::{collection::vec, option, prelude::Just};

        match minter_tx_receipt {
            None => Just(None).boxed(),
            Some(r) => (
                option::of(arb_hex20()),
                arb_hex20(),
                vec(arb_log_entry(), 1..=100),
                arb_hex256(),
                option::of(arb_hex20()),
                arb_nat_256(),
                arb_hex_byte(),
            )
                .prop_map(
                    move |(
                        contract_address,
                        from,
                        minter_logs,
                        logs_bloom,
                        to,
                        transaction_index,
                        tx_type,
                    )| {
                        Some(EvmTransactionReceipt {
                            block_hash: Hex32::from(r.block_hash.0),
                            block_number: r.block_number.into(),
                            effective_gas_price: r.effective_gas_price.into(),
                            gas_used: r.gas_used.into(),
                            status: Some(match r.status {
                                TransactionStatus::Success => Nat256::from(1_u8),
                                TransactionStatus::Failure => Nat256::ZERO,
                            }),
                            transaction_hash: Hex32::from(r.transaction_hash.0),
                            contract_address,
                            from,
                            logs: minter_logs.into_iter().map(evm_rpc_log_entry).collect(),
                            logs_bloom,
                            to,
                            transaction_index,
                            tx_type,
                        })
                    },
                )
                .boxed(),
        }
    }

    fn arb_evm_rpc_send_raw_transaction_status(
    ) -> impl Strategy<Value = EvmSendRawTransactionStatus> {
        use proptest::{
            option,
            prelude::{prop_oneof, Just},
        };
        prop_oneof![
            option::of(arb_hex32()).prop_map(EvmSendRawTransactionStatus::Ok),
            Just(EvmSendRawTransactionStatus::InsufficientFunds),
            Just(EvmSendRawTransactionStatus::NonceTooLow),
            Just(EvmSendRawTransactionStatus::NonceTooHigh),
        ]
    }
}
