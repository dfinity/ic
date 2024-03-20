mod eth_rpc_client {
    use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider, SepoliaProvider};
    use crate::eth_rpc_client::EthRpcClient;
    use crate::lifecycle::EthereumNetwork;

    #[test]
    fn should_retrieve_sepolia_providers_in_stable_order() {
        let client = EthRpcClient::new(EthereumNetwork::Sepolia);

        let providers = client.providers();

        assert_eq!(
            providers,
            &[
                RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
                RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode)
            ]
        );
    }

    #[test]
    fn should_retrieve_mainnet_providers_in_stable_order() {
        let client = EthRpcClient::new(EthereumNetwork::Mainnet);

        let providers = client.providers();

        assert_eq!(
            providers,
            &[
                RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
                RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
                RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes)
            ]
        );
    }
}

mod multi_call_results {
    use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider};

    const ANKR: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Ankr);
    const PUBLIC_NODE: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::PublicNode);
    const LLAMA_NODES: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes);

    mod reduce_with_equality {
        use crate::eth_rpc::{HttpOutcallError, JsonRpcResult};
        use crate::eth_rpc_client::tests::multi_call_results::{ANKR, PUBLIC_NODE};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults};
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
                    ANKR,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::SysTransient,
                        message: "transient".to_string(),
                    }),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_inconsistent_when_different_rpc_errors() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Ok(JsonRpcResult::Error {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Ok(JsonRpcResult::Error {
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
                (ANKR, Ok(JsonRpcResult::Result("hello".to_string()))),
                (PUBLIC_NODE, Ok(JsonRpcResult::Result("world".to_string()))),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_consistent_http_outcall_error() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Err(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }),
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
                    ANKR,
                    Ok(JsonRpcResult::Error {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Ok(JsonRpcResult::Error {
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
                (ANKR, Ok(JsonRpcResult::Result("0x01".to_string()))),
                (PUBLIC_NODE, Ok(JsonRpcResult::Result("0x01".to_string()))),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Ok("0x01".to_string()));
        }
    }

    mod reduce_with_min_by_key {
        use crate::eth_rpc::{Block, JsonRpcResult};
        use crate::eth_rpc_client::tests::multi_call_results::{ANKR, PUBLIC_NODE};
        use crate::eth_rpc_client::MultiCallResults;
        use crate::numeric::{BlockNumber, Wei};

        #[test]
        fn should_get_minimum_block_number() {
            let results: MultiCallResults<Block> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Ok(JsonRpcResult::Result(Block {
                        number: BlockNumber::new(0x411cda),
                        base_fee_per_gas: Wei::new(0x10),
                    })),
                ),
                (
                    PUBLIC_NODE,
                    Ok(JsonRpcResult::Result(Block {
                        number: BlockNumber::new(0x411cd9),
                        base_fee_per_gas: Wei::new(0x10),
                    })),
                ),
            ]);

            let reduced = results.reduce_with_min_by_key(|block| block.number);

            assert_eq!(
                reduced,
                Ok(Block {
                    number: BlockNumber::new(0x411cd9),
                    base_fee_per_gas: Wei::new(0x10),
                })
            );
        }
    }

    mod reduce_with_stable_majority_by_key {
        use crate::eth_rpc::{FeeHistory, JsonRpcResult};
        use crate::eth_rpc_client::tests::multi_call_results::{ANKR, LLAMA_NODES, PUBLIC_NODE};
        use crate::eth_rpc_client::MultiCallError::ConsistentJsonRpcError;
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults};
        use crate::numeric::{BlockNumber, WeiPerGas};

        #[test]
        fn should_get_unanimous_fee_history() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(JsonRpcResult::Result(fee_history()))),
                    (PUBLIC_NODE, Ok(JsonRpcResult::Result(fee_history()))),
                    (LLAMA_NODES, Ok(JsonRpcResult::Result(fee_history()))),
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
                let [ankr_fee_history, llama_nodes_fee_history, public_node_fee_history] = fees;
                let results: MultiCallResults<FeeHistory> =
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history))),
                        (
                            LLAMA_NODES,
                            Ok(JsonRpcResult::Result(llama_nodes_fee_history)),
                        ),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(public_node_fee_history)),
                        ),
                    ]);

                let reduced = results
                    .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

                assert_eq!(reduced, Ok(majority_fee));
            }
        }

        #[test]
        fn should_fail_when_no_strict_majority() {
            let ankr_fee_history = FeeHistory {
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
                    (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(public_node_fee_history.clone())),
                    ),
                ]);

            let reduced = three_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(public_node_fee_history))
                        ),
                    ])
                ))
            );

            let two_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(llama_nodes_fee_history.clone())),
                    ),
                ]);

            let reduced = two_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history))),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(llama_nodes_fee_history))
                        ),
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
                    (ANKR, Ok(JsonRpcResult::Result(fee.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(inconsistent_fee.clone())),
                    ),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(JsonRpcResult::Result(fee.clone()))),
                        (PUBLIC_NODE, Ok(JsonRpcResult::Result(inconsistent_fee))),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_upon_any_error() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(JsonRpcResult::Result(fee_history()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Error {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                ]);

            let reduced = results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(ConsistentJsonRpcError {
                    code: -32700,
                    message: "error".to_string()
                })
            );
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
        use super::*;
        use crate::eth_rpc::{HttpOutcallError, JsonRpcResult};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults};
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
                    (ANKR, Ok(JsonRpcResult::Result(1))),
                    (
                        LLAMA_NODES,
                        Ok(JsonRpcResult::Error {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                    (PUBLIC_NODE, Ok(JsonRpcResult::Result(1))),
                ]));
            assert!(!error_with_no_outcall_error.has_http_outcall_error_matching(always_true));

            let error_with_outcall_error =
                MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(JsonRpcResult::Result(1))),
                    (
                        LLAMA_NODES,
                        Err(HttpOutcallError::IcError {
                            code: RejectionCode::SysTransient,
                            message: "message".to_string(),
                        }),
                    ),
                    (PUBLIC_NODE, Ok(JsonRpcResult::Result(1))),
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
    use crate::eth_rpc::{BlockSpec, BlockTag};
    use crate::eth_rpc_client::requests::GetTransactionCountParams;
    use crate::numeric::TransactionCount;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    #[test]
    fn should_serialize_get_transaction_count_params_as_tuple() {
        let params = GetTransactionCountParams {
            address: Address::from_str("0x407d73d8a49eeb85d32cf465507dd71d507100c1").unwrap(),
            block: BlockSpec::Tag(BlockTag::Finalized),
        };
        let serialized_params = serde_json::to_string(&params).unwrap();
        assert_eq!(
            serialized_params,
            r#"["0x407d73d8a49eeb85d32cf465507dd71d507100c1","finalized"]"#
        );
    }

    #[test]
    fn should_deserialize_transaction_count() {
        let count: TransactionCount = serde_json::from_str("\"0x3d8\"").unwrap();
        assert_eq!(count, TransactionCount::from(0x3d8_u32));
    }
}
