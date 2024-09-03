use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider};

const ANKR: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Ankr);
const PUBLIC_NODE: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::PublicNode);
const LLAMA_NODES: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes);

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

    mod reduce_with_equality {
        use crate::eth_rpc::HttpOutcallError;
        use crate::eth_rpc_client::tests::{ANKR, PUBLIC_NODE};
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
                    ANKR,
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
                    ANKR,
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
                (ANKR, Ok("hello".to_string())),
                (PUBLIC_NODE, Ok("world".to_string())),
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
                    ANKR,
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
                (ANKR, Ok("0x01".to_string())),
                (PUBLIC_NODE, Ok("0x01".to_string())),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Ok("0x01".to_string()));
        }
    }

    mod reduce_with_min_by_key {
        use crate::eth_rpc::Block;
        use crate::eth_rpc_client::tests::{ANKR, PUBLIC_NODE};
        use crate::eth_rpc_client::MultiCallResults;
        use crate::numeric::{BlockNumber, Wei};

        #[test]
        fn should_get_minimum_block_number() {
            let results: MultiCallResults<Block> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Ok(Block {
                        number: BlockNumber::new(0x411cda),
                        base_fee_per_gas: Wei::new(0x10),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Ok(Block {
                        number: BlockNumber::new(0x411cd9),
                        base_fee_per_gas: Wei::new(0x10),
                    }),
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
        use crate::eth_rpc::{FeeHistory, HttpOutcallError};
        use crate::eth_rpc_client::tests::{ANKR, LLAMA_NODES, PUBLIC_NODE};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults, SingleCallError};
        use crate::numeric::{BlockNumber, WeiPerGas};
        use ic_cdk::api::call::RejectionCode;

        #[test]
        fn should_get_unanimous_fee_history() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(fee_history())),
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
                let [ankr_fee_history, llama_nodes_fee_history, public_node_fee_history] = fees;
                let results: MultiCallResults<FeeHistory> =
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(ankr_fee_history)),
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
                    (ANKR, Ok(fee_history())),
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
                    (ANKR, Ok(ankr_fee_history.clone())),
                    (PUBLIC_NODE, Ok(public_node_fee_history.clone())),
                ]);

            let reduced = three_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(ankr_fee_history.clone())),
                        (PUBLIC_NODE, Ok(public_node_fee_history)),
                    ])
                ))
            );

            let two_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(ankr_fee_history.clone())),
                    (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                ]);

            let reduced = two_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(ankr_fee_history.clone())),
                        (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                    ])
                ))
            );

            let two_distinct_results_and_error: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(ankr_fee_history.clone())),
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
                        (ANKR, Ok(ankr_fee_history)),
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
                    (ANKR, Ok(fee.clone())),
                    (PUBLIC_NODE, Ok(inconsistent_fee.clone())),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (ANKR, Ok(fee.clone())),
                        (PUBLIC_NODE, Ok(inconsistent_fee)),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_when_no_sufficient_ok_responses() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_non_empty_iter(vec![
                    (ANKR, Ok(fee_history())),
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
        use crate::eth_rpc_client::tests::{ANKR, LLAMA_NODES, PUBLIC_NODE};
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
                    (ANKR, Ok(1)),
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
                    (ANKR, Ok(1)),
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

mod evm_rpc_conversion {
    use crate::eth_rpc::SendRawTransactionResult;
    use crate::eth_rpc_client::responses::TransactionReceipt;
    use crate::eth_rpc_client::tests::{ANKR, LLAMA_NODES, PUBLIC_NODE};
    use crate::eth_rpc_client::{
        providers::RpcNodeProvider, Block, Equality, FeeHistory, HttpOutcallError, LogEntry,
        MinByKey, MultiCallError, MultiCallResults, Reduce, ReduceWithStrategy, SingleCallError,
    };
    use crate::numeric::{BlockNumber, TransactionCount, Wei};
    use crate::test_fixtures::arb::{
        arb_block, arb_evm_rpc_error, arb_fee_history, arb_gas_used_ratio, arb_log_entry,
        arb_nat_256, arb_transaction_receipt,
    };
    use assert_matches::assert_matches;
    use candid::Nat;
    use evm_rpc_client::types::candid::{
        Block as EvmBlock, EthMainnetService as EvmEthMainnetService, FeeHistory as EvmFeeHistory,
        HttpOutcallError as EvmHttpOutcallError, LogEntry as EvmLogEntry,
        MultiRpcResult as EvmMultiRpcResult, RpcApi as EvmRpcApi, RpcError as EvmRpcError,
        RpcResult as EvmRpcResult, RpcService as EvmRpcService, RpcService,
        SendRawTransactionStatus as EvmSendRawTransactionStatus,
        TransactionReceipt as EvmTransactionReceipt,
    };
    use num_bigint::BigUint;
    use proptest::collection::vec;
    use proptest::{prelude::Strategy, prop_assert_eq, proptest};
    use std::collections::BTreeSet;
    use std::fmt::Debug;

    #[test]
    fn should_map_consistent_result() {
        let block = evm_rpc_block();
        let evm_result = EvmMultiRpcResult::Consistent(Ok(block.clone()));

        let reduced_block: Result<_, _> = evm_result.reduce().into();

        assert_eq!(
            reduced_block,
            Ok(Block {
                number: BlockNumber::try_from(block.number).unwrap(),
                base_fee_per_gas: Wei::try_from(block.base_fee_per_gas).unwrap(),
            })
        );
    }

    #[test]
    fn should_map_inconsistent_results() {
        let block = evm_rpc_block();
        let next_block = EvmBlock {
            number: block.number.clone() + 1_u8,
            ..evm_rpc_block()
        };

        let evm_result = EvmMultiRpcResult::Inconsistent(vec![
            (
                EvmRpcService::EthMainnet(EvmEthMainnetService::Alchemy),
                Ok(block.clone()),
            ),
            (
                EvmRpcService::EthMainnet(EvmEthMainnetService::Ankr),
                Ok(next_block.clone()),
            ),
        ]);

        let reduced_block: Result<_, _> = evm_result.reduce().into();

        assert_eq!(
            reduced_block,
            Err(MultiCallError::InconsistentResults(
                MultiCallResults::from_non_empty_iter(vec![
                    (
                        RpcNodeProvider::EvmRpc(EvmRpcService::EthMainnet(
                            EvmEthMainnetService::Alchemy
                        )),
                        Ok(Block {
                            number: BlockNumber::try_from(block.number).unwrap(),
                            base_fee_per_gas: Wei::try_from(block.base_fee_per_gas).unwrap(),
                        }),
                    ),
                    (
                        RpcNodeProvider::EvmRpc(EvmRpcService::EthMainnet(
                            EvmEthMainnetService::Ankr
                        )),
                        Ok(Block {
                            number: BlockNumber::try_from(next_block.number).unwrap(),
                            base_fee_per_gas: Wei::try_from(next_block.base_fee_per_gas).unwrap(),
                        }),
                    ),
                ])
            ))
        );
    }

    #[test]
    fn should_be_consistent_when_evm_block_is_not() {
        let block = evm_rpc_block();
        let inconsistent_block = EvmBlock {
            miner: "other".to_string(),
            ..evm_rpc_block()
        };
        assert_ne!(block, inconsistent_block);
        let evm_result = EvmMultiRpcResult::Inconsistent(vec![
            (
                EvmRpcService::EthMainnet(EvmEthMainnetService::Alchemy),
                Ok(block.clone()),
            ),
            (
                EvmRpcService::EthMainnet(EvmEthMainnetService::Ankr),
                Ok(inconsistent_block),
            ),
        ]);

        let reduced_block: Result<_, _> = evm_result.reduce().into();

        assert_eq!(
            reduced_block,
            Ok(Block {
                number: BlockNumber::try_from(block.number).unwrap(),
                base_fee_per_gas: Wei::try_from(block.base_fee_per_gas).unwrap(),
            })
        );
    }

    #[test]
    fn should_fail_on_invalid_u256_nat() {
        const U256_MAX: &[u8; 64] =
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let u256_max_plus_one: Nat =
            Nat(BigUint::parse_bytes(U256_MAX, 16).expect("Failed to parse u256 max"))
                + Nat::from(1_u8);

        for invalid_block in vec![
            EvmBlock {
                number: u256_max_plus_one.clone(),
                ..evm_rpc_block()
            },
            EvmBlock {
                base_fee_per_gas: u256_max_plus_one.clone(),
                ..evm_rpc_block()
            },
        ] {
            let evm_result = EvmMultiRpcResult::Consistent(Ok(invalid_block));
            let reduced_block: Result<_, _> = evm_result.reduce().into();

            assert_matches!(
                reduced_block,
                Err(MultiCallError::ConsistentEvmRpcCanisterError(s)) if s.contains("Nat does not fit in a U256")
            );
        }
    }

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
        fn should_have_consistent_block_between_minter_and_evm_rpc
        (
            blocks in minter_and_evm_rpc_blocks(),
            first_error in arb_evm_rpc_error(),
            second_error in arb_evm_rpc_error(),
            third_error in arb_evm_rpc_error(),
        ) {
            let (minter_block, evm_rpc_block) = blocks;
            test_consistency_between_minter_and_evm_rpc(minter_block, evm_rpc_block, first_error, second_error, third_error)?;
        }
    }

    proptest! {
        #[test]
        fn should_have_consistent_log_entries_between_minter_and_evm_rpc
        (
            minter_logs in vec(arb_log_entry(), 1..=100),
            first_error in arb_evm_rpc_error(),
            second_error in arb_evm_rpc_error(),
            third_error in arb_evm_rpc_error(),
        ) {
            let evm_rpc_logs: Vec<_> = minter_logs.clone().into_iter().map(evm_rpc_log_entry).collect();
            test_consistency_between_minter_and_evm_rpc(minter_logs, evm_rpc_logs, first_error, second_error, third_error)?;
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
        fn should_have_consistent_transaction_count_between_minter_and_evm_rpc
        (
            first_tx_count in arb_evm_rpc_transaction_count(),
            second_tx_count in arb_evm_rpc_transaction_count(),
            third_tx_count in arb_evm_rpc_transaction_count(),
        ) {
            let (ankr_evm_rpc_provider, public_node_evm_rpc_provider, llama_nodes_evm_rpc_provider) =
                evm_rpc_providers();
            let evm_results = match (&first_tx_count, &second_tx_count, &third_tx_count) {
                (Ok(count_1), Ok(count_2), Ok(count_3)) if count_1 == count_2 && count_2 == count_3 => {
                    EvmMultiRpcResult::Consistent(Ok(count_1.clone()))
                }
                _ => EvmMultiRpcResult::Inconsistent(vec![
                    (ankr_evm_rpc_provider, first_tx_count.clone()),
                    (public_node_evm_rpc_provider, second_tx_count.clone()),
                    (llama_nodes_evm_rpc_provider, third_tx_count.clone()),
                ]),
            };
            let minter_results: MultiCallResults<TransactionCount> = MultiCallResults::from_non_empty_iter(vec![
                (ANKR, first_tx_count.map_err(SingleCallError::from)),
                (PUBLIC_NODE, second_tx_count.map_err(SingleCallError::from)),
                (LLAMA_NODES, third_tx_count.map_err(SingleCallError::from)),
            ])
            .map(&TransactionCount::try_from, &|e| {
                panic!("BUG: selected Nat should fit in a U256: {:?}", e)
            });

            prop_assert_eq_ignoring_provider(
                ReduceWithStrategy::<Equality>::reduce(evm_results.clone()),
                ReduceWithStrategy::<Equality>::reduce(minter_results.clone()),
            )?;
            prop_assert_eq_ignoring_provider(
                ReduceWithStrategy::<MinByKey>::reduce(evm_results),
                ReduceWithStrategy::<MinByKey>::reduce(minter_results),
            )?;
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
        let (ankr_evm_rpc_provider, public_node_evm_rpc_provider, llama_nodes_evm_rpc_provider) =
            evm_rpc_providers();

        // 0 error
        let evm_result = EvmMultiRpcResult::Consistent(Ok(evm_rpc_ok.clone()));
        let minter_result: MultiCallResults<M> = MultiCallResults::from_non_empty_iter(vec![
            (ANKR, Ok(minter_ok.clone())),
            (PUBLIC_NODE, Ok(minter_ok.clone())),
            (LLAMA_NODES, Ok(minter_ok.clone())),
        ]);
        prop_assert_eq!(evm_result.reduce(), minter_result.reduce());

        // 1 error
        for first_error_index in 0..3_usize {
            let mut evm_results = vec![
                (ankr_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
                (public_node_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
                (llama_nodes_evm_rpc_provider.clone(), Ok(evm_rpc_ok.clone())),
            ];
            evm_results.get_mut(first_error_index).unwrap().1 = Err(first_error.clone());
            let evm_result = EvmMultiRpcResult::Inconsistent(evm_results);

            let mut minter_results = vec![
                (ANKR, Ok(minter_ok.clone())),
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
                (ankr_evm_rpc_provider.clone(), Err(first_error.clone())),
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
                (ANKR, Err(SingleCallError::from(first_error.clone()))),
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
            (ankr_evm_rpc_provider.clone(), Err(first_error.clone())),
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
            (ANKR, Err(SingleCallError::from(first_error.clone()))),
            (
                PUBLIC_NODE,
                Err(SingleCallError::from(second_error.clone())),
            ),
            (LLAMA_NODES, Err(SingleCallError::from(third_error.clone()))),
        ]);
        prop_assert_eq_ignoring_provider(evm_result.reduce(), minter_result.reduce())?;

        Ok(())
    }

    fn evm_rpc_providers() -> (RpcService, RpcService, RpcService) {
        let ankr_evm_rpc_provider = EvmRpcService::Custom(EvmRpcApi {
            url: "ankr".to_string(),
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
            ankr_evm_rpc_provider,
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

    pub fn minter_and_evm_rpc_blocks() -> impl Strategy<Value = (Block, EvmBlock)> {
        use proptest::prelude::Just;
        arb_block().prop_flat_map(|minter_block| {
            (Just(minter_block.clone()), arb_evm_rpc_block(minter_block))
        })
    }

    pub fn arb_evm_rpc_block(minter_block: Block) -> impl Strategy<Value = EvmBlock> {
        use proptest::{array, collection::vec};
        //prop_map is limited to tuples of at most 11 elements, so we group the Nat and String fields
        (
            array::uniform7(arb_nat_256()),
            array::uniform9(".*"),
            vec(".*", 0..10),
            proptest::option::of(".*"),
            vec(".*", 0..10),
        )
            .prop_map(
                move |(
                    [difficulty, gas_limit, gas_used, nonce, size, timestamp, total_difficulty],
                    [extra_data, hash, logs_bloom, miner, mix_hash, parent_hash, receipts_root, sha3_uncles, state_root],
                    transactions,
                    transactions_root,
                    uncles,
                )| EvmBlock {
                    base_fee_per_gas: Nat::from(minter_block.base_fee_per_gas),
                    number: Nat::from(minter_block.number),
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
                    transactions_root,
                    uncles,
                },
            )
    }

    fn evm_rpc_log_entry(minter_log_entry: LogEntry) -> EvmLogEntry {
        EvmLogEntry {
            address: minter_log_entry.address.to_string(),
            topics: minter_log_entry
                .topics
                .into_iter()
                .map(|topic| topic.to_string())
                .collect(),
            data: format!("0x{}", hex::encode(minter_log_entry.data)),
            block_number: minter_log_entry.block_number.map(Nat::from),
            transaction_hash: minter_log_entry
                .transaction_hash
                .map(|hash| hash.to_string()),
            transaction_index: minter_log_entry
                .transaction_index
                .map(crate::eth_rpc::into_nat),
            block_hash: minter_log_entry.block_hash.map(|hash| hash.to_string()),
            log_index: minter_log_entry.log_index.map(Nat::from),
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
                .map(Nat::from)
                .collect(),
            gas_used_ratio,
            reward: minter_fee_history
                .reward
                .into_iter()
                .map(|rewards| rewards.into_iter().map(Nat::from).collect())
                .collect(),
        }
    }

    fn evm_rpc_block() -> EvmBlock {
        EvmBlock {
            base_fee_per_gas: 8_876_901_983_u64.into(),
            number: 20_061_336_u32.into(),
            difficulty: 0_u8.into(),
            extra_data: "0xd883010d0e846765746888676f312e32312e36856c696e7578".to_string(),
            gas_limit: 30_000_000_u32.into(),
            gas_used: 2_858_256_u32.into(),
            hash: "0x3a68e81a96d436f421b7cae6a66f78f6aef075340edaec5c7c1db0919c0f909b".to_string(),
            logs_bloom: "0x006000060010410010180000940006000000200040006108008801008022000900a005820000001100000300000d058962202900084080a0000031080022800000480c08100000006800000a20002028841080209044003041000940802448100002002a820085000000008400200d40204c10110810040403000210020004000a20208028104110a48429100033080e000040050501004800850042405230204230800000a0202282019080040040090a858000014014800440000208000008081804124002800030002040080610c000050002502000100005000a08002000001020500100804612440042300c0080040812000a1208420108200000000045".to_string(),
            miner: "0xd2732e3e4c264ab330af53f661f6da91cbbb594a".to_string(),
            mix_hash: "0x472d18a0b90d7007028dded03d7ef9923c2a7fc60f7e276bc6928fa9aeb6cbe8".to_string(),
            nonce: 0_u8.into(),
            parent_hash: "0xc0debe594704702ec9c2e5a56595ccbc285305108286a6a19aa33f8b3755da65".to_string(),
            receipts_root: "0x54179d043f2fe97f122a01366cd6ad18868501253282575fb00cada3fecf8fe1".to_string(),
            sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".to_string(),
            size: 17_484_u32.into(),
            state_root: "0x1e25cbd8eb25aadda3da160fd9b3fd46dfae61d7df1097d7990ca420e5c7c608".to_string(),
            timestamp: 1_718_021_363_u32.into(),
            total_difficulty: 58_750_003_716_598_352_816_469_u128.into(),
            transactions: vec![
                "0x5f17526ee5ab415ed44aa3788f0e8154230faa50f8b6d547a95858a8a90f259e",
                "0x1d0d559a2e113a4a4b738c97536c48e4a047a491614ddefe77c6e0f25b9e3a42",
                "0xd8c4f005fd4c7832205f6eda9bfde5bc5f9e0a1002b325d02348889f39e21850",
                "0xee14faac7f1d05a71ce69b11116a2ed8bf7a020a7b81a6a7a82096fdea7823a5",
                "0x63725de23700e115a48cb969a9e26eea56a65a971d63a21cc9cc660aa0cf4204",
                "0x77cbe1a9c3aef1ee9f345de7c189e9631e5458b194ba91ab2d9dc6d625e7eb68",
                "0x0e3403dcc6dea9dec03203ed9b1b89c66fd606abe3ac8bb33ed440283e5444cb",
                "0x91935e9885348f1ec4d673532c4f6709a28298f804b8054dea406407b00566af",
                "0x728b9eab683e4a59e75ebe03f1f9cdf081c04bc57f505cd8fc157a282e299c08",
                "0xb00dfcae52ef97f4f80965603f7c3a4c7f8c58e3e12caf6b636a522d0fbfef86",
                "0x604737ccc8f69cd4c1cd4c1e8f62655272d0a6db98923e907a5b0404d1822df4",
                "0x079ffeb1040d2490e248eb85047422bf3519c5fb5e3632ec3f245217c540a4b1",
                "0xd0c5a03b82d2b7cb62be59cb691cf5f6b0940b433360545e23e55044741f51dd",
                "0xe5707c1a13739613acec865053b88a03d7417004dec6086b544d92f4d9235880",
                "0x8f8541fa86b636d26b620c15741095e2920c27545b4b42efde1e15a702f99a00",
                "0x763b7f0bde974974d96e2ae1c9bee1bea8841acebf7c188477b198c93022f797",
                "0x9e518c8ced080b6d25836b506a5424ff98ca1933637e7586dd9464c48930880a",
                "0x08467c33ab74e9a379d63cbb1a03097c7cde7f85a166e60804c855cfd8bdcb96",
                "0x38928c665e5c62509066deaffcc94d497928b26bfef33d570a92b09af3a6cbbd",
                "0x2c616b1f2aa52a5f481d8aa5ebe0991f1f03d5c676f1b92cd03496ce753a5ae2",
                "0x3a4cf1999fe714e2be26f12a05270d85bb2033ee787727b94e5a7a3494e45f59",
                "0x8b3fc42aa0de7d0a181829229bc6ec8a5dd6c5d096945c0a2d149dd48a38e94a",
                "0xf1a3521cb1c73ae3bf5af18e25fdff023adabeea83503f73ca8721ce6ea27bfa",
                "0xff3265ddf367f97b50f95e4295bd101914fced55677315dee6c7618e31c721b6",
                "0xe6cc4470987f866cbddfe8e47a069a803fbda1b71055c49e96e78bdbe0cf1462",
                "0xccb8d52db4861b571240d71a58ba6cf8ea8e06567b82d68d517d383753cd8c65",
                "0x7c620a3c26299632c513f3940aae5dc971d1bedc93f669482e760cf4a86e25ee",
                "0xc2b265b37be476a291c87f10913960fe7ac790796248fb07e39fa40502e9fc03",
                "0x78083d9907ab4136e7df0cc266e4a6cddc4cf9e62948d5ab6bf81821ed26f45e",
                "0xf3776413512018e401b49b4661ecfd3f6daabe4aa52b3ae158ef8f10be424ca1",
                "0x53bc3267ef9f8f5a2d7be33f111391cbee7f13390de9bd531f5f216eef13582d",
                "0x6fc125dda0b34acd12f72fc5980fa5250ed1cfa985e60f5535123e7bfe82baca",
                "0xf9ace1b33ed117617cdae76a79a8fa758a8f3817c3aaf245a94953f565001d8a",
                "0xb186f79d1d6218ce61715f579ae2bde0582dede16d0ef9cf1cd85735f05445ea",
                "0x75e69b143d0fb26e4113c2dd0c2f702b2e917b5c23d81aaf587243525ef56e5a",
                "0xe6595bcb2ae614d890d38d153057826c3ad08063332276fa1b16e5f13b06e7a2",
                "0xd473fc760fb6cd8c81b7fe26e1bb6114d95957be22a713e1aac2cc63c2a3f0a3",
                "0x132d23074d8442c60337018bba749e0479f49b3d99a449934031289de6bd4587",
                "0xcead5cec4d5a30b28af721d8efbf77f05261daf76f60bc36298dbdc2793af703",
                "0x8b5b553313660e25a9a357c050576122e6d697314b1044f19f076df0d33f9823",
                "0xd73e844cd930c7463023fcc2eab8e40de90a5476f1c69d9466f506ec0a1c6953",
                "0x70bf1aed5af719155b036b0d761b86610e22855f60279982d1ca83c2c1493861",
                "0x5c2f23360e5247942d0b5150745cb4d8692de92e0fcb3cdfedff0341ff1f3a8e",
                "0x1c2eaceb326006f77142e3ffacc660d17b5b1ccf0ef2d22026149b9973d03752",
                "0x27f087175f96f9169e5e5320dffc920bab0181958df8385a143ac1ce9b7703a5",
                "0x672608a35f4fa4bb65955138521a887a892b0cd35d09f0359d00fdfa5cf427fd",
                "0x3b8942ca076f4e4e3e6222b577da88d888c79768d337bef14de6d75ba2540d11",
                "0x7e1614b107c5a7adc7478198b2d99d3dee48e443f1f475524479aee0a4c9e402",
                "0x5f9c5284a47ed5a6f6e672d48fea29966b3d91d63487ab47bc8f5514f231e687",
                "0x3715bb37c438c4e95fab950f573d184770faf8019018d2b47d6220003f0b35d0",
                "0x33137040d80df84243b63833eea5b34a505a2ca8fb1a34318b74cecf5f4aa7c8",
                "0x470940a47746125aae7513cb22bdac628865ee3df34e99bd0ecd48ff23b47f41",
                "0x875c9fda2e0ccffde973385ee72d106f1fea12fda8d250f55a85007e13422e40",
                "0xd3a08793b023ff2eb5c3e1d9b90254172a796095972d8dc2714cc094f6fc6c19",
                "0x135366e9141a1b871e73941f00c2e321b4ab51c99d58b95f1b201f30c3f7d0d2",
                "0xc93ec0af7511a39dfe389fb37d21144914c99ddc8d259e47146e8b45d288e8f8",
                "0x6ba2a677ff759be8e76f42e1b5d009b5a39f186fa417f00679105059b4cc725c",
                "0x8657b391f8575ab4f7323a5e24e3ca53df61cb433cf88cbef40000c05badedc7",
                "0x6e14d76d37b4dab55b5e49276b207b0e4f117ef8103728f8dadc487996e30c34",
                "0xac4489a73246f8f81503e11254003158893785ae4a603eedddec8b23945d3630",
                "0x50b5e07019621c041d061df0dc447674d719391862238c25181fd45f4bea441c",
                "0x424431243694085158cdcf5ed1666b88421fb3c7fde538acf36f8ea8316d827b",
                "0xf1d5e8256194f29e7da773ea8ef9e60ba7c5ceb7fb9ab9966d2c7b53d4c347ff",
                "0x25f85c5fcda53d733bf0dafe552984b0e17e5202fe9225a9a1bf94b50575e5d8",
                "0xe2499f7bbc8acdc3f273ac29f7757071844b739d2a84ab19440a9b1a3cbe901d",
                "0x25525be1316671638e2b6146f3e3259be8dee11cf8a24cb64b0feb2ad7f1ebf9",
                "0x0518268fb4b06a1285997efb841615a74d113571332ac7c935d2a303ca1d6f23",
                "0x1510c9bf4678ec3e67d05c908ba6d2762c4a815476638cc1d281d65a7dab6745"
            ].into_iter().map(|s| s.to_string()).collect(),
            transactions_root: Some("0xdee0b25a965ff236e4d2e89f56de233759d71ad3e3e150ceb4cf5bb1f0ecf5c0".to_string()),
            uncles: vec![],
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
                option::of(".*"),
                ".*",
                vec(arb_log_entry(), 1..=100),
                ".*",
                ".*",
                arb_nat_256(),
                ".*",
            )
                .prop_map(
                    move |(
                        contract_address,
                        from,
                        minter_logs,
                        logs_bloom,
                        to,
                        transaction_index,
                        r#type,
                    )| {
                        Some(EvmTransactionReceipt {
                            block_hash: r.block_hash.to_string(),
                            block_number: r.block_number.into(),
                            effective_gas_price: r.effective_gas_price.into(),
                            gas_used: r.gas_used.into(),
                            status: Nat::from(ethnum::u256::from(r.status).as_u8()),
                            transaction_hash: r.transaction_hash.to_string(),
                            contract_address,
                            from,
                            logs: minter_logs.into_iter().map(evm_rpc_log_entry).collect(),
                            logs_bloom,
                            to,
                            transaction_index,
                            r#type,
                        })
                    },
                )
                .boxed(),
        }
    }

    fn arb_evm_rpc_transaction_count() -> impl Strategy<Value = EvmRpcResult<Nat>> {
        proptest::result::maybe_ok(arb_nat_256(), arb_evm_rpc_error())
    }

    fn arb_evm_rpc_send_raw_transaction_status(
    ) -> impl Strategy<Value = EvmSendRawTransactionStatus> {
        use proptest::{
            option,
            prelude::{prop_oneof, Just},
        };
        prop_oneof![
            option::of(".*").prop_map(EvmSendRawTransactionStatus::Ok),
            Just(EvmSendRawTransactionStatus::InsufficientFunds),
            Just(EvmSendRawTransactionStatus::NonceTooLow),
            Just(EvmSendRawTransactionStatus::NonceTooHigh),
        ]
    }
}
