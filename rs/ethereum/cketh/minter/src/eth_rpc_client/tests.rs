use crate::{
    eth_rpc::Hash,
    eth_rpc_client::{
        MinByKey, MultiCallError, MultiCallResults, StrictMajorityByKey, ToReducedWithStrategy,
        responses::{TransactionReceipt, TransactionStatus},
    },
    numeric::{BlockNumber, GasAmount, TransactionCount, WeiPerGas},
};
use assert_matches::assert_matches;
use candid::Nat;
use evm_rpc_types::{
    EthMainnetService, FeeHistory, HttpOutcallError, JsonRpcError, LegacyRejectionCode,
    MultiRpcResult, Nat256, RpcError, RpcService as EvmRpcService,
};
use proptest::{prelude::any, proptest};
use std::str::FromStr;

const BLOCK_PI: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::BlockPi);
const PUBLIC_NODE: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::PublicNode);
const LLAMA_NODES: EvmRpcService = EvmRpcService::EthMainnet(EthMainnetService::Llama);

mod multi_call_results {
    use super::*;

    mod reduce_with_min_by_key {
        use super::*;

        #[test]
        fn should_get_minimum_tx_count() {
            let results: MultiRpcResult<Nat256> = MultiRpcResult::Inconsistent(vec![
                (BLOCK_PI, Ok(123456_u32.into())),
                (PUBLIC_NODE, Ok(123457_u32.into())),
            ]);

            let reduced: Result<TransactionCount, _> = results
                .map(TransactionCount::from)
                .reduce_with_strategy(MinByKey::new(|count: &TransactionCount| *count));

            assert_eq!(reduced, Ok(TransactionCount::new(123456)));
        }
    }

    mod reduce_with_stable_majority_by_key {
        use super::*;

        #[test]
        fn should_get_unanimous_fee_history() {
            let results: MultiRpcResult<FeeHistory> = MultiRpcResult::Consistent(Ok(fee_history()));

            let reduced: Result<FeeHistory, _> =
                results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

            assert_eq!(reduced, Ok(fee_history()));
        }

        #[test]
        fn should_get_fee_history_with_2_out_of_3() {
            for index_non_majority in 0..3_usize {
                let index_majority = (index_non_majority + 1) % 3;
                let mut fees = [fee_history(), fee_history(), fee_history()];
                fees[index_non_majority].oldest_block = 0x10f73fd_u32.into();
                assert_ne!(
                    fees[index_non_majority].oldest_block,
                    fees[index_majority].oldest_block
                );
                let majority_fee = fees[index_majority].clone();
                let [
                    block_pi_fee_history,
                    llama_nodes_fee_history,
                    public_node_fee_history,
                ] = fees;
                let results: MultiRpcResult<FeeHistory> = MultiRpcResult::Inconsistent(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history)),
                    (LLAMA_NODES, Ok(llama_nodes_fee_history)),
                    (PUBLIC_NODE, Ok(public_node_fee_history)),
                ]);

                let reduced: Result<FeeHistory, _> =
                    results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

                assert_eq!(reduced, Ok(majority_fee));
            }
        }

        #[test]
        fn should_get_fee_history_with_2_out_of_3_when_third_is_error() {
            let results: MultiRpcResult<FeeHistory> = MultiRpcResult::Inconsistent(vec![
                (BLOCK_PI, Ok(fee_history())),
                (
                    PUBLIC_NODE,
                    Err(HttpOutcallError::IcError {
                        code: LegacyRejectionCode::SysTransient,
                        message: "no consensus".to_string(),
                    }
                    .into()),
                ),
                (LLAMA_NODES, Ok(fee_history())),
            ]);

            let reduced: Result<FeeHistory, _> =
                results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

            assert_eq!(reduced, Ok(fee_history()));
        }

        #[test]
        fn should_fail_when_no_strict_majority() {
            let block_pi_fee_history = FeeHistory {
                oldest_block: 0x10f73fd_u32.into(),
                ..fee_history()
            };
            let llama_nodes_fee_history = FeeHistory {
                oldest_block: 0x10f73fc_u32.into(),
                ..fee_history()
            };
            let public_node_fee_history = FeeHistory {
                oldest_block: 0x10f73fe_u32.into(),
                ..fee_history()
            };
            let three_distinct_results: MultiRpcResult<FeeHistory> =
                MultiRpcResult::Inconsistent(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (LLAMA_NODES, Ok(llama_nodes_fee_history.clone())),
                    (PUBLIC_NODE, Ok(public_node_fee_history.clone())),
                ]);

            let reduced: Result<FeeHistory, _> =
                three_distinct_results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                        (PUBLIC_NODE, Ok(public_node_fee_history)),
                    ])
                ))
            );

            let two_distinct_results: MultiRpcResult<FeeHistory> =
                MultiRpcResult::Inconsistent(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                ]);

            let reduced: Result<FeeHistory, _> =
                two_distinct_results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                        (PUBLIC_NODE, Ok(llama_nodes_fee_history.clone())),
                    ])
                ))
            );

            let two_distinct_results_and_error: MultiRpcResult<FeeHistory> =
                MultiRpcResult::Inconsistent(vec![
                    (BLOCK_PI, Ok(block_pi_fee_history.clone())),
                    (
                        PUBLIC_NODE,
                        Err(JsonRpcError {
                            code: -32700,
                            message: "error".to_string(),
                        }
                        .into()),
                    ),
                    (LLAMA_NODES, Ok(llama_nodes_fee_history.clone())),
                ]);

            let reduced: Result<FeeHistory, _> = two_distinct_results_and_error
                .reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

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
                inconsistent_fee.base_fee_per_gas[0] = 0x729d3f3b4_u64.into();
                assert_ne!(fee, inconsistent_fee);
                (fee, inconsistent_fee)
            };

            let results: MultiRpcResult<FeeHistory> = MultiRpcResult::Inconsistent(vec![
                (BLOCK_PI, Ok(fee.clone())),
                (PUBLIC_NODE, Ok(inconsistent_fee.clone())),
            ]);

            let reduced: Result<FeeHistory, _> =
                results.reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

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
            let results: MultiRpcResult<FeeHistory> = MultiRpcResult::Inconsistent(vec![
                (BLOCK_PI, Ok(fee_history())),
                (
                    PUBLIC_NODE,
                    Err(JsonRpcError {
                        code: -32700,
                        message: "error".to_string(),
                    }
                    .into()),
                ),
            ]);

            let reduced: Result<FeeHistory, _> = results
                .clone()
                .reduce_with_strategy(StrictMajorityByKey::new(oldest_block));

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_non_empty_iter(vec![
                        (BLOCK_PI, Ok(fee_history())),
                        (
                            PUBLIC_NODE,
                            Err(JsonRpcError {
                                code: -32700,
                                message: "error".to_string(),
                            }
                            .into()),
                        ),
                    ])
                ))
            );
        }

        fn fee_history() -> FeeHistory {
            FeeHistory {
                oldest_block: 0x10f73fc_u32.into(),
                base_fee_per_gas: vec![
                    0x729d3f3b3_u64.into(),
                    0x766e503ea_u64.into(),
                    0x75b51b620_u64.into(),
                    0x74094f2b4_u64.into(),
                    0x716724f03_u64.into(),
                    0x73b467f76_u64.into(),
                ],
                gas_used_ratio: vec![1f64; 6],
                reward: vec![
                    vec![0x5f5e100_u32.into()],
                    vec![0x55d4a80_u32.into()],
                    vec![0x5f5e100_u32.into()],
                    vec![0x5f5e100_u32.into()],
                    vec![0x5f5e100_u32.into()],
                ],
            }
        }
    }

    mod has_http_outcall_error_matching {
        use super::*;

        proptest! {
            #[test]
            fn should_not_match_when_consistent_json_rpc_error(code in any::<i64>(), message in ".*") {
                let error: MultiCallError<String> = MultiCallError::ConsistentError(RpcError::JsonRpcError(JsonRpcError {
                    code,
                    message,
                }));
                let always_true = |_outcall_error: &HttpOutcallError| true;

                assert!(!error.has_http_outcall_error_matching(always_true));
            }
        }

        #[test]
        fn should_match_when_consistent_http_outcall_error() {
            let error: MultiCallError<String> = MultiCallError::ConsistentError(
                RpcError::HttpOutcallError(HttpOutcallError::IcError {
                    code: LegacyRejectionCode::SysTransient,
                    message: "message".to_string(),
                }),
            );
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
                        Err(JsonRpcError {
                            code: -32700,
                            message: "error".to_string(),
                        }
                        .into()),
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
                            code: LegacyRejectionCode::SysTransient,
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
    use super::*;

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
            let status = format!("\"0x{wrong_status:x}\"");
            let error = serde_json::from_str::<TransactionStatus>(&status);
            assert_matches!(error, Err(e) if e.to_string().contains("invalid transaction status"));
        }
    }
}

mod eth_get_transaction_count {
    use super::*;

    #[test]
    fn should_deserialize_transaction_count() {
        let count: TransactionCount = serde_json::from_str("\"0x3d8\"").unwrap();
        assert_eq!(count, TransactionCount::from(0x3d8_u32));
    }
}

fn oldest_block(fee_history: &FeeHistory) -> Nat {
    Nat::from(fee_history.oldest_block.clone())
}
