mod eth_rpc_client {
    use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider, SepoliaProvider};
    use crate::eth_rpc_client::EthRpcClient;
    use crate::lifecycle::EvmNetwork;

    #[test]
    fn should_retrieve_sepolia_providers_in_stable_order() {
        let client = EthRpcClient::new(EvmNetwork::Sepolia, None);

        let providers = client.providers();

        assert_eq!(
            providers,
            &[
                RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
                RpcNodeProvider::Sepolia(SepoliaProvider::BlockPi),
                RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode)
            ]
        );
    }

    #[test]
    fn should_retrieve_mainnet_providers_in_stable_order() {
        let client = EthRpcClient::new(EvmNetwork::Ethereum, None);

        let providers = client.providers();

        assert_eq!(
            providers,
            &[
                RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
                RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare)
            ]
        );
    }
}

mod multi_call_results {
    use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider};

    const ANKR: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Ankr);
    const CLOUDFLARE: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare);

    mod reduce_with_equality {
        use crate::eth_rpc::{HttpOutcallError, JsonRpcResult};
        use crate::eth_rpc_client::tests::multi_call_results::{ANKR, CLOUDFLARE};
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
                    CLOUDFLARE,
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
                    CLOUDFLARE,
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
                (CLOUDFLARE, Ok(JsonRpcResult::Result("world".to_string()))),
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
                    CLOUDFLARE,
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
                    CLOUDFLARE,
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
                (CLOUDFLARE, Ok(JsonRpcResult::Result("0x01".to_string()))),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Ok("0x01".to_string()));
        }
    }

    mod reduce_with_min_by_key {
        use crate::eth_rpc::{Block, JsonRpcResult};
        use crate::eth_rpc_client::tests::multi_call_results::{ANKR, CLOUDFLARE};
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
                    CLOUDFLARE,
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
}

mod eth_get_transaction_receipt {
    use crate::eth_rpc::{Hash, Quantity};
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::{BlockNumber, Wei};
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
                effective_gas_price: Wei::new(0xfefbee3e),
                gas_used: Quantity::new(0x5208),
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
    use crate::address::Address;
    use crate::eth_rpc::{BlockSpec, BlockTag};
    use crate::eth_rpc_client::requests::GetTransactionCountParams;
    use crate::numeric::TransactionCount;
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
