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
                RpcNodeProvider::Sepolia(SepoliaProvider::BlockPi)
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
                RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare)
            ]
        );
    }
}

mod multi_call_results {

    mod reduce_with_equality {
        use crate::eth_rpc::{HttpOutcallError, JsonRpcResult};
        use crate::eth_rpc_client::providers::{EthereumProvider, RpcNodeProvider};
        use crate::eth_rpc_client::{MultiCallError, MultiCallResults};
        use ic_cdk::api::call::RejectionCode;

        const ANKR: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Ankr);
        const CLOUDFLARE: RpcNodeProvider = RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare);

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
}

mod eth_get_transaction_receipt {
    use crate::address::Address;
    use crate::eth_rpc::{BlockNumber, Hash, Quantity};
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::Wei;
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
                from: Address::from_str("0x1789f79e95324a47c5fd6693071188e82e9a3558").unwrap(),
                to: Some(Address::from_str("0xdd2851cdd40ae6536831558dd46db62fac7a844d").unwrap()),
                contract_address: None,
                gas_used: Quantity::new(0x5208),
                status: TransactionStatus::Success,
                transaction_hash: Hash::from_str(
                    "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"
                )
                .unwrap(),
                transaction_index: Quantity::new(0x32)
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

    proptest! {
        #[test]
        fn should_fail_deserializing_wrong_transaction_status(wrong_status in 2_u32..u32::MAX) {
            let status = format!("\"0x{:x}\"", wrong_status);
            let error = serde_json::from_str::<TransactionStatus>(&status);
            assert_matches!(error, Err(e) if e.to_string().contains("invalid transaction status"));
        }
    }
}
