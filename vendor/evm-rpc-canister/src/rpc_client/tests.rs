use crate::rpc_client::process_result;
use crate::types::RpcMethod;
use canhttp::multi::MultiResults;
use evm_rpc_types::{MultiRpcResult, ProviderError, RpcError};

mod eth_rpc_client {
    use crate::rpc_client::EthRpcClient;
    use canhttp::multi::Timestamp;
    use evm_rpc_types::{EthMainnetService, ProviderError, RpcService, RpcServices};
    use maplit::btreeset;

    #[test]
    fn should_fail_when_providers_explicitly_set_to_empty() {
        for empty_source in [
            RpcServices::Custom {
                chain_id: 1,
                services: vec![],
            },
            RpcServices::EthMainnet(Some(vec![])),
            RpcServices::EthSepolia(Some(vec![])),
            RpcServices::ArbitrumOne(Some(vec![])),
            RpcServices::BaseMainnet(Some(vec![])),
            RpcServices::OptimismMainnet(Some(vec![])),
        ] {
            assert_eq!(
                EthRpcClient::new(empty_source, None, Timestamp::default()),
                Err(ProviderError::ProviderNotFound)
            );
        }
    }

    #[test]
    fn should_use_default_providers() {
        for empty_source in [
            RpcServices::EthMainnet(None),
            RpcServices::EthSepolia(None),
            RpcServices::ArbitrumOne(None),
            RpcServices::BaseMainnet(None),
            RpcServices::OptimismMainnet(None),
        ] {
            let client = EthRpcClient::new(empty_source, None, Timestamp::default()).unwrap();
            assert!(!client.providers.services.is_empty());
        }
    }

    #[test]
    fn should_use_specified_provider() {
        let provider1 = EthMainnetService::Alchemy;
        let provider2 = EthMainnetService::PublicNode;

        let client = EthRpcClient::new(
            RpcServices::EthMainnet(Some(vec![provider1, provider2])),
            None,
            Timestamp::default(),
        )
        .unwrap();

        assert_eq!(
            client.providers.services,
            btreeset! {
                RpcService::EthMainnet(provider1),
                RpcService::EthMainnet(provider2)
            }
        );
    }
}

mod eth_get_transaction_receipt {
    use crate::rpc_client::json::responses::{TransactionReceipt, TransactionStatus};
    use crate::rpc_client::json::{Hash, JsonByte};
    use crate::rpc_client::numeric::{BlockNumber, GasAmount, WeiPerGas};
    use assert_matches::assert_matches;
    use proptest::proptest;
    use std::str::FromStr;

    #[test]
    fn should_deserialize_pre_byzantium_transaction_receipt() {
        const RECEIPT: &str = r#"{
        "blockHash": "0x9b3c1d182975fdaa5797879cbc45d6b00a84fb3b13980a107645b2491bcca899",
        "blockNumber": "0x3d08ff",
        "contractAddress": null,
        "cumulativeGasUsed": "0x3a827d",
        "effectiveGasPrice": "0x4e3b29200",
        "from": "0xcaf8925d8e825ebe0cb3fc34a2be2c8c737c1ecc",
        "gasUsed": "0x5208",
        "logs": [],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "root": "0xc13704a89e282b166ecf5ac93f7f7c1be7141572c1ce4cc8aae28d526d535b4d",
        "to": "0x0f1f8a981160a93da959484216b0b8db0ce2cd8e",
        "transactionHash": "0x48614dab7303dda8ecfa52c6f583a3e09b3bc1724fb5a1512c361f2b36ed242d",
        "transactionIndex": "0x14",
        "type": "0x0"
    }"#;

        let receipt: TransactionReceipt = serde_json::from_str(RECEIPT).unwrap();

        assert_eq!(
            receipt,
            TransactionReceipt {
                block_hash: Hash::from_str(
                    "0x9b3c1d182975fdaa5797879cbc45d6b00a84fb3b13980a107645b2491bcca899"
                )
                    .unwrap(),
                block_number: BlockNumber::new(0x3d08ff),
                effective_gas_price: WeiPerGas::new(0x4e3b29200),
                cumulative_gas_used: GasAmount::new(0x3a827d),
                gas_used: GasAmount::new(0x5208),
                status: None,
                root: Some(Hash::from_str("0xc13704a89e282b166ecf5ac93f7f7c1be7141572c1ce4cc8aae28d526d535b4d").unwrap()),
                transaction_hash: Hash::from_str(
                    "0x48614dab7303dda8ecfa52c6f583a3e09b3bc1724fb5a1512c361f2b36ed242d"
                )
                    .unwrap(),
                contract_address: None,
                from: "0xcaf8925d8e825ebe0cb3fc34a2be2c8c737c1ecc".parse().unwrap(),
                logs: vec![],
                logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                to: Some("0x0f1f8a981160a93da959484216b0b8db0ce2cd8e".parse().unwrap()),
                transaction_index: 0x14_u32.into(),
                tx_type: JsonByte::new(0),
            }
        )
    }

    #[test]
    fn should_deserialize_post_byzantium_transaction_receipt() {
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
                cumulative_gas_used: GasAmount::new(0x8b2e10),
                gas_used: GasAmount::new(0x5208),
                status: Some(TransactionStatus::Success),
                root: None,
                transaction_hash: Hash::from_str(
                    "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"
                )
                    .unwrap(),
                contract_address: None,
                from: "0x1789f79e95324a47c5fd6693071188e82e9a3558".parse().unwrap(),
                logs: vec![],
                logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
                to: Some("0xdd2851cdd40ae6536831558dd46db62fac7a844d".parse().unwrap()),
                transaction_index: 0x32_u32.into(),
                tx_type: JsonByte::new(2),
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
    use crate::rpc_client::json::requests::{BlockSpec, BlockTag, GetTransactionCountParams};
    use crate::rpc_client::numeric::TransactionCount;
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

mod providers {
    use crate::arbitrary::{arb_custom_rpc_services, arb_rpc_services};
    use crate::rpc_client::Providers;
    use assert_matches::assert_matches;
    use canhttp::multi::Timestamp;
    use evm_rpc_types::{
        ConsensusStrategy, EthMainnetService, EthSepoliaService, L2MainnetService, ProviderError,
        RpcServices,
    };
    use proptest::arbitrary::any;
    use proptest::proptest;

    // Note that changing the number of providers is a non-trivial operation
    // that has consequences for all users of the EVM RPC canister:
    // 1) Decreasing the number of providers is a breaking change:
    //    - E.g. ConsensusStrategy::Threshold { total: Some(6), min: 3 } would fail
    //      if the number of providers is decreased from 6 to 5.
    // 2) Increasing the number of providers, while non-breaking, is a significant change
    //    since that number can no longer be decreased afterwards without a breaking change.
    #[test]
    fn should_have_stable_number_of_providers() {
        assert_eq!(EthMainnetService::all().len(), 6);
        assert_eq!(EthSepoliaService::all().len(), 5);
        assert_eq!(L2MainnetService::all().len(), 5);
    }

    proptest! {
        #[test]
        fn should_choose_custom_providers(
            not_enough_custom_providers in arb_custom_rpc_services(0..=3),
            custom_providers in arb_custom_rpc_services(4..=4),
            too_many_custom_providers in arb_custom_rpc_services(5..=10)
        ) {
            let strategy = ConsensusStrategy::Threshold {
                total: Some(4),
                min: 3,
            };

            let providers = Providers::new(
                not_enough_custom_providers,
                strategy.clone(),
                Timestamp::default()
            );
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));

             let providers = Providers::new(
                too_many_custom_providers,
                strategy.clone(),
                Timestamp::default()
            );
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));

            let _providers = Providers::new(
                custom_providers.clone(),
                strategy,
                Timestamp::default()
            ).unwrap();
        }
    }

    #[test]
    fn should_fail_when_threshold_unspecified_with_default_providers() {
        let strategy = ConsensusStrategy::Threshold {
            total: None,
            min: 3,
        };

        for default_services in [
            RpcServices::EthMainnet(None),
            RpcServices::EthSepolia(None),
            RpcServices::ArbitrumOne(None),
            RpcServices::BaseMainnet(None),
            RpcServices::OptimismMainnet(None),
        ] {
            let providers =
                Providers::new(default_services, strategy.clone(), Timestamp::default());
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_threshold_larger_than_number_of_supported_providers(min in any::<u8>()) {
            for (default_services, max_total) in [
                (
                    RpcServices::EthMainnet(None),
                    EthMainnetService::all().len(),
                ),
                (
                    RpcServices::EthSepolia(None),
                    EthSepoliaService::all().len(),
                ),
                (
                    RpcServices::ArbitrumOne(None),
                    L2MainnetService::all().len(),
                ),
                (
                    RpcServices::BaseMainnet(None),
                    L2MainnetService::all().len(),
                ),
                (
                    RpcServices::OptimismMainnet(None),
                    L2MainnetService::all().len(),
                ),
            ] {
                let strategy = ConsensusStrategy::Threshold {
                    total: Some((max_total + 1) as u8),
                    min,
                };
                let providers = Providers::new(default_services, strategy, Timestamp::default());
                assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
            }
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_threshold_invalid(services in arb_rpc_services()) {
            let strategy = ConsensusStrategy::Threshold {
                total: Some(4),
                min: 5,
            };
            let providers = Providers::new(services.clone(), strategy.clone(), Timestamp::default());
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));

             let strategy = ConsensusStrategy::Threshold {
                total: Some(4),
                min: 0,
            };
            let providers = Providers::new(services, strategy.clone(), Timestamp::default());
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
        }
    }
}

#[test]
fn test_process_result_mapping() {
    use evm_rpc_types::{EthMainnetService, RpcService};
    type ReductionError = canhttp::multi::ReductionError<RpcService, u32, RpcError>;

    assert_eq!(
        process_result(RpcMethod::EthGetTransactionCount, Ok(5)),
        MultiRpcResult::Consistent(Ok(5))
    );
    assert_eq!(
        process_result(
            RpcMethod::EthGetTransactionCount,
            Err(ReductionError::ConsistentError(RpcError::ProviderError(
                ProviderError::MissingRequiredProvider
            )))
        ),
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(
            ProviderError::MissingRequiredProvider
        )))
    );
    assert_eq!(
        process_result(
            RpcMethod::EthGetTransactionCount,
            Err(ReductionError::InconsistentResults(MultiResults::default()))
        ),
        MultiRpcResult::Inconsistent(vec![])
    );
    assert_eq!(
        process_result(
            RpcMethod::EthGetTransactionCount,
            Err(ReductionError::InconsistentResults(
                MultiResults::from_non_empty_iter(vec![(
                    RpcService::EthMainnet(EthMainnetService::Ankr),
                    Ok(5)
                )])
            ))
        ),
        MultiRpcResult::Inconsistent(vec![(
            RpcService::EthMainnet(EthMainnetService::Ankr),
            Ok(5)
        )])
    );
    assert_eq!(
        process_result(
            RpcMethod::EthGetTransactionCount,
            Err(ReductionError::InconsistentResults(
                MultiResults::from_non_empty_iter(vec![
                    (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
                    (
                        RpcService::EthMainnet(EthMainnetService::Cloudflare),
                        Err(RpcError::ProviderError(ProviderError::NoPermission))
                    )
                ])
            ))
        ),
        MultiRpcResult::Inconsistent(vec![
            (RpcService::EthMainnet(EthMainnetService::Ankr), Ok(5)),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Err(RpcError::ProviderError(ProviderError::NoPermission))
            )
        ])
    );
}
