mod static_map {
    use crate::providers::{PROVIDERS, SERVICE_PROVIDER_MAP};
    use std::collections::{BTreeSet, HashMap};

    use crate::{
        constants::API_KEY_REPLACE_STRING,
        types::{Provider, RpcAccess, RpcAuth},
    };

    #[test]
    fn test_provider_id_sequence() {
        for (i, provider) in PROVIDERS.iter().enumerate() {
            assert_eq!(provider.provider_id, i as u64);
        }
    }

    #[test]
    fn test_rpc_provider_url_patterns() {
        for provider in PROVIDERS {
            fn assert_not_url_pattern(url: &str, provider: &Provider) {
                assert!(
                    !url.contains(API_KEY_REPLACE_STRING),
                    "Unexpected API key in URL for provider: {}",
                    provider.provider_id
                )
            }
            fn assert_url_pattern(url: &str, provider: &Provider) {
                assert!(
                    url.contains(API_KEY_REPLACE_STRING),
                    "Missing API key in URL pattern for provider: {}",
                    provider.provider_id
                )
            }
            match &provider.access {
                RpcAccess::Authenticated { auth, public_url } => {
                    match auth {
                        RpcAuth::BearerToken { url } => assert_not_url_pattern(url, provider),
                        RpcAuth::UrlParameter { url_pattern } => {
                            assert_url_pattern(url_pattern, provider)
                        }
                    }
                    if let Some(public_url) = public_url {
                        assert_not_url_pattern(public_url, provider);
                    }
                }
                RpcAccess::Unauthenticated { public_url } => {
                    assert_not_url_pattern(public_url, provider);
                }
            }
        }
    }

    #[test]
    fn test_no_duplicate_service_providers() {
        SERVICE_PROVIDER_MAP.with(|map| {
            assert_eq!(
                map.len(),
                map.keys().collect::<BTreeSet<_>>().len(),
                "Duplicate service in mapping"
            );
            assert_eq!(
                map.len(),
                map.values().collect::<BTreeSet<_>>().len(),
                "Duplicate provider in mapping"
            );
        })
    }

    #[test]
    fn test_service_provider_coverage() {
        SERVICE_PROVIDER_MAP.with(|map| {
            let inverse_map: HashMap<_, _> = map.iter().map(|(k, v)| (v, k)).collect();
            for provider in PROVIDERS {
                assert!(
                    inverse_map.contains_key(&provider.provider_id),
                    "Missing service mapping for provider with ID: {}",
                    provider.provider_id
                );
            }
        })
    }
}

mod supported_rpc_service {
    use crate::providers::SupportedRpcService;
    use evm_rpc_types::{EthMainnetService, EthSepoliaService, L2MainnetService};
    use std::collections::BTreeSet;

    #[test]
    fn should_have_all_supported_providers() {
        fn assert_same_set(
            left: impl Iterator<Item = SupportedRpcService>,
            right: &[SupportedRpcService],
        ) {
            let left: BTreeSet<_> = left.collect();
            let right: BTreeSet<_> = right.iter().copied().collect();
            assert_eq!(left, right);
        }

        assert_same_set(
            EthMainnetService::all()
                .iter()
                .copied()
                .map(SupportedRpcService::EthMainnet),
            SupportedRpcService::eth_mainnet(),
        );

        assert_same_set(
            EthSepoliaService::all()
                .iter()
                .copied()
                .map(SupportedRpcService::EthSepolia),
            SupportedRpcService::eth_sepolia(),
        );

        assert_same_set(
            L2MainnetService::all()
                .iter()
                .copied()
                .map(SupportedRpcService::ArbitrumOne),
            SupportedRpcService::arbitrum_one(),
        );

        assert_same_set(
            L2MainnetService::all()
                .iter()
                .copied()
                .map(SupportedRpcService::BaseMainnet),
            SupportedRpcService::base_mainnet(),
        );

        assert_same_set(
            L2MainnetService::all()
                .iter()
                .copied()
                .map(SupportedRpcService::OptimismMainnet),
            SupportedRpcService::optimism_mainnet(),
        );
    }
}

mod supported_rpc_service_usage {
    use crate::providers::{SupportedRpcService, SupportedRpcServiceUsage};
    use canhttp::multi::Timestamp;
    use std::time::Duration;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn should_have_default_ordering_when_no_data() {
        let mut usage = SupportedRpcServiceUsage::default();

        for providers in all_supported_providers() {
            let ordered = usage.rank_ascending_evict(providers, Timestamp::UNIX_EPOCH);
            assert_eq!(ordered, providers);
        }
    }

    #[test]
    fn should_have_default_ordering_when_data_expired() {
        let mut usage = SupportedRpcServiceUsage::default();
        let now = Timestamp::UNIX_EPOCH;
        for supported_providers in all_supported_providers() {
            let last_provider = *supported_providers.last().unwrap();
            usage.record_evict(last_provider, now);
        }

        let expired = Timestamp::from_unix_epoch(21 * MINUTE);
        for supported_providers in all_supported_providers() {
            let ordered = usage.rank_ascending_evict(supported_providers, expired);
            assert_eq!(ordered, supported_providers);
        }
    }

    #[test]
    fn should_rank_based_on_non_expired_data() {
        let mut usage = SupportedRpcServiceUsage::default();
        for supported_providers in all_supported_providers() {
            assert!(supported_providers.len() >= 2);

            // 3 entries, 2 expire after > 20 minutes
            usage.record_evict(supported_providers[0], Timestamp::UNIX_EPOCH);
            usage.record_evict(supported_providers[0], Timestamp::UNIX_EPOCH);
            usage.record_evict(supported_providers[0], Timestamp::from_unix_epoch(MINUTE));

            // 3 entries, 1 expire after > 20 minutes
            usage.record_evict(supported_providers[1], Timestamp::UNIX_EPOCH);
            usage.record_evict(supported_providers[1], Timestamp::from_unix_epoch(MINUTE));
            usage.record_evict(supported_providers[1], Timestamp::from_unix_epoch(MINUTE));
        }

        for supported_providers in all_supported_providers() {
            let non_expired = Timestamp::from_unix_epoch(20 * MINUTE);
            let usage_before = usage.clone();
            let ordered = usage.rank_ascending_evict(supported_providers, non_expired);
            assert_eq!(ordered, supported_providers);
            assert_eq!(usage, usage_before);

            let expired = Timestamp::from_unix_epoch(21 * MINUTE);
            let usage_before = usage.clone();
            let ordered = usage.rank_ascending_evict(supported_providers, expired);
            let expected_order = {
                let mut expected = vec![supported_providers[1], supported_providers[0]];
                expected.extend(&supported_providers[2..]);
                expected
            };
            assert_eq!(ordered, expected_order);
            assert_ne!(usage, usage_before);
        }
    }

    fn all_supported_providers() -> [&'static [SupportedRpcService]; 5] {
        [
            SupportedRpcService::eth_mainnet(),
            SupportedRpcService::eth_sepolia(),
            SupportedRpcService::arbitrum_one(),
            SupportedRpcService::base_mainnet(),
            SupportedRpcService::optimism_mainnet(),
        ]
    }
}
