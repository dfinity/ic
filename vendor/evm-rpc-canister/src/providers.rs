#[cfg(test)]
mod tests;

use crate::{
    constants::{
        ARBITRUM_ONE_CHAIN_ID, BASE_MAINNET_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        OPTIMISM_MAINNET_CHAIN_ID,
    },
    types::{Provider, ProviderId, ResolvedRpcService, RpcAccess, RpcAuth},
};
use canhttp::multi::{TimedSizedMap, TimedSizedVec, Timestamp};
use evm_rpc_types::{
    EthMainnetService, EthSepoliaService, L2MainnetService, ProviderError, RpcApi, RpcService,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

pub const PROVIDERS: &[Provider] = &[
    Provider {
        provider_id: 0,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://cloudflare-eth.com/v1/mainnet",
            },
            public_url: Some("https://cloudflare-eth.com/v1/mainnet"),
        },
        alias: Some(SupportedRpcService::EthMainnet(
            EthMainnetService::Cloudflare,
        )),
    },
    Provider {
        provider_id: 1,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/eth/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/eth"),
        },
        alias: Some(SupportedRpcService::EthMainnet(EthMainnetService::Ankr)),
    },
    Provider {
        provider_id: 2,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://ethereum-rpc.publicnode.com",
        },
        alias: Some(SupportedRpcService::EthMainnet(
            EthMainnetService::PublicNode,
        )),
    },
    Provider {
        provider_id: 3,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://ethereum.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://ethereum.public.blockpi.network/v1/rpc/public"),
        },
        alias: Some(SupportedRpcService::EthMainnet(EthMainnetService::BlockPi)),
    },
    Provider {
        provider_id: 4,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://rpc.sepolia.org",
        },
        alias: Some(SupportedRpcService::EthSepolia(EthSepoliaService::Sepolia)),
    },
    Provider {
        provider_id: 5,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/eth_sepolia/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/eth_sepolia"),
        },
        alias: Some(SupportedRpcService::EthSepolia(EthSepoliaService::Ankr)),
    },
    Provider {
        provider_id: 6,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://ethereum-sepolia.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: None,
        },
        alias: Some(SupportedRpcService::EthSepolia(EthSepoliaService::BlockPi)),
    },
    Provider {
        provider_id: 7,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://ethereum-sepolia-rpc.publicnode.com",
        },
        alias: Some(SupportedRpcService::EthSepolia(
            EthSepoliaService::PublicNode,
        )),
    },
    Provider {
        provider_id: 8,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://eth-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://eth-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(SupportedRpcService::EthMainnet(EthMainnetService::Alchemy)),
    },
    Provider {
        provider_id: 9,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://eth-sepolia.g.alchemy.com/v2",
            },
            public_url: Some("https://eth-sepolia.g.alchemy.com/v2/demo"),
        },
        alias: Some(SupportedRpcService::EthSepolia(EthSepoliaService::Alchemy)),
    },
    Provider {
        provider_id: 10,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/arbitrum/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/arbitrum"),
        },
        alias: Some(SupportedRpcService::ArbitrumOne(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 11,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://arb-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://arb-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(SupportedRpcService::ArbitrumOne(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 12,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://arbitrum.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://arbitrum.public.blockpi.network/v1/rpc/public"),
        },
        alias: Some(SupportedRpcService::ArbitrumOne(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 13,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://arbitrum-one-rpc.publicnode.com",
        },
        alias: Some(SupportedRpcService::ArbitrumOne(
            L2MainnetService::PublicNode,
        )),
    },
    Provider {
        provider_id: 14,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/base/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/base"),
        },
        alias: Some(SupportedRpcService::BaseMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 15,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://base-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://base-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(SupportedRpcService::BaseMainnet(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 16,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://base.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://base.public.blockpi.network/v1/rpc/public"),
        },
        alias: Some(SupportedRpcService::BaseMainnet(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 17,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://base-rpc.publicnode.com",
        },
        alias: Some(SupportedRpcService::BaseMainnet(
            L2MainnetService::PublicNode,
        )),
    },
    Provider {
        provider_id: 18,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/optimism/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/optimism"),
        },
        alias: Some(SupportedRpcService::OptimismMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 19,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://opt-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://opt-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(SupportedRpcService::OptimismMainnet(
            L2MainnetService::Alchemy,
        )),
    },
    Provider {
        provider_id: 20,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://optimism.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://optimism.public.blockpi.network/v1/rpc/public"),
        },
        alias: Some(SupportedRpcService::OptimismMainnet(
            L2MainnetService::BlockPi,
        )),
    },
    Provider {
        provider_id: 21,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://optimism-rpc.publicnode.com",
        },
        alias: Some(SupportedRpcService::OptimismMainnet(
            L2MainnetService::PublicNode,
        )),
    },
    Provider {
        provider_id: 22,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://eth.llamarpc.com",
        },
        alias: Some(SupportedRpcService::EthMainnet(EthMainnetService::Llama)),
    },
    Provider {
        provider_id: 23,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://arbitrum.llamarpc.com",
        },
        alias: Some(SupportedRpcService::ArbitrumOne(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 24,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://base.llamarpc.com",
        },
        alias: Some(SupportedRpcService::BaseMainnet(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 25,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://optimism.llamarpc.com",
        },
        alias: Some(SupportedRpcService::OptimismMainnet(
            L2MainnetService::Llama,
        )),
    },
];

thread_local! {
    pub static PROVIDER_MAP: BTreeMap<ProviderId, Provider> =
        PROVIDERS.iter()
            .map(|provider| (provider.provider_id, provider.clone())).collect();

    pub static SERVICE_PROVIDER_MAP: BTreeMap<SupportedRpcService, ProviderId> =
        PROVIDERS.iter()
            .filter_map(|provider| Some((provider.alias?, provider.provider_id)))
            .collect();
}

pub fn find_provider(f: impl Fn(&Provider) -> bool) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|&provider| f(provider))
}

pub fn get_known_chain_id(service: &RpcService) -> Option<u64> {
    match service {
        RpcService::Provider(_) => None,
        RpcService::Custom(_) => None,
        RpcService::EthMainnet(_) => Some(ETH_MAINNET_CHAIN_ID),
        RpcService::EthSepolia(_) => Some(ETH_SEPOLIA_CHAIN_ID),
        RpcService::ArbitrumOne(_) => Some(ARBITRUM_ONE_CHAIN_ID),
        RpcService::BaseMainnet(_) => Some(BASE_MAINNET_CHAIN_ID),
        RpcService::OptimismMainnet(_) => Some(OPTIMISM_MAINNET_CHAIN_ID),
    }
}

pub fn resolve_rpc_service(service: RpcService) -> Result<ResolvedRpcService, ProviderError> {
    Ok(match service {
        RpcService::Provider(id) => ResolvedRpcService::Provider({
            PROVIDER_MAP.with(|provider_map| {
                provider_map
                    .get(&id)
                    .cloned()
                    .ok_or(ProviderError::ProviderNotFound)
            })?
        }),
        RpcService::Custom(RpcApi { url, headers }) => {
            ResolvedRpcService::Api(RpcApi { url, headers })
        }
        RpcService::EthMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&SupportedRpcService::EthMainnet(service))?,
        ),
        RpcService::EthSepolia(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&SupportedRpcService::EthSepolia(service))?,
        ),
        RpcService::ArbitrumOne(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&SupportedRpcService::ArbitrumOne(service))?,
        ),
        RpcService::BaseMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&SupportedRpcService::BaseMainnet(service))?,
        ),
        RpcService::OptimismMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&SupportedRpcService::OptimismMainnet(service))?,
        ),
    })
}

fn lookup_provider_for_service(service: &SupportedRpcService) -> Result<Provider, ProviderError> {
    let provider_id = SERVICE_PROVIDER_MAP.with(|map| {
        map.get(service)
            .copied()
            .ok_or(ProviderError::MissingRequiredProvider)
    })?;
    PROVIDER_MAP
        .with(|map| map.get(&provider_id).cloned())
        .ok_or(ProviderError::ProviderNotFound)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum SupportedRpcService {
    EthMainnet(EthMainnetService),
    EthSepolia(EthSepoliaService),
    ArbitrumOne(L2MainnetService),
    BaseMainnet(L2MainnetService),
    OptimismMainnet(L2MainnetService),
}

impl SupportedRpcService {
    pub fn new(service: &RpcService) -> Option<Self> {
        match service {
            RpcService::Provider(id) => find_provider(|provider| &provider.provider_id == id)
                .and_then(|provider| provider.alias),
            RpcService::Custom(_) => None,
            RpcService::EthMainnet(service) => Some(SupportedRpcService::EthMainnet(*service)),
            RpcService::EthSepolia(service) => Some(SupportedRpcService::EthSepolia(*service)),
            RpcService::ArbitrumOne(service) => Some(SupportedRpcService::ArbitrumOne(*service)),
            RpcService::BaseMainnet(service) => Some(SupportedRpcService::BaseMainnet(*service)),
            RpcService::OptimismMainnet(service) => {
                Some(SupportedRpcService::OptimismMainnet(*service))
            }
        }
    }

    // Order of providers matters!
    // The threshold consensus strategy will consider the first `total` providers in the order
    // they are specified (taking the default ones first, followed by the non default ones if necessary)
    // if the providers are not explicitly specified by the caller.
    pub const fn eth_mainnet() -> &'static [SupportedRpcService] {
        &[
            SupportedRpcService::EthMainnet(EthMainnetService::BlockPi),
            SupportedRpcService::EthMainnet(EthMainnetService::Ankr),
            SupportedRpcService::EthMainnet(EthMainnetService::PublicNode),
            SupportedRpcService::EthMainnet(EthMainnetService::Llama),
            SupportedRpcService::EthMainnet(EthMainnetService::Alchemy),
            SupportedRpcService::EthMainnet(EthMainnetService::Cloudflare),
        ]
    }

    pub const fn eth_sepolia() -> &'static [SupportedRpcService] {
        &[
            SupportedRpcService::EthSepolia(EthSepoliaService::PublicNode),
            SupportedRpcService::EthSepolia(EthSepoliaService::Ankr),
            SupportedRpcService::EthSepolia(EthSepoliaService::BlockPi),
            SupportedRpcService::EthSepolia(EthSepoliaService::Alchemy),
            SupportedRpcService::EthSepolia(EthSepoliaService::Sepolia),
        ]
    }

    pub const fn arbitrum_one() -> &'static [SupportedRpcService] {
        &[
            SupportedRpcService::ArbitrumOne(L2MainnetService::Llama),
            SupportedRpcService::ArbitrumOne(L2MainnetService::BlockPi),
            SupportedRpcService::ArbitrumOne(L2MainnetService::PublicNode),
            SupportedRpcService::ArbitrumOne(L2MainnetService::Alchemy),
            SupportedRpcService::ArbitrumOne(L2MainnetService::Ankr),
        ]
    }

    pub const fn base_mainnet() -> &'static [SupportedRpcService] {
        &[
            SupportedRpcService::BaseMainnet(L2MainnetService::Llama),
            SupportedRpcService::BaseMainnet(L2MainnetService::BlockPi),
            SupportedRpcService::BaseMainnet(L2MainnetService::PublicNode),
            SupportedRpcService::BaseMainnet(L2MainnetService::Alchemy),
            SupportedRpcService::BaseMainnet(L2MainnetService::Ankr),
        ]
    }

    pub const fn optimism_mainnet() -> &'static [SupportedRpcService] {
        &[
            SupportedRpcService::OptimismMainnet(L2MainnetService::Llama),
            SupportedRpcService::OptimismMainnet(L2MainnetService::BlockPi),
            SupportedRpcService::OptimismMainnet(L2MainnetService::PublicNode),
            SupportedRpcService::OptimismMainnet(L2MainnetService::Alchemy),
            SupportedRpcService::OptimismMainnet(L2MainnetService::Ankr),
        ]
    }
}

impl From<SupportedRpcService> for RpcService {
    fn from(value: SupportedRpcService) -> Self {
        match value {
            SupportedRpcService::EthMainnet(service) => RpcService::EthMainnet(service),
            SupportedRpcService::EthSepolia(service) => RpcService::EthSepolia(service),
            SupportedRpcService::ArbitrumOne(service) => RpcService::ArbitrumOne(service),
            SupportedRpcService::BaseMainnet(service) => RpcService::BaseMainnet(service),
            SupportedRpcService::OptimismMainnet(service) => RpcService::OptimismMainnet(service),
        }
    }
}

/// Record when a supported RPC service was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportedRpcServiceUsage(TimedSizedMap<SupportedRpcService, ()>);

impl Default for SupportedRpcServiceUsage {
    fn default() -> Self {
        Self::new()
    }
}

impl SupportedRpcServiceUsage {
    pub fn new() -> SupportedRpcServiceUsage {
        Self(TimedSizedMap::new(
            Duration::from_secs(20 * 60),
            NonZeroUsize::new(500).unwrap(),
        ))
    }

    pub fn record_evict(&mut self, service: SupportedRpcService, now: Timestamp) {
        self.0.insert_evict(now, service, ());
    }

    pub fn rank_ascending_evict(
        &mut self,
        services: &[SupportedRpcService],
        now: Timestamp,
    ) -> Vec<SupportedRpcService> {
        fn ascending_num_elements<V>(values: Option<&TimedSizedVec<V>>) -> impl Ord {
            std::cmp::Reverse(values.map(|v| v.len()).unwrap_or_default())
        }

        self.0.evict_expired(services, now);
        self.0
            .sort_keys_by(services, ascending_num_elements)
            .copied()
            .collect()
    }
}
