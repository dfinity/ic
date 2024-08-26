use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::{Deserialize, Serialize};

pub(crate) const MAINNET_PROVIDERS: &[RpcService] = &[
    RpcService::EthMainnet(EthMainnetService::Alchemy),
    RpcService::EthMainnet(EthMainnetService::Ankr),
    RpcService::EthMainnet(EthMainnetService::PublicNode),
    RpcService::EthMainnet(EthMainnetService::Cloudflare),
    RpcService::EthMainnet(EthMainnetService::Llama),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcService] = &[
    RpcService::EthSepolia(EthSepoliaService::Alchemy),
    RpcService::EthSepolia(EthSepoliaService::Ankr),
    RpcService::EthSepolia(EthSepoliaService::BlockPi),
    RpcService::EthSepolia(EthSepoliaService::PublicNode),
    RpcService::EthSepolia(EthSepoliaService::Sepolia),
];

pub(crate) const ARBITRUM_PROVIDERS: &[RpcService] = &[
    RpcService::ArbitrumOne(L2MainnetService::Alchemy),
    RpcService::ArbitrumOne(L2MainnetService::Ankr),
    RpcService::ArbitrumOne(L2MainnetService::PublicNode),
    RpcService::ArbitrumOne(L2MainnetService::Llama),
];

pub(crate) const BASE_PROVIDERS: &[RpcService] = &[
    RpcService::BaseMainnet(L2MainnetService::Alchemy),
    RpcService::BaseMainnet(L2MainnetService::Ankr),
    RpcService::BaseMainnet(L2MainnetService::PublicNode),
    RpcService::BaseMainnet(L2MainnetService::Llama),
];

pub(crate) const OPTIMISM_PROVIDERS: &[RpcService] = &[
    RpcService::OptimismMainnet(L2MainnetService::Alchemy),
    RpcService::OptimismMainnet(L2MainnetService::Ankr),
    RpcService::OptimismMainnet(L2MainnetService::PublicNode),
    RpcService::OptimismMainnet(L2MainnetService::Llama),
];

// Default RPC services for unknown EVM network
pub(crate) const UNKNOWN_PROVIDERS: &[RpcService] = &[];

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Option<Vec<HttpHeader>>,
}

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType)]
pub enum RpcService {
    Chain(u64),
    Provider(u64),
    Custom(RpcApi),
    EthMainnet(EthMainnetService),
    EthSepolia(EthSepoliaService),
    ArbitrumOne(L2MainnetService),
    BaseMainnet(L2MainnetService),
    OptimismMainnet(L2MainnetService),
}

impl std::fmt::Debug for RpcService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcService::Chain(chain_id) => write!(f, "Chain({})", chain_id),
            RpcService::Provider(provider_id) => write!(f, "Provider({})", provider_id),
            RpcService::Custom(_) => write!(f, "Custom(..)"), // Redact credentials
            RpcService::EthMainnet(service) => write!(f, "{:?}", service),
            RpcService::EthSepolia(service) => write!(f, "{:?}", service),
            RpcService::ArbitrumOne(service)
            | RpcService::BaseMainnet(service)
            | RpcService::OptimismMainnet(service) => write!(f, "{:?}", service),
        }
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
)]
pub enum EthMainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Cloudflare,
    Llama,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
)]
pub enum EthSepoliaService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Sepolia,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
)]
pub enum L2MainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Llama,
}
