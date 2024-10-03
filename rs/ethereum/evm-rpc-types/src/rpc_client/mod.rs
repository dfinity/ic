pub use ic_cdk::api::management_canister::http_request::HttpHeader;
use std::fmt::Debug;

use candid::{CandidType, Deserialize};
use serde::Serialize;
use strum::VariantArray;

#[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
pub struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,

    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
pub enum ConsensusStrategy {
    /// All providers must return the same non-error result.
    #[default]
    Equality,

    /// A subset of providers must return the same non-error result.
    Threshold {
        /// Total number of providers to be queried:
        /// * If `None`, will be set to the number of providers manually specified in `RpcServices`.
        /// * If `Some`, must correspond to the number of manually specified providers in `RpcServices`;
        ///   or if they are none indicating that default providers should be used, select the corresponding number of providers.
        total: Option<u8>,

        /// Minimum number of providers that must return the same (non-error) result.
        min: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum RpcServices {
    Custom {
        #[serde(rename = "chainId")]
        chain_id: u64,
        services: Vec<RpcApi>,
    },
    EthMainnet(Option<Vec<EthMainnetService>>),
    EthSepolia(Option<Vec<EthSepoliaService>>),
    ArbitrumOne(Option<Vec<L2MainnetService>>),
    BaseMainnet(Option<Vec<L2MainnetService>>),
    OptimismMainnet(Option<Vec<L2MainnetService>>),
}

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Option<Vec<HttpHeader>>,
}

impl Debug for RpcApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RpcApi {{ url: ***, headers: *** }}",) //URL or header value could contain API keys
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    CandidType,
    VariantArray,
)]
pub enum EthMainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Cloudflare,
    Llama,
}

impl EthMainnetService {
    pub const fn all() -> &'static [Self] {
        EthMainnetService::VARIANTS
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    CandidType,
    VariantArray,
)]
pub enum EthSepoliaService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Sepolia,
}

impl EthSepoliaService {
    pub const fn all() -> &'static [Self] {
        EthSepoliaService::VARIANTS
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    CandidType,
    VariantArray,
)]
pub enum L2MainnetService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
    Llama,
}

impl L2MainnetService {
    pub const fn all() -> &'static [Self] {
        L2MainnetService::VARIANTS
    }
}

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType)]
pub enum RpcService {
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
