#[cfg(test)]
mod tests;

use candid::CandidType;
pub use ic_management_canister_types::HttpHeader;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use strum::VariantArray;

#[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
pub struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,

    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
pub struct GetLogsRpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    pub response_size_estimate: Option<u64>,

    #[serde(rename = "responseConsensus")]
    pub response_consensus: Option<ConsensusStrategy>,

    #[serde(rename = "maxBlockRange")]
    pub max_block_range: Option<u32>,
}

impl From<GetLogsRpcConfig> for RpcConfig {
    fn from(config: GetLogsRpcConfig) -> Self {
        Self {
            response_size_estimate: config.response_size_estimate,
            response_consensus: config.response_consensus,
        }
    }
}

impl From<RpcConfig> for GetLogsRpcConfig {
    fn from(config: RpcConfig) -> Self {
        Self {
            response_size_estimate: config.response_size_estimate,
            response_consensus: config.response_consensus,
            max_block_range: None,
        }
    }
}

impl GetLogsRpcConfig {
    pub fn max_block_range_or_default(&self) -> u32 {
        const DEFAULT_ETH_GET_LOGS_MAX_BLOCK_RANGE: u32 = 500;
        self.max_block_range
            .unwrap_or(DEFAULT_ETH_GET_LOGS_MAX_BLOCK_RANGE)
    }
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

impl RpcApi {
    pub fn host_str(&self) -> Option<String> {
        url::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(|host| host.to_string()))
    }
}

impl Debug for RpcApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = self.host_str().unwrap_or("N/A".to_string());
        write!(f, "RpcApi {{ host: {}, url/headers: *** }}", host) //URL or header value could contain API keys
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

impl Debug for RpcService {
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

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub struct Provider {
    #[serde(rename = "providerId")]
    pub provider_id: u64,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub access: RpcAccess,
    pub alias: Option<RpcService>,
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub enum RpcAccess {
    Authenticated {
        auth: RpcAuth,
        /// Public URL to use when the API key is not available.
        #[serde(rename = "publicUrl")]
        public_url: Option<String>,
    },
    Unauthenticated {
        #[serde(rename = "publicUrl")]
        public_url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub enum RpcAuth {
    /// API key will be used in an Authorization header as Bearer token, e.g.,
    /// `Authorization: Bearer API_KEY`
    BearerToken { url: String },
    UrlParameter {
        #[serde(rename = "urlPattern")]
        url_pattern: String,
    },
}
