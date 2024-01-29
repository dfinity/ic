use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::{Deserialize, Serialize};

pub(crate) const MAINNET_PROVIDERS: &[RpcService] = &[
    RpcService::EthMainnet(EthMainnetService::Alchemy),
    RpcService::EthMainnet(EthMainnetService::Ankr),
    RpcService::EthMainnet(EthMainnetService::PublicNode),
    RpcService::EthMainnet(EthMainnetService::Cloudflare),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcService] = &[
    RpcService::EthSepolia(EthSepoliaService::Alchemy),
    RpcService::EthSepolia(EthSepoliaService::Ankr),
    RpcService::EthSepolia(EthSepoliaService::BlockPi),
    RpcService::EthSepolia(EthSepoliaService::PublicNode),
];

#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Vec<HttpHeader>,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
)]
pub enum RpcService {
    EthMainnet(EthMainnetService),
    EthSepolia(EthSepoliaService),
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
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
)]
pub enum EthSepoliaService {
    Alchemy,
    Ankr,
    BlockPi,
    PublicNode,
}
