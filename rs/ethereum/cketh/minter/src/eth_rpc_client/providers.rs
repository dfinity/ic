use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::Deserialize;

pub(crate) const MAINNET_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::EthMainnet(EthMainnetService::Ankr),
    RpcNodeProvider::EthMainnet(EthMainnetService::PublicNode),
    RpcNodeProvider::EthMainnet(EthMainnetService::Cloudflare),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::EthSepolia(EthSepoliaService::Ankr),
    RpcNodeProvider::EthSepolia(EthSepoliaService::BlockPi),
    RpcNodeProvider::EthSepolia(EthSepoliaService::PublicNode),
];

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Vec<HttpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum RpcNodeProvider {
    EthMainnet(EthMainnetService),
    EthSepolia(EthSepoliaService),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthMainnetService {
    Ankr,
    BlockPi,
    PublicNode,
    Cloudflare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthSepoliaService {
    Ankr,
    BlockPi,
    PublicNode,
}
