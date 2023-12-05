use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::Deserialize;

pub(crate) const MAINNET_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::EthMainnet(EthMainnetProvider::Ankr),
    RpcNodeProvider::EthMainnet(EthMainnetProvider::PublicNode),
    RpcNodeProvider::EthMainnet(EthMainnetProvider::Cloudflare),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::EthSepolia(EthSepoliaProvider::Ankr),
    RpcNodeProvider::EthSepolia(EthSepoliaProvider::BlockPi),
    RpcNodeProvider::EthSepolia(EthSepoliaProvider::PublicNode),
];

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Vec<HttpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum RpcNodeProvider {
    EthMainnet(EthMainnetProvider),
    EthSepolia(EthSepoliaProvider),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthMainnetProvider {
    Ankr,
    BlockPi,
    PublicNode,
    Cloudflare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthSepoliaProvider {
    Ankr,
    BlockPi,
    PublicNode,
}
