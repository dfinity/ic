use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::Deserialize;

pub(crate) const MAINNET_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
    RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
    RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
    RpcNodeProvider::Sepolia(SepoliaProvider::BlockPi),
    RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode),
];

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub struct RpcApi {
    pub url: String,
    pub headers: Vec<HttpHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum RpcNodeProvider {
    Ethereum(EthereumProvider),
    Sepolia(SepoliaProvider),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthereumProvider {
    Ankr,
    BlockPi,
    PublicNode,
    Cloudflare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum SepoliaProvider {
    Ankr,
    BlockPi,
    PublicNode,
}
