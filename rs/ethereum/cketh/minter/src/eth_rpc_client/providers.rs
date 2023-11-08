use candid::CandidType;
use ic_cdk::api::management_canister::http_request::HttpHeader;
use serde::Deserialize;

use super::RpcTransport;

pub(crate) const MAINNET_PROVIDERS: &[RpcNodeProvider] = &[
    RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
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

impl RpcNodeProvider {
    pub fn api<T: RpcTransport>(&self) -> RpcApi {
        let url = match self {
            Self::Ethereum(provider) => provider.ethereum_mainnet_endpoint_url(),
            Self::Sepolia(provider) => provider.ethereum_sepolia_endpoint_url(),
        }
        .to_string();
        RpcApi {
            url,
            headers: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum EthereumProvider {
    //https://www.ankr.com/rpc/
    Ankr,
    //https://developers.cloudflare.com/web3/ethereum-gateway/
    Cloudflare,
}

impl EthereumProvider {
    fn ethereum_mainnet_endpoint_url(&self) -> &str {
        match self {
            EthereumProvider::Ankr => "https://rpc.ankr.com/eth",
            EthereumProvider::Cloudflare => "https://cloudflare-eth.com",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, CandidType)]
pub enum SepoliaProvider {
    //https://www.ankr.com/rpc/
    Ankr,
    //https://public.blockpi.io/
    BlockPi,
    //https://publicnode.com/
    PublicNode,
}

impl SepoliaProvider {
    fn ethereum_sepolia_endpoint_url(&self) -> &str {
        match self {
            SepoliaProvider::Ankr => "https://rpc.ankr.com/eth_sepolia",
            SepoliaProvider::BlockPi => "https://ethereum-sepolia.blockpi.network/v1/rpc/public",
            SepoliaProvider::PublicNode => "https://ethereum-sepolia.publicnode.com",
        }
    }
}
