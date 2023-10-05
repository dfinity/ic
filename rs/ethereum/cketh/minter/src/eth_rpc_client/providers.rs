pub(crate) const MAINNET_PROVIDERS: [RpcNodeProvider; 2] = [
    RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
    RpcNodeProvider::Ethereum(EthereumProvider::Cloudflare),
];

pub(crate) const SEPOLIA_PROVIDERS: [RpcNodeProvider; 3] = [
    RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
    RpcNodeProvider::Sepolia(SepoliaProvider::BlockPi),
    RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub(crate) enum RpcNodeProvider {
    Ethereum(EthereumProvider),
    Sepolia(SepoliaProvider),
}

impl RpcNodeProvider {
    pub(crate) fn url(&self) -> &str {
        match self {
            Self::Ethereum(provider) => provider.ethereum_mainnet_endpoint_url(),
            Self::Sepolia(provider) => provider.ethereum_sepolia_endpoint_url(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub(crate) enum EthereumProvider {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub(crate) enum SepoliaProvider {
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
