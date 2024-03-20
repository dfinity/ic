pub(crate) const MAINNET_PROVIDERS: [RpcNodeProvider; 3] = [
    RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
    RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
    RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes),
];

pub(crate) const SEPOLIA_PROVIDERS: [RpcNodeProvider; 2] = [
    RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
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
    // https://www.ankr.com/rpc/
    Ankr,
    // https://publicnode.com/
    PublicNode,
    // https://llamanodes.com/
    LlamaNodes,
}

impl EthereumProvider {
    fn ethereum_mainnet_endpoint_url(&self) -> &str {
        match self {
            EthereumProvider::Ankr => "https://rpc.ankr.com/eth",
            EthereumProvider::PublicNode => "https://ethereum.publicnode.com",
            EthereumProvider::LlamaNodes => "https://eth.llamarpc.com",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub(crate) enum SepoliaProvider {
    // https://www.ankr.com/rpc/
    Ankr,
    // https://publicnode.com/
    PublicNode,
}

impl SepoliaProvider {
    fn ethereum_sepolia_endpoint_url(&self) -> &str {
        match self {
            SepoliaProvider::Ankr => "https://rpc.ankr.com/eth_sepolia",
            SepoliaProvider::PublicNode => "https://ethereum-sepolia.publicnode.com",
        }
    }
}
