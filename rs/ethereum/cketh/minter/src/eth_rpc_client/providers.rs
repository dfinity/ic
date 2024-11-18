use evm_rpc_client::RpcService as EvmRpcService;

pub(crate) const MAINNET_PROVIDERS: [RpcNodeProvider; 4] = [
    RpcNodeProvider::Ethereum(EthereumProvider::BlockPi),
    RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
    RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes),
    RpcNodeProvider::Ethereum(EthereumProvider::Alchemy),
];

pub(crate) const SEPOLIA_PROVIDERS: [RpcNodeProvider; 4] = [
    RpcNodeProvider::Sepolia(SepoliaProvider::BlockPi),
    RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode),
    RpcNodeProvider::Sepolia(SepoliaProvider::Alchemy),
    RpcNodeProvider::Sepolia(SepoliaProvider::RpcSepolia),
];

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub(crate) enum RpcNodeProvider {
    Ethereum(EthereumProvider),
    Sepolia(SepoliaProvider),
    EvmRpc(EvmRpcService),
}

impl RpcNodeProvider {
    //TODO XC-27: remove this method
    pub(crate) fn url(&self) -> &str {
        match self {
            Self::Ethereum(provider) => provider.ethereum_mainnet_endpoint_url(),
            Self::Sepolia(provider) => provider.ethereum_sepolia_endpoint_url(),
            RpcNodeProvider::EvmRpc(_) => {
                panic!("BUG: should not need URL of provider from EVM RPC canister")
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) enum EthereumProvider {
    // https://blockpi.io/
    BlockPi,
    // https://publicnode.com/
    PublicNode,
    // https://llamanodes.com/
    LlamaNodes,
    Alchemy,
}

impl EthereumProvider {
    fn ethereum_mainnet_endpoint_url(&self) -> &str {
        match self {
            EthereumProvider::BlockPi => "https://ethereum.blockpi.network/v1/rpc/public",
            EthereumProvider::PublicNode => "https://ethereum-rpc.publicnode.com",
            EthereumProvider::LlamaNodes => "https://eth.llamarpc.com",
            EthereumProvider::Alchemy => "https://eth-mainnet.g.alchemy.com/v2/demo",
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) enum SepoliaProvider {
    // https://blockpi.io/
    BlockPi,
    // https://publicnode.com/
    PublicNode,
    // https://www.alchemy.com/chain-connect/endpoints/rpc-sepolia-sepolia
    Alchemy,
    RpcSepolia,
}

impl SepoliaProvider {
    fn ethereum_sepolia_endpoint_url(&self) -> &str {
        match self {
            SepoliaProvider::BlockPi => "https://ethereum-sepolia.blockpi.network/v1/rpc/public",
            SepoliaProvider::PublicNode => "https://ethereum-sepolia-rpc.publicnode.com",
            SepoliaProvider::Alchemy => "https://eth-sepolia.g.alchemy.com/v2/demo",
            SepoliaProvider::RpcSepolia => "https://rpc.sepolia.org",
        }
    }
}
