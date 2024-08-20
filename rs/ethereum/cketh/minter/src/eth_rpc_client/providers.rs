use evm_rpc_client::types::candid::{
    EthSepoliaService as EvmEthSepoliaService, RpcService as EvmRpcService,
    RpcServices as EvmRpcServices,
};

pub(crate) const MAINNET_PROVIDERS: [RpcNodeProvider; 3] = [
    RpcNodeProvider::Ethereum(EthereumProvider::Ankr),
    RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
    RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes),
];

pub(crate) const SEPOLIA_PROVIDERS: [RpcNodeProvider; 2] = [
    RpcNodeProvider::Sepolia(SepoliaProvider::Ankr),
    RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode),
];

const EVM_RPC_SEPOLIA_PROVIDERS: [EvmEthSepoliaService; 2] =
    [EvmEthSepoliaService::Ankr, EvmEthSepoliaService::PublicNode];

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
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
            EthereumProvider::PublicNode => "https://ethereum-rpc.publicnode.com",
            EthereumProvider::LlamaNodes => "https://eth.llamarpc.com",
        }
    }

    // TODO XC-131: Replace using Custom providers with EthMainnetService,
    // when LlamaNodes is supported as a provider.
    pub(crate) fn evm_rpc_node_providers() -> EvmRpcServices {
        use evm_rpc_client::types::candid::RpcApi as EvmRpcApi;

        let services = MAINNET_PROVIDERS
            .iter()
            .map(|provider| EvmRpcApi {
                url: provider.url().to_string(),
                headers: None,
            })
            .collect();
        EvmRpcServices::Custom {
            chain_id: 1,
            services,
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
            SepoliaProvider::PublicNode => "https://ethereum-sepolia-rpc.publicnode.com",
        }
    }

    pub(crate) fn evm_rpc_node_providers() -> EvmRpcServices {
        EvmRpcServices::EthSepolia(Some(EVM_RPC_SEPOLIA_PROVIDERS.to_vec()))
    }
}
