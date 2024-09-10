use crate::lifecycle::EthereumNetwork;
use evm_rpc_client::types::candid::{RpcService as EvmRpcService, RpcServices as EvmRpcServices};

pub(crate) const MAINNET_PROVIDERS: [RpcNodeProvider; 3] = [
    RpcNodeProvider::Ethereum(EthereumProvider::Pokt),
    RpcNodeProvider::Ethereum(EthereumProvider::PublicNode),
    RpcNodeProvider::Ethereum(EthereumProvider::LlamaNodes),
];

pub(crate) const SEPOLIA_PROVIDERS: [RpcNodeProvider; 2] = [
    RpcNodeProvider::Sepolia(SepoliaProvider::Sepolia),
    RpcNodeProvider::Sepolia(SepoliaProvider::PublicNode),
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
    // https://eth-pokt.nodies.app/
    Pokt,
    // https://publicnode.com/
    PublicNode,
    // https://llamanodes.com/
    LlamaNodes,
}

impl EthereumProvider {
    fn ethereum_mainnet_endpoint_url(&self) -> &str {
        match self {
            EthereumProvider::Pokt => "https://eth-pokt.nodies.app",
            EthereumProvider::PublicNode => "https://ethereum-rpc.publicnode.com",
            EthereumProvider::LlamaNodes => "https://eth.llamarpc.com",
        }
    }

    // TODO XC-131: Replace using Custom providers with EthMainnetService,
    // when LlamaNodes is supported as a provider.
    pub(crate) fn evm_rpc_node_providers() -> EvmRpcServices {
        evm_rpc_node_providers(&EthereumNetwork::Mainnet)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) enum SepoliaProvider {
    // https://sepolia.org/
    Sepolia,
    // https://publicnode.com/
    PublicNode,
}

impl SepoliaProvider {
    fn ethereum_sepolia_endpoint_url(&self) -> &str {
        match self {
            SepoliaProvider::Sepolia => "https://rpc.sepolia.org/",
            SepoliaProvider::PublicNode => "https://ethereum-sepolia-rpc.publicnode.com",
        }
    }

    pub(crate) fn evm_rpc_node_providers() -> EvmRpcServices {
        evm_rpc_node_providers(&EthereumNetwork::Sepolia)
    }
}

fn evm_rpc_node_providers(ethereum_network: &EthereumNetwork) -> EvmRpcServices {
    use evm_rpc_client::types::candid::RpcApi as EvmRpcApi;

    let providers = match ethereum_network {
        EthereumNetwork::Mainnet => MAINNET_PROVIDERS.as_slice(),
        EthereumNetwork::Sepolia => SEPOLIA_PROVIDERS.as_slice(),
    };
    let chain_id = ethereum_network.chain_id();
    let services = providers
        .iter()
        .map(|provider| EvmRpcApi {
            url: provider.url().to_string(),
            headers: None,
        })
        .collect();
    EvmRpcServices::Custom { chain_id, services }
}
