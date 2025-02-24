#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, strum_macros::EnumIter)]
pub enum JsonRpcProvider {
    //order is top-to-bottom and must match order used in production
    Provider1,
    Provider2,
    Provider3,
    Provider4,
}

impl JsonRpcProvider {
    pub fn url(&self) -> &str {
        match self {
            JsonRpcProvider::Provider1 => "https://ethereum.blockpi.network/v1/rpc/public",
            JsonRpcProvider::Provider2 => "https://ethereum-rpc.publicnode.com",
            JsonRpcProvider::Provider3 => "https://eth.llamarpc.com",
            JsonRpcProvider::Provider4 => "https://eth-mainnet.g.alchemy.com/v2/demo",
        }
    }
}
