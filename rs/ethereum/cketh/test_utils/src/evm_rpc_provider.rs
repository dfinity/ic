#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, strum_macros::EnumIter)]
pub enum JsonRpcProvider {
    // Order is top-to-bottom and must match order used in production.
    // See: <https://github.com/dfinity/evm-rpc-canister/blob/8f000154020ba870e824927ef040d46d0663228e/src/rpc_client/mod.rs#L72>
    Provider1,
    Provider2,
    Provider3,
    Provider4,
}

impl JsonRpcProvider {
    pub fn url(&self) -> &str {
        match self {
            // URLs should either include a trailing '/' or specify a path
            JsonRpcProvider::Provider1 => "https://rpc.ankr.com/eth",
            JsonRpcProvider::Provider2 => "https://ethereum.public.blockpi.network/v1/rpc/public",
            JsonRpcProvider::Provider3 => "https://ethereum-rpc.publicnode.com/",
            JsonRpcProvider::Provider4 => "https://eth.llamarpc.com/",
        }
    }
}
