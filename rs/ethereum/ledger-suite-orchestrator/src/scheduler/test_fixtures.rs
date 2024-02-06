use crate::scheduler::Erc20Contract;

pub const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
pub const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
pub fn usdc() -> Erc20Contract {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: USDC_ADDRESS.to_string(),
    }
    .try_into()
    .unwrap()
}

pub fn usdt() -> Erc20Contract {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: USDT_ADDRESS.to_string(),
    }
    .try_into()
    .unwrap()
}
