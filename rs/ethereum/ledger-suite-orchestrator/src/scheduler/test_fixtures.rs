use crate::scheduler::Erc20Token;
use crate::state::{CanistersMetadata, TokenId};

pub const DAI_ADDRESS: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
pub const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
pub const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

pub fn dai() -> Erc20Token {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: DAI_ADDRESS.to_string(),
    }
    .try_into()
    .unwrap()
}

pub fn dai_metadata() -> CanistersMetadata {
    CanistersMetadata {
        token_symbol: "ckDAI".to_string(),
    }
}

pub fn usdc() -> Erc20Token {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: USDC_ADDRESS.to_string(),
    }
    .try_into()
    .unwrap()
}

pub fn usdc_token_id() -> TokenId {
    TokenId::from(usdc())
}

pub fn usdc_metadata() -> CanistersMetadata {
    CanistersMetadata {
        token_symbol: "ckUSDC".to_string(),
    }
}

pub fn usdt() -> Erc20Token {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: USDT_ADDRESS.to_string(),
    }
    .try_into()
    .unwrap()
}

pub fn usdt_token_id() -> TokenId {
    TokenId::from(usdt())
}

pub fn usdt_metadata() -> CanistersMetadata {
    CanistersMetadata {
        token_symbol: "ckUSDT".to_string(),
    }
}
