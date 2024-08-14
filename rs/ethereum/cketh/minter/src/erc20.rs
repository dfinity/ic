#[cfg(test)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;

use crate::endpoints::AddCkErc20Token;
use crate::lifecycle::EthereumNetwork;
use crate::state::State;
use candid::Principal;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use num_traits::ToPrimitive;
use std::fmt::Display;
use std::str::FromStr;

pub const MAX_CK_TOKEN_SYMBOL_NUM_BYTES: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct CkErc20Token {
    #[n(0)]
    pub erc20_ethereum_network: EthereumNetwork,
    #[n(1)]
    pub erc20_contract_address: Address,
    #[n(2)]
    pub ckerc20_token_symbol: CkTokenSymbol,
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub ckerc20_ledger_id: Principal,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
#[cbor(transparent)]
pub struct CkTokenSymbol(#[n(0)] String);

impl Display for CkTokenSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CkTokenSymbol {
    pub fn cketh_symbol_from_state(state: &State) -> Self {
        match state.ethereum_network {
            EthereumNetwork::Mainnet => Self::from_str("ckETH").unwrap(),
            EthereumNetwork::Sepolia => Self::from_str("ckSepoliaETH").unwrap(),
        }
    }
}

impl FromStr for CkTokenSymbol {
    type Err = String;

    fn from_str(token_symbol: &str) -> Result<Self, Self::Err> {
        if !token_symbol.starts_with("ck") {
            return Err("ERROR: token symbol does not start with 'ck' prefix".to_string());
        }
        if token_symbol.len() > MAX_CK_TOKEN_SYMBOL_NUM_BYTES {
            return Err(format!(
                "ERROR: token symbol is too long: expected at most {} characters, but got {}",
                MAX_CK_TOKEN_SYMBOL_NUM_BYTES,
                token_symbol.len()
            ));
        }
        if !token_symbol.is_ascii() {
            return Err("ERROR: token symbol contains non-ascii characters".to_string());
        }
        Ok(Self(token_symbol.to_string()))
    }
}

impl TryFrom<AddCkErc20Token> for CkErc20Token {
    type Error = String;

    fn try_from(value: AddCkErc20Token) -> Result<Self, Self::Error> {
        let erc20_ethereum_network = EthereumNetwork::try_from(
            value
                .chain_id
                .0
                .to_u64()
                .ok_or("ERROR: chain_id does not fit in a u64")?,
        )?;
        let erc20_contract_address =
            Address::from_str(&value.address).map_err(|e| format!("ERROR: {}", e))?;
        Ok(Self {
            erc20_ethereum_network,
            erc20_contract_address,
            ckerc20_token_symbol: value.ckerc20_token_symbol.parse()?,
            ckerc20_ledger_id: value.ckerc20_ledger_id,
        })
    }
}
