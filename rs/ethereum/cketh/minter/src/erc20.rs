use crate::endpoints::AddCkErc20Token;
use crate::lifecycle::EthereumNetwork;
use candid::Principal;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use num_traits::ToPrimitive;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct CkErc20Token {
    #[n(0)]
    pub erc20_ethereum_network: EthereumNetwork,
    #[n(1)]
    pub erc20_contract_address: Address,
    #[n(2)]
    pub ckerc20_token_symbol: String,
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub ckerc20_ledger_id: Principal,
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
            ckerc20_token_symbol: value.ckerc20_token_symbol,
            ckerc20_ledger_id: value.ckerc20_ledger_id,
        })
    }
}
