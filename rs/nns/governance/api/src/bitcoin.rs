use std::str::FromStr;

#[derive(candid::CandidType, serde::Serialize, candid::Deserialize, Clone, Debug, Copy)]
pub enum BitcoinNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
}

impl FromStr for BitcoinNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            other => Err(format!("Unknown bitcoin network {}. Valid bitcoin networks are \"mainnet\" and \"testnet\".", other))
        }
    }
}

// A proposal payload to set the Bitcoin configuration.
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize, Clone, Debug)]
pub struct BitcoinSetConfigProposal {
    pub network: BitcoinNetwork,
    pub payload: Vec<u8>,
}
