use std::str::FromStr;

#[derive(Copy, Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
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
            other => Err(format!(
                "Unknown bitcoin network {other}. Valid bitcoin networks are \"mainnet\" and \"testnet\"."
            )),
        }
    }
}

// A proposal payload to set the Bitcoin configuration.
#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct BitcoinSetConfigProposal {
    pub network: BitcoinNetwork,
    pub payload: Vec<u8>,
}
