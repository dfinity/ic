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
            other => Err(format!("Unknown bitcoin network {}. Valid bitcoin networks are \"mainnet\" and \"testnet\".", other))
        }
    }
}

// A proposal payload to set the Bitcoin configuration.
#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct BitcoinSetConfigProposal {
    pub network: BitcoinNetwork,
    pub payload: Vec<u8>,
}

#[derive(
    candid::CandidType, serde::Serialize, candid::Deserialize, PartialEq, Eq, Debug, Clone, Default,
)]
pub struct Fees {
    /// The base fee to charge for all `get_utxos` requests.
    pub get_utxos_base: u128,

    /// The number of cycles to charge per 10 instructions.
    pub get_utxos_cycles_per_ten_instructions: u128,

    /// The maximum amount of cycles that can be charged in a `get_utxos` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_utxos_maximum: u128,

    /// The flat fee to charge for a `get_balance` request.
    pub get_balance: u128,

    /// The maximum amount of cycles that can be charged in a `get_balance` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_balance_maximum: u128,

    /// The flat fee to charge for a `get_current_fee_percentiles` request.
    pub get_current_fee_percentiles: u128,

    /// The maximum amount of cycles that can be charged in a `get_current_fee_percentiles` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_current_fee_percentiles_maximum: u128,

    /// The base fee to charge for all `send_transaction` requests.
    pub send_transaction_base: u128,

    /// The number of cycles to charge for each byte in the transaction.
    pub send_transaction_per_byte: u128,

    /// The base fee to charge for all `get_block_headers` requests.
    pub get_block_headers_base: u128,

    /// The number of cycles to charge per 10 instructions.
    pub get_block_headers_cycles_per_ten_instructions: u128,

    /// The maximum amount of cycles that can be charged in a `get_block_headers` request.
    /// A request must send at least this amount for it to be accepted.
    pub get_block_headers_maximum: u128,
}
