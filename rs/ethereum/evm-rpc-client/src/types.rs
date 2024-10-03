pub mod candid {
    use candid::{CandidType, Deserialize, Nat};

    #[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize)]
    pub enum BlockTag {
        #[default]
        Latest,
        Finalized,
        Safe,
        Earliest,
        Pending,
        Number(Nat),
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct GetLogsArgs {
        #[serde(rename = "fromBlock")]
        pub from_block: Option<BlockTag>,
        #[serde(rename = "toBlock")]
        pub to_block: Option<BlockTag>,
        pub addresses: Vec<String>,
        pub topics: Option<Vec<Vec<String>>>,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct FeeHistoryArgs {
        /// Number of blocks in the requested range.
        /// Typically, providers request this to be between 1 and 1024.
        #[serde(rename = "blockCount")]
        pub block_count: u128,

        /// Highest block of the requested range.
        /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
        #[serde(rename = "newestBlock")]
        pub newest_block: BlockTag,

        /// A monotonically increasing list of percentile values between 0 and 100.
        /// For each block in the requested range, the transactions will be sorted in ascending order
        /// by effective tip per gas and the corresponding effective tip for the percentile
        /// will be determined, accounting for gas consumed.
        #[serde(rename = "rewardPercentiles")]
        pub reward_percentiles: Option<Vec<u8>>,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct GetTransactionCountArgs {
        /// The address for which the transaction count is requested.
        pub address: String,
        /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
        pub block: BlockTag,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub enum SendRawTransactionStatus {
        Ok(Option<String>),
        InsufficientFunds,
        NonceTooLow,
        NonceTooHigh,
    }
}
