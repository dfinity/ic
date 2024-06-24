pub mod candid {
    use candid::{CandidType, Deserialize, Nat};
    use ic_cdk::api::call::RejectionCode;
    use serde::Serialize;
    use std::iter;

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Default)]
    pub enum BlockTag {
        #[default]
        Latest,
        Finalized,
        Safe,
        Earliest,
        Pending,
        Number(Nat),
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
    pub struct Block {
        #[serde(rename = "baseFeePerGas")]
        pub base_fee_per_gas: Nat,
        pub number: Nat,
        pub difficulty: Nat,
        #[serde(rename = "extraData")]
        pub extra_data: String,
        #[serde(rename = "gasLimit")]
        pub gas_limit: Nat,
        #[serde(rename = "gasUsed")]
        pub gas_used: Nat,
        pub hash: String,
        #[serde(rename = "logsBloom")]
        pub logs_bloom: String,
        pub miner: String,
        #[serde(rename = "mixHash")]
        pub mix_hash: String,
        pub nonce: Nat,
        #[serde(rename = "parentHash")]
        pub parent_hash: String,
        #[serde(rename = "receiptsRoot")]
        pub receipts_root: String,
        #[serde(rename = "sha3Uncles")]
        pub sha3_uncles: String,
        pub size: Nat,
        #[serde(rename = "stateRoot")]
        pub state_root: String,
        #[serde(rename = "timestamp")]
        pub timestamp: Nat,
        #[serde(rename = "totalDifficulty")]
        pub total_difficulty: Nat,
        #[serde(default)]
        pub transactions: Vec<String>,
        #[serde(rename = "transactionsRoot")]
        pub transactions_root: Option<String>,
        #[serde(default)]
        pub uncles: Vec<String>,
    }

    pub type RpcResult<T> = Result<T, RpcError>;

    #[derive(Clone, Debug, Eq, PartialEq, CandidType, Deserialize)]
    pub enum MultiRpcResult<T> {
        Consistent(RpcResult<T>),
        Inconsistent(Vec<(RpcService, RpcResult<T>)>),
    }

    impl<T> MultiRpcResult<T> {
        pub fn iter(&self) -> Box<dyn Iterator<Item = &RpcResult<T>> + '_> {
            match self {
                Self::Consistent(result) => Box::new(iter::once(result)),
                Self::Inconsistent(results) => {
                    Box::new(results.iter().map(|(_service, result)| result))
                }
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub enum RpcError {
        ProviderError(ProviderError),
        HttpOutcallError(HttpOutcallError),
        JsonRpcError(JsonRpcError),
        ValidationError(ValidationError),
    }

    impl RpcError {
        pub(crate) fn from_rejection(code: RejectionCode, message: String) -> Self {
            Self::HttpOutcallError(HttpOutcallError::IcError { code, message })
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
    pub enum ProviderError {
        NoPermission,
        TooFewCycles { expected: u128, received: u128 },
        ProviderNotFound,
        MissingRequiredProvider,
    }

    #[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
    pub enum HttpOutcallError {
        /// Error from the IC system API.
        IcError {
            code: RejectionCode,
            message: String,
        },
        /// Response is not a valid JSON-RPC response,
        /// which means that the response was not successful (status other than 2xx)
        /// or that the response body could not be deserialized into a JSON-RPC response.
        InvalidHttpJsonRpcResponse {
            status: u16,
            body: String,
            #[serde(rename = "parsingError")]
            parsing_error: Option<String>,
        },
    }

    #[derive(
        Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Serialize, Deserialize,
    )]
    pub struct JsonRpcError {
        pub code: i64,
        pub message: String,
    }

    #[derive(Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
    pub enum ValidationError {
        Custom(String),
        InvalidHex(String),
        UrlParseError(String),
        HostNotAllowed(String),
        CredentialPathNotAllowed,
        CredentialHeaderNotAllowed,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub enum RpcServices {
        EthMainnet(Option<Vec<EthMainnetService>>),
        EthSepolia(Option<Vec<EthSepoliaService>>),
    }

    #[derive(
        Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
    )]
    pub enum RpcService {
        EthMainnet(EthMainnetService),
        EthSepolia(EthSepoliaService),
    }

    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
    )]
    pub enum EthMainnetService {
        Alchemy,
        Ankr,
        BlockPi,
        PublicNode,
        Cloudflare,
    }

    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize, CandidType,
    )]
    pub enum EthSepoliaService {
        Alchemy,
        Ankr,
        BlockPi,
        PublicNode,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Default, CandidType, Deserialize)]
    pub struct RpcConfig {
        #[serde(rename = "responseSizeEstimate")]
        pub response_size_estimate: Option<u64>,
    }
}
