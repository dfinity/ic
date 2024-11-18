use crate::eth_rpc::{Hash, JsonRpcReply, JsonRpcResult, SendRawTransactionResult};
use crate::logs::DEBUG;
use ic_canister_log::log;

#[cfg(test)]
mod tests;

/// Possible errors returned by calling `eth_sendRawTransaction` endpoint.
/// Unfortunately, error codes and error messages are not standardized in
/// [Ethereum JSON-RPC specification](https://ethereum.github.io/execution-apis/api-documentation/).
///
/// Note that `eth_sendRawTransaction` endpoint is not idempotent,
/// meaning that when called via HTTP outcalls it's expected that one node will receive
/// a successful answer and other nodes will receive an error but we still need the consensus
/// result to indicate whether the transaction was sent to the network or not.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SendRawTransactionError {
    /// The transaction is known to the mempool and may indicate
    /// that the transaction was correctly sent to the network.
    AlreadyKnown,
    /// The total cost of executing a transaction is higher than the balance of the user's account
    /// (determined by retrieving the public key from the signed transaction).
    InsufficientFunds,
    /// If the nonce of a transaction is lower than the one present in the local chain.
    NonceTooLow,
    /// if the nonce of a transaction is higher than the next one expected based on the local chain.
    NonceTooHigh,
}

impl<T> From<SendRawTransactionError> for JsonRpcResult<T> {
    fn from(value: SendRawTransactionError) -> Self {
        match value {
            SendRawTransactionError::AlreadyKnown => JsonRpcResult::Error {
                code: -32_000,
                message: "Transaction already known".to_string(),
            },
            SendRawTransactionError::InsufficientFunds => JsonRpcResult::Error {
                code: -32_000,
                message: "insufficient funds for gas * price + value".to_string(),
            },
            SendRawTransactionError::NonceTooLow => JsonRpcResult::Error {
                code: -32_000,
                message: "nonce too low".to_string(),
            },
            SendRawTransactionError::NonceTooHigh => JsonRpcResult::Error {
                code: -32_000,
                message: "nonce too high".to_string(),
            },
        }
    }
}

pub trait ErrorParser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError>;
}

struct GoEthereumParser;
// https://github.com/ethereum/go-ethereum/blob/5976e58415a633c24a0d903e8a60a3780abdfe59/core/txpool/errors.go#L24
impl ErrorParser for GoEthereumParser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError> {
        match (code, message.to_lowercase()) {
            (-32_000, msg) if msg.contains("already known") => {
                Some(SendRawTransactionError::AlreadyKnown)
            }
            (-32_000, msg) if msg.contains("insufficient funds") => {
                Some(SendRawTransactionError::InsufficientFunds)
            }
            (-32_000, msg) if msg.contains("nonce too low") => {
                Some(SendRawTransactionError::NonceTooLow)
            }
            (-32_000, msg) if msg.contains("nonce too high") => {
                Some(SendRawTransactionError::NonceTooHigh)
            }
            _ => None,
        }
    }
}

struct NethermindParser;
//https://github.com/NethermindEth/nethermind/blob/ac86855116c652a68443b52c6377b3a55e9b8af5/src/Nethermind/Nethermind.TxPool/AcceptTxResult.cs#L21
//https://github.com/NethermindEth/nethermind/blob/09bd1aebee402c682a3ce46ae7137cb0e2988a5e/src/Nethermind/Nethermind.JsonRpc/ErrorType.cs#L53
impl ErrorParser for NethermindParser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError> {
        match (code, message.to_lowercase()) {
            (-32_010, msg) if msg.contains("AlreadyKnown") => {
                Some(SendRawTransactionError::AlreadyKnown)
            }
            (-32_010, msg) if msg.contains("InsufficientFunds") => {
                Some(SendRawTransactionError::InsufficientFunds)
            }
            (-32_010, msg) if msg.contains("OldNonce") => {
                Some(SendRawTransactionError::NonceTooLow)
            }
            (-32_010, msg) if msg.contains("NonceGap") => {
                Some(SendRawTransactionError::NonceTooHigh)
            }
            _ => None,
        }
    }
}

struct ErigonParser;
//https://github.com/ledgerwatch/erigon-lib/blob/3aa5249d48c1dacd95462c2653fd48179898db6f/types/txn.go#L123
//https://github.com/ledgerwatch/erigon-lib/blob/3aa5249d48c1dacd95462c2653fd48179898db6f/txpool/txpoolcfg/txpoolcfg.go#L96
impl ErrorParser for ErigonParser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError> {
        match (code, message.to_lowercase()) {
            (-32_000, msg) if msg.contains("already known") => {
                Some(SendRawTransactionError::AlreadyKnown)
            }
            (-32_000, msg) if msg.contains("insufficient funds") => {
                Some(SendRawTransactionError::InsufficientFunds)
            }
            (-32_000, msg) if msg.contains("nonce too low") => {
                Some(SendRawTransactionError::NonceTooLow)
            }
            //no NonceTooHigh in Erigon
            _ => None,
        }
    }
}

struct BesuParser;
//https://github.com/hyperledger/besu/blob/92a3c5b139bf57d1521c8f8ec623934c50430353/ethereum/api/src/main/java/org/hyperledger/besu/ethereum/api/jsonrpc/internal/response/RpcErrorType.java
//https://github.com/hyperledger/besu/blob/92a3c5b139bf57d1521c8f8ec623934c50430353/evm/src/main/java/org/hyperledger/besu/evm/frame/ExceptionalHaltReason.java#L77
impl ErrorParser for BesuParser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError> {
        match (code, message.to_lowercase()) {
            (-32_000, msg) if msg.contains("known transaction") => {
                Some(SendRawTransactionError::AlreadyKnown)
            }
            (-32_000, msg) if msg.contains("out of gas") => {
                Some(SendRawTransactionError::InsufficientFunds)
            }
            (-32_001, msg) if msg.contains("nonce too low") => {
                Some(SendRawTransactionError::NonceTooLow)
            }
            (-32_006, msg) if msg.contains("nonce too high") => {
                Some(SendRawTransactionError::NonceTooHigh)
            }
            _ => None,
        }
    }
}

pub struct Parser {
    parsers: Vec<Box<dyn ErrorParser>>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(GoEthereumParser),
                Box::new(NethermindParser),
                Box::new(ErigonParser),
                Box::new(BesuParser),
            ],
        }
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorParser for Parser {
    fn try_parse_send_raw_transaction_error(
        &self,
        code: i64,
        message: String,
    ) -> Option<SendRawTransactionError> {
        self.parsers
            .iter()
            .find_map(|parser| parser.try_parse_send_raw_transaction_error(code, message.clone()))
    }
}

/// Sanitizes the response of `eth_sendRawTransaction` to hide implementation details of the various Ethereum clients
/// queried by HTTP outcalls and the fact that `eth_sendRawTransaction` is not idempotent.
/// The type `JsonRpcReply<Hash>` of the original response is transformed into `JsonRpcReply<SendRawTxResult>`.
pub fn sanitize_send_raw_transaction_result<T: ErrorParser>(body_bytes: &mut Vec<u8>, parser: T) {
    let response: JsonRpcReply<Hash> = match serde_json::from_slice(body_bytes) {
        Ok(response) => response,
        Err(e) => {
            log!(DEBUG, "Error deserializing: {:?}", e);
            return;
        }
    };

    let sanitized_result = match response.result {
        JsonRpcResult::Result(_) => JsonRpcResult::Result(SendRawTransactionResult::Ok),
        JsonRpcResult::Error { code, message } => {
            if let Some(error) = parser.try_parse_send_raw_transaction_error(code, message.clone())
            {
                match error {
                    //transaction already in the mempool, so it was sent successfully
                    SendRawTransactionError::AlreadyKnown => {
                        JsonRpcResult::Result(SendRawTransactionResult::Ok)
                    }
                    SendRawTransactionError::InsufficientFunds => {
                        JsonRpcResult::Result(SendRawTransactionResult::InsufficientFunds)
                    }
                    SendRawTransactionError::NonceTooLow => {
                        JsonRpcResult::Result(SendRawTransactionResult::NonceTooLow)
                    }
                    SendRawTransactionError::NonceTooHigh => {
                        JsonRpcResult::Result(SendRawTransactionResult::NonceTooHigh)
                    }
                }
            } else {
                JsonRpcResult::Error { code, message }
            }
        }
    };
    let sanitized_reply: JsonRpcReply<SendRawTransactionResult> = JsonRpcReply {
        id: response.id,
        jsonrpc: response.jsonrpc,
        result: sanitized_result,
    };

    *body_bytes = serde_json::to_string(&sanitized_reply)
        .expect("BUG: failed to serialize error response")
        .into_bytes();
}
