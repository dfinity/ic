#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::eth_rpc::{FixedSizeData, Hash, LogEntry};
use crate::eth_rpc_client::EthRpcClient;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, LogIndex, Wei};
use crate::state::read_state;
use candid::Principal;
use hex_literal::hex;
use ic_canister_log::log;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub(crate) const RECEIVED_ETH_EVENT_TOPIC: [u8; 32] =
    hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ReceivedEthEvent {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub block_number: BlockNumber,
    #[cbor(n(2))]
    pub log_index: LogIndex,
    #[n(3)]
    pub from_address: Address,
    #[n(4)]
    pub value: Wei,
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub principal: Principal,
}

impl fmt::Debug for ReceivedEthEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedEthEvent")
            .field("transaction_hash", &self.transaction_hash)
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("from_address", &self.from_address)
            .field("value", &self.value)
            .field("principal", &format_args!("{}", self.principal))
            .finish()
    }
}

/// A unique identifier of the event source: the source transaction hash and the log
/// entry index.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode,
)]
pub struct EventSource {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub log_index: LogIndex,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}:{}", self.transaction_hash, self.log_index)
    }
}

impl ReceivedEthEvent {
    pub fn source(&self) -> EventSource {
        EventSource {
            transaction_hash: self.transaction_hash,
            log_index: self.log_index,
        }
    }
}

pub async fn last_received_eth_events(
    contract_address: Address,
    from: BlockNumber,
    to: BlockNumber,
) -> (Vec<ReceivedEthEvent>, Vec<ReceivedEthEventError>) {
    use crate::eth_rpc::GetLogsParam;

    if from > to {
        ic_cdk::trap(&format!(
            "BUG: invalid block range. {:?} should not be greater than {:?}",
            from, to
        ));
    }

    let result: Vec<LogEntry> = read_state(EthRpcClient::from_state)
        .eth_get_logs(GetLogsParam {
            from_block: from.into(),
            to_block: to.into(),
            address: vec![contract_address],
            topics: vec![FixedSizeData(RECEIVED_ETH_EVENT_TOPIC)],
        })
        .await
        .expect("HTTP call failed");

    let (ok, not_ok): (Vec<_>, Vec<_>) = result
        .into_iter()
        .map(ReceivedEthEvent::try_from)
        .partition(Result::is_ok);
    let valid_transactions: Vec<ReceivedEthEvent> = ok.into_iter().map(Result::unwrap).collect();
    let errors: Vec<ReceivedEthEventError> = not_ok.into_iter().map(Result::unwrap_err).collect();
    (valid_transactions, errors)
}

pub fn report_transaction_error(error: ReceivedEthEventError) {
    match error {
        ReceivedEthEventError::PendingLogEntry => {
            log!(
                DEBUG,
                "[report_transaction_error]: ignoring pending log entry",
            );
        }
        ReceivedEthEventError::InvalidEventSource { source, error } => {
            log!(
                INFO,
                "[report_transaction_error]: cannot process {source} due to {error}",
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedEthEventError {
    PendingLogEntry,
    InvalidEventSource {
        source: EventSource,
        error: EventSourceError,
    },
}

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSourceError {
    #[error("failed to decode principal from bytes {invalid_principal}")]
    InvalidPrincipal { invalid_principal: FixedSizeData },
    #[error("invalid ReceivedEthEvent: {0}")]
    InvalidEvent(String),
}

impl TryFrom<LogEntry> for ReceivedEthEvent {
    type Error = ReceivedEthEventError;

    fn try_from(entry: LogEntry) -> Result<Self, Self::Error> {
        let _block_hash = entry
            .block_hash
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;
        let block_number = entry
            .block_number
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;
        let transaction_hash = entry
            .transaction_hash
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;
        let _transaction_index = entry
            .transaction_index
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;
        let log_index = entry
            .log_index
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;
        let event_source = EventSource {
            transaction_hash,
            log_index,
        };

        if entry.topics.len() != 3 {
            return Err(ReceivedEthEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Expected exactly 3 topics, got {}",
                    entry.topics.len()
                )),
            });
        }
        let from_address = Address::try_from(&entry.topics[1].0).map_err(|err| {
            ReceivedEthEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid address in log entry: {}",
                    err
                )),
            }
        })?;
        let principal = parse_principal_from_slice(entry.topics[2].as_ref()).map_err(|_err| {
            ReceivedEthEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidPrincipal {
                    invalid_principal: entry.topics[2].clone(),
                },
            }
        })?;
        let value_bytes: [u8; 32] =
            entry
                .data
                .0
                .try_into()
                .map_err(|data| ReceivedEthEventError::InvalidEventSource {
                    source: event_source,
                    error: EventSourceError::InvalidEvent(format!(
                        "Invalid data length; expected 32-byte value, got {}",
                        hex::encode(data)
                    )),
                })?;
        let value = Wei::from_be_bytes(value_bytes);

        Ok(ReceivedEthEvent {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value,
            principal,
        })
    }
}

/// Decode a candid::Principal from a slice of at most 32 bytes
/// encoded as follows
/// - the first byte is the number of bytes in the principal
/// - the next N bytes are the principal
/// - the remaining bytes are zero
///
/// Any other encoding will return an error.
/// Some specific valid [`Principal`]s are also not allowed
/// since the decoded principal will be used to receive ckETH:
/// * the management canister principal
/// * the anonymous principal
///
/// This method MUST never panic (decode bytes from untrusted sources).
fn parse_principal_from_slice(slice: &[u8]) -> Result<Principal, String> {
    const ANONYMOUS_PRINCIPAL_BYTES: [u8; 1] = [4];

    if slice.is_empty() {
        return Err("slice too short".to_string());
    }
    if slice.len() > 32 {
        return Err(format!("Expected at most 32 bytes, got {}", slice.len()));
    }
    let num_bytes = slice[0] as usize;
    if num_bytes == 0 {
        return Err("management canister principal is not allowed".to_string());
    }
    if num_bytes > 29 {
        return Err(format!(
            "invalid number of bytes: expected a number in the range [1,29], got {num_bytes}",
        ));
    }
    if slice.len() < 1 + num_bytes {
        return Err("slice too short".to_string());
    }
    let (principal_bytes, trailing_zeroes) = slice[1..].split_at(num_bytes);
    if !trailing_zeroes
        .iter()
        .all(|trailing_zero| *trailing_zero == 0)
    {
        return Err("trailing non-zero bytes".to_string());
    }
    if principal_bytes == ANONYMOUS_PRINCIPAL_BYTES {
        return Err("anonymous principal is not allowed".to_string());
    }
    Principal::try_from_slice(principal_bytes).map_err(|err| err.to_string())
}
