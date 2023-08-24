#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::eth_rpc::{BlockNumber, FixedSizeData, Hash, LogEntry};
use crate::eth_rpc_client::EthRpcClient;
use crate::logs::{DEBUG, INFO};
use crate::numeric::Wei;
use crate::state::{read_state, State};
use candid::Principal;
use ethnum::u256;
use hex_literal::hex;
use ic_canister_log::log;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const RECEIVED_ETH_EVENT_TOPIC: [u8; 32] =
    hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
pub const SMART_CONTRACT_ADDRESS: [u8; 20] = hex!("b44B5e756A894775FC32EDdf3314Bb1B1944dC34");

pub enum EthLogIndexTag {}
pub type LogIndex = phantom_newtype::Id<EthLogIndexTag, u256>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedEthEvent {
    pub transaction_hash: Hash,
    pub block_number: BlockNumber,
    pub log_index: LogIndex,
    pub from_address: Address,
    pub value: Wei,
    pub principal: Principal,
}

/// A unique identifier of the event source: the source transaction hash and the log
/// entry index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventSource(Hash, LogIndex);

impl EventSource {
    pub fn txhash(&self) -> &Hash {
        &self.0
    }
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}:{}", self.0, self.1)
    }
}

impl ReceivedEthEvent {
    pub fn source(&self) -> EventSource {
        EventSource(self.transaction_hash, self.log_index)
    }
}

pub async fn last_received_eth_events(
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
            address: vec![Address::new(SMART_CONTRACT_ADDRESS)],
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

pub fn report_transaction_error(state: &mut State, error: ReceivedEthEventError) {
    match error {
        ReceivedEthEventError::PendingLogEntry => {
            log!(
                DEBUG,
                "[report_transaction_error]: ignoring pending log entry",
            );
        }
        ReceivedEthEventError::InvalidLogEntry(err) => {
            log!(
                INFO,
                "[report_transaction_error]: Ignoring invalid log entry: {}. This is either a BUG or there is a problem with the queried provider",
                err,
            );
        }
        ReceivedEthEventError::InvalidIcPrincipal {
            event_source,
            invalid_principal,
        } => {
            if state.record_invalid_deposit(event_source) {
                log!(
                    INFO,
                    "[report_transaction_error]: cannot process event {event_source} since the given IC principal {invalid_principal:?} is invalid",
                );
            } else {
                log!(
                    DEBUG,
                    "[report_transaction_error]: Ignoring invalid event {event_source} since it was already reported",
                );
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedEthEventError {
    PendingLogEntry,
    InvalidLogEntry(String),
    InvalidIcPrincipal {
        event_source: EventSource,
        invalid_principal: FixedSizeData,
    },
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
            .map(LogIndex::new)
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;

        if entry.topics.len() != 3 {
            return Err(ReceivedEthEventError::InvalidLogEntry(format!(
                "Expected exactly 3 topics, got {}",
                entry.topics.len()
            )));
        }
        let from_address = Address::try_from(&entry.topics[1].0).map_err(|err| {
            ReceivedEthEventError::InvalidLogEntry(format!("Invalid address in log entry: {}", err))
        })?;
        let principal = parse_principal_from_slice(entry.topics[2].as_ref()).map_err(|_err| {
            ReceivedEthEventError::InvalidIcPrincipal {
                event_source: EventSource(transaction_hash, log_index),
                invalid_principal: entry.topics[2].clone(),
            }
        })?;
        let value_bytes: [u8; 32] = entry.data.0.try_into().map_err(|data| {
            ReceivedEthEventError::InvalidLogEntry(format!(
                "Invalid data length; expected 32-byte value, got {}",
                hex::encode(data),
            ))
        })?;
        let value = Wei::from(u256::from_be_bytes(value_bytes));

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
