#[cfg(test)]
mod tests;

use crate::eth_rpc::{FixedSizeData, Hash, LogEntry};
use crate::eth_rpc_client::{EthRpcClient, MultiCallError};
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
use crate::state::read_state;
use candid::Principal;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use std::fmt;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ReceivedErc20Event {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub block_number: BlockNumber,
    #[cbor(n(2))]
    pub log_index: LogIndex,
    #[n(3)]
    pub from_address: Address,
    #[n(4)]
    pub value: Erc20Value,
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub principal: Principal,
    #[n(6)]
    pub erc20_contract_address: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedEvent {
    Eth(ReceivedEthEvent),
    Erc20(ReceivedErc20Event),
}

impl From<ReceivedEthEvent> for ReceivedEvent {
    fn from(event: ReceivedEthEvent) -> Self {
        ReceivedEvent::Eth(event)
    }
}

impl From<ReceivedErc20Event> for ReceivedEvent {
    fn from(event: ReceivedErc20Event) -> Self {
        ReceivedEvent::Erc20(event)
    }
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

impl fmt::Debug for ReceivedErc20Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedErc20Event")
            .field("transaction_hash", &self.transaction_hash)
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("from_address", &self.from_address)
            .field("value", &self.value)
            .field("principal", &format_args!("{}", self.principal))
            .field("contract_address", &self.erc20_contract_address)
            .finish()
    }
}

/// A unique identifier of the event source: the source transaction hash and the log
/// entry index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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

impl ReceivedErc20Event {
    pub fn source(&self) -> EventSource {
        EventSource {
            transaction_hash: self.transaction_hash,
            log_index: self.log_index,
        }
    }
}

impl ReceivedEvent {
    /// Return event source, which is globally unique regardless of whether
    /// it is for ETH or ERC-20. This is because the `transaction_hash` already
    /// unique determines the transaction, and `log_index` would match the place
    /// in which event appears for this transaction.
    pub fn source(&self) -> EventSource {
        match self {
            ReceivedEvent::Eth(evt) => evt.source(),
            ReceivedEvent::Erc20(evt) => evt.source(),
        }
    }
    pub fn from_address(&self) -> Address {
        match self {
            ReceivedEvent::Eth(evt) => evt.from_address,
            ReceivedEvent::Erc20(evt) => evt.from_address,
        }
    }
    pub fn principal(&self) -> Principal {
        match self {
            ReceivedEvent::Eth(evt) => evt.principal,
            ReceivedEvent::Erc20(evt) => evt.principal,
        }
    }
    pub fn block_number(&self) -> BlockNumber {
        match self {
            ReceivedEvent::Eth(evt) => evt.block_number,
            ReceivedEvent::Erc20(evt) => evt.block_number,
        }
    }
    pub fn log_index(&self) -> LogIndex {
        match self {
            ReceivedEvent::Eth(evt) => evt.log_index,
            ReceivedEvent::Erc20(evt) => evt.log_index,
        }
    }
    pub fn transaction_hash(&self) -> Hash {
        match self {
            ReceivedEvent::Eth(evt) => evt.transaction_hash,
            ReceivedEvent::Erc20(evt) => evt.transaction_hash,
        }
    }
    pub fn value(&self) -> candid::Nat {
        match self {
            ReceivedEvent::Eth(evt) => evt.value.into(),
            ReceivedEvent::Erc20(evt) => evt.value.into(),
        }
    }
}

pub async fn last_received_events(
    topic: &[u8; 32],
    contract_address: Address,
    token_contract_addresses: &[Address],
    from: BlockNumber,
    to: BlockNumber,
) -> Result<(Vec<ReceivedEvent>, Vec<ReceivedEventError>), MultiCallError<Vec<LogEntry>>> {
    use crate::eth_rpc::GetLogsParam;

    if from > to {
        ic_cdk::trap(&format!(
            "BUG: invalid block range. {:?} should not be greater than {:?}",
            from, to
        ));
    }
    let mut topics: Vec<_> = vec![FixedSizeData(*topic).into()];
    // We add token contract addresses as additional topics to match.
    // It has a disjunction semantics, so it will match if event matches any one of these addresses.
    if !token_contract_addresses.is_empty() {
        topics.push(
            token_contract_addresses
                .iter()
                .map(|address| FixedSizeData(address.into()))
                .collect::<Vec<_>>()
                .into(),
        )
    }

    let result = read_state(EthRpcClient::from_state)
        .eth_get_logs(GetLogsParam {
            from_block: from.into(),
            to_block: to.into(),
            address: vec![contract_address],
            topics,
        })
        .await?;

    let (ok, not_ok): (Vec<_>, Vec<_>) = result
        .into_iter()
        .map(ReceivedEvent::try_from)
        .partition(Result::is_ok);
    let valid_transactions: Vec<ReceivedEvent> = ok.into_iter().map(Result::unwrap).collect();
    let errors: Vec<ReceivedEventError> = not_ok.into_iter().map(Result::unwrap_err).collect();
    Ok((valid_transactions, errors))
}

pub fn report_transaction_error(error: ReceivedEventError) {
    match error {
        ReceivedEventError::PendingLogEntry => {
            log!(
                DEBUG,
                "[report_transaction_error]: ignoring pending log entry",
            );
        }
        ReceivedEventError::InvalidEventSource { source, error } => {
            log!(
                INFO,
                "[report_transaction_error]: cannot process {source} due to {error}",
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedEventError {
    PendingLogEntry,
    InvalidEventSource {
        source: EventSource,
        error: EventSourceError,
    },
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EventSourceError {
    #[error("failed to decode principal from bytes {invalid_principal}")]
    InvalidPrincipal { invalid_principal: FixedSizeData },
    #[error("invalid ReceivedEthEvent: {0}")]
    InvalidEvent(String),
}

impl TryFrom<LogEntry> for ReceivedEvent {
    type Error = ReceivedEventError;

    fn try_from(entry: LogEntry) -> Result<Self, Self::Error> {
        let _block_hash = entry
            .block_hash
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let block_number = entry
            .block_number
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let transaction_hash = entry
            .transaction_hash
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let _transaction_index = entry
            .transaction_index
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let log_index = entry.log_index.ok_or(ReceivedEventError::PendingLogEntry)?;
        let event_source = EventSource {
            transaction_hash,
            log_index,
        };

        if entry.removed {
            return Err(ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(
                    "this event has been removed from the chain".to_string(),
                ),
            });
        }

        let parse_address = |address: &FixedSizeData| -> Result<Address, ReceivedEventError> {
            Address::try_from(&address.0).map_err(|err| ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid address in log entry: {}",
                    err
                )),
            })
        };

        let parse_principal = |principal: &FixedSizeData| -> Result<Principal, ReceivedEventError> {
            parse_principal_from_slice(&principal.0).map_err(|_err| {
                ReceivedEventError::InvalidEventSource {
                    source: event_source,
                    error: EventSourceError::InvalidPrincipal {
                        invalid_principal: principal.clone(),
                    },
                }
            })
        };

        // We have only one non-indexed data field for both ETH and ERC20 events.
        let value_bytes: [u8; 32] = entry.data.0.clone().try_into().map_err(|data| {
            ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid data length; expected 32-byte value, got {}",
                    hex::encode(data)
                )),
            }
        })?;

        // We either have 3 indexed topics for ETH events: (hash, from_address, principal),
        // or 4 indexed topics for ERC20 events: (hash, erc20_contract_address, from_address, principal)
        match entry.topics[0] {
            FixedSizeData(crate::deposit::RECEIVED_ETH_EVENT_TOPIC) => {
                if entry.topics.len() != 3 {
                    return Err(ReceivedEventError::InvalidEventSource {
                        source: event_source,
                        error: EventSourceError::InvalidEvent(format!(
                            "Expected 3 topics for ReceivedEth event, got {}",
                            entry.topics.len()
                        )),
                    });
                };
                let from_address = parse_address(&entry.topics[1])?;
                let principal = parse_principal(&entry.topics[2])?;
                Ok(ReceivedEthEvent {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value: Wei::from_be_bytes(value_bytes),
                    principal,
                }
                .into())
            }
            FixedSizeData(crate::deposit::RECEIVED_ERC20_EVENT_TOPIC) => {
                if entry.topics.len() != 4 {
                    return Err(ReceivedEventError::InvalidEventSource {
                        source: event_source,
                        error: EventSourceError::InvalidEvent(format!(
                            "Expected 4 topics for ReceivedERC20 event, got {}",
                            entry.topics.len()
                        )),
                    });
                };
                let erc20_contract_address = parse_address(&entry.topics[1])?;
                let from_address = parse_address(&entry.topics[2])?;
                let principal = parse_principal(&entry.topics[3])?;
                Ok(ReceivedErc20Event {
                    transaction_hash,
                    block_number,
                    log_index,
                    from_address,
                    value: Erc20Value::from_be_bytes(value_bytes),
                    principal,
                    erc20_contract_address,
                }
                .into())
            }
            _ => Err(ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Expected either ReceivedEth or ReceivedERC20 topics, got {}",
                    entry.topics[0]
                )),
            }),
        }
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
