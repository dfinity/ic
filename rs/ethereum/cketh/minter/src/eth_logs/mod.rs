#[cfg(test)]
mod tests;

use crate::checked_amount::CheckedAmountOf;
use crate::eth_rpc::{Data, FixedSizeData, Hash, LogEntry};
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
use candid::Principal;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Decode, Encode)]
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
    #[n(6)]
    pub subaccount: Option<LedgerSubaccount>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Decode, Encode)]
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
    #[n(7)]
    pub subaccount: Option<LedgerSubaccount>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
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
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Decode, Encode)]
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

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ReceivedEventError {
    PendingLogEntry,
    InvalidEventSource {
        source: EventSource,
        error: EventSourceError,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum EventSourceError {
    #[error("failed to decode principal from bytes {invalid_principal}")]
    InvalidPrincipal { invalid_principal: FixedSizeData },
    #[error("invalid ReceivedEthEvent: {0}")]
    InvalidEvent(String),
}

pub trait LogParser {
    fn parse_log(log: LogEntry) -> Result<ReceivedEvent, ReceivedEventError>;
}

pub struct EthWithoutSubaccountLogParser {}

impl LogParser for EthWithoutSubaccountLogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 3
                    && topics.first()
                        == Some(&FixedSizeData(crate::deposit::RECEIVED_ETH_EVENT_TOPIC))
            },
            event_source,
        )?;
        let from_address = parse_address(&entry.topics[1], event_source)?;
        let principal = parse_principal(&entry.topics[2], event_source)?;

        let [value_bytes] = parse_data_into_32_byte_words(entry.data, event_source)?;
        let EventSource {
            transaction_hash,
            log_index,
        } = event_source;

        Ok(ReceivedEthEvent {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value: Wei::from_be_bytes(value_bytes),
            principal,
            subaccount: None,
        }
        .into())
    }
}

pub struct Erc20WithoutSubaccountLogParser {}

impl LogParser for Erc20WithoutSubaccountLogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 4
                    && topics.first()
                        == Some(&FixedSizeData(crate::deposit::RECEIVED_ERC20_EVENT_TOPIC))
            },
            event_source,
        )?;
        let erc20_contract_address = parse_address(&entry.topics[1], event_source)?;
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;

        let [value_bytes] = parse_data_into_32_byte_words(entry.data, event_source)?;
        let EventSource {
            transaction_hash,
            log_index,
        } = event_source;

        Ok(ReceivedErc20Event {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value: Erc20Value::from_be_bytes(value_bytes),
            principal,
            erc20_contract_address,
            subaccount: None,
        }
        .into())
    }
}

pub struct Erc20WithSubaccountLogParser {}

impl LogParser for Erc20WithSubaccountLogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 4
                    && topics.first()
                        == Some(&FixedSizeData(
                            crate::deposit::RECEIVED_ERC20_EVENT_WITH_SUBACCOUNT_TOPIC,
                        ))
            },
            event_source,
        )?;
        let erc20_contract_address = parse_address(&entry.topics[1], event_source)?;
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;
        let [value_bytes, subaccount_bytes] =
            parse_data_into_32_byte_words(entry.data, event_source)?;
        let value = Erc20Value::from_be_bytes(value_bytes);
        let subaccount = LedgerSubaccount::from_bytes(subaccount_bytes);
        let EventSource {
            transaction_hash,
            log_index,
        } = event_source;

        Ok(ReceivedErc20Event {
            transaction_hash,
            block_number,
            log_index,
            from_address,
            value,
            principal,
            erc20_contract_address,
            subaccount,
        }
        .into())
    }
}

fn ensure_not_pending(entry: &LogEntry) -> Result<(BlockNumber, EventSource), ReceivedEventError> {
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
    Ok((
        block_number,
        EventSource {
            transaction_hash,
            log_index,
        },
    ))
}

fn ensure_not_removed(
    entry: &LogEntry,
    event_source: EventSource,
) -> Result<(), ReceivedEventError> {
    if entry.removed {
        return Err(ReceivedEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidEvent(
                "this event has been removed from the chain".to_string(),
            ),
        });
    }
    Ok(())
}

fn ensure_topics<P>(
    entry: &LogEntry,
    predicate: P,
    event_source: EventSource,
) -> Result<(), ReceivedEventError>
where
    P: FnOnce(&[FixedSizeData]) -> bool,
{
    if !predicate(&entry.topics) {
        return Err(ReceivedEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidEvent("Invalid topics".to_string()),
        });
    }
    Ok(())
}

fn parse_address(
    address: &FixedSizeData,
    event_source: EventSource,
) -> Result<Address, ReceivedEventError> {
    Address::try_from(&address.0).map_err(|err| ReceivedEventError::InvalidEventSource {
        source: event_source,
        error: EventSourceError::InvalidEvent(format!("Invalid address in log entry: {}", err)),
    })
}

fn parse_principal(
    principal: &FixedSizeData,
    event_source: EventSource,
) -> Result<Principal, ReceivedEventError> {
    parse_principal_from_slice(&principal.0).map_err(|_err| {
        ReceivedEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidPrincipal {
                invalid_principal: principal.clone(),
            },
        }
    })
}

fn parse_data_into_32_byte_words<const N: usize>(
    data: Data,
    event_source: EventSource,
) -> Result<[[u8; 32]; N], ReceivedEventError> {
    let data = data.0;
    if data.len() != 32 * N {
        return Err(ReceivedEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidEvent(format!(
                "Expected {} bytes, got {}",
                32 * N,
                data.len()
            )),
        });
    }
    let mut result = Vec::with_capacity(N);
    for chunk in data.chunks_exact(32) {
        let mut word = [0; 32];
        word.copy_from_slice(chunk);
        result.push(word);
    }
    Ok(result.try_into().unwrap())
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

enum InternalLedgerSubaccountTag {}
type InternalLedgerSubaccount = CheckedAmountOf<InternalLedgerSubaccountTag>;

/// Ledger subaccount.
///
/// Internally represented as a u256 to optimize cbor encoding for low values,
/// which can be represented as a u32 or a u64.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Decode, Encode)]
pub struct LedgerSubaccount(#[n(0)] InternalLedgerSubaccount);

impl LedgerSubaccount {
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        const DEFAULT_SUBACCOUNT: [u8; 32] = [0; 32];
        if bytes == DEFAULT_SUBACCOUNT {
            return None;
        }
        Some(Self(InternalLedgerSubaccount::from_be_bytes(bytes)))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }
}
