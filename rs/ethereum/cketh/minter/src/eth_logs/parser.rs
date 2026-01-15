use crate::eth_logs::{
    EventSource, EventSourceError, LedgerSubaccount, RECEIVED_ERC20_EVENT_TOPIC,
    RECEIVED_ETH_EVENT_TOPIC, RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
    ReceivedErc20Event, ReceivedEthEvent, ReceivedEvent, ReceivedEventError,
    parse_principal_from_slice,
};
use crate::eth_rpc::Hash;
use crate::numeric::{BlockNumber, Erc20Value, Wei};
use candid::Principal;
use evm_rpc_types::{Hex, Hex32, LogEntry};
use ic_ethereum_types::Address;

/// Parse an Ethereum log event into a `ReceivedEvent`.
pub trait LogParser {
    fn parse_log(log: LogEntry) -> Result<ReceivedEvent, ReceivedEventError>;

    /// Parse a list of Ethereum log events into a list of `ReceivedEvent`s and a list of errors.
    ///
    /// All logs are parsed, even if some of them are invalid.
    fn parse_all_logs(logs: Vec<LogEntry>) -> (Vec<ReceivedEvent>, Vec<ReceivedEventError>) {
        let (ok, not_ok): (Vec<_>, Vec<_>) = logs
            .into_iter()
            .map(Self::parse_log)
            .partition(Result::is_ok);
        let valid_transactions: Vec<ReceivedEvent> = ok.into_iter().map(Result::unwrap).collect();
        let errors: Vec<ReceivedEventError> = not_ok.into_iter().map(Result::unwrap_err).collect();
        (valid_transactions, errors)
    }
}

pub enum ReceivedEthLogParser {}

impl LogParser for ReceivedEthLogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 3 && topics.first() == Some(&Hex32::from(RECEIVED_ETH_EVENT_TOPIC))
            },
            event_source,
        )?;
        let from_address = parse_address(&entry.topics[1], event_source)?;
        let principal = parse_principal(&entry.topics[2], event_source)?;

        let [value_bytes] = parse_hex_into_32_byte_words(entry.data, event_source)?;
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

pub enum ReceivedErc20LogParser {}

impl LogParser for ReceivedErc20LogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 4
                    && topics.first() == Some(&Hex32::from(RECEIVED_ERC20_EVENT_TOPIC))
            },
            event_source,
        )?;
        let erc20_contract_address = parse_address(&entry.topics[1], event_source)?;
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;

        let [value_bytes] = parse_hex_into_32_byte_words(entry.data, event_source)?;
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

pub enum ReceivedEthOrErc20LogParser {}

impl LogParser for ReceivedEthOrErc20LogParser {
    fn parse_log(entry: LogEntry) -> Result<ReceivedEvent, ReceivedEventError> {
        let (block_number, event_source) = ensure_not_pending(&entry)?;
        ensure_not_removed(&entry, event_source)?;

        ensure_topics(
            &entry,
            |topics| {
                topics.len() == 4
                    && topics.first()
                        == Some(&Hex32::from(
                            RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
                        ))
            },
            event_source,
        )?;
        let erc20_contract_address = parse_address(&entry.topics[1], event_source)?;
        let from_address = parse_address(&entry.topics[2], event_source)?;
        let principal = parse_principal(&entry.topics[3], event_source)?;
        let [value_bytes, subaccount_bytes] =
            parse_hex_into_32_byte_words(entry.data, event_source)?;
        let subaccount = LedgerSubaccount::from_bytes(subaccount_bytes);
        let EventSource {
            transaction_hash,
            log_index,
        } = event_source;

        if erc20_contract_address == Address::ZERO {
            let value = Wei::from_be_bytes(value_bytes);
            return Ok(ReceivedEthEvent {
                transaction_hash,
                block_number,
                log_index,
                from_address,
                value,
                principal,
                subaccount,
            }
            .into());
        }

        let value = Erc20Value::from_be_bytes(value_bytes);
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
        .as_ref()
        .ok_or(ReceivedEventError::PendingLogEntry)?;
    let block_number = entry
        .block_number
        .clone()
        .ok_or(ReceivedEventError::PendingLogEntry)?;
    let transaction_hash = entry
        .transaction_hash
        .clone()
        .ok_or(ReceivedEventError::PendingLogEntry)?;
    let _transaction_index = entry
        .transaction_index
        .as_ref()
        .ok_or(ReceivedEventError::PendingLogEntry)?;
    let log_index = entry
        .log_index
        .clone()
        .ok_or(ReceivedEventError::PendingLogEntry)?;
    Ok((
        block_number.into(),
        EventSource {
            transaction_hash: Hash(transaction_hash.into()),
            log_index: log_index.into(),
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
    P: FnOnce(&[Hex32]) -> bool,
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
    address: &Hex32,
    event_source: EventSource,
) -> Result<Address, ReceivedEventError> {
    let array: &[u8; 32] = &address.clone().into();

    Address::try_from(array).map_err(|err| ReceivedEventError::InvalidEventSource {
        source: event_source,
        error: EventSourceError::InvalidEvent(format!("Invalid address in log entry: {err}")),
    })
}

fn parse_principal(
    principal: &Hex32,
    event_source: EventSource,
) -> Result<Principal, ReceivedEventError> {
    parse_principal_from_slice(principal.as_ref()).map_err(|_err| {
        ReceivedEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidPrincipal {
                invalid_principal: principal.clone(),
            },
        }
    })
}

fn parse_hex_into_32_byte_words<const N: usize>(
    data: Hex,
    event_source: EventSource,
) -> Result<[[u8; 32]; N], ReceivedEventError> {
    let data = data.as_ref();
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
