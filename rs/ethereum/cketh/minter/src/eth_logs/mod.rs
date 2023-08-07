#[cfg(test)]
mod tests;

use crate::address::Address;
use crate::endpoints::ReceivedEthEvent;
use crate::eth_rpc;
use crate::eth_rpc::{
    into_nat, BlockNumber, FixedSizeData, Hash, LogEntry, BLOCK_PI_RPC_PROVIDER_URL,
};
use candid::Principal;
use hex_literal::hex;
use num_bigint::BigUint;
use std::collections::BTreeSet;

pub(crate) const RECEIVED_ETH_EVENT_TOPIC: [u8; 32] =
    hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
pub const SMART_CONTRACT_ADDRESS: [u8; 20] = hex!("b44B5e756A894775FC32EDdf3314Bb1B1944dC34");

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

    let result: Vec<LogEntry> = eth_rpc::call(
        BLOCK_PI_RPC_PROVIDER_URL,
        "eth_getLogs",
        vec![GetLogsParam {
            from_block: from.into(),
            to_block: to.into(),
            address: vec![Address::new(SMART_CONTRACT_ADDRESS)],
            topics: vec![FixedSizeData(RECEIVED_ETH_EVENT_TOPIC)],
        }],
    )
    .await
    .expect("HTTP call failed")
    .unwrap();

    let (ok, not_ok): (Vec<_>, Vec<_>) = result
        .into_iter()
        .map(|log| ReceivedEthEvent::try_from(log))
        .partition(Result::is_ok);
    let valid_transactions: Vec<ReceivedEthEvent> = ok.into_iter().map(Result::unwrap).collect();
    let errors: Vec<ReceivedEthEventError> = not_ok.into_iter().map(Result::unwrap_err).collect();
    (valid_transactions, errors)
}

pub fn mint_transaction(minted_transactions: &mut BTreeSet<Hash>, event: ReceivedEthEvent) {
    use std::str::FromStr;

    let transaction_hash = Hash::from_str(&event.transaction_hash).expect("valid transaction hash");
    if minted_transactions.insert(transaction_hash) {
        ic_cdk::println!(
            "Received new event {:?}: Minting {} wei to {}",
            event,
            event.value,
            event.principal
        );
    } else {
        ic_cdk::println!(
            "Ignoring event {:?} since transaction {:?} was already minted",
            event,
            event.transaction_hash
        );
    }
}

pub fn report_transaction_error(
    invalid_transactions: &mut BTreeSet<Hash>,
    error: ReceivedEthEventError,
) {
    match error {
        ReceivedEthEventError::PendingLogEntry => {
            ic_cdk::println!("Ignoring pending log entry");
        }
        ReceivedEthEventError::InvalidLogEntry(err) => {
            ic_cdk::println!("ERROR: Ignoring invalid log entry: {}. This is either a BUG or there is a problem with the queried provider", err);
        }
        ReceivedEthEventError::InvalidIcPrincipal {
            transaction_hash,
            invalid_principal,
        } => {
            if invalid_transactions.insert(transaction_hash.clone()) {
                ic_cdk::println!(
                    "WARN: Cannot process transaction with hash {:?} since the given IC principal {:?} is invalid",
                    transaction_hash,
                    invalid_principal
                );
            } else {
                ic_cdk::println!(
                    "Ignoring invalid transaction with hash {:?} since it was already reported",
                    transaction_hash,
                );
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReceivedEthEventError {
    PendingLogEntry,
    InvalidLogEntry(String),
    InvalidIcPrincipal {
        transaction_hash: Hash,
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
            .ok_or(ReceivedEthEventError::PendingLogEntry)?;

        if entry.topics.len() != 3 {
            return Err(ReceivedEthEventError::InvalidLogEntry(format!(
                "Expected exactly 3 topics, got {}",
                entry.topics.len()
            )));
        }
        let address = Address::try_from(&entry.topics[1].0).map_err(|err| {
            ReceivedEthEventError::InvalidLogEntry(format!("Invalid address in log entry: {}", err))
        })?;
        let principal = parse_principal_from_slice(entry.topics[2].as_ref()).map_err(|_err| {
            ReceivedEthEventError::InvalidIcPrincipal {
                transaction_hash: transaction_hash.clone(),
                invalid_principal: entry.topics[2].clone(),
            }
        })?;
        Ok(ReceivedEthEvent {
            transaction_hash: transaction_hash.to_string(),
            block_number: candid::Nat::from(block_number),
            log_index: into_nat(log_index),
            from_address: format!("{:x}", address),
            value: candid::Nat::from(BigUint::from_bytes_be(&entry.data.0)),
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
