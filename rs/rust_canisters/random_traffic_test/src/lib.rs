use candid::CandidType;
use ic_base_types::CanisterId;
use ic_error_types::RejectCode;
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;

/// A full config for generating random calls and replies. Ranges are stored as individual u32
/// because ranges don't implement `CandidType`.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType)]
pub struct Config {
    pub receivers: Vec<CanisterId>,
    pub call_bytes_min: u32,
    pub call_bytes_max: u32,
    pub reply_bytes_min: u32,
    pub reply_bytes_max: u32,
    pub instructions_count_min: u32,
    pub instructions_count_max: u32,
}

impl Default for Config {
    /// Default using the full range of payloads and no delayed responses.
    fn default() -> Self {
        Self {
            receivers: vec![],
            call_bytes_min: 0,
            call_bytes_max: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32,
            reply_bytes_min: 0,
            reply_bytes_max: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32,
            instructions_count_min: 0,
            instructions_count_max: 0,
        }
    }
}

impl Config {
    /// Convenience constructor that sanity checks input.
    pub fn try_new(
        receivers: Vec<CanisterId>,
        call_bytes: RangeInclusive<u32>,
        reply_bytes: RangeInclusive<u32>,
        instructions_count: RangeInclusive<u32>,
    ) -> Result<Self, String> {
        // Sanity checks. After passing these, the canister should run as intended.
        if call_bytes.is_empty() {
            return Err("empty call_bytes range".to_string());
        }
        if *call_bytes.end() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32 {
            return Err(format!(
                "call_bytes range max exceeds {}",
                MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64
            ));
        }
        if reply_bytes.is_empty() {
            return Err("empty reply_bytes range".to_string());
        }
        if *reply_bytes.end() > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32 {
            return Err(format!(
                "reply_bytes range max exceeds {}",
                MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64
            ));
        }
        if instructions_count.is_empty() {
            return Err("empty instructions_count range".to_string());
        }

        Ok(Self {
            receivers,
            call_bytes_min: *call_bytes.start(),
            call_bytes_max: *call_bytes.end(),
            reply_bytes_min: *reply_bytes.start(),
            reply_bytes_max: *reply_bytes.end(),
            instructions_count_min: *instructions_count.start(),
            instructions_count_max: *instructions_count.end(),
        })
    }
}

/// Records the outcome of an outgoing call.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
pub enum Reply {
    /// A response including a data payload of a distinct size was received.
    Bytes(u32),
    /// The call was rejected synchronously by the system with an error code.
    SynchronousRejection(i32),
    /// The call was rejected asynchronously through a reject response, which
    /// includes an error code and a reject message.
    AsynchronousRejection(i32, String),
}

/// Record for one outgoing call. Records how many bytes were sent out; and what kind of
/// reply was received (either data or a synchronous or asynchronous rejection).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
pub struct Record {
    pub receiver: CanisterId,
    pub sent_bytes: u32,
    pub reply: Option<Reply>,
}

/// Human readable printer.
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} | sending {} bytes | ",
            &self.receiver.to_string()[..5],
            self.sent_bytes
        )?;
        match &self.reply {
            None => write!(f, "..."),
            Some(Reply::Bytes(bytes)) => write!(f, "received {} bytes", bytes),
            Some(Reply::SynchronousRejection(error_code)) => {
                write!(
                    f,
                    "sync {}",
                    RejectCode::try_from(*error_code as u64).unwrap(),
                )
            }
            Some(Reply::AsynchronousRejection(error_code, error_msg)) => {
                write!(
                    f,
                    "async {}: '{error_msg}'",
                    RejectCode::try_from(*error_code as u64).unwrap(),
                )
            }
        }
    }
}

/// Basic metrics extracted from the records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Metrics {
    pub hanging_calls: u32,
    pub calls_attempted: u32,
    pub calls_replied: u32,
    pub calls_rejected_synchronously: u32,
    pub calls_rejected_asynchronously: u32,
    pub sent_bytes: u32,
    pub sync_rejected_bytes: u32,
    pub async_rejected_bytes: u32,
    pub received_bytes: u32,
}

/// Extracts some basic metrics from the records.
pub fn extract_metrics(records: &Vec<Record>) -> Metrics {
    let mut metrics = Metrics::default();

    for record in records {
        metrics.calls_attempted += 1;
        metrics.sent_bytes += record.sent_bytes;

        match record.reply {
            Some(Reply::Bytes(received_bytes)) => {
                metrics.calls_replied += 1;
                metrics.received_bytes += received_bytes;
            }
            Some(Reply::SynchronousRejection(_)) => {
                metrics.calls_rejected_synchronously += 1;
                metrics.sync_rejected_bytes += record.sent_bytes;
            }
            Some(Reply::AsynchronousRejection(_, _)) => {
                metrics.calls_rejected_asynchronously += 1;
                metrics.async_rejected_bytes += record.sent_bytes;
            }
            None => {
                metrics.hanging_calls += 1;
            }
        }
    }
    metrics
}
