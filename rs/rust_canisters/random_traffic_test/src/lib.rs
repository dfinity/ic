use candid::CandidType;
use ic_base_types::CanisterId;
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
    pub downstream_call_weight: u32,
    pub reply_weight: u32,
}

impl Default for Config {
    /// Default using the full range of payloads, no delayed responses and no downstream calls.
    fn default() -> Self {
        Self {
            call_bytes_min: 0,
            call_bytes_max: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32,
            receivers: vec![],
            reply_bytes_min: 0,
            reply_bytes_max: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32,
            instructions_count_min: 0,
            instructions_count_max: 0,
            downstream_call_weight: 0,
            reply_weight: 1,
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
        downstream_call_weight: u32,
        reply_weight: u32,
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
        if downstream_call_weight + reply_weight == 0 {
            return Err("both weights are 0".to_string());
        }

        Ok(Self {
            receivers,
            call_bytes_min: *call_bytes.start(),
            call_bytes_max: *call_bytes.end(),
            reply_bytes_min: *reply_bytes.start(),
            reply_bytes_max: *reply_bytes.end(),
            instructions_count_min: *instructions_count.start(),
            instructions_count_max: *instructions_count.end(),
            downstream_call_weight,
            reply_weight,
        })
    }
}

/// Indicate whether a call was made successfully including the size of the payload; or rejected
/// synchronously by the IC including the error code.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, CandidType)]
pub enum Call {
    Data(u32),
    Rejected(i32),
}

/// Indicates whether a reply was received including the size of the payload; or rejected
/// including the message in the reject response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, CandidType)]
pub enum Reply {
    Data(u32),
    Rejected(String),
}

/// Record for one message cycle. Records whether and how many bytes were sent out; and received.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
pub struct Record {
    pub receiver: CanisterId,
    pub call: Call,
    pub reply: Option<Reply>,
}

/// Human readable printer.
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Calling {}, ", self.receiver)?;
        match self.call {
            Call::Data(bytes) => write!(f, "sending {} bytes", bytes),
            Call::Rejected(error_code) => {
                write!(f, "synchronously rejected with error code {}", error_code)
            }
        }?;
        if let Some(reply) = &self.reply {
            match reply {
                Reply::Data(bytes) => write!(f, ", reply received with {} bytes", bytes),
                Reply::Rejected(msg) => write!(f, ", call rejected: '{}'", msg),
            }
        } else {
            write!(f, "...")
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
    pub bytes_sent: u32,
    pub bytes_received: u32,
}

/// Extracts some basic metrics from the records.
pub fn extract_metrics(records: &Vec<Record>) -> Metrics {
    let mut metrics = Metrics::default();

    for record in records {
        metrics.calls_attempted += 1;
        match record.call {
            Call::Data(bytes) => {
                metrics.bytes_sent += bytes;
                match record.reply {
                    Some(Reply::Data(bytes)) => {
                        metrics.calls_replied += 1;
                        metrics.bytes_received += bytes;
                    }
                    Some(Reply::Rejected(_)) => {
                        metrics.calls_rejected_asynchronously += 1;
                    }
                    None => {
                        metrics.hanging_calls += 1;
                    }
                }
            }
            Call::Rejected(_) => {
                metrics.calls_rejected_synchronously += 1;
                assert!(record.reply.is_none());
            }
        }
    }
    metrics
}
