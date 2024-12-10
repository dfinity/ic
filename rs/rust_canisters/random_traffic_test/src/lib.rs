use candid::CandidType;
use ic_base_types::CanisterId;
use ic_error_types::RejectCode;
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

/// A full config for generating random calls and replies. Ranges are stored as individual u32
/// because ranges don't implement `CandidType`.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType, Hash)]
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
    /// Convenience constructor that sanity checks input. After passing the checks, the canister
    /// should run as intended.
    ///
    /// Note:
    /// - `reply_bytes` are used to determine the size of the payload in a reply. This must
    ///   be checked against the maximum payload size because a payload exceeding this limit
    ///   will trap the canister.
    /// - 'call_bytes' are used to determine the size of the payload in a call. This is not
    ///   checked because sending a payload exceeding the limit will trigger a rejection rather
    ///   than trapping the canister. This is a possible use-case for tests.
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
    /// The call was rejected with a reject code and a reject message.
    Reject(u32, String),
}

/// Record for an outgoing call.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, CandidType)]
pub struct Record {
    /// The `receiver` of the call.
    pub receiver: CanisterId,
    /// The caller if any, i.e. if this is a downstream call to a call made by `caller`.
    pub caller: Option<CanisterId>,
    /// A unique ID for the whole call tree; this is passed on to downstream calls.
    pub call_tree_id: u32,
    /// The call depth; starting with 0 for the first (non-downstream) call.
    pub call_depth: u32,
    /// The number of bytes included in the payload.
    pub sent_bytes: u32,
    /// The kind of reply received, i.e. a payload or a reject response.
    pub reply: Option<Reply>,
}

/// Human readable printer.
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self.caller {
            None => write!(
                f,
                "{} ({:x}) | ",
                &self.receiver.to_string()[..5],
                self.call_tree_id,
            ),
            Some(caller) => write!(
                f,
                "{} ({:x}) (caller {} @ depth {}) | ",
                &self.receiver.to_string()[..5],
                self.call_tree_id,
                &caller.to_string()[..5],
                self.call_depth,
            ),
        }?;

        write!(f, "sending {} bytes | ", self.sent_bytes)?;

        match &self.reply {
            None => write!(f, "..."),
            Some(Reply::Bytes(bytes)) => write!(f, "received {} bytes", bytes),
            Some(Reply::Reject(error_code, error_msg)) => write!(
                f,
                "reject({}): {error_msg}",
                RejectCode::try_from(*error_code as u64).unwrap(),
            ),
        }
    }
}

/// Basic metrics extracted from the records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Metrics {
    pub pending_calls: u32,
    pub calls_attempted: u32,
    pub downstream_calls_attempted: u32,
    pub calls_replied: u32,
    pub calls_rejected: u32,
    pub sent_bytes: u32,
    pub received_bytes: u32,
    pub rejected_bytes: u32,
}

/// Extracts some basic metrics from the records.
pub fn extract_metrics(records: &BTreeMap<u32, Record>) -> Metrics {
    let mut metrics = Metrics::default();

    for record in records.values() {
        metrics.calls_attempted += 1;
        metrics.sent_bytes += record.sent_bytes;
        if record.caller.is_some() {
            metrics.downstream_calls_attempted += 1;
        }

        match &record.reply {
            Some(Reply::Bytes(received_bytes)) => {
                metrics.calls_replied += 1;
                metrics.received_bytes += received_bytes;
            }
            Some(Reply::Reject(_, _)) => {
                metrics.calls_rejected += 1;
                metrics.rejected_bytes += record.sent_bytes;
            }
            None => {
                metrics.pending_calls += 1;
            }
        }
    }
    metrics
}

// Enable Candid export.
ic_cdk::export_candid!();
