use candid::CandidType;
use ic_base_types::CanisterId;
use ic_error_types::RejectCode;
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::time::Duration;

/// A full config for generating random calls and replies. Ranges are stored as individual u32
/// because ranges don't implement `CandidType`.
#[derive(Serialize, Deserialize, Clone, Debug, CandidType, Hash)]
pub struct Config {
    /// A list of canister IDs, i.e. receivers for calls made by this canister.
    pub receivers: Vec<CanisterId>,
    /// `(min, max)` for the payload size in bytes included in a call.
    pub call_bytes_range: (u32, u32),
    /// `(min, max)` for the payload size in bytes included in a reply.
    pub reply_bytes_range: (u32, u32),
    /// `(min, max)` for the simulated number of instructions to generate a reply.
    pub instructions_count_range: (u32, u32),
    /// `(min, max)` for the timeout in seconds used for best-effort calls.
    pub timeout_secs_range: (u32, u32),
    /// The maximum number of calls attempted per heartbeat.
    pub calls_per_heartbeat: u32,
    /// The weight for making a reply used in a binominal distribution together with
    /// `downstream_call_weight`.
    pub reply_weight: u32,
    /// The weight for making a downstream call used in a binomial distribution together with
    /// `downstream_call_weight`.
    pub downstream_call_weight: u32,
    /// The weight for making a best-effort call used in a binomial distribution together with
    /// `guaranteed_response_weight`.
    pub best_effort_weight: u32,
    /// The weight for making a guaranteed response call used in a binomial distribution together
    /// with `best_effort_weight`.
    pub guaranteed_response_weight: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            receivers: vec![],
            call_bytes_range: (0, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32),
            reply_bytes_range: (0, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32),
            instructions_count_range: (0, 0),
            timeout_secs_range: (10, 100),
            calls_per_heartbeat: 3,
            reply_weight: 1,
            downstream_call_weight: 0,
            best_effort_weight: 1,
            guaranteed_response_weight: 0,
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
        timeout_secs: RangeInclusive<u32>,
        calls_per_heartbeat: u32,
        reply_weight: u32,
        downstream_call_weight: u32,
        best_effort_weight: u32,
        guaranteed_response_weight: u32,
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
        if timeout_secs.is_empty() {
            return Err("empty timeout range".to_string());
        }
        if reply_weight == 0 && downstream_call_weight == 0 {
            return Err("bad downstream call weights, both 0".to_string());
        }
        if best_effort_weight == 0 && guaranteed_response_weight == 0 {
            return Err("bad call type weights, both 0".to_string());
        }

        Ok(Self {
            receivers,
            call_bytes_range: (*call_bytes.start(), *call_bytes.end()),
            reply_bytes_range: (*reply_bytes.start(), *reply_bytes.end()),
            instructions_count_range: (*instructions_count.start(), *instructions_count.end()),
            timeout_secs_range: (*timeout_secs.start(), *timeout_secs.end()),
            calls_per_heartbeat,
            reply_weight,
            downstream_call_weight,
            best_effort_weight,
            guaranteed_response_weight,
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
    /// The timeout in seconds set for a best-effort call; `None` for a guaranteed response call.
    pub timeout_secs: Option<u32>,
    /// The kind of reply received, i.e. a payload or a reject response; and the duration after
    /// which the reply was received (from when the call was made).
    pub duration_and_reply: Option<(Duration, Reply)>,
}

/// Human readable printer.
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{} ({:x}) ",
            &self.receiver.to_string()[..5],
            self.call_tree_id
        )?;

        // A timeout indicates a best-effort message.
        if let Some(timeout_secs) = self.timeout_secs {
            write!(f, "timeout[s]: {} ", timeout_secs)?;
        }

        // A caller indicates a downstream call.
        if let Some(caller) = self.caller {
            write!(
                f,
                "(caller {} @ depth {}) ",
                &caller.to_string()[..5],
                self.call_depth
            )?;
        }

        write!(f, " sending {} bytes | ", self.sent_bytes)?;

        match &self.duration_and_reply {
            None => write!(f, "..."),
            Some((call_duration, Reply::Bytes(bytes))) => {
                write!(
                    f,
                    "duration[s]: {}, received {} bytes",
                    call_duration.as_secs(),
                    bytes
                )
            }
            Some((call_duration, Reply::Reject(error_code, error_msg))) => write!(
                f,
                "duration[s]: {}, reject({}): {error_msg}",
                call_duration.as_secs(),
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

        match &record.duration_and_reply {
            Some((_, Reply::Bytes(received_bytes))) => {
                metrics.calls_replied += 1;
                metrics.received_bytes += received_bytes;
            }
            Some((_, Reply::Reject(..))) => {
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
