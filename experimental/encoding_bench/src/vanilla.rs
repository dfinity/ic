use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// An Ingress message as we might use it internally.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Ingress {
    pub source: u64,
    pub receiver: u64,
    pub method_name: String,
    pub method_payload: Vec<u8>,
    pub message_id: u64,

    // This is an example of how we might want to have a field where
    // the 'internal' type is richer than the type on the wire, and
    // we need to marshall back and forth between the types.
    pub message_time: SystemTime,
}

// I assume that ordinarily we'd implement From traits for both of these
// to construct one from the other.

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct IngressWire {
    pub source: u64,
    pub receiver: u64,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Vec<u8>,
    pub message_id: u64,

    // On the wire we represent the time as nanoseconds since
    // the epoch. To keep things readable we include the unit
    // in the name of the field.
    pub message_time_ns: u64, // Note: Rust uses u128 for nanos...
}
