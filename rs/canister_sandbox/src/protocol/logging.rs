use serde::{Deserialize, Serialize};

/// Describes a request for logging to the replica. We provide a log
/// level and the description.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogRequest(pub LogLevel, pub String);

/// We can inform the replica that we have one of the following debug
/// levels.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LogLevel {
    Info,
    Debug,
    Trace,
}
