use std::time::{Duration, SystemTime};

use ic_cdk::api::time;

pub mod metrics;
pub mod node_operator_sync;
pub mod recovery_proposal;

pub fn now_nanoseconds() -> u64 {
    if cfg!(target_arch = "wasm32") {
        time()
    } else {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get time since epoch")
            .as_nanos()
            .try_into()
            .expect("Failed to convert time to u64")
    }
}

pub fn now_seconds() -> u64 {
    Duration::from_nanos(now_nanoseconds()).as_secs()
}
