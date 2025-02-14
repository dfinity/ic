use std::time::{Duration, SystemTime};

pub fn now_nanoseconds() -> u64 {
    if cfg!(target_arch = "wasm32") {
        ic_cdk::api::time()
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
