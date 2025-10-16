use std::time::{Duration, SystemTime};

#[cfg(target_arch = "wasm32")]
pub fn now_nanoseconds() -> u64 {
    ic_cdk::api::time()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_nanoseconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get time since epoch")
        .as_nanos()
        .try_into()
        .expect("Failed to convert time to u64")
}

pub fn now_seconds() -> u64 {
    Duration::from_nanos(now_nanoseconds()).as_secs()
}

pub fn now_system_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_nanos(now_nanoseconds())
}
