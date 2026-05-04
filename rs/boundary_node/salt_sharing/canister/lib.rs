#[cfg(any(target_family = "wasm", test))]
mod canister;
#[allow(dead_code)]
#[cfg(any(target_family = "wasm", test))]
mod helpers;
#[allow(dead_code)]
mod logs;
#[allow(dead_code)]
mod metrics;
#[allow(dead_code)]
mod storage;
#[allow(dead_code)]
mod time;

#[allow(dead_code)]
fn main() {}
