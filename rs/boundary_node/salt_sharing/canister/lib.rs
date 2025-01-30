#[cfg(any(target_family = "wasm", test))]
mod canister;
#[allow(dead_code)]
mod storage;
#[allow(dead_code)]
mod time;

#[allow(dead_code)]
fn main() {}
