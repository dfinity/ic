#[allow(dead_code)]
mod access_control;
#[allow(dead_code)]
mod add_config;
#[cfg(any(target_family = "wasm", test))]
mod canister;
#[allow(dead_code)]
mod confidentiality_formatting;
#[allow(dead_code)]
mod disclose;
#[allow(dead_code)]
mod getter;
#[allow(dead_code)]
mod logs;
#[allow(dead_code)]
mod metrics;
mod random;
#[allow(dead_code)]
mod state;
mod storage;
mod types;

#[allow(dead_code)]
fn main() {}
