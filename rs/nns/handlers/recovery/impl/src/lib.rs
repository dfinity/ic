pub mod metrics;
pub mod node_operator_sync;
pub mod recovery_proposal;

#[cfg(target_arch = "wasm32")]
use ic_cdk::println;

const PREFIX: &str = "[Recovery canister] ";
#[inline]
pub fn print_with_prefix<S: AsRef<str>>(message: S) {
    println!("{}{}", PREFIX, message.as_ref())
}
