mod address_utxoset;
pub mod block;
mod blocktree;
mod canister;
mod page_map_memory;
use page_map_memory::PageMapMemory;
pub mod state;
pub mod store;
#[cfg(test)]
mod test_builder;
mod types;
mod unstable_blocks;
mod utxos;
mod utxoset;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/btc_canister.rs"));
}

// Expose the canister's interface directly.
pub use canister::*;
