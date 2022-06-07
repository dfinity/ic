mod address_utxoset;
mod blocktree;
mod canister;
mod heartbeat;
mod metrics;
mod page_map_memory;
use page_map_memory::PageMapMemory;
pub mod fees;
pub mod state;
pub mod store;
mod types;
mod unstable_blocks;
mod utxos;
mod utxoset;

// TODO(EXC-1093): Guard this with a rust feature. It's only needed in local scripts.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/btc_canister.rs"));
}

// Expose the canister's interface directly.
pub use canister::*;
pub use metrics::BitcoinCanisterMetrics;
