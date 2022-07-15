use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};

use clap::Parser;
use ic_ledger_canister_blocks_synchronizer::{
    canister_access::CanisterAccess,
    ledger_blocks_sync::{LedgerBlocksSynchronizer, LedgerBlocksSynchronizerMetrics},
};
use ic_ledger_core::block::BlockHeight;
use ic_types::CanisterId;
use url::Url;

#[derive(Parser, Debug)]
#[clap(version, author, about)]
struct Args {
    /// The IC url, e.g. https://ic0.app for mainnet or https://rosetta-exchanges.ic0.app for testnet
    #[clap(long)]
    pub ic_url: Url,

    /// The canister id of the ledger, e.g. ryjl3-tyaaa-aaaaa-aaaba-cai on mainnet and testnet
    #[clap(short = 'c', long)]
    pub ledger_canister_id: CanisterId,

    #[clap(long)]
    pub store_location: PathBuf, // Path is unsized so we need to use PathBuf

    /// Sync the chain up to this block. This block will be available in the local copy, the next one won't.
    #[clap(short = 'b', long)]
    pub up_to_block: Option<BlockHeight>,
}

struct PrintMetrics {}

impl LedgerBlocksSynchronizerMetrics for PrintMetrics {
    fn set_target_height(&self, _height: u64) {}
    fn set_synced_height(&self, height: u64) {
        println!("Synced blocks up to height {}", height);
    }
    fn set_verified_height(&self, height: u64) {
        println!("Verified blocks up to height {}", height);
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let canister_access = CanisterAccess::new(args.ic_url.clone(), args.ledger_canister_id);
    println!("Initializing the synchronizer");
    let synchronizer = LedgerBlocksSynchronizer::new(
        Some(Arc::new(canister_access)),
        Some(args.store_location.as_ref()),
        /* store_max_blocks = */ None,
        /* verification_info = */ None,
        Box::new(PrintMetrics {}),
    )
    .await
    .expect("Failed to initialize synchronizer");
    println!(
        "Synchronizer initialized, starting the synchronization against the ledger {} {}",
        args.ic_url, args.ledger_canister_id
    );
    synchronizer
        .sync_blocks(Arc::new(AtomicBool::new(false)), args.up_to_block)
        .await
        .expect("Failed to sync blocks");
    println!("Synchronization done");
}
