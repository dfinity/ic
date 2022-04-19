//! A script for building the Bitcoin UTXO set.
//!
//! Example run:
//!
//! cargo run --release --example build-utxo-set -- \
//!     --state-path ./state-path \
//!     --blocks-path /home/ubuntu/.bitcoin/testnet3/blocks \
//!     --network testnet \
//!     --start-file 0 \
//!     --end-file 10 \
//!     --until-height 25000
use bitcoin::{
    blockdata::constants::genesis_block, consensus::Decodable, Block, BlockHash, Network,
};
use byteorder::{LittleEndian, ReadBytesExt};
use clap::Parser;
use ic_btc_canister::{state::State, store::insert_block};
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Parser, Debug)]
struct Args {
    /// A path to load/store the state.
    #[clap(long, parse(from_os_str), value_hint = clap::ValueHint::DirPath)]
    state_path: PathBuf,

    /// The path to the "blocks" folder created by bitcoind.
    #[clap(long, parse(from_os_str), value_hint = clap::ValueHint::DirPath)]
    blocks_path: PathBuf,

    /// The bitcoin network.
    #[clap(long)]
    network: Network,

    /// The first file to start loading blocks from.
    #[clap(long)]
    start_file: u32,

    /// The last file to load blocks from.
    #[clap(long)]
    end_file: u32,

    /// The number of blocks to insert before checkpointing.
    #[clap(long, default_value_t = 1000)]
    checkpoint_interval: u32,

    /// Insert blocks until this specific height. Defaults to inserting all
    /// blocks possible.
    #[clap(long)]
    until_height: Option<u32>,
}

fn main() {
    let args = Args::parse();

    let mut start = SystemTime::now();

    let mut state = if args.state_path.exists() {
        println!("Loading state from path {:?}", args.state_path.to_str());
        State::load(&args.state_path).expect("Failed to load state")
    } else {
        println!("Initializing state at path {:?}", args.state_path.to_str());
        State::new(0, args.network, genesis_block(args.network))
    };

    let mut blocks: HashMap<BlockHash, Block> = HashMap::new();

    // Load block files.
    for file in args.start_file..=args.end_file {
        println!("Opening file {}", file);
        let mut blk_file = BufReader::new(
            File::open(args.blocks_path.join(format!("blk{:0>5}.dat", file))).unwrap(),
        );

        // Load blocks in the file and insert them into the state.
        loop {
            let magic = match blk_file.read_u32::<LittleEndian>() {
                Err(_) => break,
                Ok(magic) => {
                    if magic == 0 {
                        // Reached EOF
                        break;
                    }
                    magic
                }
            };
            if args.network == Network::Bitcoin {
                assert_eq!(magic, 0xD9B4BEF9);
            } else {
                assert_eq!(magic, 0x0709110b);
            }

            let _block_size = blk_file.read_u32::<LittleEndian>().unwrap();

            let block = Block::consensus_decode(&mut blk_file).unwrap();

            blocks.insert(block.header.prev_blockhash, block);

            while let Some(block) = blocks.remove(&state.unstable_blocks.tree.root.block_hash()) {
                insert_block(&mut state, block).unwrap();

                if state.height % 1000 == 0 {
                    let now = SystemTime::now();
                    let since_last = now.duration_since(start).expect("Time went backwards");
                    start = now;
                    println!(
                        "Reached height {} (took {} seconds)",
                        state.height,
                        since_last.as_secs()
                    );

                    if state.height % args.checkpoint_interval == 0 {
                        checkpoint(&state, &args.state_path);
                    }
                }

                if let Some(until_height) = args.until_height {
                    if state.height >= until_height {
                        // Reached the desired height. Checkpoint and exist.
                        checkpoint(&state, &args.state_path);
                        return;
                    }
                }
            }
        }
    }

    checkpoint(&state, &args.state_path);
}

fn checkpoint(state: &State, path: &Path) {
    print!("Checkpointing... ");
    let start = SystemTime::now();
    state.serialize(path).expect("Serialization failed");
    let now = SystemTime::now();
    let since_last = now.duration_since(start).expect("Time went backwards");
    println!("Done. Took {} seconds", since_last.as_secs());
}
