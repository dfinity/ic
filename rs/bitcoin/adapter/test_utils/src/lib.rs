use std::collections::HashSet;

use bitcoin::{
    Block, BlockHash, Target, Transaction, TxMerkleNode,
    block::{Header as BlockHeader, Version},
    consensus::deserialize,
    hashes::Hash,
};
use hex::FromHex;
use rand::{Rng, SeedableRng, prelude::StdRng};

pub mod bitcoind;
pub mod rpc_client;
pub mod rpc_json;

// Re-export bitcoin
pub use bitcoin;

type BlockHeight = u32;

/// This is a hex dump of the first block on the BTC network: 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
pub const BLOCK_1_ENCODED: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000";

/// This is a hex dump of the first block on the BTC network: 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
pub const BLOCK_2_ENCODED: &str = "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd610101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d010bffffffff0100f2052a010000004341047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77ac00000000";

/// This const is the lowest possible proof of work limit for regtest. Using this as
/// an overflow occurs if bits is set to 0.
///
/// https://github.com/bitcoin/bitcoin/blame/master/src/chainparams.cpp#L402
const TARGET: Target = Target::MAX_ATTAINABLE_REGTEST;

fn decode_block(hex_str: &str) -> Block {
    let encoded_block_1 = Vec::from_hex(hex_str).expect("failed to covert hex to vec");
    deserialize(&encoded_block_1).expect("failed to decoded block 1")
}

pub fn block_1() -> Block {
    decode_block(BLOCK_1_ENCODED)
}

pub fn block_2() -> Block {
    decode_block(BLOCK_2_ENCODED)
}

pub fn headers_to_hashes(headers: &[BlockHeader]) -> Vec<BlockHash> {
    headers.iter().map(|h| h.block_hash()).collect()
}

/// Generates a singular large block.
fn large_block(prev_blockhash: &BlockHash, prev_time: u32, tx: Transaction) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: Version::ONE,
            prev_blockhash: *prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: prev_time + gen_time_delta(),
            bits: TARGET.to_compact_lossy(),
            nonce: 0,
        },
        txdata: vec![],
    };

    for _ in 0..25_000 {
        // 25_000 transactions will generate just a bit over a 2 MiB block
        block.txdata.push(tx.clone());
    }

    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or(TxMerkleNode::all_zeros());
    solve_proof_of_work(&mut block.header);
    block
}

/// Generates a blockchain containing large blocks (blocks over 2MiB) starting at a given hash and time.
pub fn generate_large_block_blockchain(
    initial_blockhash: BlockHash,
    initial_time: u32,
    limit: BlockHeight,
) -> Vec<Block> {
    let block_1 = decode_block(BLOCK_1_ENCODED);
    let tx = block_1.txdata.first().cloned().unwrap();
    let mut blocks = vec![];

    let mut prev_blockhash = initial_blockhash;
    let mut prev_time = initial_time;
    for _ in 0..limit {
        let block = large_block(&prev_blockhash, prev_time, tx.clone());
        prev_blockhash = block.header.block_hash();
        prev_time = block.header.time;
        blocks.push(block);
    }

    blocks
}

/// This helper generates a header chain starting at the given header until the given height.
pub fn generate_headers(
    initial_blockhash: BlockHash,
    initial_time: u32,
    limit: BlockHeight,
    previous_blockhashes: &[BlockHash],
) -> Vec<BlockHeader> {
    let mut headers = vec![];
    if limit == 0 {
        return headers;
    }

    let mut prev_blockhash = initial_blockhash;
    let mut prev_time = initial_time;

    let known_hashes: HashSet<BlockHash> = previous_blockhashes.iter().copied().collect();

    for _ in 0..limit {
        let mut header = generate_header(prev_blockhash, prev_time, 0);
        while known_hashes.contains(&header.block_hash()) {
            header = generate_header(prev_blockhash, prev_time, 0);
        }
        prev_blockhash = header.block_hash();
        prev_time = header.time;
        headers.push(header);
    }

    headers
}

/// This helper generates a single header with a given previous blockhash.
pub fn generate_header(prev_blockhash: BlockHash, prev_time: u32, nonce: u32) -> BlockHeader {
    let mut header = BlockHeader {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::all_zeros(),
        time: prev_time + gen_time_delta(),
        bits: TARGET.to_compact_lossy(),
        nonce,
    };

    solve_proof_of_work(&mut header);
    header
}

/// Generates a number of seconds used for adding to the previous time (1 to 10 minutes).
fn gen_time_delta() -> u32 {
    let mut rng = StdRng::from_entropy();
    rng.gen_range(60..600)
}

/// This method is used to solve a header's proof of work puzzle.
fn solve_proof_of_work(header: &mut BlockHeader) {
    let target = header.target();
    while header.validate_pow(target).is_err() {
        header.nonce += 1;
    }
}
