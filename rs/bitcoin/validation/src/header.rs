use bitcoin::{
    block::Header as BlockHeader, block::ValidationError, BlockHash, CompactTarget, Network, Target,
};

use crate::{
    constants::{
        max_target, no_pow_retargeting, pow_limit_bits, DIFFICULTY_ADJUSTMENT_INTERVAL, TEN_MINUTES,
    },
    BlockHeight,
};

/// An error thrown when trying to validate a header.
#[derive(Debug, PartialEq)]
pub enum ValidateHeaderError {
    /// Used when the timestamp in the header is lower than
    /// the median of timestamps of past 11 headers.
    HeaderIsOld,
    /// Used when the timestamp in the header is more than 2 hours
    /// from the current time.
    HeaderIsTooFarInFuture {
        block_time: u64,
        max_allowed_time: u64,
    },
    /// Used when the PoW in the header is invalid as per the target mentioned
    /// in the header.
    InvalidPoWForHeaderTarget,
    /// Used when the PoW in the header is invalid as per the target
    /// computed based on the previous headers.
    InvalidPoWForComputedTarget,
    /// Used when the target in the header is greater than the max possible
    /// value.
    TargetDifficultyAboveMax,
    /// Used when the predecessor of the input header is not found in the
    /// HeaderStore.
    PrevHeaderNotFound,
}

pub trait HeaderStore {
    /// Returns the header with the given block hash.
    fn get_header(&self, hash: &BlockHash) -> Option<(BlockHeader, BlockHeight)>;

    /// Returns the initial hash the store starts from.
    fn get_initial_hash(&self) -> BlockHash;
}

/// Validates a header. If a failure occurs, a
/// [ValidateHeaderError](ValidateHeaderError) will be returned.
pub fn validate_header(
    network: &Network,
    store: &impl HeaderStore,
    header: &BlockHeader,
) -> Result<(), ValidateHeaderError> {
    let (prev_header, prev_height) = match store.get_header(&header.prev_blockhash) {
        Some(result) => result,
        None => {
            return Err(ValidateHeaderError::PrevHeaderNotFound);
        }
    };

    let header_target = header.target();
    if header_target > max_target(network) {
        return Err(ValidateHeaderError::TargetDifficultyAboveMax);
    }

    if header.validate_pow(header_target).is_err() {
        return Err(ValidateHeaderError::InvalidPoWForHeaderTarget);
    }

    let compact_target =
        get_next_compact_target(network, store, &prev_header, prev_height, header.time);
    if let Err(err) = header.validate_pow(Target::from_compact(compact_target)) {
        match err {
            ValidationError::BadProofOfWork => println!("bad proof of work"),
            ValidationError::BadTarget => println!(
                "bad target {:?}, {:?}",
                Target::from_compact(compact_target),
                header.target()
            ),
            _ => {}
        };
        return Err(ValidateHeaderError::InvalidPoWForComputedTarget);
    }

    Ok(())
}

// Returns the next required target at the given timestamp.
// The target is the number that a block hash must be below for it to be accepted.
fn get_next_compact_target(
    network: &Network,
    store: &impl HeaderStore,
    prev_header: &BlockHeader,
    prev_height: BlockHeight,
    timestamp: u32,
) -> CompactTarget {
    match network {
        Network::Testnet | Network::Regtest | Network::Testnet4 => {
            if (prev_height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
                // This if statements is reached only for Regtest and Testnet networks
                // Here is the quote from "https://en.bitcoin.it/wiki/Testnet"
                // "If no block has been found in 20 minutes, the difficulty automatically
                // resets back to the minimum for a single block, after which it
                // returns to its previous value."
                if timestamp > prev_header.time + TEN_MINUTES * 2 {
                    //If no block has been found in 20 minutes, then use the maximum difficulty
                    // target
                    max_target(network).to_compact_lossy()
                } else {
                    //If the block has been found within 20 minutes, then use the previous
                    // difficulty target that is not equal to the maximum difficulty target
                    find_next_difficulty_in_chain(network, store, prev_header, prev_height)
                }
            } else {
                compute_next_difficulty(network, store, prev_header, prev_height)
            }
        }
        Network::Bitcoin | Network::Signet => {
            compute_next_difficulty(network, store, prev_header, prev_height)
        }
        &other => unreachable!("Unsupported network: {:?}", other),
    }
}

/// This method is only valid when used for testnet and regtest networks.
/// As per "https://en.bitcoin.it/wiki/Testnet",
/// "If no block has been found in 20 minutes, the difficulty automatically
/// resets back to the minimum for a single block, after which it
/// returns to its previous value." This function is used to compute the
/// difficulty target in case the block has been found within 20
/// minutes.
fn find_next_difficulty_in_chain(
    network: &Network,
    store: &impl HeaderStore,
    prev_header: &BlockHeader,
    prev_height: BlockHeight,
) -> CompactTarget {
    // This is the maximum difficulty target for the network
    let pow_limit_bits = pow_limit_bits(network);

    match network {
        Network::Testnet | Network::Regtest | Network::Testnet4 => {
            let mut current_header = *prev_header;
            let mut current_height = prev_height;
            let mut current_hash = current_header.block_hash();
            let initial_header_hash = store.get_initial_hash();

            // Keep traversing the blockchain backwards from the recent block to initial
            // header hash.
            loop {
                // Check if non-limit PoW found or it's time to adjust difficulty.
                if current_header.bits != pow_limit_bits
                    || current_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0
                {
                    return current_header.bits;
                }

                // Stop if we reach the initial header.
                if current_hash == initial_header_hash {
                    break;
                }

                // Traverse to the previous header.
                let prev_blockhash = current_header.prev_blockhash;
                (current_header, _) = store
                    .get_header(&prev_blockhash)
                    .expect("previous header should be in the header store");
                // Update the current height and hash.
                current_height -= 1;
                current_hash = prev_blockhash;
            }
            pow_limit_bits
        }
        Network::Bitcoin | Network::Signet => pow_limit_bits,
        &other => unreachable!("Unsupported network: {:?}", other),
    }
}

/// This function returns the difficult target to be used for the current
/// header given the previous header
fn compute_next_difficulty(
    network: &Network,
    store: &impl HeaderStore,
    prev_header: &BlockHeader,
    prev_height: BlockHeight,
) -> CompactTarget {
    // Difficulty is adjusted only once in every interval of 2 weeks (2016 blocks)
    // If an interval boundary is not reached, then previous difficulty target is
    // returned Regtest network doesn't adjust PoW difficult levels. For
    // regtest, simply return the previous difficulty target

    let height = prev_height + 1;
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 || no_pow_retargeting(network) {
        return prev_header.bits;
    }

    // Computing the last header with height multiple of 2016
    let mut current_header = *prev_header;
    for _i in 0..(DIFFICULTY_ADJUSTMENT_INTERVAL - 1) {
        if let Some((header, _)) = store.get_header(&current_header.prev_blockhash) {
            current_header = header;
        }
    }
    // last_adjustment_header is the last header with height multiple of 2016
    let last_adjustment_header = current_header;
    let last_adjustment_time = last_adjustment_header.time;

    // Computing the time interval between the last adjustment header time and
    // current time. The expected value actual_interval is 2 weeks assuming
    // the expected block time is 10 mins. But most of the time, the
    // actual_interval will deviate slightly from 2 weeks. Our goal is to
    // readjust the difficulty target so that the expected time taken for the next
    // 2016 blocks is again 2 weeks.
    let actual_interval =
        std::cmp::max((prev_header.time as i64) - (last_adjustment_time as i64), 0) as u64; 

    //TODO: ideally from_next_work_required works by itself
    // On Testnet networks, prev_header.bits could be different than last_adjustment_header.bits 
    // if prev_header took more than 20 minutes to be created. 
    // Testnet3 (mistakenly) uses the temporary difficulty drop of prev_header to calculate
    // the difficulty of th next epoch; this results in the whole epoch having a very low difficulty,
    // and therefore likely blockstorms. 
    // Testnet4 uses the last_adjustment_header.bits to calculate the next epoch's difficulty, making it 
    // more stable.
    //TODO(mihailjianu): add a test for testnet4.
    let previous_difficulty = match network {
        Network::Testnet4 => last_adjustment_header.bits,
        _ => prev_header.bits,
    };
    CompactTarget::from_next_work_required(previous_difficulty, actual_interval, *network)
}

#[cfg(test)]
mod test {

    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use bitcoin::{
        block::Version, consensus::deserialize, hashes::hex::FromHex, hashes::Hash, TxMerkleNode,
    };
    use csv::Reader;

    use super::*;
    use crate::constants::test::{
        MAINNET_HEADER_586656, MAINNET_HEADER_705600, MAINNET_HEADER_705601, MAINNET_HEADER_705602,
        TESTNET_HEADER_2132555, TESTNET_HEADER_2132556,
    };

    #[derive(Clone)]
    struct StoredHeader {
        header: BlockHeader,
        height: BlockHeight,
    }

    struct SimpleHeaderStore {
        headers: HashMap<BlockHash, StoredHeader>,
        height: BlockHeight,
        tip_hash: BlockHash,
        initial_hash: BlockHash,
    }

    impl SimpleHeaderStore {
        fn new(initial_header: BlockHeader, height: BlockHeight) -> Self {
            let initial_hash = initial_header.block_hash();
            let tip_hash = initial_header.block_hash();
            let mut headers = HashMap::new();
            headers.insert(
                initial_hash,
                StoredHeader {
                    header: initial_header,
                    height,
                },
            );

            Self {
                headers,
                height,
                tip_hash,
                initial_hash,
            }
        }

        fn add(&mut self, header: BlockHeader) {
            let prev = self
                .headers
                .get(&header.prev_blockhash)
                .expect("prev hash missing");
            let stored_header = StoredHeader {
                header,
                height: prev.height + 1,
            };

            self.height = stored_header.height;
            self.headers.insert(header.block_hash(), stored_header);
            self.tip_hash = header.block_hash();
        }
    }

    impl HeaderStore for SimpleHeaderStore {
        fn get_header(&self, hash: &BlockHash) -> Option<(BlockHeader, BlockHeight)> {
            self.headers
                .get(hash)
                .map(|stored| (stored.header, stored.height))
        }

        fn get_initial_hash(&self) -> BlockHash {
            self.initial_hash
        }
    }

    fn deserialize_header(encoded_bytes: &str) -> BlockHeader {
        let bytes = Vec::from_hex(encoded_bytes).expect("failed to decoded bytes");
        deserialize(bytes.as_slice()).expect("failed to deserialize")
    }

    /// This function reads `num_headers` headers from `tests/data/headers.csv`
    /// and returns them.
    fn get_bitcoin_headers() -> Vec<BlockHeader> {
        let rdr = Reader::from_path(
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("tests/data/headers.csv"),
        );
        assert!(rdr.is_ok(), "Unable to find blockchain_headers.csv file");
        let mut rdr = rdr.unwrap();
        let mut headers = vec![];
        for result in rdr.records() {
            let record = result.unwrap();
            let header = BlockHeader {
                version: Version::from_consensus(
                    i32::from_str_radix(record.get(0).unwrap(), 16).unwrap(),
                ),
                prev_blockhash: BlockHash::from_str(record.get(1).unwrap()).unwrap(),
                merkle_root: TxMerkleNode::from_str(record.get(2).unwrap()).unwrap(),
                time: u32::from_str_radix(record.get(3).unwrap(), 16).unwrap(),
                bits: CompactTarget::from_consensus(
                    u32::from_str_radix(record.get(4).unwrap(), 16).unwrap(),
                ),
                nonce: u32::from_str_radix(record.get(5).unwrap(), 16).unwrap(),
            };
            headers.push(header);
        }
        headers
    }

    #[test]
    fn test_simple_mainnet() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let header_705601 = deserialize_header(MAINNET_HEADER_705601);
        let store = SimpleHeaderStore::new(header_705600, 705_600);
        let result = validate_header(&Network::Bitcoin, &store, &header_705601);
        assert!(result.is_ok());
    }

    #[test]
    fn test_simple_testnet() {
        let header_2132555 = deserialize_header(TESTNET_HEADER_2132555);
        let header_2132556 = deserialize_header(TESTNET_HEADER_2132556);
        let store = SimpleHeaderStore::new(header_2132555, 2_132_555);
        let result = validate_header(&Network::Testnet, &store, &header_2132556);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_header_valid() {
        let header_586656 = deserialize_header(MAINNET_HEADER_586656);
        let mut store = SimpleHeaderStore::new(header_586656, 586_656);
        let headers = get_bitcoin_headers();
        for (i, header) in headers.iter().enumerate() {
            let result = validate_header(&Network::Bitcoin, &store, header);
            assert!(
                result.is_ok(),
                "Failed to validate header on line {}: {:?}",
                i,
                result
            );
            store.add(*header);
        }
    }

    #[test]
    fn test_is_header_valid_missing_prev_header() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let header_705602 = deserialize_header(MAINNET_HEADER_705602);
        let store = SimpleHeaderStore::new(header_705600, 705_600);
        let result = validate_header(&Network::Bitcoin, &store, &header_705602);
        assert!(matches!(
            result,
            Err(ValidateHeaderError::PrevHeaderNotFound)
        ));
    }

    #[test]
    fn test_is_header_valid_invalid_header_target() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let mut header = deserialize_header(MAINNET_HEADER_705601);
        header.bits = pow_limit_bits(&Network::Bitcoin);
        let store = SimpleHeaderStore::new(header_705600, 705_600);
        let result = validate_header(&Network::Bitcoin, &store, &header);
        assert!(matches!(
            result,
            Err(ValidateHeaderError::InvalidPoWForHeaderTarget)
        ));
    }

    #[test]
    fn test_is_header_valid_invalid_computed_target() {
        let pow_bitcoin = pow_limit_bits(&Network::Bitcoin);
        let pow_regtest = pow_limit_bits(&Network::Regtest);
        let h0 = genesis_header(pow_bitcoin);
        let h1 = next_block_header(h0, pow_regtest);
        let h2 = next_block_header(h1, pow_regtest);
        let h3 = next_block_header(h2, pow_regtest);
        let mut store = SimpleHeaderStore::new(h0, 0);
        store.add(h1);
        store.add(h2);
        let result = validate_header(&Network::Regtest, &store, &h3);
        assert!(matches!(
            result,
            Err(ValidateHeaderError::InvalidPoWForComputedTarget)
        ));
    }

    #[test]
    fn test_is_header_valid_target_difficulty_above_max() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let mut header = deserialize_header(MAINNET_HEADER_705601);
        header.bits = pow_limit_bits(&Network::Regtest);
        let store = SimpleHeaderStore::new(header_705600, 705_600);
        let result = validate_header(&Network::Bitcoin, &store, &header);
        assert!(matches!(
            result,
            Err(ValidateHeaderError::TargetDifficultyAboveMax)
        ));
    }

    fn genesis_header(bits: CompactTarget) -> BlockHeader {
        BlockHeader {
            version: Version::ONE,
            prev_blockhash: Hash::all_zeros(),
            merkle_root: Hash::all_zeros(),
            time: 1296688602,
            bits,
            nonce: 0,
        }
    }

    fn next_block_header(prev: BlockHeader, bits: CompactTarget) -> BlockHeader {
        BlockHeader {
            prev_blockhash: prev.block_hash(),
            time: prev.time + TEN_MINUTES,
            bits,
            ..prev
        }
    }

    /// Creates a chain of headers with the given length and
    /// proof of work for the first header.
    fn create_chain(
        network: &Network,
        initial_pow: CompactTarget,
        chain_length: u32,
    ) -> (SimpleHeaderStore, BlockHeader) {
        let pow_limit = pow_limit_bits(network);
        let h0 = genesis_header(initial_pow);
        let mut store = SimpleHeaderStore::new(h0, 0);
        let mut last_header = h0;

        for _ in 1..chain_length {
            let new_header = next_block_header(last_header, pow_limit);
            store.add(new_header);
            last_header = new_header;
        }

        (store, last_header)
    }

    #[test]
    fn test_next_target_regtest() {
        // This test checks the chain of headers of different lengths
        // with non-limit PoW in the first block header and PoW limit
        // in all the other headers.
        // Expect difficulty to be equal to the non-limit PoW.

        // Arrange.
        let network = Network::Regtest;
        let expected_pow = CompactTarget::from_consensus(7); // Some non-limit PoW, the actual value is not important.
        for chain_length in 1..10 {
            let (store, last_header) = create_chain(&network, expected_pow, chain_length);
            // Act.
            let compact_target = get_next_compact_target(
                &network,
                &store,
                &last_header,
                chain_length - 1,
                last_header.time + TEN_MINUTES,
            );
            // Assert.
            assert_eq!(compact_target, expected_pow);
        }
    }

    //TODO(mihailjianu): clean comments.
    /// Creates a chain of `chain_length` blocks.
    ///   - All blocks have `bits = initial_difficulty` except possibly
    ///     for the block that we want to test the 20-min rule on.
    ///   - If `trigger_20_min_rule_block` is Some(block_index) then that block
    ///     will have timestamp artificially large to trigger the 20-minute rule,
    ///     so that block's `bits` will be set to `max_target`.
    fn create_chain_for_testnet4(
        network: &Network,
        initial_difficulty: CompactTarget,
        chain_length: usize,
        trigger_20_min_rule_block: Option<usize>, // e.g. block #5
    ) -> (SimpleHeaderStore, BlockHeader, BlockHeight) {
        // you already seem to have a create_chain-like helper, so you’d adapt that
        // approach. Or you can do something like this:

        let mut prev_header = genesis_header(initial_difficulty);
        let mut prev_height = 0;
        let mut store = SimpleHeaderStore::new(prev_header, prev_height); // your in-memory or mock store
        let mut prev_hash = store.get_initial_hash(); // or however you do it

        // The actual value is not important, but must be consistent for the test
        let max_diff = max_target(network).to_compact_lossy();

        for i in 0..chain_length {
            // create the next header
            let mut header = BlockHeader {
                bits: initial_difficulty,
                prev_blockhash: prev_hash,
                // pick a timestamp
                time: {
                    if Some(i) == trigger_20_min_rule_block {
                        // artificially set time so that
                        // (header.time > prev_header.time + 20 minutes)
                        // to ensure the next block's difficulty is forced to max
                        prev_header.time + (TEN_MINUTES * 3) // 30 minutes or so
                    } else {
                        // normal 10 minute increments
                        prev_header.time + TEN_MINUTES
                    }
                },
                ..prev_header
            };

            // if we triggered the 20-minute rule, the difficulty for the *next* block
            // is allowed to go to `max_target`. But in practice, Bitcoin’s logic for
            // “use max target if > 20 min” applies to the block *after* we observe the delay.
            // So you might need to do something like forcibly set that block's bits
            // to max if the rule was triggered on the *previous* block.  
            // In short, the exact approach depends on how your test harness is structured.

            if i > 0 && Some(i - 1) == trigger_20_min_rule_block {
                // we are “the block after the 20-minute-late block”, so we can expect a forced drop to max
                header.bits = max_diff;
            }

            // add to store
            let current_hash = header.block_hash();
            store.add(header);

            // update for next iteration
            prev_header = header;
            prev_height += 1;
            prev_hash = current_hash;
        }

        (store, prev_header, prev_height)
    }

    //TODO(mihailjianu): clean comments
    //TODO(mihailjianu): this fails for both prev_header.bits and last_adjustment_header.bits. it should only work for last_adjustment_header.bits
    #[test]
    fn test_testnet4_ignores_temporary_diff_drop_for_new_epoch() {
        let network = Network::Testnet4;

        // 1) Choose an initial difficulty that is *not* the max target
        //    (simulate that we start from some intermediate difficulty).
        let initial_diff = CompactTarget::from_consensus(0x1c010000); 

        // 2) Build first (2016 - 10) blocks with normal difficulty
        //    i.e. so that we are "almost" at the boundary.  We'll leave
        //    ~10 more blocks to cross the boundary in the test scenario.
        let chain_length = 2016 - 10;
        let (mut store, prev_header, prev_height) = create_chain_for_testnet4(
            &network,
            initial_diff,
            chain_length,
            None, // no 20-min triggers yet
        );

        // 3) Now create 1 block that is found after >20 min so that the next block’s
        //    difficulty is forced to max. This is effectively the “Testnet override block”.
        let (mut store, prev_header, prev_height) = {
            // Rebuild the chain but continuing from the store above. 
            // Or adapt create_chain_for_testnet4 to accept an existing store if you prefer.
            // For illustration, let’s do it in a simplistic way:

            // We just add 1 block that is delayed. Then 1 block that forcibly sets bits = max
            //TODO(mihailjianu): add a helper function to create headers. 
            let delayed_block = BlockHeader {
                bits: initial_diff,
                prev_blockhash: prev_header.block_hash(),
                time: prev_header.time + (TEN_MINUTES * 3), // 30 min => triggers 20-min rule
                ..prev_header
            };
            store.add(delayed_block);

            let forced_drop_block = BlockHeader {
                bits: max_target(&network).to_compact_lossy(),
                prev_blockhash: delayed_block.block_hash(),
                time: delayed_block.time + TEN_MINUTES, // found 10 min later
                ..prev_header
            };
            store.add(forced_drop_block);

            (store, forced_drop_block, prev_height + 2)
        };

        // 4) Now add enough blocks so that we cross the 2016-boundary. 
        //    In total, we want to produce (2016 - (chain_length+2)) more blocks 
        //    so that the final block is exactly at a multiple of 2016, 
        //    triggering a difficulty retarget.
        let blocks_to_retarg = 2016 - (prev_height as usize); // how many we need to cross boundary

        // Keep track of the "expected bits" for these next blocks (which presumably 
        // remain the same as forced_drop_block.bits until we cross the boundary).
        let forced_drop_diff = max_target(&network).to_compact_lossy();

        let mut last_header = prev_header;
        let mut last_height = prev_height;
        for _i in 0..blocks_to_retarg {
            let header = BlockHeader {
                bits: forced_drop_diff,
                prev_blockhash: last_header.block_hash(),
                time: last_header.time + TEN_MINUTES,
                ..last_header
            };
            // add to store
            store.add(header);

            last_header = header;
            last_height += 1;
        }
        // We have now exactly landed on a retarget boundary.

        // 5) The next block is the one that will call compute_next_difficulty()
        //    with `prev_height+1 == 2017`, i.e. 2016 was fully completed. 
        //    That is where your new code should choose “last_adjustment_header.bits”
        //    (the bits from the block at height=2016-1).
        let new_block_time = last_header.time + TEN_MINUTES;
        let next_target = get_next_compact_target(
            &network,
            &store,
            &last_header,
            last_height,
            new_block_time,
        );

        // 6) This is the crucial check: if we were on “Testnet3-like” logic,
        //    it might use the ephemeral forced_drop_diff as the base. 
        //    But with “Testnet4”, we expect it to use the old epoch’s (which is `initial_diff`).
        //    You would likely do a real calculation or at least assert it’s not forced_drop_diff.
        assert_eq!(
            next_target,
            initial_diff,
            "On Testnet4, we expect the new epoch difficulty to be derived from the last retarget block, not the forced-drop block."
        );

        // you might refine the assertion if your real test expects a slightly
        // adjusted bits after factoring in actual_interval, etc.
    }

}
