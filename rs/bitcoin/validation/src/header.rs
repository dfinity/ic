use bitcoin::{util::uint::Uint256, BlockHash, BlockHeader, Network};

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

    if header.validate_pow(&header_target).is_err() {
        return Err(ValidateHeaderError::InvalidPoWForHeaderTarget);
    }

    let target = get_next_target(network, store, &prev_header, prev_height, header.time);
    if let Err(err) = header.validate_pow(&target) {
        match err {
            bitcoin::Error::BlockBadProofOfWork => println!("bad proof of work"),
            bitcoin::Error::BlockBadTarget => println!("bad target"),
            _ => {}
        };
        return Err(ValidateHeaderError::InvalidPoWForComputedTarget);
    }

    Ok(())
}

// Returns the next required target at the given timestamp.
// The target is the number that a block hash must be below for it to be accepted.
fn get_next_target(
    network: &Network,
    store: &impl HeaderStore,
    prev_header: &BlockHeader,
    prev_height: BlockHeight,
    timestamp: u32,
) -> Uint256 {
    match network {
        Network::Testnet | Network::Regtest => {
            if (prev_height + 1) % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
                // This if statements is reached only for Regtest and Testnet networks
                // Here is the quote from "https://en.bitcoin.it/wiki/Testnet"
                // "If no block has been found in 20 minutes, the difficulty automatically
                // resets back to the minimum for a single block, after which it
                // returns to its previous value."
                if timestamp > prev_header.time + TEN_MINUTES * 2 {
                    //If no block has been found in 20 minutes, then use the maximum difficulty
                    // target
                    max_target(network)
                } else {
                    //If the block has been found within 20 minutes, then use the previous
                    // difficulty target that is not equal to the maximum difficulty target
                    BlockHeader::u256_from_compact_target(find_next_difficulty_in_chain(
                        network,
                        store,
                        prev_header,
                        prev_height,
                    ))
                }
            } else {
                BlockHeader::u256_from_compact_target(compute_next_difficulty(
                    network,
                    store,
                    prev_header,
                    prev_height,
                ))
            }
        }
        Network::Bitcoin | Network::Signet => BlockHeader::u256_from_compact_target(
            compute_next_difficulty(network, store, prev_header, prev_height),
        ),
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
) -> u32 {
    // This is the maximum difficulty target for the network
    let pow_limit_bits = pow_limit_bits(network);

    match network {
        Network::Testnet | Network::Regtest => {
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
    }
}

/// This function returns the difficult target to be used for the current
/// header given the previous header
fn compute_next_difficulty(
    network: &Network,
    store: &impl HeaderStore,
    prev_header: &BlockHeader,
    prev_height: BlockHeight,
) -> u32 {
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
    let actual_interval = (prev_header.time as i64) - (last_adjustment_time as i64);

    // The target_adjustment_interval_time is 2 weeks of time expressed in seconds
    let target_adjustment_interval_time: i64 =
        (DIFFICULTY_ADJUSTMENT_INTERVAL * TEN_MINUTES) as i64; //Number of seconds in 2 weeks

    // Adjusting the actual_interval to [0.5 week, 8 week] range in case the
    // actual_interval deviates too much from the expected 2 weeks.
    let adjusted_interval = actual_interval.clamp(
        target_adjustment_interval_time / 4,
        target_adjustment_interval_time * 4,
    ) as u32;

    // Computing new difficulty target.
    // new difficulty target = old difficult target * (adjusted_interval /
    // 2_weeks);
    let mut target = prev_header.target();
    target = target.mul_u32(adjusted_interval);
    target = target / Uint256::from_u64(target_adjustment_interval_time as u64).unwrap();

    // Adjusting the newly computed difficulty target so that it doesn't exceed the
    // max_difficulty_target limit
    target = Uint256::min(target, max_target(network));

    // Converting the target (Uint256) into a 32 bit representation used by Bitcoin
    BlockHeader::compact_target_from_u256(&target)
}

#[cfg(test)]
mod test {

    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use bitcoin::{consensus::deserialize, hashes::hex::FromHex, TxMerkleNode};
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
                version: i32::from_str_radix(record.get(0).unwrap(), 16).unwrap(),
                prev_blockhash: BlockHash::from_str(record.get(1).unwrap()).unwrap(),
                merkle_root: TxMerkleNode::from_str(record.get(2).unwrap()).unwrap(),
                time: u32::from_str_radix(record.get(3).unwrap(), 16).unwrap(),
                bits: u32::from_str_radix(record.get(4).unwrap(), 16).unwrap(),
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

    fn genesis_header(bits: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: Default::default(),
            merkle_root: Default::default(),
            time: 1296688602,
            bits,
            nonce: 0,
        }
    }

    fn next_block_header(prev: BlockHeader, bits: u32) -> BlockHeader {
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
        initial_pow: u32,
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
        let expected_pow = 7; // Some non-limit PoW, the actual value is not important.
        for chain_length in 1..10 {
            let (store, last_header) = create_chain(&network, expected_pow, chain_length);
            // Act.
            let compact_target = get_next_target(
                &network,
                &store,
                &last_header,
                chain_length - 1,
                last_header.time + TEN_MINUTES,
            );
            // Assert.
            assert_eq!(
                compact_target,
                BlockHeader::u256_from_compact_target(expected_pow)
            );
        }
    }

    #[test]
    fn test_compute_next_difficulty_for_backdated_blocks() {
        // Arrange: Set up the test network and parameters
        let network = Network::Testnet;
        let chain_length = DIFFICULTY_ADJUSTMENT_INTERVAL - 1; // To trigger the difficulty adjustment.
        let genesis_difficulty = 486604799;

        // Create the genesis header and initialize the header store
        let genesis_header = genesis_header(genesis_difficulty);
        let mut store = SimpleHeaderStore::new(genesis_header, 0);
        let mut last_header = genesis_header;
        for _ in 1..chain_length {
            let new_header = BlockHeader {
                prev_blockhash: last_header.block_hash(),
                time: last_header.time - 1, // Each new block is 1 second earlier
                ..last_header
            };
            store.add(new_header);
            last_header = new_header;
        }

        // Act.
        let difficulty = compute_next_difficulty(&network, &store, &last_header, chain_length);

        // Assert.
        assert_eq!(difficulty, 473956288);
    }
}
