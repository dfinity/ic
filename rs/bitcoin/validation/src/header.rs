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

const ONE_HOUR: u64 = 3_600;

pub trait HeaderStore {
    /// Returns the header with the given block hash.
    fn get_with_block_hash(&self, hash: &BlockHash) -> Option<BlockHeader>;

    /// Returns the header at the given height.
    fn get_with_height(&self, height: u32) -> Option<BlockHeader>;

    /// Returns the height of the tip that the new header will extend.
    fn height(&self) -> u32;

    /// Returns the initial hash the store starts from.
    fn get_initial_hash(&self) -> BlockHash {
        self.get_with_height(0)
            .expect("genesis block header not found")
            .block_hash()
    }
}

/// Validates a header. If a failure occurs, a
/// [ValidateHeaderError](ValidateHeaderError) will be returned.
pub fn validate_header(
    network: &Network,
    store: &impl HeaderStore,
    header: &BlockHeader,
    current_time: u64,
) -> Result<(), ValidateHeaderError> {
    let prev_height = store.height();
    let prev_header = match store.get_with_block_hash(&header.prev_blockhash) {
        Some(result) => result,
        None => {
            return Err(ValidateHeaderError::PrevHeaderNotFound);
        }
    };

    is_timestamp_valid(store, header, current_time)?;

    let header_target = header.target();
    if header_target > max_target(network) {
        return Err(ValidateHeaderError::TargetDifficultyAboveMax);
    }

    if header.validate_pow(header_target).is_err() {
        return Err(ValidateHeaderError::InvalidPoWForHeaderTarget);
    }

    let target = get_next_target(network, store, &prev_header, prev_height, header.time);
    if let Err(err) = header.validate_pow(Target::from_compact(target)) {
        match err {
            ValidationError::BadProofOfWork => println!("bad proof of work"),
            ValidationError::BadTarget => println!("bad target"),
            _ => {}
        };
        return Err(ValidateHeaderError::InvalidPoWForComputedTarget);
    }

    Ok(())
}

fn timestamp_is_less_than_2h_in_future(
    block_time: u64,
    current_time: u64,
) -> Result<(), ValidateHeaderError> {
    let max_allowed_time = current_time + 2 * ONE_HOUR;

    if block_time > max_allowed_time {
        return Err(ValidateHeaderError::HeaderIsTooFarInFuture {
            block_time,
            max_allowed_time,
        });
    }

    Ok(())
}

/// Validates if a header's timestamp is valid.
/// Bitcoin Protocol Rules wiki https://en.bitcoin.it/wiki/Protocol_rules says,
/// "Reject if timestamp is the median time of the last 11 blocks or before"
/// "Block timestamp must not be more than two hours in the future"
fn is_timestamp_valid(
    store: &impl HeaderStore,
    header: &BlockHeader,
    current_time: u64,
) -> Result<(), ValidateHeaderError> {
    timestamp_is_less_than_2h_in_future(header.time as u64, current_time)?;
    let mut times = vec![];
    let mut current_header = *header;
    let initial_hash = store.get_initial_hash();
    for _ in 0..11 {
        if let Some(prev_header) = store.get_with_block_hash(&current_header.prev_blockhash) {
            times.push(prev_header.time);
            if current_header.prev_blockhash == initial_hash {
                break;
            }
            current_header = prev_header;
        }
    }

    times.sort_unstable();
    let median = times[times.len() / 2];
    if header.time <= median {
        return Err(ValidateHeaderError::HeaderIsOld);
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
) -> CompactTarget {
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
        _ => unreachable!(),
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
                current_header = store
                    .get_with_block_hash(&prev_blockhash)
                    .expect("previous header should be in the header store");
                // Update the current height and hash.
                current_height -= 1;
                current_hash = prev_blockhash;
            }
            pow_limit_bits
        }
        Network::Bitcoin | Network::Signet => pow_limit_bits,
        _ => unreachable!(),
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
    use primitive_types::U256;
    // Difficulty is adjusted only once in every interval of 2 weeks (2016 blocks)
    // If an interval boundary is not reached, then previous difficulty target is
    // returned Regtest network doesn't adjust PoW difficult levels. For
    // regtest, simply return the previous difficulty target

    let height = prev_height + 1;
    if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 || no_pow_retargeting(network) {
        return prev_header.bits;
    }

    // Computing the `last_adjustment_header`.
    // `last_adjustment_header` is the last header with height multiple of 2016
    let last_adjustment_height = if height < DIFFICULTY_ADJUSTMENT_INTERVAL {
        0
    } else {
        height - DIFFICULTY_ADJUSTMENT_INTERVAL
    };
    let last_adjustment_header = store
        .get_with_height(last_adjustment_height)
        .expect("Last adjustment header must exist");
    let last_adjustment_time = last_adjustment_header.time;

    // Computing the time interval between the last adjustment header time and
    // current time. The expected value actual_interval is 2 weeks assuming
    // the expected block time is 10 mins. But most of the time, the
    // actual_interval will deviate slightly from 2 weeks. Our goal is to
    // readjust the difficulty target so that the expected time taken for the next
    // 2016 blocks is again 2 weeks.
    let actual_interval = prev_header.time - last_adjustment_time;
    let mut adjusted_interval = actual_interval;

    // The target_adjustment_interval_time is 2 weeks of time expressed in seconds
    let target_adjustment_interval_time: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL * TEN_MINUTES; //Number of seconds in 2 weeks

    // Adjusting the actual_interval to [0.5 week, 8 week] range in case the
    // actual_interval deviates too much from the expected 2 weeks.
    adjusted_interval = u32::max(adjusted_interval, target_adjustment_interval_time / 4);
    adjusted_interval = u32::min(adjusted_interval, target_adjustment_interval_time * 4);

    // Computing new difficulty target.
    // new difficulty target = old difficult target * (adjusted_interval /
    // 2_weeks);
    let mut target = U256::from_big_endian(&prev_header.target().to_be_bytes());
    target *= U256::from(adjusted_interval);
    target /= U256::from(target_adjustment_interval_time);
    let target = Target::from_be_bytes(target.into());

    // Adjusting the newly computed difficulty target so that it doesn't exceed the
    // max_difficulty_target limit
    target.min(max_target(network)).to_compact_lossy()
}

#[cfg(test)]
mod test {

    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use bitcoin::{
        block::Version, consensus::deserialize, hashes::hex::FromHex, hashes::Hash, TxMerkleNode,
    };
    use csv::Reader;
    use proptest::prelude::*;

    use super::*;
    use crate::constants::test::{
        MAINNET_HEADER_586656, MAINNET_HEADER_705600, MAINNET_HEADER_705601, MAINNET_HEADER_705602,
        TESTNET_HEADER_2132555, TESTNET_HEADER_2132556,
    };

    const MOCK_CURRENT_TIME: u64 = 2_634_590_600;

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
        fn get_with_block_hash(&self, hash: &BlockHash) -> Option<BlockHeader> {
            self.headers.get(hash).map(|stored| stored.header)
        }

        fn get_with_height(&self, height: u32) -> Option<BlockHeader> {
            let blocks_to_traverse = self.height - height;
            let mut header = self.headers.get(&self.tip_hash).unwrap().header;
            for _ in 0..blocks_to_traverse {
                header = self.headers.get(&header.prev_blockhash).unwrap().header;
            }
            Some(header)
        }

        fn height(&self) -> u32 {
            self.height
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
        let result = validate_header(&Network::Bitcoin, &store, &header_705601, MOCK_CURRENT_TIME);
        assert!(result.is_ok());
    }

    #[test]
    fn test_simple_testnet() {
        let header_2132555 = deserialize_header(TESTNET_HEADER_2132555);
        let header_2132556 = deserialize_header(TESTNET_HEADER_2132556);
        let store = SimpleHeaderStore::new(header_2132555, 2_132_555);
        let result = validate_header(
            &Network::Testnet,
            &store,
            &header_2132556,
            MOCK_CURRENT_TIME,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_header_valid() {
        let header_586656 = deserialize_header(MAINNET_HEADER_586656);
        let mut store = SimpleHeaderStore::new(header_586656, 586_656);
        let headers = get_bitcoin_headers();
        for (i, header) in headers.iter().enumerate() {
            let result = validate_header(&Network::Bitcoin, &store, header, MOCK_CURRENT_TIME);
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
    fn test_timestamp_is_less_than_2h_in_future() {
        // Time is represented as the number of seconds after 01.01.1970 00:00.
        // Hence, if block time is 10 seconds after that time,
        // 'timestamp_is_less_than_2h_in_future' should return true.

        assert!(timestamp_is_less_than_2h_in_future(10, MOCK_CURRENT_TIME).is_ok());

        assert!(timestamp_is_less_than_2h_in_future(
            MOCK_CURRENT_TIME - ONE_HOUR,
            MOCK_CURRENT_TIME
        )
        .is_ok());

        assert!(timestamp_is_less_than_2h_in_future(MOCK_CURRENT_TIME, MOCK_CURRENT_TIME).is_ok());

        assert!(timestamp_is_less_than_2h_in_future(
            MOCK_CURRENT_TIME + ONE_HOUR,
            MOCK_CURRENT_TIME
        )
        .is_ok());

        assert!(timestamp_is_less_than_2h_in_future(
            MOCK_CURRENT_TIME + 2 * ONE_HOUR - 5,
            MOCK_CURRENT_TIME
        )
        .is_ok());

        // 'timestamp_is_less_than_2h_in_future' should return false
        // because the time is more than 2 hours from the current time.
        assert_eq!(
            timestamp_is_less_than_2h_in_future(
                MOCK_CURRENT_TIME + 2 * ONE_HOUR + 10,
                MOCK_CURRENT_TIME
            ),
            Err(ValidateHeaderError::HeaderIsTooFarInFuture {
                block_time: MOCK_CURRENT_TIME + 2 * ONE_HOUR + 10,
                max_allowed_time: MOCK_CURRENT_TIME + 2 * ONE_HOUR
            })
        );
    }

    #[test]
    fn test_is_timestamp_valid() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let header_705601 = deserialize_header(MAINNET_HEADER_705601);
        let header_705602 = deserialize_header(MAINNET_HEADER_705602);
        let mut store = SimpleHeaderStore::new(header_705600, 705_600);
        store.add(header_705601);
        store.add(header_705602);

        let mut header = BlockHeader {
            version: Version::from_consensus(0x20800004),
            prev_blockhash: BlockHash::from_str(
                "00000000000000000001eea12c0de75000c2546da22f7bf42d805c1d2769b6ef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "c120ff2ae1363593a0b92e0d281ec341a0cc989b4ee836dc3405c9f4215242a6",
            )
            .unwrap(),
            time: 1634590600,
            bits: CompactTarget::from_consensus(0x170e0408),
            nonce: 0xb48e8b0a,
        };
        assert!(is_timestamp_valid(&store, &header, MOCK_CURRENT_TIME).is_ok());

        // Monday, October 18, 2021 20:26:40
        header.time = 1634588800;
        assert!(matches!(
            is_timestamp_valid(&store, &header, MOCK_CURRENT_TIME),
            Err(ValidateHeaderError::HeaderIsOld)
        ));

        let result = validate_header(&Network::Bitcoin, &store, &header, MOCK_CURRENT_TIME);
        assert!(matches!(result, Err(ValidateHeaderError::HeaderIsOld)));

        header.time = (MOCK_CURRENT_TIME - ONE_HOUR) as u32;

        assert!(is_timestamp_valid(&store, &header, MOCK_CURRENT_TIME).is_ok());

        header.time = (MOCK_CURRENT_TIME + 2 * ONE_HOUR + 10) as u32;
        assert_eq!(
            is_timestamp_valid(&store, &header, MOCK_CURRENT_TIME),
            Err(ValidateHeaderError::HeaderIsTooFarInFuture {
                block_time: header.time as u64,
                max_allowed_time: MOCK_CURRENT_TIME + 2 * ONE_HOUR
            })
        );

        let result = validate_header(&Network::Bitcoin, &store, &header, MOCK_CURRENT_TIME);
        assert_eq!(
            result,
            Err(ValidateHeaderError::HeaderIsTooFarInFuture {
                block_time: header.time as u64,
                max_allowed_time: MOCK_CURRENT_TIME + 2 * ONE_HOUR,
            })
        );
    }

    #[test]
    fn test_is_header_valid_missing_prev_header() {
        let header_705600 = deserialize_header(MAINNET_HEADER_705600);
        let header_705602 = deserialize_header(MAINNET_HEADER_705602);
        let store = SimpleHeaderStore::new(header_705600, 705_600);
        let result = validate_header(&Network::Bitcoin, &store, &header_705602, MOCK_CURRENT_TIME);
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
        let result = validate_header(&Network::Bitcoin, &store, &header, MOCK_CURRENT_TIME);
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
        let result = validate_header(&Network::Regtest, &store, &h3, MOCK_CURRENT_TIME);
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
        let result = validate_header(&Network::Bitcoin, &store, &header, MOCK_CURRENT_TIME);
        assert!(matches!(
            result,
            Err(ValidateHeaderError::TargetDifficultyAboveMax)
        ));
    }

    fn test_next_targets(network: Network, headers_path: &str, up_to_height: usize) {
        use bitcoin::consensus::Decodable;
        use std::io::BufRead;
        let file = std::fs::File::open(
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(headers_path),
        )
        .unwrap();

        let rdr = std::io::BufReader::new(file);

        println!("Loading headers...");
        let mut headers = vec![];
        for line in rdr.lines() {
            let header = line.unwrap();
            let header = hex::decode(header.trim()).unwrap();
            let header = BlockHeader::consensus_decode(&mut header.as_slice()).unwrap();
            headers.push(header);
        }

        println!("Creating header store...");
        let mut store = SimpleHeaderStore::new(headers[0], 0);
        for header in headers[1..].iter() {
            store.add(*header);
        }

        println!("Verifying next targets...");
        proptest!(|(i in 0..up_to_height)| {
            // Compute what the target of the next header should be.
            let expected_next_target =
                get_next_target(&network, &store, &headers[i], i as u32, headers[i + 1].time);

            // Assert that the expected next target matches the next header's target.
            assert_eq!(
                expected_next_target,
                headers[i + 1].bits
            );
        });
    }

    #[test]
    fn mainnet_next_targets() {
        test_next_targets(
            Network::Bitcoin,
            "tests/data/block_headers_mainnet.csv",
            700_000,
        );
    }

    #[test]
    fn testnet_next_targets() {
        test_next_targets(
            Network::Testnet,
            "tests/data/block_headers_testnet.csv",
            2_400_000,
        );
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
            assert_eq!(store.height() + 1, chain_length);
            // Act.
            let target = get_next_target(
                &network,
                &store,
                &last_header,
                chain_length - 1,
                last_header.time + TEN_MINUTES,
            );
            // Assert.
            assert_eq!(target, expected_pow);
        }
    }
}
