use bitcoin::dogecoin::Header as AuxPowHeader;
use bitcoin::{
    BlockHash, CompactTarget, Network, Target, block::Header as BlockHeader, block::ValidationError,
};
use std::time::Duration;

use crate::{
    BlockHeight,
    constants::{
        BLOCKS_IN_ONE_YEAR, DIFFICULTY_ADJUSTMENT_INTERVAL, TEN_MINUTES, checkpoints,
        latest_checkpoint_height, max_target, no_pow_retargeting, pow_limit_bits,
    },
};

/// An error thrown when trying to validate a header.
#[derive(Debug, Eq, PartialEq)]
pub enum ValidateHeaderError {
    /// Used when the timestamp in the header is lower than
    /// the median of timestamps of past 11 headers.
    HeaderIsOld,
    /// Used when the header doesn't match with a checkpoint.
    DoesNotMatchCheckpoint,
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
    /// The next height is less than the tip height - 52_596 (one year worth of blocks).
    HeightTooLow,
    /// Used when the predecessor of the input header is not found in the
    /// HeaderStore.
    PrevHeaderNotFound,
}

#[derive(Debug, PartialEq)]
pub enum ValidateAuxPowHeaderError {
    /// Used when the PureHeader fails validation
    ValidatePureHeader(ValidateHeaderError),
    /// Used when version field is obsolete
    VersionObsolete,
    /// Used when legacy blocks are not allowed
    LegacyBlockNotAllowed,
    /// Used when AuxPow blocks are not allowed
    AuxPowBlockNotAllowed,
    /// Used when the chain ID in the header is invalid
    InvalidChainId,
    /// Used when the AuxPow bit in the version field is not set properly
    InconsistentAuxPowBitSet,
    /// Used when the AuxPow proof is incorrect
    InvalidAuxPoW,
    /// Used when the PoW in the parent block is invalid
    InvalidParentPoW,
}

impl From<ValidateHeaderError> for ValidateAuxPowHeaderError {
    fn from(err: ValidateHeaderError) -> Self {
        ValidateAuxPowHeaderError::ValidatePureHeader(err)
    }
}

pub trait HeaderStore {
    /// Returns the header with the given block hash.
    fn get_header(&self, hash: &BlockHash) -> Option<(BlockHeader, BlockHeight)>;

    /// Returns the initial hash the store starts from.
    fn get_initial_hash(&self) -> BlockHash;

    fn get_height(&self) -> BlockHeight;
}

pub trait HeaderValidator {
    type Network;

    fn network(&self) -> &Self::Network;

    /// Returns the maximum difficulty target depending on the network
    fn max_target(&self) -> Target;

    /// Returns false iff PoW difficulty level of blocks can be
    /// readjusted in the network after a fixed time interval.
    fn no_pow_retargeting(&self) -> bool;

    /// Returns the PoW limit bits depending on the network
    fn pow_limit_bits(&self) -> CompactTarget;

    /// Returns the target spacing between blocks in seconds.
    fn pow_target_spacing(&self) -> Duration;

    /// Returns the number of blocks between difficulty adjustments at the given height.
    fn difficulty_adjustment_interval(&self, height: u32) -> u32;

    /// Returns `true` if mining a min-difficulty block is allowed after some delay.
    fn allow_min_difficulty_blocks(&self, height: u32) -> bool;

    /// Checkpoints used to validate blocks at certain heights.
    fn checkpoints(&self) -> &[(BlockHeight, &str)];

    /// This validates the header against the network's checkpoints.
    /// 1. If the next header is at a checkpoint height, the checkpoint is compared to the next header's block hash.
    /// 2. If the header is not the same height, the function then compares the height to the latest checkpoint.
    ///    If the next header's height is less than the last checkpoint's height, the header is invalid.
    fn is_checkpoint_valid(
        &self,
        prev_height: BlockHeight,
        header: &BlockHeader,
        chain_height: BlockHeight,
    ) -> bool;

    /// Validates a header. If a failure occurs, a
    /// [ValidateHeaderError](ValidateHeaderError) will be returned.
    fn validate_header(
        &self,
        store: &impl HeaderStore,
        header: &BlockHeader,
    ) -> Result<(), ValidateHeaderError>;

    /// Returns the next required target at the given timestamp.
    /// The target is the number that a block hash must be below for it to be accepted.
    fn get_next_target(
        &self,
        store: &impl HeaderStore,
        prev_header: &BlockHeader,
        prev_height: BlockHeight,
        timestamp: u32,
    ) -> Target;

    /// This method is only valid when used for testnet and regtest networks.
    /// As per "https://en.bitcoin.it/wiki/Testnet",
    /// "If no block has been found in 20 minutes, the difficulty automatically
    /// resets back to the minimum for a single block, after which it
    /// returns to its previous value." This function is used to compute the
    /// difficulty target in case the block has been found within 20
    /// minutes.
    fn find_next_difficulty_in_chain(
        &self,
        store: &impl HeaderStore,
        prev_header: &BlockHeader,
        prev_height: BlockHeight,
    ) -> CompactTarget;

    /// This function returns the difficulty target to be used for the current
    /// header given the previous header in the Bitcoin network
    fn compute_next_difficulty(
        &self,
        store: &impl HeaderStore,
        prev_header: &BlockHeader,
        prev_height: BlockHeight,
    ) -> CompactTarget;

    /// This validates that the header has a height that is within 1 year of the tip height.
    fn is_header_within_one_year_of_tip(
        &self,
        prev_height: BlockHeight,
        chain_height: BlockHeight,
    ) -> bool;
}

pub trait AuxPowHeaderValidator: HeaderValidator {
    /// Returns `true` if the strict-chain-id rule is enabled.
    fn strict_chain_id(&self) -> bool;

    /// Returns the chain id used in this blockchain for AuxPow mining.
    fn auxpow_chain_id(&self) -> i32;

    /// Returns `true` if mining a legacy block is allowed.
    fn allow_legacy_blocks(&self, height: u32) -> bool;

    /// Performs context-dependent validity checks for AuxPow headers.
    fn contextual_check_header_auxpow(
        &self,
        header: &BlockHeader,
        height: BlockHeight,
    ) -> Result<(), ValidateAuxPowHeaderError>;

    /// Validates an AuxPow header. If a failure occurs, a
    /// [ValidateAuxPowHeaderError](ValidateAuxPowHeaderError) will be returned.
    fn validate_auxpow_header(
        &self,
        store: &impl HeaderStore,
        header: &AuxPowHeader,
    ) -> Result<(), ValidateAuxPowHeaderError>;
}

/// Validates a header. If a failure occurs, a
/// [ValidateHeaderError](ValidateHeaderError) will be returned.
pub fn validate_header(
    network: &Network,
    store: &impl HeaderStore,
    header: &BlockHeader,
) -> Result<(), ValidateHeaderError> {
    let chain_height = store.get_height();
    let (prev_header, prev_height) = match store.get_header(&header.prev_blockhash) {
        Some(result) => result,
        None => {
            return Err(ValidateHeaderError::PrevHeaderNotFound);
        }
    };

    if !is_header_within_one_year_of_tip(prev_height, chain_height) {
        return Err(ValidateHeaderError::HeightTooLow);
    }

    if !is_timestamp_valid(store, header) {
        return Err(ValidateHeaderError::HeaderIsOld);
    }

    if !is_checkpoint_valid(network, prev_height, header, chain_height) {
        return Err(ValidateHeaderError::DoesNotMatchCheckpoint);
    }

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

/// This validates the header against the network's checkpoints.
/// 1. If the next header is at a checkpoint height, the checkpoint is compared to the next header's block hash.
/// 2. If the header is not the same height, the function then compares the height to the latest checkpoint.
///    If the next header's height is less than the last checkpoint's height, the header is invalid.
fn is_checkpoint_valid(
    network: &Network,
    prev_height: BlockHeight,
    header: &BlockHeader,
    chain_height: BlockHeight,
) -> bool {
    let checkpoints = checkpoints(network);
    if prev_height == u32::MAX {
        return false;
    }
    let next_height = prev_height + 1;
    if let Some(next_hash) = checkpoints.get(&next_height) {
        return *next_hash == header.block_hash();
    }

    let checkpoint_height = latest_checkpoint_height(network, chain_height);
    next_height > checkpoint_height
}

/// This validates that the header has a height that is within 1 year of the tip height.
fn is_header_within_one_year_of_tip(prev_height: BlockHeight, chain_height: BlockHeight) -> bool {
    // perhaps checked_add would be preferable here, if the next height would cause an overflow,
    // we should know about it instead of being swallowed.
    let header_height = prev_height
        .checked_add(1)
        .expect("next height causes an overflow");

    let height_one_year_ago = chain_height.saturating_sub(BLOCKS_IN_ONE_YEAR);
    header_height >= height_one_year_ago
}

/// Validates if a header's timestamp is valid.
/// Bitcoin Protocol Rules wiki https://en.bitcoin.it/wiki/Protocol_rules says,
/// "Reject if timestamp is the median time of the last 11 blocks or before"
pub(crate) fn is_timestamp_valid(store: &impl HeaderStore, header: &BlockHeader) -> bool {
    let mut times = vec![];
    let mut current_header = *header;
    let initial_hash = store.get_initial_hash();
    for _ in 0..11 {
        if let Some((prev_header, _)) = store.get_header(&current_header.prev_blockhash) {
            times.push(prev_header.time);
            if current_header.prev_blockhash == initial_hash {
                break;
            }
            current_header = prev_header;
        }
    }

    times.sort_unstable();
    let median = times[times.len() / 2];
    header.time > median
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
            if !(prev_height + 1).is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
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
                    || current_height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL)
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
    if !height.is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) || no_pow_retargeting(network) {
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
        TxMerkleNode, block::Version, consensus::deserialize, hashes::Hash, hashes::hex::FromHex,
    };
    use csv::Reader;

    use rstest::rstest;

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

        fn get_height(&self) -> BlockHeight {
            self.height
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
                "Failed to validate header on line {i}: {result:?}"
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

    #[test]
    fn test_compute_next_difficulty_for_temporary_difficulty_drops_testnet4() {
        // Arrange
        let network = Network::Testnet4;
        let chain_length = DIFFICULTY_ADJUSTMENT_INTERVAL - 1; // To trigger the difficulty adjustment.
        let genesis_difficulty = CompactTarget::from_consensus(473956288);

        // Create the genesis header and initialize the header store with 2014 blocks
        let genesis_header = genesis_header(genesis_difficulty);
        let mut store = SimpleHeaderStore::new(genesis_header, 0);
        let mut last_header = genesis_header;
        for _ in 1..(chain_length - 1) {
            let new_header = BlockHeader {
                prev_blockhash: last_header.block_hash(),
                time: last_header.time + 1,
                ..last_header
            };
            store.add(new_header);
            last_header = new_header;
        }
        // Add the last header in the epoch, which has the lowest difficulty, or highest possible target.
        // This can happen if the block is created more than 20 minutes after the previous block.
        let last_header_in_epoch = BlockHeader {
            prev_blockhash: last_header.block_hash(),
            time: last_header.time + 1,
            bits: max_target(&network).to_compact_lossy(),
            ..last_header
        };
        store.add(last_header_in_epoch);

        // Act.
        let difficulty =
            compute_next_difficulty(&network, &store, &last_header_in_epoch, chain_length);

        // Assert.
        // Note: testnet3 would produce 473956288, as it depends on the previous header's difficulty.
        assert_eq!(difficulty, CompactTarget::from_consensus(470810608));
    }

    #[rstest]
    #[case(Network::Testnet)]
    #[case(Network::Testnet4)]
    fn test_compute_next_difficulty_for_backdated_blocks(#[case] network: Network) {
        // Arrange: Set up the test network and parameters
        let chain_length = DIFFICULTY_ADJUSTMENT_INTERVAL - 1; // To trigger the difficulty adjustment.
        let genesis_difficulty = CompactTarget::from_consensus(486604799);

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
        assert_eq!(difficulty, CompactTarget::from_consensus(473956288));
    }
}
