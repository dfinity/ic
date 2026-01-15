mod doge;
mod utils;

use crate::ValidateHeaderError;
use crate::header::AuxPowHeaderValidator;
use crate::header::{HeaderValidator, is_timestamp_valid};
use crate::tests::utils::{deserialize_auxpow_header, get_auxpow_headers, get_headers};
use crate::{BlockHeight, HeaderStore};
use bitcoin::block::{Header, Version};
use bitcoin::{CompactTarget, Target, TxMerkleNode};
use std::str::FromStr;
use utils::{SimpleHeaderStore, deserialize_header, next_block_header};

fn verify_consecutive_headers<T: HeaderValidator>(
    validator: &T,
    header_1: &str,
    height_1: BlockHeight,
    header_2: &str,
) {
    let header_1 = deserialize_header(header_1);
    let header_2 = deserialize_header(header_2);
    let store = SimpleHeaderStore::new(header_1, height_1);
    let result = validator.validate_header(&store, &header_2);
    assert!(result.is_ok());
}

fn verify_consecutive_headers_auxpow<T: AuxPowHeaderValidator>(
    validator: T,
    header_0: &str,
    height_0: BlockHeight,
    header_1: &str,
    header_2: &str,
) {
    let header_0 = deserialize_auxpow_header(header_0);
    let header_1 = deserialize_auxpow_header(header_1);
    let header_2 = deserialize_auxpow_header(header_2);
    let mut store = SimpleHeaderStore::new(*header_0, height_0);
    store.add(*header_1);
    let result = validator.validate_auxpow_header(&store, &header_2);
    assert!(result.is_ok());
}

fn verify_header_sequence<T: HeaderValidator>(
    validator: &T,
    file: &str,
    start_header: Header,
    start_height: BlockHeight,
) {
    let mut store = SimpleHeaderStore::new(start_header, start_height);
    let headers = get_headers(file);
    for (i, header) in headers.iter().enumerate() {
        let result = validator.validate_header(&store, header);
        assert!(
            result.is_ok(),
            "Failed to validate header on line {} for header {}: {:?}",
            i,
            header.block_hash(),
            result
        );
        store.add(*header);
    }
}

fn verify_header_sequence_auxpow<T: AuxPowHeaderValidator>(
    validator: T,
    file: &str,
    header_1: Header,
    height_1: BlockHeight,
    header_2: Header,
) {
    let mut store = SimpleHeaderStore::new(header_1, height_1);
    store.add(header_2);
    let headers = get_auxpow_headers(file);
    for (i, header) in headers.iter().enumerate() {
        let result = validator.validate_auxpow_header(&store, header);
        assert!(
            result.is_ok(),
            "Failed to validate header on line {} for header {}: {:?}",
            i,
            header.block_hash(),
            result
        );
        store.add(header.pure_header);
    }
}

fn verify_with_missing_parent<T: HeaderValidator>(
    validator: &T,
    header_1: &str,
    height_1: BlockHeight,
    header_2: &str,
) {
    let header_1 = deserialize_header(header_1);
    let header_2 = deserialize_header(header_2);
    let store = SimpleHeaderStore::new(header_1, height_1);
    let result = validator.validate_header(&store, &header_2);
    assert!(matches!(
        result,
        Err(ValidateHeaderError::PrevHeaderNotFound)
    ));
}

fn verify_with_invalid_pow<T: HeaderValidator>(
    validator: &T,
    header_1: &str,
    height_1: BlockHeight,
    header_2: &str,
) {
    let header_1 = deserialize_header(header_1);
    let mut header_2 = deserialize_header(header_2);
    header_2.bits = validator.pow_limit_bits(); // Modify header to invalidate PoW
    let store = SimpleHeaderStore::new(header_1, height_1);
    let result = validator.validate_header(&store, &header_2);
    assert!(matches!(
        result,
        Err(ValidateHeaderError::InvalidPoWForHeaderTarget)
            | Err(ValidateHeaderError::InvalidPoWForComputedTarget)
    ));
}

fn verify_with_invalid_pow_with_computed_target<T: HeaderValidator>(
    validator_regtest: &T,
    genesis_header: Header,
) {
    let pow_regtest = validator_regtest.pow_limit_bits();
    let h0 = genesis_header;
    let h1 = next_block_header(validator_regtest, h0, pow_regtest);
    let h2 = next_block_header(validator_regtest, h1, pow_regtest);
    let h3 = next_block_header(validator_regtest, h2, pow_regtest);
    let mut store = SimpleHeaderStore::new(h0, 0);
    store.add(h1);
    store.add(h2);
    // In regtest, this will use the previous difficulty target that is not equal to the
    // maximum difficulty target (`pow_regtest`), meaning that of `genesis_header`.
    // See [`crate::header::find_next_difficulty_in_chain`]
    let result = validator_regtest.validate_header(&store, &h3);
    assert!(matches!(
        result,
        Err(ValidateHeaderError::InvalidPoWForComputedTarget)
    ));
}

fn verify_with_excessive_target<T: HeaderValidator>(
    validator_mainnet: &T,
    validator_regtest: &T,
    header_1: &str,
    height_1: BlockHeight,
    header_2: &str,
) {
    let header_1 = deserialize_header(header_1);
    let mut header_2 = deserialize_header(header_2);
    header_2.bits = validator_regtest.pow_limit_bits(); // Target exceeds what is allowed on mainnet
    let store = SimpleHeaderStore::new(header_1, height_1);
    let result = validator_mainnet.validate_header(&store, &header_2);
    assert!(matches!(
        result,
        Err(ValidateHeaderError::TargetDifficultyAboveMax)
    ));
}

fn verify_difficulty_adjustment<T: HeaderValidator>(
    validator: &T,
    headers_path: &str,
    up_to_height: usize,
) {
    use bitcoin::consensus::Decodable;
    use std::io::BufRead;
    let file = std::fs::File::open(headers_path).unwrap();

    let rdr = std::io::BufReader::new(file);

    println!("Loading headers...");
    let mut headers = vec![];
    for line in rdr.lines() {
        let header = line.unwrap();
        // If this line fails make sure you install git-lfs.
        let decoded = hex::decode(header.trim()).unwrap();
        let header = Header::consensus_decode(&mut &decoded[..]).unwrap();
        headers.push(header);
    }

    println!("Creating header store...");
    let mut store = SimpleHeaderStore::new(headers[0], 0);
    for header in headers[1..].iter() {
        store.add(*header);
    }

    println!("Verifying next targets...");
    for i in 0..up_to_height {
        // Compute what the target of the next header should be.
        let expected_next_target =
            validator.get_next_target(&store, &headers[i], i as u32, headers[i + 1].time);

        // Assert that the expected next target matches the next header's target.
        assert_eq!(
            expected_next_target,
            Target::from_compact(headers[i + 1].bits)
        );
    }
}

// This checks the chain of headers of different lengths
// with non-limit PoW in the first block header and PoW limit
// in all the other headers.
// Expect difficulty to be equal to the non-limit PoW.
fn verify_regtest_difficulty_calculation<T: HeaderValidator>(
    validator: &T,
    genesis_header: Header,
    expected_pow: CompactTarget,
) {
    // Arrange.
    for chain_length in 1..10 {
        let (store, last_header) =
            utils::build_header_chain(validator, genesis_header, chain_length);
        assert_eq!(store.get_height() + 1, chain_length);
        // Act.
        let target = validator.get_next_target(
            &store,
            &last_header,
            chain_length - 1,
            last_header.time + validator.pow_target_spacing().as_secs() as u32,
        );
        // Assert.
        assert_eq!(target, Target::from_compact(expected_pow));
    }
}

fn verify_backdated_block_difficulty<T: HeaderValidator>(
    validator: &T,
    difficulty_adjustment_interval: u32,
    genesis_header: Header,
    expected_target: CompactTarget,
) {
    let chain_length = difficulty_adjustment_interval - 1; // To trigger the difficulty adjustment.

    // Initialize the header store
    let mut store = SimpleHeaderStore::new(genesis_header, 0);
    let mut last_header = genesis_header;
    for _ in 1..chain_length {
        let new_header = Header {
            prev_blockhash: last_header.block_hash(),
            time: last_header.time - 1, // Each new block is 1 second earlier
            ..last_header
        };
        store.add(new_header);
        last_header = new_header;
    }

    // Act.
    let difficulty = validator.compute_next_difficulty(&store, &last_header, chain_length);

    // Assert.
    assert_eq!(difficulty, expected_target);
}

fn verify_timestamp_rules<T: HeaderValidator>(
    validator: &T,
    header_1: &str,
    height_1: u32,
    header_2: &str,
    header_3: &str,
) {
    let header_1 = deserialize_header(header_1);
    let header_2 = deserialize_header(header_2);
    let header_3 = deserialize_header(header_3);
    let mut store = SimpleHeaderStore::new(header_1, height_1);
    store.add(header_2);
    store.add(header_3);

    let mut header = Header {
        version: Version::from_consensus(0x20800004),
        prev_blockhash: header_3.block_hash(),
        merkle_root: TxMerkleNode::from_str(
            "c120ff2ae1363593a0b92e0d281ec341a0cc989b4ee836dc3405c9f4215242a6",
        )
        .unwrap(),
        time: header_2.time + 1, // Larger than median time past
        bits: CompactTarget::from_consensus(0x170e0408),
        nonce: 0xb48e8b0a,
    };
    assert!(is_timestamp_valid(&store, &header));

    // Mon Apr 16 2012 15:06:40
    header.time = 1334588800;
    assert!(!is_timestamp_valid(&store, &header));

    let result = validator.validate_header(&store, &header);
    assert!(matches!(result, Err(ValidateHeaderError::HeaderIsOld)));
}
