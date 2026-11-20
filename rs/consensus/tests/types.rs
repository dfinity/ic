use ic_protobuf::types::v1 as pb;
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_test_utilities_consensus::{fake::Fake, make_genesis};
use ic_types::{
    consensus::{HashedBlock, HashedRandomBeacon, catchup::*, dkg::DkgSummary, hashed::Hashed},
    crypto::{CryptoHash, CryptoHashOf, Signable, crypto_hash},
};
use prost::Message;
use std::convert::TryFrom;
use tempfile::Builder;

#[test]
fn ensure_equality_of_signed_bytes_of_catch_up_package_wrappers() {
    let cup = make_genesis(DkgSummary::fake());
    let protobuf = pb::CatchUpPackage::from(cup.clone());

    assert_eq!(
        CatchUpContentProtobufBytes::from(&protobuf).as_signed_bytes(),
        cup.content.as_signed_bytes()
    );
    let from_proto = CatchUpPackage::try_from(&protobuf).unwrap();
    assert_eq!(from_proto, cup);

    let filepath = Builder::new().tempfile().unwrap().path().to_path_buf();
    write_protobuf_using_tmp_file(&filepath, &protobuf).unwrap();

    let read_from_file = pb::CatchUpPackage::read_from_file(&filepath)
        .map_err(|e| panic!("Failed to read CUP {e}"))
        .unwrap();

    // Ensure that the value we get after transforming into protobuf, writing to
    // a file, reading from that file back into a protobuf and then into a
    // normal cup is the same as the original value we started with.
    assert_eq!(read_from_file, protobuf);
    assert_eq!(cup, CatchUpPackage::try_from(&read_from_file).unwrap())
}

/// Replicas made genesis CUPs whose block parent, random beacon parent and state hash were empty,
/// and such CUPs are still in use. Decoding one must keep those hashes exactly as they were signed,
/// rather than normalizing them to 32 bytes.
#[test]
fn ensure_empty_hashes_and_signed_bytes_of_catch_up_package_are_preserved() {
    let empty_hash = || CryptoHash::from(Vec::new());
    let genesis = make_genesis(DkgSummary::fake());
    let mut block = genesis.content.block.into_inner();
    block.parent = CryptoHashOf::new(empty_hash());
    let mut random_beacon = genesis.content.random_beacon.into_inner();
    random_beacon.content.parent = CryptoHashOf::new(empty_hash());
    let cup = CatchUpPackage {
        content: CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            CryptoHashOf::new(empty_hash()),
            genesis
                .content
                .oldest_registry_version_in_use_by_replicated_state,
        ),
        signature: genesis.signature,
    };
    let encoded = pb::CatchUpPackage::from(cup.clone()).encode_to_vec();

    let protobuf = pb::CatchUpPackage::decode(encoded.as_slice()).unwrap();
    let decoded = CatchUpPackage::try_from(&protobuf).unwrap();

    let block_parent = &decoded.content.block.get_value().parent;
    let random_beacon_parent = &decoded.content.random_beacon.get_value().content.parent;
    assert!(block_parent.get_ref().as_ref().is_empty());
    assert!(random_beacon_parent.get_ref().as_ref().is_empty());
    assert!(decoded.content.state_hash.get_ref().as_ref().is_empty());
    assert_eq!(decoded, cup);
    assert_eq!(
        CatchUpContentProtobufBytes::from(&protobuf).as_signed_bytes(),
        cup.content.as_signed_bytes()
    );
    assert_eq!(
        decoded.content.as_signed_bytes(),
        cup.content.as_signed_bytes()
    );
}

#[test]
fn check_cup_integrity_from_protobuf() {
    let summary = DkgSummary::fake();
    let mut cup = make_genesis(summary);
    let value = cup.content.block.get_value().clone();
    // Corrupt the hash value.
    cup.content.block = Hashed::recompose(CryptoHashOf::new(CryptoHash::from([1; 32])), value);

    let protobuf = pb::CatchUpPackage::from(cup);
    let result = CatchUpPackage::try_from(&protobuf);
    assert!(result.is_err());
}
