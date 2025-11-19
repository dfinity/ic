use ic_protobuf::types::v1 as pb;
use ic_sys::fs::write_protobuf_using_tmp_file;
use ic_test_utilities_consensus::{fake::Fake, make_genesis};
use ic_types::{
    consensus::{catchup::*, dkg::DkgSummary, hashed::Hashed},
    crypto::{CryptoHash, CryptoHashOf, Signable},
};
use std::convert::TryFrom;
use tempfile::Builder;

#[test]
fn ensure_equality_of_signed_bytes_of_catch_up_package_wrappers() {
    let cup = make_genesis(DkgSummary::fake());
    let protobuf = pb::CatchUpPackage::from(&cup);

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

#[test]
fn check_cup_integrity_from_protobuf() {
    let summary = DkgSummary::fake();
    let mut cup = make_genesis(summary);
    let value = cup.content.block.get_value().clone();
    // Corrupt the hash value.
    cup.content.block = Hashed::recompose(CryptoHashOf::new(CryptoHash(vec![1; 32])), value);

    let protobuf = pb::CatchUpPackage::from(&cup);
    let result = CatchUpPackage::try_from(&protobuf);
    assert!(result.is_err());
}
