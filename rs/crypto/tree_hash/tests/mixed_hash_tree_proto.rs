use ic_crypto_tree_hash::MixedHashTree as T;
use ic_crypto_tree_hash_test_utils::arbitrary::arbitrary_mixed_hash_tree;
use ic_protobuf::messaging::xnet::v1::{MixedHashTree as PbTree, mixed_hash_tree::TreeEnum};
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};

use proptest::prelude::*;

#[test_strategy::proptest]
fn encoding_roundtrip(#[strategy(arbitrary_mixed_hash_tree())] t: T) {
    prop_assert_eq!(
        t.clone(),
        PbTree::proxy_decode(&PbTree::proxy_encode(t)).unwrap()
    )
}

fn encode(t: &PbTree) -> Vec<u8> {
    use prost::Message;
    let mut buf = Vec::new();
    t.encode(&mut buf)
        .unwrap_or_else(|e| panic!("Failed to encode {t:?} into protobuf: {e}"));
    buf
}

#[test]
fn decode_bad_digest_fails() {
    match PbTree::proxy_decode(
        encode(&PbTree {
            tree_enum: Some(TreeEnum::PrunedDigest(vec![0u8; 10])),
        })
        .as_ref(),
    ) as Result<T, _>
    {
        Err(ProxyDecodeError::InvalidDigestLength {
            expected: 32,
            actual: 10,
        }) => (),
        other => panic!(
            "Expected to get InvalidDigestLength {{ expected: 32, actual: 10 }} error, got {other:?}"
        ),
    }
}
