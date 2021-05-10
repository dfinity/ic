#![allow(clippy::unwrap_used)]
use crate::arbitrary::arbitrary_mixed_hash_tree;
use crate::MixedHashTree as T;
use ic_protobuf::messaging::xnet::v1::{mixed_hash_tree::TreeEnum, MixedHashTree as PbTree};
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};

use proptest::prelude::*;

proptest! {
    #[test]
    fn encoding_roundtrip(t in arbitrary_mixed_hash_tree()) {
        prop_assert_eq!(t.clone(), PbTree::proxy_decode(&PbTree::proxy_encode(t).unwrap()).unwrap())
    }
}

fn encode(t: &PbTree) -> Vec<u8> {
    use prost::Message;
    let mut buf = Vec::new();
    t.encode(&mut buf)
        .unwrap_or_else(|e| panic!("Failed to encode {:?} into protobuf: {}", t, e));
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
            "Expected to get InvalidDigestLength {{ expected: 32, actual: 10 }} error, got {:?}",
            other
        ),
    }
}
