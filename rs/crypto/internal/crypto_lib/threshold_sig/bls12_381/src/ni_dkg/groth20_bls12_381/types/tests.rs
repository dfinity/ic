use super::*;
use crate::test_utils::assert_bte_node_components_are_redacted;

#[test]
fn should_redact_bte_node_debug() {
    let node = BTENode {
        tau: vec![1, 2, 3],
        a: G1Bytes([1; G1Bytes::SIZE]),
        b: G2Bytes([1; G2Bytes::SIZE]),
        d_t: vec![G2Bytes([1; G2Bytes::SIZE])],
        d_h: vec![G2Bytes([1; G2Bytes::SIZE])],
        e: G2Bytes([1; G2Bytes::SIZE]),
    };

    let full_str = format!("{:?}", node);
    assert!(
        full_str.contains("a: REDACTED, b: REDACTED, d_t: REDACTED, d_h: REDACTED, e: REDACTED")
    );

    assert_bte_node_components_are_redacted(&node, &full_str);
}

#[test]
fn should_redact_fs_encryption_secret_key_debug() {
    let node = BTENode {
        tau: vec![1, 2, 3],
        a: G1Bytes([1; G1Bytes::SIZE]),
        b: G2Bytes([1; G2Bytes::SIZE]),
        d_t: vec![G2Bytes([1; G2Bytes::SIZE])],
        d_h: vec![G2Bytes([1; G2Bytes::SIZE])],
        e: G2Bytes([1; G2Bytes::SIZE]),
    };

    let sk = FsEncryptionSecretKey {
        bte_nodes: vec![node; 3],
    };

    let full_str = format!("{:?}", sk);

    for node in sk.bte_nodes {
        assert_bte_node_components_are_redacted(&node, &full_str);
    }
}
