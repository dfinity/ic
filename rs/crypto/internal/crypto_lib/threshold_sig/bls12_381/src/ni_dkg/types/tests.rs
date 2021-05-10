use super::super::groth20_bls12_381::types::{BTENode, FsEncryptionSecretKey};
use super::*;
use crate::test_utils::assert_bte_node_components_are_redacted;
use ic_crypto_internal_types::curves::bls12_381::{G1 as G1Bytes, G2 as G2Bytes};

#[test]
fn should_redact_csp_fs_encryption_secretkey_debug() {
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

    let csp_sk = CspFsEncryptionSecretKey::Groth20_Bls12_381(sk);

    let full_str = format!("{:?}", csp_sk);

    match csp_sk {
        CspFsEncryptionSecretKey::Groth20_Bls12_381(sk) => {
            for node in sk.bte_nodes {
                assert_bte_node_components_are_redacted(&node, &full_str);
            }
        }
    }
}
