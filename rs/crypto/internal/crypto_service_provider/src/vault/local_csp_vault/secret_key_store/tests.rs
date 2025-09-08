//! Verifies the implementation of SecretKeyStoreCspVault for LocalCspVault.
use crate::KeyId;
use crate::LocalCspVault;
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::api::TlsHandshakeCspVault;
use ic_types_test_utils::ids::node_test_id;

const NODE_1: u64 = 4241;

#[test]
fn key_should_be_present_only_after_generation() {
    let csp_vault1 = LocalCspVault::builder_for_test().build_into_arc();
    let csp_vault2 = LocalCspVault::builder_for_test().build_into_arc();
    let public_key1 = csp_vault1
        .gen_node_signing_key_pair()
        .expect("Test setup failed: Failed to generate keys");
    let key_id1 = KeyId::from(&public_key1);
    assert!(
        csp_vault1.sks_contains(key_id1).expect("SKS call failed"),
        "Key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(key_id1).expect("SKS call failed"),
        "Key should be absent if not generated in the CSP."
    );

    let public_key2 = csp_vault2
        .gen_node_signing_key_pair()
        .expect("Test setup failed: Failed to generate keys");
    let key_id2 = KeyId::from(&public_key2);
    assert_ne!(
        key_id1, key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(key_id2).expect("SKS call failed"),
        "Key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(key_id1).expect("SKS call failed"),
        "The second CSP should not contain the keys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(key_id2).expect("SKS call failed"),
        "Key first CSP should not contain the keys of the second."
    );
}

#[test]
fn tls_key_should_be_present_only_after_generation() {
    let csp_vault1 = LocalCspVault::builder_for_test().build_into_arc();
    let csp_vault2 = LocalCspVault::builder_for_test().build_into_arc();
    let public_key_cert1 = csp_vault1
        .gen_tls_key_pair(node_test_id(NODE_1))
        .expect("error generating TLS key pair");
    let key_id1 = KeyId::from(&public_key_cert1);
    assert!(
        csp_vault1.sks_contains(key_id1).expect("SKS call failed"),
        "TLS key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(key_id1).expect("SKS call failed"),
        "TLS key should be absent if not generated in the CSP."
    );

    let public_key_cert2 = csp_vault2
        .gen_tls_key_pair(node_test_id(NODE_1))
        .expect("error generating TLS key pair");
    let key_id2 = KeyId::from(&public_key_cert2);
    assert_ne!(
        key_id1, key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(key_id2).expect("SKS call failed"),
        "TLS key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(key_id1).expect("SKS call failed"),
        "The second CSP should not contain the TLS keys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(key_id2).expect("SKS call failed"),
        "Key first CSP should not contain the TLS keys of the second."
    );
}
