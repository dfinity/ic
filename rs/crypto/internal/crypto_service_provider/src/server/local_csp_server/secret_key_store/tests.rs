//! Verifies the implementation of SecretKeyStoreCspServer for LocalCspServer.
use super::*;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::server::api::BasicSignatureCspServer;
use ic_types::crypto::AlgorithmId;

use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaChaRng;

/// Key should be present only after key generation.
///
/// Note:  Theoretically the invariant is: The key should be present only in the
/// CSP that generated it, and only after generation and before deletion, if
/// deletion is supported for that key type.  Thus ideally there should be a
/// test that generates many sequences of events and verifies that this
/// invariant holds, regardless of the sequence of events, the number or type of
/// keys in the CSP and so on.  Making such a test is hard, so this is just one
/// sequence of events.
#[test]
fn key_should_be_present_only_after_generation() {
    let csp_server1 = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };
    let csp_server2 = {
        let key_store = TempSecretKeyStore::new();
        let csprng = ChaChaRng::from_seed(thread_rng().gen::<[u8; 32]>());
        LocalCspServer::new_for_test(csprng, key_store)
    };

    let (key_id1, _public_key) = csp_server1
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        csp_server1.sks_contains(&key_id1),
        "Key should be present after generation."
    );
    assert!(
        !csp_server2.sks_contains(&key_id1),
        "Key should be absent if not generated in the CSP."
    );

    let (key_id2, _public_key) = csp_server2
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        key_id1 != key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_server2.sks_contains(&key_id2),
        "Key should be present in the CSP that generated it."
    );
    assert!(
        !csp_server2.sks_contains(&key_id1),
        "The second CSP should not contain th ekeys of the first."
    );
    assert!(
        !csp_server1.sks_contains(&key_id2),
        "Key first CSP should not contain the keys of the second."
    );
}
