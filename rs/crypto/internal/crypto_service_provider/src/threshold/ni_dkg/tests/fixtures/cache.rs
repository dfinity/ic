//! Cached DKG transcripts for tests.
//!
//! Note: Using one precomputed test fixture provides less thorough testing than
//! generating many fixtures with proptest.  However computing a fixture is
//! expensive and can be prohibitive for small tests, and unjustified in cases
//! where the exact contents of the fixture is not hugely relevant for the test.
//! Caching the fixture allows fine grained tests with minimal per-test runtime
//! cost.
//!
//! Warning: Nothing comes for free.  The CSP has a small mutable state - the
//! RNG and the key store - and it is not cloneable and should not be cloneable.
//! Theoretically one test could cause another to fail.  Given that the CSP
//! should be able to run as a service and satisfy each test sequentially,
//! running one test followed by another SHOULD not affect the outcome.  This is
//! morally equivalent to spinning up a testnet and firing requests at the
//! testnet, expecting each request to be handled correctly regardless of
//! previous requests.  If this assumption is unreasonable for your test, do not
//! use the static fixture.  Generate your own NiDKG.

use super::*;
use std::sync::LazyLock;
use std::sync::Mutex;

/// Alert: Creating this element costs about 30 seconds on a 2GHz AMD64 CPU.
pub static STATE_WITH_TRANSCRIPT: LazyLock<Mutex<StateWithTranscript>> = LazyLock::new(|| {
    let seed = [69u8; 32];
    let network_size = 4;
    let rng = &mut ChaCha20Rng::from_seed(seed);
    let network = MockNetwork::random(rng, network_size);
    let config = MockDkgConfig::from_network(rng, &network, None);
    let state = state_with_transcript(&config, network);
    Mutex::new(state)
});
