//! Utilities for proptest-based testing

use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

/// A list of list of Vec<u8>
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ListOfLists {
    Leaf(#[serde(with = "serde_bytes")] Vec<u8>),
    Node(Vec<ListOfLists>),
}

prop_compose! {
    /// Proptest utility to create a ListOfLists for testing
    pub fn list_of_lists() (seed in any::<Vec<u8>>()) -> ListOfLists {
        // TODO(DFN-793): Make this recursive
        ListOfLists::Leaf(seed)
    }
}

/// Return an arbitrary ephemeral public key (used for proptest-based testing)
pub fn arbitrary_ephemeral_public_key_bytes() -> BoxedStrategy<EphemeralPublicKeyBytes> {
    proptest::collection::vec(
        any::<u8>(),
        EphemeralPublicKeyBytes::SIZE..=EphemeralPublicKeyBytes::SIZE,
    )
    .prop_map(|bytes| {
        let mut buffer = [0u8; EphemeralPublicKeyBytes::SIZE];
        buffer.copy_from_slice(&bytes[..]);
        EphemeralPublicKeyBytes(buffer)
    })
    .boxed()
}
