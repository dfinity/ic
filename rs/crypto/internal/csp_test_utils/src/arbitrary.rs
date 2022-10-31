//! Utilities for proptest-based testing

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
