use ic_stable_structures::{Memory, StableBTreeMap, Storable};

pub mod neuron_following;
pub mod neuron_principal;

/// Validates a StableBTreeMap by reading a value out of it. Should only be called in post_upgrade.
pub(crate) fn validate_stable_btree_map<Key, Value, M>(btree_map: &StableBTreeMap<Key, Value, M>)
where
    Key: Storable + Ord + Clone,
    Value: Storable,
    M: Memory,
{
    // This is just to verify that any key-value pair can be deserialized without panicking. It is
    // not guaranteed to catch all deserializations, but should catch a lot of common issues.
    let _ = btree_map.first_key_value();
}
