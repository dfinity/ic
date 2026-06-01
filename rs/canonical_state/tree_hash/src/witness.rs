use crate::{
    hash_tree::HashTree,
    lazy_tree::{LazyTree, materialize::materialize_partial},
};
use ic_crypto_tree_hash::{Witness, sparse_labeled_tree_from_paths};

pub fn compute_state_height_witness(lazy_tree: &LazyTree, hash_tree: &HashTree) -> Witness {
    let paths = vec![vec!["metadata".into(), "height".into()].into()];
    let labeled_tree =
        sparse_labeled_tree_from_paths(&paths).expect("Failed to compute labeled tree for height");
    let partial_tree = materialize_partial(lazy_tree, &labeled_tree, None);
    hash_tree
        .witness::<Witness>(&partial_tree)
        .expect("Failed to compute witness for state height")
}
