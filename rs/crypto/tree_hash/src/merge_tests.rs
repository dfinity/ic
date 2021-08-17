use crate::{arbitrary::arbitrary_mixed_hash_tree, MixedHashTree};
use proptest::prelude::*;
use MixedHashTree::*;

fn prune_leaves(t: &MixedHashTree) -> MixedHashTree {
    match t {
        Leaf(_) => Pruned(t.digest()),
        Empty => Empty,
        Pruned(h) => Pruned(h.clone()),
        Fork(p) => Fork(Box::new((prune_leaves(&p.0), prune_leaves(&p.1)))),
        Labeled(l, s) => Labeled(l.clone(), Box::new(prune_leaves(s))),
    }
}

fn prune_left_forks(t: &MixedHashTree) -> MixedHashTree {
    match t {
        Fork(p) => Fork(Box::new((Pruned(p.0.digest()), prune_left_forks(&p.1)))),
        Labeled(l, s) => Labeled(l.clone(), Box::new(prune_left_forks(s))),
        _ => t.clone(),
    }
}

fn prune_right_forks(t: &MixedHashTree) -> MixedHashTree {
    match t {
        Fork(p) => Fork(Box::new((prune_right_forks(&p.0), Pruned(p.1.digest())))),
        Labeled(l, s) => Labeled(l.clone(), Box::new(prune_right_forks(s))),
        _ => t.clone(),
    }
}

fn prune_labels(t: &MixedHashTree) -> MixedHashTree {
    match t {
        Fork(p) => Fork(Box::new((prune_labels(&p.0), prune_labels(&p.1)))),
        Labeled(_, _) => Pruned(t.digest()),
        _ => t.clone(),
    }
}

proptest! {
    #[test]
    fn merge_is_idempotent(t in arbitrary_mixed_hash_tree()) {
        assert_eq!(t, MixedHashTree::merge(t.clone(), t.clone()));
    }

    #[test]
    fn merge_with_pruned_is_idempotent(t in arbitrary_mixed_hash_tree()) {
        assert_eq!(t, MixedHashTree::merge(t.clone(), prune_leaves(&t)));
        assert_eq!(t, MixedHashTree::merge(t.clone(), prune_left_forks(&t)));
        assert_eq!(t, MixedHashTree::merge(t.clone(), prune_right_forks(&t)));
        assert_eq!(t, MixedHashTree::merge(t.clone(), prune_labels(&t)));
    }
}
