use assert_matches::assert_matches;
use ic_crypto_sha2::Sha256;
use ic_crypto_tree_hash::{Digest, Label, WitnessBuilder, WitnessGenerationError};
use ic_crypto_tree_hash_test_utils::MAX_HASH_TREE_DEPTH;

mod mixed_hash_tree {
    use super::*;
    use MixedHashTree::*;
    use ic_crypto_tree_hash::MixedHashTree;
    use ic_crypto_tree_hash_test_utils::arbitrary::arbitrary_mixed_hash_tree;

    #[test_strategy::proptest]
    fn merge_of_big_tree_is_idempotent(#[strategy(arbitrary_mixed_hash_tree())] t: MixedHashTree) {
        assert_eq!(Ok(t.clone()), MixedHashTree::merge_trees(t.clone(), t));
    }

    #[test_strategy::proptest]
    fn merge_of_pruned_with_anything_else_is_idempotent(
        #[strategy(arbitrary_mixed_hash_tree())] t: MixedHashTree,
    ) {
        assert_eq!(
            Ok(t.clone()),
            MixedHashTree::merge_trees(t.clone(), prune_leaves(&t))
        );
        assert_eq!(
            Ok(t.clone()),
            MixedHashTree::merge_trees(t.clone(), prune_left_forks(&t))
        );
        assert_eq!(
            Ok(t.clone()),
            MixedHashTree::merge_trees(t.clone(), prune_right_forks(&t))
        );
        assert_eq!(
            Ok(t.clone()),
            MixedHashTree::merge_trees(t.clone(), prune_labels(&t))
        );
    }

    #[test]
    fn merge_of_pruned_is_idempotent() {
        let pruned = Pruned(Digest([0u8; Sha256::DIGEST_LEN]));
        assert_eq!(
            Ok(pruned.clone()),
            MixedHashTree::merge_trees(pruned.clone(), pruned)
        );
    }

    #[test]
    fn merge_of_empty_is_idempotent() {
        assert_eq!(Ok(Empty), MixedHashTree::merge_trees(Empty, Empty));
    }

    #[test]
    fn merge_of_fork_is_idempotent() {
        let fork = Fork(Box::new((Empty, Empty)));
        assert_eq!(
            Ok(fork.clone()),
            MixedHashTree::merge_trees(fork.clone(), fork)
        );
    }

    #[test]
    fn merge_of_labeled_is_idempotent() {
        let labeled = Labeled(Label::from(vec![0]), Box::new(Empty));
        assert_eq!(
            Ok(labeled.clone()),
            MixedHashTree::merge_trees(labeled.clone(), labeled)
        );
    }

    #[test]
    fn merge_of_leaf_is_idempotent() {
        let leaf = Leaf(vec![0]);
        assert_eq!(
            Ok(leaf.clone()),
            MixedHashTree::merge_trees(leaf.clone(), leaf)
        );
    }

    #[test]
    fn merge_of_pruned_with_mismatching_digests_is_error() {
        let pruned1 = Pruned(Digest([0u8; Sha256::DIGEST_LEN]));
        let pruned2 = Pruned(Digest([1u8; Sha256::DIGEST_LEN]));
        assert_eq!(
            Err(
                WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(
                    pruned1.clone(),
                    pruned2.clone()
                )
            ),
            MixedHashTree::merge_trees(pruned1, pruned2)
        );
    }

    #[test]
    fn merge_of_labeled_with_mismatching_labels_is_error() {
        let labeled1 = Labeled(Label::from(vec![0]), Box::new(Empty));
        let labeled2 = Labeled(Label::from(vec![1]), Box::new(Empty));
        assert_eq!(
            Err(
                WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(
                    labeled1.clone(),
                    labeled2.clone()
                )
            ),
            MixedHashTree::merge_trees(labeled1, labeled2)
        );
    }

    #[test]
    fn merge_of_forks_with_mismatching_subtrees_is_error() {
        let mismatching = (Leaf(vec![0]), Leaf(vec![1]));
        let fork1 = Fork(Box::new((Empty, mismatching.0.clone())));
        let fork2 = Fork(Box::new((Empty, mismatching.1.clone())));
        assert_eq!(
            Err(
                WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(
                    mismatching.0,
                    mismatching.1,
                )
            ),
            MixedHashTree::merge_trees(fork1, fork2)
        );
    }

    #[test]
    fn merge_between_empty_fork_leaf_or_labeled_is_error() {
        let trees = [
            Empty,
            Leaf(vec![0]),
            Fork(Box::new((Empty, Empty))),
            Labeled(Label::from(vec![0]), Box::new(Empty)),
        ];
        for t1 in trees.iter() {
            for t2 in trees.iter() {
                if t1 == t2 {
                    continue;
                }
                assert_eq!(
                    MixedHashTree::merge_trees(t1.clone(), t2.clone()),
                    inconsistent_witnesses(t1, t2)
                );
                assert_eq!(
                    MixedHashTree::merge_trees(t2.clone(), t1.clone()),
                    inconsistent_witnesses(t2, t1)
                );
            }
        }
    }

    #[test]
    fn merge_with_too_deep_recursion_is_error() {
        let mut w = Empty;
        for depth in 0..127 {
            assert_matches!(
                MixedHashTree::merge_trees(w.clone(), w.clone()),
                Ok(_),
                "depth={depth}"
            );
            assert_eq!(
                MixedHashTree::merge_trees(w.clone(), w.clone()),
                MixedHashTree::merge_trees(w.clone(), w.clone()),
                "depth={depth}"
            );
            w = Labeled(Label::from("dummy_label"), Box::new(w));
        }

        // the depth of `w` is 128, which is the max valid depth, and thus `merge`
        // should work
        assert_eq!(
            MixedHashTree::merge_trees(w.clone(), w.clone()),
            Ok(w.clone())
        );
        assert_eq!(
            MixedHashTree::merge_trees(w.clone(), w.clone()),
            MixedHashTree::merge_trees(w.clone(), w.clone()),
        );

        w = Labeled(Label::from("dummy_label"), Box::new(w));

        // the depth of `w` is 129, which is one deeper than the max valid depth, and thus `merge`
        // should fail
        assert_eq!(
            MixedHashTree::merge_trees(w.clone(), w.clone()),
            Err(WitnessGenerationError::TooDeepRecursion(
                MAX_HASH_TREE_DEPTH + 1
            ))
        );
        assert_eq!(
            MixedHashTree::merge_trees(w.clone(), w.clone()),
            MixedHashTree::merge_trees(w.clone(), w),
        );
    }

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

    fn inconsistent_witnesses(
        l: &MixedHashTree,
        r: &MixedHashTree,
    ) -> Result<MixedHashTree, WitnessGenerationError<MixedHashTree>> {
        Err(
            WitnessGenerationError::<MixedHashTree>::MergingInconsistentWitnesses(
                l.clone(),
                r.clone(),
            ),
        )
    }
}

mod witness {
    use super::*;
    use Witness::*;
    use ic_crypto_tree_hash::Witness;

    #[test]
    fn merge_of_pruned_is_idempotent() {
        let pruned = Pruned {
            digest: Digest([0u8; 32]),
        };
        assert_eq!(
            Ok(pruned.clone()),
            Witness::merge_trees(pruned.clone(), pruned)
        );
    }

    #[test]
    fn merge_of_pruned_with_anything_else_is_idempotent() {
        let pruned = Pruned {
            digest: Digest([0u8; 32]),
        };
        for other in [
            Known(),
            Node {
                label: Label::from(vec![0]),
                sub_witness: Box::new(Known()),
            },
            Fork {
                left_tree: Box::new(Known()),
                right_tree: Box::new(Known()),
            },
        ] {
            assert_eq!(
                Ok(other.clone()),
                Witness::merge_trees(pruned.clone(), other.clone())
            );
            assert_eq!(
                Ok(other.clone()),
                Witness::merge_trees(other.clone(), pruned.clone())
            );
        }
    }

    #[test]
    fn merge_of_known_is_idempotent() {
        let known = Known();
        assert_eq!(
            Ok(known.clone()),
            Witness::merge_trees(known.clone(), known)
        );
    }

    #[test]
    fn merge_of_fork_is_idempotent() {
        let fork = Fork {
            left_tree: Box::new(Known()),
            right_tree: Box::new(Known()),
        };
        assert_eq!(Ok(fork.clone()), Witness::merge_trees(fork.clone(), fork));
    }

    #[test]
    fn merge_of_node_is_idempotent() {
        let node = Node {
            label: Label::from(vec![0]),
            sub_witness: Box::new(Known()),
        };
        assert_eq!(Ok(node.clone()), Witness::merge_trees(node.clone(), node));
    }

    #[test]
    fn merge_of_pruned_with_mismatching_digests_is_error() {
        let pruned1 = Pruned {
            digest: Digest([0u8; 32]),
        };
        let pruned2 = Pruned {
            digest: Digest([1u8; 32]),
        };
        assert_eq!(
            Err(
                WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(
                    pruned1.clone(),
                    pruned2.clone()
                )
            ),
            Witness::merge_trees(pruned1, pruned2)
        );
    }

    #[test]
    fn merge_of_nodes_with_mismatching_labels_is_error() {
        let node1 = Node {
            label: Label::from(vec![0]),
            sub_witness: Box::new(Known()),
        };
        let node2 = Node {
            label: Label::from(vec![1]),
            sub_witness: Box::new(Known()),
        };
        assert_eq!(
            Err(
                WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(
                    node1.clone(),
                    node2.clone()
                )
            ),
            Witness::merge_trees(node1, node2)
        );
    }

    #[test]
    fn merge_between_known_node_or_fork_is_error() {
        let witnesses = [
            Known(),
            Node {
                label: Label::from(vec![0]),
                sub_witness: Box::new(Known()),
            },
            Fork {
                left_tree: Box::new(Known()),
                right_tree: Box::new(Known()),
            },
        ];
        for w1 in witnesses.iter() {
            for w2 in witnesses.iter() {
                if w1 == w2 {
                    continue;
                }
                assert_eq!(
                    Witness::merge_trees(w1.clone(), w2.clone()),
                    inconsistent_witnesses(w1, w2)
                );
                assert_eq!(
                    Witness::merge_trees(w2.clone(), w1.clone()),
                    inconsistent_witnesses(w2, w1)
                );
            }
        }
    }

    #[test]
    fn merge_of_forks_with_mismatching_subtrees_is_error() {
        let mismatching = (
            Known(),
            Node {
                label: Label::from(vec![0]),
                sub_witness: Box::new(Known()),
            },
        );
        let fork1 = Fork {
            left_tree: Box::new(Known()),
            right_tree: Box::new(mismatching.0.clone()),
        };
        let fork2 = Fork {
            left_tree: Box::new(Known()),
            right_tree: Box::new(mismatching.1.clone()),
        };
        assert_eq!(
            Err(
                WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(
                    mismatching.0,
                    mismatching.1,
                )
            ),
            Witness::merge_trees(fork1, fork2)
        );
    }

    #[test]
    fn merge_of_nodes_with_mismatching_subtrees_is_error() {
        let mismatching = (
            Known(),
            Node {
                label: Label::from(vec![0]),
                sub_witness: Box::new(Known()),
            },
        );
        let node1 = Node {
            label: Label::from(vec![0]),
            sub_witness: Box::new(mismatching.0.clone()),
        };
        let node2 = Node {
            label: Label::from(vec![0]),
            sub_witness: Box::new(mismatching.1.clone()),
        };
        assert_eq!(
            Err(
                WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(
                    mismatching.0,
                    mismatching.1,
                )
            ),
            Witness::merge_trees(node1, node2)
        );
    }

    #[test]
    fn merge_with_too_deep_recursion_is_error() {
        let mut w = Witness::Known();
        for depth in 1..MAX_HASH_TREE_DEPTH {
            assert_matches!(
                Witness::merge_trees(w.clone(), w.clone()),
                Ok(_),
                "depth={depth}"
            );
            assert_eq!(
                Witness::merge_trees(w.clone(), w.clone()),
                Witness::merge_trees(w.clone(), w.clone()),
                "depth={depth}"
            );
            w = Node {
                label: Label::from("dummy_label"),
                sub_witness: Box::new(w),
            };
        }

        // the depth of `w` is 128, which is the max valid depth, and thus `merge`
        // should work
        assert_eq!(Witness::merge_trees(w.clone(), w.clone()), Ok(w.clone()));
        assert_eq!(
            Witness::merge_trees(w.clone(), w.clone()),
            Witness::merge_trees(w.clone(), w.clone())
        );

        w = Witness::Node {
            label: Label::from("dummy_label"),
            sub_witness: Box::new(w),
        };

        // the depth of `w` is 129, which is one deeper than the max valid depth, and thus `merge`
        // should fail
        assert_eq!(
            Witness::merge_trees(w.clone(), w.clone()),
            Err(WitnessGenerationError::TooDeepRecursion(
                MAX_HASH_TREE_DEPTH + 1
            ))
        );
        assert_eq!(
            Witness::merge_trees(w.clone(), w.clone()),
            Witness::merge_trees(w.clone(), w)
        );
    }

    fn inconsistent_witnesses(
        l: &Witness,
        r: &Witness,
    ) -> Result<Witness, WitnessGenerationError<Witness>> {
        Err(WitnessGenerationError::<Witness>::MergingInconsistentWitnesses(l.clone(), r.clone()))
    }
}
