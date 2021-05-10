#![allow(clippy::unwrap_used)]
#![allow(clippy::redundant_clone)]
use crate::{flatmap, Digest, FlatMap, Label, LabeledTree, Witness};
use ic_protobuf::messaging::xnet::v1;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};

#[test]
fn labeled_tree_roundtrip() {
    let labeled_tree = labeled_tree_for_test();
    assert_eq!(
        labeled_tree.clone(),
        v1::LabeledTree::proxy_decode(&v1::LabeledTree::proxy_encode(labeled_tree).unwrap())
            .unwrap()
    );
}

#[test]
fn large_labeled_tree_roundtrip() {
    let labeled_tree = large_labeled_tree_for_test();
    assert_eq!(
        labeled_tree.clone(),
        v1::LabeledTree::proxy_decode(&v1::LabeledTree::proxy_encode(labeled_tree).unwrap())
            .unwrap()
    );
}

#[test]
fn witness_roundtrip() {
    let witness = witness_for_test();
    assert_eq!(
        witness.clone(),
        v1::Witness::proxy_decode(&v1::Witness::proxy_encode(witness).unwrap()).unwrap()
    );
}

#[test]
fn large_witness_roundtrip() {
    let witness = large_witness_for_test();
    assert_eq!(
        witness.clone(),
        v1::Witness::proxy_decode(&v1::Witness::proxy_encode(witness).unwrap()).unwrap()
    );
}

#[test]
fn error_invalid_digest() {
    use v1::witness::*;
    let witness = v1::Witness {
        witness_enum: Some(WitnessEnum::Pruned(Pruned {
            digest: vec![3, 2, 1, 0],
        })),
    };
    let witness_vec = v1::Witness::proxy_encode(witness).unwrap();

    match <v1::Witness as ProtoProxy<Witness>>::proxy_decode(&witness_vec) {
        Err(ProxyDecodeError::InvalidDigestLength { actual: 4, .. }) => (),
        other => panic!(
            "Expected ProxyDecodeError::InvalidDigestLength {{ actual: 4 }}, got {:?}",
            other
        ),
    }
}

fn labeled_tree_for_test() -> LabeledTree<Vec<u8>> {
    use LabeledTree::*;
    let subtree = flatmap!(
        Label::from("first") => Leaf(vec![7, 5, 3]),
        Label::from("second") => SubTree(Default::default()),
    );
    SubTree(subtree)
}

fn large_labeled_tree_for_test() -> LabeledTree<Vec<u8>> {
    // Triple fork:
    // (root)
    //    +-- label_a
    //           +-- label_a_3
    //                  +-- label_a_3_2
    //                          \__ leaf
    //    +-- label_b
    //           +-- label_b_2  // empty subtree
    //           +-- label_b_4
    //                  +-- label_b_4_3
    //                          \__ leaf
    //    +-- label_c
    //           \__ leaf
    let label_a = Label::from("label_a");
    let label_a_3 = Label::from("label_a_3");
    let label_a_3_2 = Label::from("label_a_3_2");
    let label_b = Label::from("label_b");
    let label_b_2 = Label::from("label_b_2");
    let label_b_4 = Label::from("label_b_4");
    let label_b_4_3 = Label::from("label_b_4_3");
    let label_c = Label::from("label_c");

    let subtree_a_3_map = flatmap!(
        label_a_3_2 => LabeledTree::Leaf(Vec::from("a_3_2"))
    );

    let subtree_a_map = flatmap!(
        label_a_3 => LabeledTree::SubTree(subtree_a_3_map),
    );

    let subtree_b_4_map = flatmap!(
        label_b_4_3 => LabeledTree::Leaf(Vec::from("b_4_3")),
    );

    let subtree_b_map = flatmap!(
        label_b_2 => LabeledTree::SubTree(FlatMap::new()),
        label_b_4 => LabeledTree::SubTree(subtree_b_4_map),
    );

    let root_map = flatmap!(
        label_a => LabeledTree::SubTree(subtree_a_map),
        label_b => LabeledTree::SubTree(subtree_b_map),
        label_c => LabeledTree::Leaf(Vec::from("c")),
    );

    LabeledTree::SubTree(root_map)
}

fn witness_for_test() -> Witness {
    use Witness::*;
    Fork {
        left_tree: Box::new(Node {
            label: Label::from("left"),
            sub_witness: Box::new(Known {}),
        }),
        right_tree: Box::new(Pruned {
            digest: Digest([15; 32]),
        }),
    }
}

fn large_witness_for_test() -> Witness {
    // Triple fork:
    // Fork
    //    +-- Fork
    //        +-- Node(label_a)
    //            +-- Fork
    //                +-- Digest([0xa1; 32])
    //                +-- Node(label_a_3)
    //                    +-- Fork
    //                        +-- Digest([0xa3; 32])
    //                        +-- Node(label_a_3_2)
    //                            \__ Known
    //        +-- Node(label_b)
    //            +-- Fork
    //                +-- Fork
    //                    +-- Fork
    //                        +-- Digest([0xb1; 32])
    //                        +-- Node(label_b_2)
    //                            \__ Known
    //                    +-- Fork
    //                        +-- Digest([0xb3; 32])
    //                        +-- Node(label_b_4)
    //                            +-- Fork
    //                                +-- Digest([0xb4; 32])
    //                                +-- Node(label_b_4_3)
    //                                    \__ Known
    //                +-- Digest([0xb1; 32])
    //    +-- Node(label_c)
    //        \__ Known
    let label_a = Label::from("label_a");
    let label_a_3 = Label::from("label_a_3");
    let label_a_3_2 = Label::from("label_a_3_2");
    let label_b = Label::from("label_b");
    let label_b_2 = Label::from("label_b_2");
    let label_b_4 = Label::from("label_b_4");
    let label_b_4_3 = Label::from("label_b_4_3");
    let label_c = Label::from("label_c");

    Witness::Fork {
        left_tree: Box::new(Witness::Fork {
            left_tree: Box::new(Witness::Node {
                label: label_a,
                sub_witness: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Pruned {
                        digest: Digest([0xa1; 32]),
                    }),
                    right_tree: Box::new(Witness::Node {
                        label: label_a_3,
                        sub_witness: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: Digest([0xa3; 32]),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: label_a_3_2,
                                sub_witness: Box::new(Witness::Known()),
                            }),
                        }),
                    }),
                }),
            }),
            right_tree: Box::new(Witness::Node {
                label: label_b,
                sub_witness: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Fork {
                        left_tree: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: Digest([0xb1; 32]),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: label_b_2,
                                sub_witness: Box::new(Witness::Known()),
                            }),
                        }),
                        right_tree: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: Digest([0xb3; 32]),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: label_b_4,
                                sub_witness: Box::new(Witness::Fork {
                                    left_tree: Box::new(Witness::Pruned {
                                        digest: Digest([0xb4; 32]),
                                    }),
                                    right_tree: Box::new(Witness::Node {
                                        label: label_b_4_3,
                                        sub_witness: Box::new(Witness::Known()),
                                    }),
                                }),
                            }),
                        }),
                    }),
                    right_tree: Box::new(Witness::Pruned {
                        digest: Digest([0xb5; 32]),
                    }),
                }),
            }),
        }),
        right_tree: Box::new(Witness::Node {
            label: label_c,
            sub_witness: Box::new(Witness::Known()),
        }),
    }
}
