#![allow(clippy::unwrap_used)]
use super::*;
use crate::hasher::Hasher;
use crate::*;
use std::collections::BTreeMap;
use std::convert::TryFrom;

fn assert_labeled_equal(tree_1: &LabeledTree<Digest>, tree_2: &LabeledTree<Digest>) {
    assert_eq!(tree_1, tree_2);
}

fn assert_hash_equal(tree_1: &HashTree, tree_2: &HashTree) {
    assert_eq!(tree_1, tree_2);
}

fn assert_witness_equal(witness_1: &Witness, witness_2: &Witness) {
    assert_eq!(witness_1, witness_2);
}

fn leaf_digest(data: &str) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_LEAF);
    hasher.update(data.as_ref());
    hasher.finalize()
}

fn node_digest(label: &Label, digest: &[u8; 32]) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_NODE);
    hasher.update(label.as_bytes());
    hasher.update(digest);
    hasher.finalize()
}

fn fork_digest(left_digest: &[u8; 32], right_digest: &[u8; 32]) -> Digest {
    let mut hasher = Hasher::for_domain(DOMAIN_HASHTREE_FORK);
    hasher.update(left_digest);
    hasher.update(right_digest);
    hasher.finalize()
}

// Returns a HashTree::HashNode that contains a HashLeaf with the given data.
fn hash_node_with_leaf(label: &Label, leaf_data: &str) -> HashTree {
    let hash_leaf = HashTree::Leaf {
        digest: leaf_digest(leaf_data),
    };
    HashTree::Node {
        digest: node_digest(&label, &hash_leaf.digest().0),
        label: label.clone(),
        hash_tree: Box::new(hash_leaf),
    }
}

// Returns a HashTree::HashNode that contains a HashLeaf with the given data.
fn hash_node_with_hash_tree(label: &Label, hash_tree: HashTree) -> HashTree {
    HashTree::Node {
        digest: node_digest(&label, &hash_tree.digest().0),
        label: label.clone(),
        hash_tree: Box::new(hash_tree),
    }
}

// Returns a HashTree::HashNode that contains the given subtrees.
fn fork(left_tree: HashTree, right_tree: HashTree) -> HashTree {
    HashTree::Fork {
        digest: fork_digest(&left_tree.digest().0, &right_tree.digest().0),
        left_tree: Box::new(left_tree),
        right_tree: Box::new(right_tree),
    }
}

#[test]
fn should_return_none_if_incomplete() {
    let mut builder = HashTreeBuilderImpl::new();
    assert!(builder.as_labeled_tree().is_none());
    builder.start_subtree();
    assert!(builder.as_labeled_tree().is_none());
    builder.new_edge(Label::from("some label"));
    assert!(builder.as_labeled_tree().is_none());
    builder.start_leaf();
    assert!(builder.as_labeled_tree().is_none());
    builder.finish_leaf();
    assert!(builder.as_labeled_tree().is_none());
    builder.finish_subtree();
    assert!(builder.as_labeled_tree().is_some());
}

#[test]
fn leaf_with_empty_contents_equals_leaf_with_no_contents() {
    // empty contents
    let mut builder_1 = HashTreeBuilderImpl::new();
    builder_1.start_leaf();
    builder_1.write_leaf("");
    builder_1.finish_leaf();

    // no contents
    let mut builder_2 = HashTreeBuilderImpl::new();
    builder_2.start_leaf();
    builder_2.finish_leaf();

    assert_eq!(builder_1.as_labeled_tree(), builder_2.as_labeled_tree());
    assert_eq!(builder_1.as_hash_tree(), builder_2.as_hash_tree());
}

#[test]
fn leaf_only_labeled_tree() {
    let leaf_contents = "some leaf contents";
    let expected_tree = LabeledTree::Leaf(leaf_digest(leaf_contents));
    let expected_hash_tree = HashTree::Leaf {
        digest: leaf_digest(leaf_contents),
    };

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.write_leaf(leaf_contents);
    builder.finish_leaf();

    assert_labeled_equal(&expected_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

#[test]
fn empty_leaf_only_labeled_tree() {
    let expected_labeled_tree = LabeledTree::Leaf(leaf_digest(""));
    let expected_hash_tree = HashTree::Leaf {
        digest: leaf_digest(""),
    };

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.finish_leaf();

    assert_labeled_equal(&expected_labeled_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

#[test]
fn empty_subtree_only_labeled_tree() {
    let expected_labeled_tree = LabeledTree::SubTree(FlatMap::new());
    let expected_hash_tree = HashTree::Leaf {
        digest: empty_subtree_hash(),
    };

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.finish_subtree();

    assert_labeled_equal(&expected_labeled_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

#[test]
fn long_leaf_only_labeled_tree() {
    let leaf_contents_1 = "some leaf contents part 1 (of 2)";
    let leaf_contents_2 = "part 2 (of 2) of leaf contents";
    let leaf_contents = leaf_contents_1.to_owned() + leaf_contents_2;
    let expected_labeled_tree = LabeledTree::Leaf(leaf_digest(leaf_contents.as_ref()));

    let expected_hash_tree = HashTree::Leaf {
        digest: leaf_digest(leaf_contents.as_ref()),
    };

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.write_leaf(leaf_contents_1);
    builder.write_leaf(leaf_contents_2);
    builder.finish_leaf();

    assert_labeled_equal(&expected_labeled_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

#[test]
fn labeled_tree_with_a_few_leaves_at_root() {
    let leaf_a_label = Label::from("label A");
    let leaf_b_label = Label::from("label B");
    let leaf_c_label = Label::from("label C");
    let leaf_a_contents = ""; // intentionally empty
    let leaf_b_contents = "contents of leaf B";
    let leaf_c_contents_1 = "contents of leaf C part 1";
    let leaf_c_contents_2 = "the rest of the contents of leaf C";
    let leaf_c_contents = leaf_c_contents_1.to_owned() + leaf_c_contents_2;

    let root_map = flatmap!(
        leaf_a_label.clone() => LabeledTree::Leaf(leaf_digest(leaf_a_contents)),
        leaf_b_label.clone() => LabeledTree::Leaf(leaf_digest(leaf_b_contents)),
        leaf_c_label.clone() => LabeledTree::Leaf(leaf_digest(leaf_c_contents.as_ref())),
    );
    let expected_labeled_tree = LabeledTree::SubTree(root_map);

    let hash_node_a = hash_node_with_leaf(&leaf_a_label, leaf_a_contents);
    let hash_node_b = hash_node_with_leaf(&leaf_b_label, leaf_b_contents);
    let hash_node_c = hash_node_with_leaf(&leaf_c_label, leaf_c_contents.as_ref());
    let fork_ab = fork(hash_node_a, hash_node_b);
    let expected_hash_tree = fork(fork_ab, hash_node_c);

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();

    builder.new_edge(leaf_a_label);
    builder.start_leaf();
    builder.write_leaf(leaf_a_contents);
    builder.finish_leaf();

    builder.new_edge(leaf_b_label);
    builder.start_leaf();
    builder.write_leaf(leaf_b_contents);
    builder.finish_leaf();

    builder.new_edge(leaf_c_label);
    builder.start_leaf();
    builder.write_leaf(leaf_c_contents_1);
    builder.write_leaf(leaf_c_contents_2);
    builder.finish_leaf();

    builder.finish_subtree();

    assert_labeled_equal(&expected_labeled_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

#[test]
fn labeled_tree_with_a_subtree() {
    let label_a = Label::from("label A");
    let label_b = Label::from("label B");
    let label_c = Label::from("label C");
    let label_d = Label::from("label D");
    let label_e = Label::from("label E");
    let label_f = Label::from("label F");
    let leaf_a_contents = "contents of leaf_A";
    let leaf_c_contents = ""; // intentionally empty
    let leaf_d_contents_1 = "contents of leaf_D part 1";
    let leaf_d_contents_2 = "the rest of the contents of leaf_D";
    let leaf_d_contents = leaf_d_contents_1.to_owned() + leaf_d_contents_2;
    let leaf_e_contents = "contents of leaf_A"; // same as leaf_a_contents
    let leaf_f_contents = "contents of leaf_F";

    // (root)
    //    +-- label_a
    //           \__ leaf_a_contents
    //    +-- label_b
    //           +-- label_c
    //                  \__ leaf: leaf_c_contents
    //           +-- label_d
    //                  \__ leaf_d_contents
    //           +-- label_e
    //                  \__ leaf_e_contents
    //           +-- label_f
    //                  \__ leaf_f_contents
    let subtree_map = flatmap!(
        label_c.clone() => LabeledTree::Leaf(leaf_digest(leaf_c_contents)),
        label_d.clone() => LabeledTree::Leaf(leaf_digest(leaf_d_contents.as_ref())),
        label_e.clone() => LabeledTree::Leaf(leaf_digest(leaf_e_contents)),
        label_f.clone() => LabeledTree::Leaf(leaf_digest(leaf_f_contents)),
    );
    let root_map = flatmap!(
        label_a.clone() => LabeledTree::Leaf(leaf_digest(leaf_a_contents)),
        label_b.clone() => LabeledTree::SubTree(subtree_map)
    );
    let expected_labeled_tree = LabeledTree::SubTree(root_map);

    let hash_node_a = hash_node_with_leaf(&label_a, leaf_a_contents);
    let hash_node_c = hash_node_with_leaf(&label_c, leaf_c_contents);
    let hash_node_d = hash_node_with_leaf(&label_d, leaf_d_contents.as_ref());
    let hash_node_e = hash_node_with_leaf(&label_e, leaf_e_contents);
    let hash_node_f = hash_node_with_leaf(&label_f, leaf_f_contents);
    let fork_cd = fork(hash_node_c, hash_node_d);
    let fork_ef = fork(hash_node_e, hash_node_f);
    let fork_cdef = fork(fork_cd, fork_ef);
    let hash_node_b = hash_node_with_hash_tree(&label_b, fork_cdef);
    let expected_hash_tree = fork(hash_node_a, hash_node_b);

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree(); // subtree at root

    builder.new_edge(label_a);
    builder.start_leaf();
    builder.write_leaf(leaf_a_contents);
    builder.finish_leaf();

    builder.new_edge(label_b);
    builder.start_subtree(); // subtree at label_b

    builder.new_edge(label_f); // intentionally non-alphabetically
    builder.start_leaf();
    builder.write_leaf(leaf_f_contents);
    builder.finish_leaf();

    builder.new_edge(label_c);
    builder.start_leaf();
    builder.write_leaf(leaf_c_contents);
    builder.finish_leaf();

    builder.new_edge(label_e);
    builder.start_leaf();
    builder.write_leaf(leaf_e_contents);
    builder.finish_leaf();

    builder.new_edge(label_d);
    builder.start_leaf();
    builder.write_leaf(leaf_d_contents_1);
    builder.write_leaf(leaf_d_contents_2);
    builder.finish_leaf();

    builder.finish_subtree(); // finish subtree at label_b
    builder.finish_subtree(); // finish subtree at root

    assert_labeled_equal(&expected_labeled_tree, &builder.as_labeled_tree().unwrap());
    assert_hash_equal(&expected_hash_tree, &builder.as_hash_tree().unwrap());
}

// ---------- panic! on start_leaf()
#[test]
#[should_panic(expected = "Invalid operation, expected Undefined-node.")]
fn should_panic_on_start_leaf_at_leaf_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.start_leaf();
}

#[test]
#[should_panic(expected = "Invalid operation, expected Undefined-node.")]
fn should_panic_on_start_leaf_at_subtree_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.start_leaf();
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_start_leaf_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.finish_subtree();
    builder.start_leaf();
}

// ---------- panic! on write_leaf()
#[test]
#[should_panic(expected = "Invalid operation, expected Leaf-node.")]
fn should_panic_on_write_leaf_at_undefined_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.write_leaf("some bytes");
}

#[test]
#[should_panic(expected = "Invalid operation, expected Leaf-node.")]
fn should_panic_on_write_leaf_at_subtree_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.write_leaf("some bytes");
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_write_leaf_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.finish_subtree();
    builder.write_leaf("some bytes");
}

// ---------- panic! on finish_leaf()
#[test]
#[should_panic(expected = "Invalid operation, expected Leaf-node.")]
fn should_panic_on_finish_leaf_at_undefined_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.finish_leaf();
}

#[test]
#[should_panic(expected = "Invalid operation, expected Leaf-node.")]
fn should_panic_on_finish_leaf_at_subtree_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.finish_leaf();
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_finish_leaf_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.finish_subtree();
    builder.finish_leaf();
}

// ---------- panic! on start_subtree()
#[test]
#[should_panic(expected = "Invalid operation, expected Undefined-node.")]
fn should_panic_on_start_subtree_at_leaf_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.start_subtree();
}

#[test]
#[should_panic(expected = "Invalid operation, expected Undefined-node.")]
fn should_panic_on_start_subtree_at_subtree_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.start_subtree();
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_start_subtree_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.finish_leaf();
    builder.start_subtree();
}

// ---------- panic! on new_edge()
#[test]
#[should_panic(expected = "Invalid operation, expected SubTree-node.")]
fn should_panic_on_new_edge_at_undefined_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.new_edge(Label::from("some edge"));
}

#[test]
#[should_panic(expected = "Invalid operation, expected SubTree-node.")]
fn should_panic_on_new_edge_at_leaf_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.new_edge(Label::from("some edge"));
}

#[test]
#[should_panic(expected = "Invalid operation, expected SubTree-node.")]
fn should_panic_on_duplicate_label_in_new_edge() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();
    builder.new_edge(Label::from("some edge"));
    builder.new_edge(Label::from("some edge"));
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_new_edge_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.finish_leaf();
    builder.new_edge(Label::from("some edge"));
}

// ---------- panic! on finish_subtree()
#[test]
#[should_panic(expected = "Invalid operation, expected SubTree-node.")]
fn should_panic_on_finish_subtree_at_undefined_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.finish_subtree();
}

#[test]
#[should_panic(expected = "Invalid operation, expected SubTree-node.")]
fn should_panic_on_finish_subtree_at_leaf_node() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.finish_subtree();
}

#[test]
#[should_panic(expected = "Construction completed.")]
fn should_panic_on_finish_subtree_at_a_completed_tree() {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_leaf();
    builder.finish_leaf();
    builder.finish_subtree();
}

// ---------- tests for generation of witnesses

#[test]
fn witness_generator_from_hash_tree_empty_tree() {
    let hash_tree = HashTree::Leaf {
        digest: empty_subtree_hash(),
    };
    let expected_labeled_tree = LabeledTree::SubTree(FlatMap::new());

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree).unwrap();
    assert_labeled_equal(&expected_labeled_tree, &witness_generator.orig_tree);
}

#[test]
fn witness_generator_from_hash_tree_single_leaf_tree() {
    let leaf_contents = "some leaf contents";
    let hash_tree = HashTree::Leaf {
        digest: leaf_digest(leaf_contents),
    };
    let expected_labeled_tree = LabeledTree::Leaf(leaf_digest(leaf_contents));

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree).unwrap();
    assert_labeled_equal(&expected_labeled_tree, &witness_generator.orig_tree);
}

#[test]
fn witness_generator_from_hash_tree_with_a_few_leaves() {
    let leaf_a_label = Label::from("label A");
    let leaf_b_label = Label::from("label B");
    let leaf_c_label = Label::from("label C");
    let leaf_a_contents = ""; // intentionally empty
    let leaf_b_contents = "contents of leaf B";
    let leaf_c_contents = "contents of leaf C";

    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree();

    builder.new_edge(leaf_a_label);
    builder.start_leaf();
    builder.write_leaf(leaf_a_contents);
    builder.finish_leaf();

    builder.new_edge(leaf_b_label);
    builder.start_leaf();
    builder.write_leaf(leaf_b_contents);
    builder.finish_leaf();

    builder.new_edge(leaf_c_label);
    builder.start_leaf();
    builder.write_leaf(leaf_c_contents);
    builder.finish_leaf();

    builder.finish_subtree();

    let expected_witness_generator = builder.witness_generator().unwrap();
    let witness_generator =
        WitnessGeneratorImpl::try_from(builder.as_hash_tree().unwrap()).unwrap();
    assert_eq!(expected_witness_generator, witness_generator);
}

#[test]
fn witness_generator_from_hash_tree_with_a_subtree() {
    let builder = tree_with_a_subtree();
    let expected_witness_generator = builder.witness_generator().unwrap();
    let witness_generator =
        WitnessGeneratorImpl::try_from(builder.as_hash_tree().unwrap()).unwrap();
    assert_eq!(expected_witness_generator, witness_generator);
}

#[test]
fn witness_generator_from_hash_tree_with_three_levels() {
    let builder = tree_with_three_levels();
    let expected_witness_generator = builder.witness_generator().unwrap();
    let witness_generator =
        WitnessGeneratorImpl::try_from(builder.as_hash_tree().unwrap()).unwrap();
    assert_eq!(expected_witness_generator, witness_generator);
}

#[test]
fn witness_generator_from_hash_tree_should_fail_on_fork_without_nodes() {
    let hash_leaf_a = HashTree::Leaf {
        digest: leaf_digest("some leaf a data"),
    };
    let hash_leaf_b = HashTree::Leaf {
        digest: leaf_digest("some leaf b data"),
    };
    let hash_tree = fork(hash_leaf_a, hash_leaf_b);
    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree);
    assert!(witness_generator.is_err());
    assert_eq!(
        TreeHashError::InvalidArgument {
            info: "subtree leaf without a node at path ".to_owned() + &path_as_string(&[]),
        },
        witness_generator.unwrap_err()
    );
}

#[test]
fn witness_generator_from_hash_tree_should_fail_on_duplicate_labels() {
    let label = Label::from("some label");
    let hash_tree_a = hash_node_with_leaf(&label, "some data");
    let hash_tree_b = hash_node_with_leaf(&label, "some other data");
    let hash_tree = fork(hash_tree_a, hash_tree_b);

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree);
    assert!(witness_generator.is_err());
    assert_eq!(
        TreeHashError::InvalidArgument {
            info: "non-sorted labels in a subtree at path []".to_owned(),
        },
        witness_generator.unwrap_err()
    );
}

#[test]
fn witness_generator_from_hash_tree_should_fail_on_non_sorted_labels() {
    let smaller_label = Label::from("aaaa");
    let larger_label = Label::from("bbbb");
    let left_hash_tree = hash_node_with_leaf(&larger_label, "some data");
    let right_hash_tree = hash_node_with_leaf(&smaller_label, "some other data");
    let hash_tree = fork(left_hash_tree, right_hash_tree);

    let witness_generator = WitnessGeneratorImpl::try_from(hash_tree);
    assert!(witness_generator.is_err());
    assert_eq!(
        TreeHashError::InvalidArgument {
            info: "non-sorted labels in a subtree at path []".to_owned(),
        },
        witness_generator.unwrap_err()
    );
}

#[test]
fn witness_should_fail_for_non_existing_path_at_root() {
    // Missing label at root: (root) -> wrong_label.
    let wrong_label = Label::from("wrong label");
    let contents = Vec::from("ignored");
    let root_map = flatmap!(
        wrong_label.to_owned() => LabeledTree::Leaf(contents)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree);
    assert!(witness.is_err());
    assert_eq!(
        TreeHashError::InconsistentPartialTree {
            offending_path: vec![wrong_label],
        },
        witness.unwrap_err()
    )
}

#[test]
fn witness_should_fail_for_non_existing_sub_path() {
    // Simple path: label_b -> wrong_label

    let label_b = Label::from("label_b");
    let wrong_label = Label::from("wrong label");
    let contents = Vec::from("ignored");

    let subtree_map = flatmap!(
        wrong_label.to_owned() => LabeledTree::Leaf(contents)
    );
    let root_map = flatmap!(
        label_b.to_owned() => LabeledTree::SubTree(subtree_map)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree);
    assert!(witness.is_err());
    assert_eq!(
        TreeHashError::InconsistentPartialTree {
            offending_path: vec![label_b, wrong_label],
        },
        witness.unwrap_err()
    )
}

fn add_leaf<T>(label: T, contents: &str, builder: &mut HashTreeBuilderImpl)
where
    T: std::convert::AsRef<[u8]>,
{
    let label = Label::from(label);
    builder.new_edge(label);
    builder.start_leaf();
    builder.write_leaf(contents);
    builder.finish_leaf();
}

fn start_subtree<T>(label: T, builder: &mut HashTreeBuilderImpl)
where
    T: std::convert::AsRef<[u8]>,
{
    let label = Label::from(label);
    builder.new_edge(label);
    builder.start_subtree();
}

// Generates a builder with a tree, used for witness tests.
// (root)
//    +-- label_a
//           \__ contents_a
//    +-- label_b
//           +-- label_c
//                  \__ contents_c
//           +-- label_d
//                  \__ contents_d
//           +-- label_e
//                  \__ contents_e
//           +-- label_f
//                  \__ contents_f
fn tree_with_a_subtree() -> HashTreeBuilderImpl {
    let default_contents = &FlatMap::new();
    tree_with_a_subtree_and_custom_contents(default_contents)
}

fn contents(label_str: &str, contents: &FlatMap<String, String>) -> String {
    contents
        .get(&label_str.to_owned())
        .map_or(label_str.to_owned() + "_default_contents", |v| v.to_owned())
}

fn tree_with_a_subtree_and_custom_contents(
    custom_contents: &FlatMap<String, String>,
) -> HashTreeBuilderImpl {
    let mut builder = HashTreeBuilderImpl::new();
    builder.start_subtree(); // subtree at root

    let c = custom_contents;
    add_leaf("label_a", &contents("label_a", c), &mut builder);

    start_subtree("label_b", &mut builder);
    add_leaf("label_c", &contents("label_c", c), &mut builder);
    add_leaf("label_d", &contents("label_d", c), &mut builder);
    add_leaf("label_e", &contents("label_e", c), &mut builder);
    add_leaf("label_f", &contents("label_f", c), &mut builder);

    builder.finish_subtree(); // finish subtree at label_b

    builder.finish_subtree(); // finish subtree at root
    builder
}

fn mfork(l: MixedHashTree, r: MixedHashTree) -> MixedHashTree {
    MixedHashTree::Fork(Box::new((l, r)))
}

fn mleaf<B: AsRef<[u8]>>(blob: B) -> MixedHashTree {
    MixedHashTree::Leaf(blob.as_ref().to_vec())
}

fn mpruned(d: &Digest) -> MixedHashTree {
    MixedHashTree::Pruned(d.to_owned())
}

fn mlabeled(label: &Label, t: MixedHashTree) -> MixedHashTree {
    MixedHashTree::Labeled(label.clone(), Box::new(t))
}

#[test]
fn witness_for_a_simple_path() {
    // Simple path: label_b -> label_c
    // (root)
    //    +-- label_b
    //           +-- label_c
    //                  \__ leaf
    let label_b = Label::from("label_b");
    let label_c = Label::from("label_c");
    let contents = Vec::from("ignored");

    let subtree_map = flatmap!(
        label_c => LabeledTree::Leaf(contents)
    );
    let root_map = flatmap!(
        label_b => LabeledTree::SubTree(subtree_map)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();

    // Build expected_witness.
    let hash_tree = builder.as_hash_tree().unwrap();
    let (a_subtree, b_subtree) = (hash_tree.left_tree(), hash_tree.right_tree());
    let cd_subtree = b_subtree.node_tree().left_tree();
    let ef_subtree = b_subtree.node_tree().right_tree();
    let (c_subtree, d_subtree) = (cd_subtree.left_tree(), cd_subtree.right_tree());
    let expected_witness = Witness::Fork {
        left_tree: Box::new(Witness::Pruned {
            digest: a_subtree.digest().to_owned(),
        }),
        right_tree: Box::new(Witness::Node {
            label: b_subtree.label().to_owned(),
            sub_witness: Box::new(Witness::Fork {
                left_tree: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Node {
                        label: c_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Known()),
                    }),
                    right_tree: Box::new(Witness::Pruned {
                        digest: d_subtree.digest().to_owned(),
                    }),
                }),
                right_tree: Box::new(Witness::Pruned {
                    digest: ef_subtree.digest().to_owned(),
                }),
            }),
        }),
    };

    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree).unwrap();

    assert_witness_equal(&expected_witness, &witness);

    let expected_mixed_hash_tree = mfork(
        mpruned(a_subtree.digest()),
        mlabeled(
            b_subtree.label(),
            mfork(
                mfork(
                    mlabeled(c_subtree.label(), mleaf("ignored")),
                    mpruned(d_subtree.digest()),
                ),
                mpruned(ef_subtree.digest()),
            ),
        ),
    );

    assert_eq!(
        expected_mixed_hash_tree,
        witness_generator.mixed_hash_tree(&partial_tree).unwrap()
    );
}

#[test]
fn witness_for_paths_with_a_common_prefix() {
    // Two paths with a common prefix: label_b -> label_c, label_b -> label_d
    // (root)
    //    +-- label_b
    //           +-- label_c
    //                  \__ leaf
    //           +-- label_d
    //                  \__ leaf

    let label_b = Label::from("label_b");
    let label_c = Label::from("label_c");
    let label_d = Label::from("label_d");
    let contents = Vec::from("ignored");

    let subtree_map = flatmap!(
        label_c => LabeledTree::Leaf(contents.to_owned()),
        label_d => LabeledTree::Leaf(contents),
    );

    let root_map = flatmap!(
        label_b => LabeledTree::SubTree(subtree_map)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();

    // Build expected_witness.
    let hash_tree = builder.as_hash_tree().unwrap();
    let (a_subtree, b_subtree) = (hash_tree.left_tree(), hash_tree.right_tree());
    let cd_subtree = b_subtree.node_tree().left_tree();
    let ef_subtree = b_subtree.node_tree().right_tree();
    let (c_subtree, d_subtree) = (cd_subtree.left_tree(), cd_subtree.right_tree());
    let expected_witness = Witness::Fork {
        left_tree: Box::new(Witness::Pruned {
            digest: a_subtree.digest().to_owned(),
        }),
        right_tree: Box::new(Witness::Node {
            label: b_subtree.label().to_owned(),
            sub_witness: Box::new(Witness::Fork {
                left_tree: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Node {
                        label: c_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Known()),
                    }),
                    right_tree: Box::new(Witness::Node {
                        label: d_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Known()),
                    }),
                }),
                right_tree: Box::new(Witness::Pruned {
                    digest: ef_subtree.digest().to_owned(),
                }),
            }),
        }),
    };

    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree).unwrap();

    assert_witness_equal(&expected_witness, &witness);

    let expected_mixed_hash_tree = mfork(
        mpruned(a_subtree.digest()),
        mlabeled(
            b_subtree.label(),
            mfork(
                mfork(
                    mlabeled(c_subtree.label(), mleaf("ignored")),
                    mlabeled(d_subtree.label(), mleaf("ignored")),
                ),
                mpruned(ef_subtree.digest()),
            ),
        ),
    );

    assert_eq!(
        expected_mixed_hash_tree,
        witness_generator.mixed_hash_tree(&partial_tree).unwrap()
    );
}

#[test]
fn witness_for_paths_forking_at_root() {
    // Two paths forking at root : label_a --> leaf, label_b -> label_e --> leaf
    // (root)
    //    +-- label_a
    //           \__ leaf
    //    +-- label_b
    //           +-- label_e
    //                  \__ leaf

    let label_a = Label::from("label_a");
    let label_b = Label::from("label_b");
    let label_e = Label::from("label_e");
    let contents = Vec::from("ignored");

    let subtree_map = flatmap!(
        label_e => LabeledTree::Leaf(contents.to_owned())
    );
    let root_map = flatmap!(
        label_a => LabeledTree::Leaf(contents),
        label_b => LabeledTree::SubTree(subtree_map),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();

    // Build expected_witness.
    let hash_tree = builder.as_hash_tree().unwrap();
    let (a_subtree, b_subtree) = (hash_tree.left_tree(), hash_tree.right_tree());
    let cd_subtree = b_subtree.node_tree().left_tree();
    let ef_subtree = b_subtree.node_tree().right_tree();
    let (e_subtree, f_subtree) = (ef_subtree.left_tree(), ef_subtree.right_tree());
    let expected_witness = Witness::Fork {
        left_tree: Box::new(Witness::Node {
            label: a_subtree.label().to_owned(),
            sub_witness: Box::new(Witness::Known()),
        }),
        right_tree: Box::new(Witness::Node {
            label: b_subtree.label().to_owned(),
            sub_witness: Box::new(Witness::Fork {
                left_tree: Box::new(Witness::Pruned {
                    digest: cd_subtree.digest().to_owned(),
                }),
                right_tree: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Node {
                        label: e_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Known()),
                    }),
                    right_tree: Box::new(Witness::Pruned {
                        digest: f_subtree.digest().to_owned(),
                    }),
                }),
            }),
        }),
    };

    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree).unwrap();

    assert_witness_equal(&expected_witness, &witness);

    let expected_mixed_hash_tree = mfork(
        mlabeled(a_subtree.label(), mleaf("ignored")),
        mlabeled(
            b_subtree.label(),
            mfork(
                mpruned(cd_subtree.digest()),
                mfork(
                    mlabeled(e_subtree.label(), mleaf("ignored")),
                    mpruned(f_subtree.digest()),
                ),
            ),
        ),
    );

    assert_eq!(
        expected_mixed_hash_tree,
        witness_generator.mixed_hash_tree(&partial_tree).unwrap()
    );
}

// Checks that `recompute_digest()` works properly.
// Arguments:
//  * two HashTrees `orig_builder` and `modified_builder`, that have identical
//    tree structure, but differing values in the leaves indicated by
//    `partial_tree`
//  * 'partial_tree`, that represents a query for getting a witness and for
//    recomputing the digest;  'partial_tree' contains leaf values consistent
//    with `modified_builder`
//
// The function does the following:
//
// 1. checks that both trees have differing digests at the root
// 2. checks that both trees generate identical witnesses for `partial_tree`
//    (because the trees differ only in the leaves indicated by `partial_tree`
// 3. checks that `recompute_digest(partial_tree, witness)` is equal
//    to the digest of the `modified_builder`.
fn check_recompute_digest_works(
    orig_builder: &HashTreeBuilderImpl,
    modified_builder: &HashTreeBuilderImpl,
    partial_tree: &LabeledTree<Vec<u8>>,
) {
    let orig_digest = orig_builder.as_hash_tree().unwrap().digest().to_owned();
    let orig_witness_generator = orig_builder.witness_generator().unwrap();
    let orig_witness = orig_witness_generator.witness(&partial_tree).unwrap();

    let modified_digest = modified_builder.as_hash_tree().unwrap().digest().to_owned();
    let modified_witness_generator = modified_builder.witness_generator().unwrap();
    let modified_witness = modified_witness_generator.witness(&partial_tree).unwrap();
    let mixed_hash_tree = modified_witness_generator
        .mixed_hash_tree(&partial_tree)
        .unwrap();

    assert_eq!(orig_witness, modified_witness);
    let witness = &orig_witness;
    assert_ne!(orig_digest, modified_digest);

    let recomputed_digest = recompute_digest(&partial_tree, witness).unwrap();
    assert_eq!(recomputed_digest, modified_digest);
    assert_eq!(recomputed_digest, mixed_hash_tree.digest());
    assert_eq!(
        partial_tree,
        &LabeledTree::<Vec<u8>>::try_from(mixed_hash_tree).unwrap()
    );
}

#[test]
fn recompute_digest_for_a_simple_path() {
    // Simple path: label_b -> label_c
    // (root)
    //    +-- label_b
    //           +-- label_c
    //                  \__ leaf
    let label_b = Label::from("label_b");
    let label_c = Label::from("label_c");
    let new_leaf_c_contents = "new_leaf_c_contents";
    let custom_contents = flatmap!(
        label_c.to_string() => new_leaf_c_contents.to_owned(),
    );

    let subtree_map = flatmap!(
        label_c => LabeledTree::Leaf(Vec::from(new_leaf_c_contents)),
    );
    let root_map = flatmap!(
        label_b => LabeledTree::SubTree(subtree_map),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let orig_builder = tree_with_a_subtree();
    let modified_builder = tree_with_a_subtree_and_custom_contents(&custom_contents);

    check_recompute_digest_works(&orig_builder, &modified_builder, &partial_tree);
}

#[test]
fn recompute_digest_for_paths_with_a_common_prefix() {
    // Two paths with a common prefix: label_b -> label_c, label_b -> label_d
    // (root)
    //    +-- label_b
    //           +-- label_c
    //                  \__ leaf
    //           +-- label_d
    //                  \__ leaf

    let label_b = Label::from("label_b");
    let label_c = Label::from("label_c");
    let label_d = Label::from("label_d");
    let new_leaf_c_contents = "new_leaf_c_contents";
    let new_leaf_d_contents = "new_leaf_d_contents";

    let custom_contents = flatmap!(
        label_c.to_string() => new_leaf_c_contents.to_owned(),
        label_d.to_string() => new_leaf_d_contents.to_owned(),
    );

    let subtree_map = flatmap!(
        label_c => LabeledTree::Leaf(Vec::from(new_leaf_c_contents)),
        label_d => LabeledTree::Leaf(Vec::from(new_leaf_d_contents)),
    );
    let root_map = flatmap!(
        label_b => LabeledTree::SubTree(subtree_map),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let orig_builder = tree_with_a_subtree();
    let modified_builder = tree_with_a_subtree_and_custom_contents(&custom_contents);

    check_recompute_digest_works(&orig_builder, &modified_builder, &partial_tree);
}

#[test]
fn recompute_digest_for_paths_forking_at_root() {
    // Two paths forking at root : label_a --> leaf, label_b -> label_e --> leaf
    // (root)
    //    +-- label_a
    //           \__ leaf
    //    +-- label_b
    //           +-- label_e
    //                  \__ leaf

    let label_a = Label::from("label_a");
    let label_b = Label::from("label_b");
    let label_e = Label::from("label_e");
    let new_leaf_a_contents = "new_leaf_a_contents";
    let new_leaf_e_contents = "new_leaf_e_contents";

    let custom_contents = flatmap!(
        label_a.to_string() => new_leaf_a_contents.to_owned(),
        label_e.to_string() => new_leaf_e_contents.to_owned(),
    );

    let subtree_map = flatmap!(
        label_e => LabeledTree::Leaf(Vec::from(new_leaf_e_contents)),
    );
    let root_map = flatmap!(
        label_a => LabeledTree::Leaf(Vec::from(new_leaf_a_contents)),
        label_b => LabeledTree::SubTree(subtree_map),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let orig_builder = tree_with_a_subtree();
    let modified_builder = tree_with_a_subtree_and_custom_contents(&custom_contents);

    check_recompute_digest_works(&orig_builder, &modified_builder, &partial_tree);
}

#[test]
fn recompute_digest_matching_partial_tree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22, &fixture.p23, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let digest = recompute_digest(&partial_tree, &witness).unwrap();

    assert_eq!(fixture.builder.into_hash_tree().unwrap().digest(), &digest);
}

#[test]
fn recompute_digest_extra_leaf() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p23, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_extra_leaf = fixture.partial_tree(&[&fixture.p22, &fixture.p23, &fixture.p3]);
    let res = recompute_digest(&partial_tree_extra_leaf, &witness);

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p22.0
        }),
        res
    );
}

#[test]
fn recompute_digest_missing_leaf() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22, &fixture.p23, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_missing_leaf = fixture.partial_tree(&[&fixture.p23, &fixture.p3]);
    let res = recompute_digest(&partial_tree_missing_leaf, &witness);

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p22.0
        }),
        res
    );
}

#[test]
fn recompute_digest_extra_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_extra_leaf = fixture.partial_tree(&[&fixture.p22, &fixture.p3]);
    let res = recompute_digest(&partial_tree_extra_leaf, &witness);

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p3.0
        }),
        res
    );
}

#[test]
fn recompute_digest_missing_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_missing_leaf = fixture.partial_tree(&[&fixture.p22]);
    let res = recompute_digest(&partial_tree_missing_leaf, &witness);

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p3.0
        }),
        res
    );
}

// Generates a builder with a more complex tree, used for witness tests.
// (root)
//    +-- label_a
//           +-- label_a_1
//                  \__ contents_a_1
//           +-- label_a_2
//                  \__ contents_a_2
//           +-- label_a_3
//                  +-- label_a_3_1
//                          \__ contents_a_3_1
//                  +-- label_a_3_2
//                          \__ contents_a_3_2
//    +-- label_b
//           +-- label_b_1
//                  \__ contents_b_1
//           +-- label_b_2
//                  // empty subtree
//           +-- label_b_3
//                  \__ contents_b_3
//           +-- label_b_4
//                  +-- label_b_4_1
//                          \__ contents_b_4_1
//                  +-- label_b_4_2
//                          \__ contents_b_4_2
//                  +-- label_b_4_3
//                          \__ contents_b_4_3
//           +-- label_b_5
//                  +-- label_b_5_1
//                          \__ contents_b_5_1
//    +-- label_c
//           \__ contents_c
fn tree_with_three_levels() -> HashTreeBuilderImpl {
    let mut builder = HashTreeBuilderImpl::new();

    builder.start_subtree(); // start subtree at root

    start_subtree("label_a", &mut builder);
    {
        add_leaf("label_a_1", "contents_a_1", &mut builder);
        add_leaf("label_a_2", "contents_a_2", &mut builder);

        start_subtree("label_a_3", &mut builder);
        {
            add_leaf("label_a_3_1", "contents_a_3_1", &mut builder);
            add_leaf("label_a_3_2", "contents_a_3_2", &mut builder);
        }
        builder.finish_subtree(); // finish subtree label_a_3
    }
    builder.finish_subtree(); // finish subtree label_a

    start_subtree("label_b", &mut builder);
    {
        add_leaf("label_b_1", "contents_b_1", &mut builder);

        start_subtree("label_b_2", &mut builder);
        builder.finish_subtree(); // finish subtree label_b_2

        add_leaf("label_b_3", "contents_b_3", &mut builder);

        start_subtree("label_b_4", &mut builder);
        {
            add_leaf("label_b_4_1", "contents_b_4_1", &mut builder);
            add_leaf("label_b_4_2", "contents_b_4_2", &mut builder);
            add_leaf("label_b_4_3", "contents_b_4_3", &mut builder);
        }
        builder.finish_subtree(); // finish subtree label_b_4

        start_subtree("label_b_5", &mut builder);
        {
            add_leaf("label_b_5_1", "contents_b_5_1", &mut builder);
        }
        builder.finish_subtree(); // finish subtree label_b_5
    }
    builder.finish_subtree(); // finish subtree label_b

    add_leaf("label_c", "contents_c", &mut builder);

    builder.finish_subtree(); // finish subtree at root

    builder
}

#[test]
fn witness_for_simple_path_in_a_big_tree() {
    // Simple path : label_b -> label_b_5 -> label_b_5_1 -> leaf
    // (root)
    //    +-- label_b
    //           +-- label_b_5
    //                  +-- label_b_5_1
    //                          \__ leaf

    let label_b = Label::from("label_b");
    let label_b_5 = Label::from("label_b_5");
    let label_b_5_1 = Label::from("label_b_5_1");
    let contents = Vec::from("ignored");

    let subtree_b_5_map = flatmap!(
        label_b_5_1 => LabeledTree::Leaf(contents),
    );
    let subtree_b_map = flatmap!(
        label_b_5 => LabeledTree::SubTree(subtree_b_5_map),
    );
    let root_map = flatmap!(
        label_b => LabeledTree::SubTree(subtree_b_map),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_three_levels();

    // Build expected_witness.
    let hash_tree = builder.as_hash_tree().unwrap();
    let (ab_subtree, c_subtree) = (hash_tree.left_tree(), hash_tree.right_tree());
    let (a_subtree, b_subtree) = (ab_subtree.left_tree(), ab_subtree.right_tree());
    let b_14_subtree = b_subtree.node_tree().left_tree();
    let b_5_subtree = b_subtree.node_tree().right_tree();
    let b_5_1_subtree = b_5_subtree.node_tree();

    let expected_witness = Witness::Fork {
        left_tree: Box::new(Witness::Fork {
            left_tree: Box::new(Witness::Pruned {
                digest: a_subtree.digest().to_owned(),
            }),
            right_tree: Box::new(Witness::Node {
                label: b_subtree.label().to_owned(),
                sub_witness: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Pruned {
                        digest: b_14_subtree.digest().to_owned(),
                    }),
                    right_tree: Box::new(Witness::Node {
                        label: b_5_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Node {
                            label: b_5_1_subtree.label().to_owned(),
                            sub_witness: Box::new(Witness::Known()),
                        }),
                    }),
                }),
            }),
        }),
        right_tree: Box::new(Witness::Pruned {
            digest: c_subtree.digest().to_owned(),
        }),
    };

    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree).unwrap();

    assert_witness_equal(&expected_witness, &witness);

    let expected_mixed_hash_tree = mfork(
        mfork(
            mpruned(a_subtree.digest()),
            mlabeled(
                b_subtree.label(),
                mfork(
                    mpruned(b_14_subtree.digest()),
                    mlabeled(
                        b_5_subtree.label(),
                        mlabeled(b_5_1_subtree.label(), mleaf("ignored")),
                    ),
                ),
            ),
        ),
        mpruned(c_subtree.digest()),
    );
    assert_eq!(
        expected_mixed_hash_tree,
        witness_generator.mixed_hash_tree(&partial_tree).unwrap()
    );
}

#[test]
fn witness_for_a_triple_fork_in_a_big_tree() {
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
    let contents = Vec::from("ignored");

    let subtree_a_3_map = flatmap!(
        label_a_3_2 => LabeledTree::Leaf(contents.to_owned()),
    );
    let subtree_a_map = flatmap!(
        label_a_3 => LabeledTree::SubTree(subtree_a_3_map),
    );
    let subtree_b_4_map = flatmap!(
        label_b_4_3 => LabeledTree::Leaf(contents.to_owned()),
    );
    let subtree_b_map = flatmap!(
        label_b_2 => LabeledTree::SubTree(FlatMap::new()),
        label_b_4 => LabeledTree::SubTree(subtree_b_4_map),
    );
    let root_map = flatmap!(
        label_a => LabeledTree::SubTree(subtree_a_map),
        label_b => LabeledTree::SubTree(subtree_b_map),
        label_c => LabeledTree::Leaf(contents),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_three_levels();

    // Build expected_witness.
    let hash_tree = builder.as_hash_tree().unwrap();
    let (ab_subtree, c_subtree) = (hash_tree.left_tree(), hash_tree.right_tree());
    let (a_subtree, b_subtree) = (ab_subtree.left_tree(), ab_subtree.right_tree());
    let a_12_subtree = a_subtree.node_tree().left_tree();
    let a_3_subtree = a_subtree.node_tree().right_tree();
    let a_3_1_subtree = a_3_subtree.node_tree().left_tree();
    let a_3_2_subtree = a_3_subtree.node_tree().right_tree();
    let b_14_subtree = b_subtree.node_tree().left_tree();
    let b_5_subtree = b_subtree.node_tree().right_tree();
    let b_1_subtree = b_14_subtree.left_tree().left_tree();
    let b_2_subtree = b_14_subtree.left_tree().right_tree();
    let b_3_subtree = b_14_subtree.right_tree().left_tree();
    let b_4_subtree = b_14_subtree.right_tree().right_tree();
    let b_4_12_subtree = b_4_subtree.node_tree().left_tree();
    let b_4_3_subtree = b_4_subtree.node_tree().right_tree();

    let expected_witness = Witness::Fork {
        left_tree: Box::new(Witness::Fork {
            left_tree: Box::new(Witness::Node {
                label: a_subtree.label().to_owned(),
                sub_witness: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Pruned {
                        digest: a_12_subtree.digest().to_owned(),
                    }),
                    right_tree: Box::new(Witness::Node {
                        label: a_3_subtree.label().to_owned(),
                        sub_witness: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: a_3_1_subtree.digest().to_owned(),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: a_3_2_subtree.label().to_owned(),
                                sub_witness: Box::new(Witness::Known()),
                            }),
                        }),
                    }),
                }),
            }),
            right_tree: Box::new(Witness::Node {
                label: b_subtree.label().to_owned(),
                sub_witness: Box::new(Witness::Fork {
                    left_tree: Box::new(Witness::Fork {
                        left_tree: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: b_1_subtree.digest().to_owned(),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: b_2_subtree.label().to_owned(),
                                sub_witness: Box::new(Witness::Known()),
                            }),
                        }),
                        right_tree: Box::new(Witness::Fork {
                            left_tree: Box::new(Witness::Pruned {
                                digest: b_3_subtree.digest().to_owned(),
                            }),
                            right_tree: Box::new(Witness::Node {
                                label: b_4_subtree.label().to_owned(),
                                sub_witness: Box::new(Witness::Fork {
                                    left_tree: Box::new(Witness::Pruned {
                                        digest: b_4_12_subtree.digest().to_owned(),
                                    }),
                                    right_tree: Box::new(Witness::Node {
                                        label: b_4_3_subtree.label().to_owned(),
                                        sub_witness: Box::new(Witness::Known()),
                                    }),
                                }),
                            }),
                        }),
                    }),
                    right_tree: Box::new(Witness::Pruned {
                        digest: b_5_subtree.digest().to_owned(),
                    }),
                }),
            }),
        }),
        right_tree: Box::new(Witness::Node {
            label: c_subtree.label().to_owned(),
            sub_witness: Box::new(Witness::Known()),
        }),
    };

    let witness_generator = builder.witness_generator().unwrap();
    let witness = witness_generator.witness(&partial_tree).unwrap();

    assert_witness_equal(&expected_witness, &witness);

    let expected_mixed_hash_tree = mfork(
        mfork(
            mlabeled(
                a_subtree.label(),
                mfork(
                    mpruned(a_12_subtree.digest()),
                    mlabeled(
                        a_3_subtree.label(),
                        mfork(
                            mpruned(a_3_1_subtree.digest()),
                            mlabeled(a_3_2_subtree.label(), mleaf("ignored")),
                        ),
                    ),
                ),
            ),
            mlabeled(
                b_subtree.label(),
                mfork(
                    mfork(
                        mfork(
                            mpruned(b_1_subtree.digest()),
                            mlabeled(b_2_subtree.label(), MixedHashTree::Empty),
                        ),
                        mfork(
                            mpruned(b_3_subtree.digest()),
                            mlabeled(
                                b_4_subtree.label(),
                                mfork(
                                    mpruned(b_4_12_subtree.digest()),
                                    mlabeled(b_4_3_subtree.label(), mleaf("ignored")),
                                ),
                            ),
                        ),
                    ),
                    mpruned(b_5_subtree.digest()),
                ),
            ),
        ),
        mlabeled(c_subtree.label(), mleaf("ignored")),
    );

    assert_eq!(
        expected_mixed_hash_tree,
        witness_generator.mixed_hash_tree(&partial_tree).unwrap()
    );
}

#[test]
fn sparse_labeled_tree_empty() {
    assert_eq!(
        sparse_labeled_tree_from_paths(&mut []),
        LabeledTree::Leaf(())
    );
}

#[test]
fn sparse_labeled_tree_shallow_path() {
    assert_eq!(
        sparse_labeled_tree_from_paths(&mut [Path::from(Label::from("0"))]),
        LabeledTree::SubTree(flatmap! {
            Label::from("0") => LabeledTree::Leaf(())
        })
    );
}

#[test]
fn sparse_labeled_tree_deep_path() {
    let (segment1, segment2, segment3) = (Label::from("0"), Label::from("1"), Label::from("2"));
    let path = Path::from_iter(vec![&segment1, &segment2, &segment3]);

    let labeled_tree = LabeledTree::SubTree(flatmap! {
        segment1 => LabeledTree::SubTree(flatmap!{
            segment2 => LabeledTree::SubTree(flatmap!{
                segment3 => LabeledTree::Leaf(())
            })
        })
    });

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&mut [path]));
}

#[test]
fn sparse_labeled_tree_duplicate_paths() {
    let (segment1, segment2, segment3) = (Label::from("0"), Label::from("1"), Label::from("2"));

    let mut paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
    ];

    let labeled_tree = LabeledTree::SubTree(flatmap! {
        segment1 => LabeledTree::SubTree(flatmap!{
            segment2 => LabeledTree::SubTree(flatmap!{
                segment3 => LabeledTree::Leaf(())
            })
        })
    });

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&mut paths));
}

#[test]
fn sparse_labeled_tree_path_prefixes_another_path() {
    let (segment1, segment2, segment3, segment4) = (
        Label::from("0"),
        Label::from("1"),
        Label::from("2"),
        Label::from("3"),
    );

    let labeled_tree = LabeledTree::SubTree(flatmap! {
        segment1.clone() => LabeledTree::SubTree(flatmap!{
            segment2.clone() => LabeledTree::SubTree(flatmap!{
                segment3.clone() => LabeledTree::Leaf(())
            })
        })
    });

    let mut paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
    ];

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&mut paths));

    let mut paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
    ];

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&mut paths));
}

#[test]
fn sparse_labeled_tree_multiple_paths_with_prefixes() {
    let (segment1, segment2, segment3, segment4, segment5, segment6, segment7, segment8) = (
        Label::from("0"),
        Label::from("1"),
        Label::from("2"),
        Label::from("3"),
        Label::from("4"),
        Label::from("5"),
        Label::from("6"),
        Label::from("7"),
    );

    let labeled_tree = LabeledTree::SubTree(flatmap! {
        segment1.clone() => LabeledTree::SubTree(flatmap!{
            segment2.clone() => LabeledTree::SubTree(flatmap!{
                segment3.clone() => LabeledTree::Leaf(())
            })
        }),
        segment5.clone() => LabeledTree::SubTree(flatmap!{
            segment6.clone() => LabeledTree::Leaf(()),
            segment7.clone() => LabeledTree::Leaf(()),
        })
    });

    let mut paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
        Path::from_iter(vec![&segment5, &segment6]),
        Path::from_iter(vec![&segment5, &segment7, &segment8]),
        Path::from_iter(vec![&segment5, &segment7]),
    ];

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&mut paths));
}

/// Recursive implementation of `prune_labeled_tree()`.
fn prune_labeled_tree_impl<T, U>(
    tree: LabeledTree<T>,
    selection: &LabeledTree<U>,
    path: &mut Vec<Label>,
) -> Result<LabeledTree<T>, TreeHashError> {
    match selection {
        LabeledTree::Leaf(_) => match tree {
            LabeledTree::Leaf(_) => Ok(tree),

            LabeledTree::SubTree(_) => Ok(LabeledTree::SubTree(Default::default())),
        },
        LabeledTree::SubTree(selection_children) => {
            if let LabeledTree::SubTree(children) = tree {
                let mut children: BTreeMap<_, _> = children.into_iter().collect();
                let mut res = BTreeMap::new();
                for (k, sel_v) in selection_children.iter() {
                    path.push(k.to_owned());
                    let (k, v) = children.remove_entry(k).ok_or_else(|| {
                        TreeHashError::InconsistentPartialTree {
                            offending_path: path.to_owned(),
                        }
                    })?;
                    res.insert(k, prune_labeled_tree_impl(v, sel_v, path)?);
                    path.pop();
                }
                Ok(LabeledTree::SubTree(FlatMap::from_key_values(
                    res.into_iter().collect(),
                )))
            } else {
                Err(TreeHashError::InconsistentPartialTree {
                    offending_path: path.to_owned(),
                })
            }
        }
    }
}

/// Prunes the given tree down to strictly the partial tree covered by
/// `selection` (e.g. if `tree` contains the path `a -> b -> c` but selection
/// only contains `a -> b`, then the returned partial tree will contain an empty
/// `LabeledTree::SubTree` at `a -> b`).
///
/// Node types don't need to match between `tree` and `selection`, but if any
/// path covered by `selection` does not exist in `tree`, an error is returned.
///
/// Never panics.
fn prune_labeled_tree<T, U>(
    tree: LabeledTree<T>,
    selection: &LabeledTree<U>,
) -> Result<LabeledTree<T>, TreeHashError> {
    prune_labeled_tree_impl(tree, selection, &mut vec![])
}

/// A fixture for `prune_witness()` tests providing:
/// * a `LabeledTree` with a combination of leaves on multiple levels,
///   unbalanced binary forks and an empty subtree;
/// * a matching `HashTreeBuilder`; and
/// * methods for constructing partial trees and witnesses.
///
/// ```ignore
/// (root)
///    +-- 1
///    |   +-- 1.1
///    |        \__ "v1.1"
///    +-- 2
///    |   +-- 2.1
///    |   |    \__ "v2.1"
///    |   +-- 2.2
///    |   |    \__ "v2.2"
///    |   +-- 2.3
///    |        \__ "v2.3"
///    +-- 3
///        +  // empty subtree
/// ```
struct LabeledTreeFixture {
    labeled_tree: LabeledTree<Vec<u8>>,
    builder: HashTreeBuilderImpl,

    p11: Path,
    p12: Path,
    p2: Path,
    p21: Path,
    p22: Path,
    p23: Path,
    p3: Path,
}

impl LabeledTreeFixture {
    fn new() -> Self {
        let l1 = Label::from("1");
        let l11 = Label::from("1.1");
        let l12 = Label::from("1.2");
        let l2 = Label::from("2");
        let l21 = Label::from("2.1");
        let l22 = Label::from("2.2");
        let l23 = Label::from("2.3");
        let l3 = Label::from("3");

        let v11 = "v1.1";
        let v21 = "v2.1";
        let v22 = "v2.2";
        let v23 = "v2.3";

        let labeled_tree = LabeledTree::SubTree(flatmap! {
            l1.clone() => LabeledTree::SubTree(flatmap!{
                l11.clone() => LabeledTree::Leaf(v11.into())
            }),
            l2.clone() => LabeledTree::SubTree(flatmap!{
                l21.clone() => LabeledTree::Leaf(v21.into()),
                l22.clone() => LabeledTree::Leaf(v22.into()),
                l23.clone() => LabeledTree::Leaf(v23.into()),
            }),
            l3.clone() => LabeledTree::SubTree(flatmap!{}),
        });

        let mut builder = HashTreeBuilderImpl::new();
        builder.start_subtree(); // start subtree at root
        {
            start_subtree(l1.as_bytes(), &mut builder);
            {
                add_leaf(l11.as_bytes(), v11, &mut builder);
            }
            builder.finish_subtree();

            start_subtree(l2.as_bytes(), &mut builder);
            {
                add_leaf(l21.as_bytes(), v21, &mut builder);
                add_leaf(l22.as_bytes(), v22, &mut builder);
                add_leaf(l23.as_bytes(), v23, &mut builder);
            }
            builder.finish_subtree();

            start_subtree(l3.as_bytes(), &mut builder);
            builder.finish_subtree();
        }
        builder.finish_subtree();

        let p11 = Path::from_iter(vec![&l1, &l11]);
        let p12 = Path::from_iter(vec![&l1, &l12]);
        let p2 = Path::from_iter(vec![&l2]);
        let p21 = Path::from_iter(vec![&l2, &l21]);
        let p22 = Path::from_iter(vec![&l2, &l22]);
        let p23 = Path::from_iter(vec![&l2, &l23]);
        let p3 = Path::from_iter(vec![&l3]);

        Self {
            labeled_tree,
            builder,
            p11,
            p12,
            p2,
            p21,
            p22,
            p23,
            p3,
        }
    }

    fn partial_tree(&self, paths: &[&Path]) -> LabeledTree<Vec<u8>> {
        let mut paths: Vec<_> = paths.iter().map(|p| p.to_owned().to_owned()).collect();
        let selection = sparse_labeled_tree_from_paths(&mut paths);
        prune_labeled_tree(self.labeled_tree.clone(), &selection).unwrap()
    }

    // Returns a partial tree with a 1.2 node that doesn't exist in `labeled_tree`.
    fn partial_tree_12(&self) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap! {
            Label::from("1") => LabeledTree::SubTree(flatmap!{
                Label::from("1.1") => LabeledTree::Leaf("v1.1".into()),
                Label::from("1.2") => LabeledTree::Leaf("v1.2".into())
            })
        })
    }

    // Returns a partial tree with a 3.1 node that doesn't exist in `labeled_tree`.
    fn partial_tree_31(&self) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap! {
            Label::from("3") => LabeledTree::SubTree(flatmap!{
                Label::from("3.1") => LabeledTree::Leaf("v3.1".into())
            })
        })
    }

    fn witness_for(&self, partial_tree: &LabeledTree<Vec<u8>>) -> Witness {
        let witness_gen = self.builder.witness_generator().unwrap();
        witness_gen.witness(&partial_tree).unwrap()
    }
}

#[test]
fn prune_witness_prune_all() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = &fixture.labeled_tree;
    let witness = fixture.witness_for(partial_tree);

    match prune_witness(&witness, partial_tree).unwrap() {
        Witness::Pruned { digest } => {
            assert_eq!(fixture.builder.into_hash_tree().unwrap().digest(), &digest)
        }
        other => panic!("Expected a Witness::Pruned, got {:?}", other),
    }
}

#[test]
fn prune_witness_prune_all2() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p22, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    match prune_witness(&witness, &partial_tree).unwrap() {
        Witness::Pruned { digest } => {
            assert_eq!(fixture.builder.into_hash_tree().unwrap().digest(), &digest)
        }
        other => panic!("Expected a Witness::Pruned, got {:?}", other),
    }
}

#[test]
fn prune_witness_prune_nothing() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = &fixture.labeled_tree;
    let witness = fixture.witness_for(partial_tree);

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: vec![]
        }),
        prune_witness(&witness, &LabeledTree::SubTree(flatmap! {}))
    );
}

#[test]
fn prune_witness_prune_middle_leaf() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = &fixture.labeled_tree;
    let witness = fixture.witness_for(partial_tree);

    let pruned_witness = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p22])).unwrap();

    let pruned_tree =
        fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p23, &fixture.p3]);
    let expected_witness = fixture.witness_for(&pruned_tree);
    assert_eq!(expected_witness, pruned_witness);
}

#[test]
fn prune_witness_prune_all_leaves() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = &fixture.labeled_tree;
    let witness = fixture.witness_for(partial_tree);

    let pruned_witness = prune_witness(
        &witness,
        &fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p22, &fixture.p23]),
    )
    .unwrap();

    let pruned_tree = fixture.partial_tree(&[&fixture.p3]);
    let expected_witness = fixture.witness_for(&pruned_tree);
    assert_eq!(expected_witness, pruned_witness);
}

#[test]
fn prune_witness_prune_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p22, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let pruned_witness = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p3])).unwrap();

    let pruned_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p22]);
    let expected_witness = fixture.witness_for(&pruned_tree);
    assert_eq!(expected_witness, pruned_witness);
}

#[test]
fn prune_witness_prune_already_pruned_leaf() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree =
        fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p23, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p22]));

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p22.0
        }),
        res
    );
}

#[test]
fn prune_witness_prune_leaf_from_already_pruned_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p22]));

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p2.0
        }),
        res
    );
}

#[test]
fn prune_witness_prune_already_pruned_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree =
        fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p22, &fixture.p23]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p3]));

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p3.0
        }),
        res
    );
}

#[test]
fn prune_witness_prune_some_already_pruned_leaves() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree =
        fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p22, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(
        &witness,
        &fixture.partial_tree(&[&fixture.p22, &fixture.p23]),
    );

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p23.0
        }),
        res
    );
}

#[test]
fn prune_witness_prune_inexistent_leaf_from_single_node_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree_12());

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p12.0
        }),
        res
    );
}

#[test]
fn prune_witness_prune_inexistent_leaf_from_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree_31());

    assert_eq!(
        Err(TreeHashError::InconsistentPartialTree {
            offending_path: fixture.p3.0
        }),
        res
    );
}

#[test]
fn sub_witness_test() {
    let l1 = Label::from("1");
    let l2 = Label::from("2");
    let l3 = Label::from("3");

    let witness = Witness::make_fork(
        Witness::make_fork(
            Witness::make_pruned(leaf_digest("")),
            Witness::make_node(l2.clone(), Witness::make_leaf(b"")),
        ),
        Witness::make_node(l3, Witness::make_leaf(b"")),
    );

    // Pruned / inexistent node.
    assert!(sub_witness(&witness, &l1).is_none());

    // Existing node.
    assert_eq!(Some(&Witness::Known()), sub_witness(&witness, &l2));

    // `Known` has no sub-witness.
    let known = Witness::Known();
    assert!(sub_witness(&known, &l1).is_none());

    // `Pruned` has no sub-witness.
    let pruned = Witness::make_pruned(leaf_digest(""));
    assert!(sub_witness(&pruned, &l1).is_none());

    // `Node` has a single sub-witness.
    let node = Witness::make_node(l2.clone(), Witness::Known());
    assert!(sub_witness(&node, &l1).is_none());
    assert_eq!(Some(&Witness::Known()), sub_witness(&node, &l2));
}

#[test]
fn first_sub_witness_test() {
    let l2 = Label::from("2");
    let l3 = Label::from("3");

    let witness = Witness::make_fork(
        Witness::make_fork(
            Witness::make_pruned(leaf_digest("")),
            Witness::make_node(l2.clone(), Witness::Known()),
        ),
        Witness::make_node(l3, Witness::Known()),
    );

    // First label is `l2`, the one before it was pruned.
    assert_eq!(Some((&l2, &Witness::Known())), first_sub_witness(&witness));

    // `Known` has no first child.
    let known = Witness::Known();
    assert!(first_sub_witness(&known).is_none());

    // `Pruned` has no first child.
    let pruned = Witness::make_pruned(leaf_digest(""));
    assert!(first_sub_witness(&pruned).is_none());

    // `Node` has a first child (it is the equivalent of a `LabeledTree::SubTree`
    // with a single child).
    let node = Witness::make_node(l2.clone(), Witness::Known());
    assert_eq!(Some((&l2, &Witness::Known())), first_sub_witness(&node));
}

#[test]
fn labeled_tree_lookup() {
    use LabeledTree::{Leaf, SubTree};
    let t: LabeledTree<Vec<u8>> = SubTree(flatmap! {
        Label::from("sig") => SubTree(flatmap!{
                Label::from("a") => SubTree(flatmap!{
                        Label::from("b") => Leaf(b"leaf_b".to_vec())
                }),
                Label::from("c") => Leaf(b"leaf_c".to_vec()),
        })
    });

    assert_eq!(
        lookup_path(&t, &[&b"sig"[..], &b"a"[..], &b"b"[..]]),
        Some(&Leaf(b"leaf_b".to_vec()))
    );

    assert_eq!(
        lookup_path(&t, &[&b"sig"[..], &b"c"[..]]),
        Some(&Leaf(b"leaf_c".to_vec()))
    );

    assert!(lookup_path(&t, &[&b"sig"[..], &b"d"[..]]).is_none());
    assert!(lookup_path(&t, &[&b"sieg"[..]]).is_none());
    assert!(lookup_path(&t, &[&b"sig"[..], &b"a"[..], &b"d"[..]]).is_none());
}
