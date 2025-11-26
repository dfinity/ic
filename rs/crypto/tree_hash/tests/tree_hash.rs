use assert_matches::assert_matches;
use ic_crypto_sha2::Sha256;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::*;
use ic_crypto_tree_hash_test_utils::*;
use rand::Rng;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::convert::TryFrom;

trait HashTreeTestUtils {
    /// Returns the left sub-tree of the tree, assuming the tree is
    /// `HashTree::Fork`. panic!s if the tree is not a fork.
    fn left_tree(&self) -> &Self;

    /// Returns the right sub-tree of the tree, assuming the tree is
    /// `HashTree::Fork`. panic!s if the tree is not a fork.
    fn right_tree(&self) -> &Self;

    /// Returns the contained `hash_tree` of the tree, assuming the tree is
    /// `HashTree::Node`. panic!s if the tree is not `HashTree::Node`.
    fn node_tree(&self) -> &Self;

    /// Returns the label of the tree, assuming the tree is `HashTree::Node`.
    /// panic!s if the tree is not `HashTree::Node`.
    fn label(&self) -> &Label;
}

impl HashTreeTestUtils for HashTree {
    fn left_tree(&self) -> &Self {
        match &self {
            Self::Fork { left_tree, .. } => left_tree,
            _ => panic!("Not a fork: {self:?}"),
        }
    }

    fn right_tree(&self) -> &Self {
        match &self {
            Self::Fork { right_tree, .. } => right_tree,
            _ => panic!("Not a fork: {self:?}"),
        }
    }

    fn node_tree(&self) -> &Self {
        match &self {
            Self::Node { hash_tree, .. } => hash_tree,
            _ => panic!("Not a node: {self:?}"),
        }
    }

    fn label(&self) -> &Label {
        match &self {
            Self::Node { label, .. } => label,
            _ => panic!("Not a node: {self:?}"),
        }
    }
}

fn assert_labeled_equal(tree_1: &LabeledTree<Digest>, tree_2: &LabeledTree<Digest>) {
    assert_eq!(tree_1, tree_2);
}

fn assert_hash_equal(tree_1: &HashTree, tree_2: &HashTree) {
    assert_eq!(tree_1, tree_2);
}

fn assert_witness_equal(witness_1: &Witness, witness_2: &Witness) {
    assert_eq!(witness_1, witness_2);
}

// Returns a HashTree::HashNode that contains a HashLeaf with the given data.
fn hash_node_with_leaf(label: &Label, leaf_data: &str) -> HashTree {
    let hash_leaf = HashTree::Leaf {
        digest: compute_leaf_digest(leaf_data.as_bytes()),
    };
    HashTree::Node {
        digest: compute_node_digest(label, hash_leaf.digest()),
        label: label.clone(),
        hash_tree: Box::new(hash_leaf),
    }
}

// Returns a HashTree::HashNode that contains a HashLeaf with the given data.
fn hash_node_with_hash_tree(label: &Label, hash_tree: HashTree) -> HashTree {
    HashTree::Node {
        digest: compute_node_digest(label, hash_tree.digest()),
        label: label.clone(),
        hash_tree: Box::new(hash_tree),
    }
}

// Returns a HashTree::HashNode that contains the given subtrees.
fn fork(left_tree: HashTree, right_tree: HashTree) -> HashTree {
    HashTree::Fork {
        digest: compute_fork_digest(left_tree.digest(), right_tree.digest()),
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
    let expected_tree = LabeledTree::Leaf(compute_leaf_digest(leaf_contents.as_bytes()));
    let expected_hash_tree = HashTree::Leaf {
        digest: compute_leaf_digest(leaf_contents.as_bytes()),
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
    let expected_labeled_tree = LabeledTree::Leaf(compute_leaf_digest(b""));
    let expected_hash_tree = HashTree::Leaf {
        digest: compute_leaf_digest(b""),
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
    let expected_labeled_tree = LabeledTree::Leaf(compute_leaf_digest(leaf_contents.as_bytes()));

    let expected_hash_tree = HashTree::Leaf {
        digest: compute_leaf_digest(leaf_contents.as_bytes()),
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
        leaf_a_label.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_a_contents.as_bytes())),
        leaf_b_label.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_b_contents.as_bytes())),
        leaf_c_label.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_c_contents.as_bytes())),
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
        label_c.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_c_contents.as_bytes())),
        label_d.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_d_contents.as_bytes())),
        label_e.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_e_contents.as_bytes())),
        label_f.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_f_contents.as_bytes())),
    );
    let root_map = flatmap!(
        label_a.clone() => LabeledTree::Leaf(compute_leaf_digest(leaf_a_contents.as_bytes())),
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
fn witness_should_include_absence_proof_with_both_subtrees_at_root() {
    // Generating a witness for +-- label_aa ... should result in the following
    // absence proof
    //
    //    +-- label_a
    //           \__ Pruned
    //    +-- label_b
    //           +-- Pruned

    let label_non_existing = Label::from("label_aa");
    let contents = Vec::from("v");
    let root_map = flatmap!(
        label_non_existing => LabeledTree::Leaf(contents)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();

    let res = witness_generator.witness(&partial_tree);
    let root_nodes = builder
        .as_hash_tree()
        .expect("failed to generate hash tree");

    let expected_result = Ok(Witness::Fork {
        left_tree: Box::new(Witness::Node {
            label: Label::from("label_a"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.left_tree().node_tree().digest().clone(),
            }),
        }),
        right_tree: Box::new(Witness::Node {
            label: Label::from("label_b"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.right_tree().node_tree().digest().clone(),
            }),
        }),
    });
    assert_eq!(res, expected_result);
}

#[test]
fn witness_should_include_absence_proof_with_smaller_labeled_subtree_at_root() {
    // Generating a witness for +-- a ... should result in the following
    // absence proof
    //
    //    +-- label_a
    //           \__ Pruned
    //    +-- Pruned

    let label_non_existing = Label::from("a");
    let contents = Vec::from("v");
    let root_map = flatmap!(
        label_non_existing => LabeledTree::Leaf(contents)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();

    let res = witness_generator.witness(&partial_tree);
    let root_nodes = builder
        .as_hash_tree()
        .expect("failed to generate hash tree");

    let expected_result = Ok(Witness::Fork {
        left_tree: Box::new(Witness::Node {
            label: Label::from("label_a"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.left_tree().node_tree().digest().clone(),
            }),
        }),
        right_tree: Box::new(Witness::Pruned {
            digest: root_nodes.right_tree().digest().clone(),
        }),
    });
    assert_eq!(res, expected_result);
}

#[test]
fn witness_should_include_absence_proof_with_largest_labeled_subtree_at_root() {
    // Generating a witness for +-- label_bb ... should result in the following
    // absence proof
    //
    //    +-- Pruned
    //    +-- label_b
    //           \__ Pruned
    //

    let label_non_existing = Label::from("label_bb");
    let contents = Vec::from("v");
    let root_map = flatmap!(
        label_non_existing => LabeledTree::Leaf(contents)
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();

    let res = witness_generator.witness(&partial_tree);
    let root_nodes = builder
        .as_hash_tree()
        .expect("failed to generate hash tree");

    let expected_result = Ok(Witness::Fork {
        left_tree: Box::new(Witness::Pruned {
            digest: root_nodes.left_tree().digest().clone(),
        }),
        right_tree: Box::new(Witness::Node {
            label: Label::from("label_b"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.right_tree().node_tree().digest().clone(),
            }),
        }),
    });
    assert_eq!(res, expected_result);
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

/// Generates a builder with a tree, used for witness tests.
/// ```text
/// (root)
///    +-- label_a
///           \__ contents_a
///    +-- label_b
///           +-- label_c
///                  \__ contents_c
///           +-- label_d
///                  \__ contents_d
///           +-- label_e
///                  \__ contents_e
///           +-- label_f
///                  \__ contents_f
/// ```
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

fn gmlabeled(label: impl Into<Label>, t: MixedHashTree) -> MixedHashTree {
    MixedHashTree::Labeled(label.into(), Box::new(t))
}
fn gmpruned(digest: impl Into<Digest>) -> MixedHashTree {
    MixedHashTree::Pruned(digest.into())
}

/// Returns an `Err(InconsistentPartialTree)` with the given `offending_path`.
fn err_inconsistent_partial_tree<T>(offending_path: Vec<Label>) -> Result<T, TreeHashError> {
    Err(TreeHashError::InconsistentPartialTree { offending_path })
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
    let orig_witness = orig_witness_generator.witness(partial_tree).unwrap();

    let modified_digest = modified_builder.as_hash_tree().unwrap().digest().to_owned();
    let modified_witness_generator = modified_builder.witness_generator().unwrap();
    let modified_witness = modified_witness_generator.witness(partial_tree).unwrap();
    let mixed_hash_tree = modified_witness_generator
        .mixed_hash_tree(partial_tree)
        .unwrap();

    assert_eq!(orig_witness, modified_witness);
    let witness = &orig_witness;
    assert_ne!(orig_digest, modified_digest);

    let recomputed_digest = recompute_digest(partial_tree, witness).unwrap();
    assert_eq!(recomputed_digest, modified_digest);
    assert_eq!(recomputed_digest, mixed_hash_tree.digest());
    let labeled_tree = LabeledTree::<Vec<u8>>::try_from(mixed_hash_tree.clone()).unwrap();
    assert_eq!(
        partial_tree, &labeled_tree,
        "mixed_hash_tree: {mixed_hash_tree:#?}"
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

    assert_eq!(err_inconsistent_partial_tree(fixture.p22.to_vec()), res);
}

#[test]
fn recompute_digest_missing_leaf() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22, &fixture.p23, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_missing_leaf = fixture.partial_tree(&[&fixture.p23, &fixture.p3]);
    let res = recompute_digest(&partial_tree_missing_leaf, &witness);

    assert_eq!(err_inconsistent_partial_tree(fixture.p22.to_vec()), res);
}

#[test]
fn recompute_digest_extra_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_extra_leaf = fixture.partial_tree(&[&fixture.p22, &fixture.p3]);
    let res = recompute_digest(&partial_tree_extra_leaf, &witness);

    assert_eq!(err_inconsistent_partial_tree(fixture.p3.to_vec()), res);
}

#[test]
fn recompute_digest_missing_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p22, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let partial_tree_missing_leaf = fixture.partial_tree(&[&fixture.p22]);
    let res = recompute_digest(&partial_tree_missing_leaf, &witness);

    assert_eq!(err_inconsistent_partial_tree(fixture.p3.to_vec()), res);
}

/// Ensure that a witness containing a `Fork` with two `Pruned` children fails
/// `recompute_digest()` even if the respective digests are valid.
///
/// While the above is otherwise valid, we only want to accept minimal
/// witnesses.
#[test]
fn recompute_digest_not_pruned_fork_with_pruned_children() {
    let l1 = Label::from("l1");
    let l2 = Label::from("l2");
    let l3 = Label::from("l3");
    let v1: &str = "v1";
    let v2: &str = "v2";
    let v3: &str = "v3";

    // Compute root digest.
    let labeled_tree = LabeledTree::SubTree(flatmap! {
        l1.clone() => LabeledTree::Leaf(Vec::from(v1)),
        l2.clone() => LabeledTree::Leaf(Vec::from(v2)),
        l3.clone() => LabeledTree::Leaf(Vec::from(v3))
    });
    let witness = Witness::Fork {
        left_tree: Witness::Fork {
            left_tree: Witness::Node {
                label: l1.clone(),
                sub_witness: Witness::Known().into(),
            }
            .into(),
            right_tree: Witness::Node {
                label: l2.clone(),
                sub_witness: Witness::Known().into(),
            }
            .into(),
        }
        .into(),
        right_tree: Witness::Node {
            label: l3.clone(),
            sub_witness: Witness::Known().into(),
        }
        .into(),
    };
    let root_digest = recompute_digest(&labeled_tree, &witness).unwrap();

    let l1_digest = compute_node_digest(&l1, &compute_leaf_digest(v1.as_ref()));
    let l2_digest = compute_node_digest(&l2, &compute_leaf_digest(v2.as_ref()));

    // Sanity check that `l1_digest` and `l2_digest` are valid.
    {
        let partial_tree_no_l1 = LabeledTree::SubTree(flatmap! {
            l2.clone() => LabeledTree::Leaf(Vec::from(v2)),
            l3.clone() => LabeledTree::Leaf(Vec::from(v3))
        });
        let witness_no_l1 = Witness::Fork {
            left_tree: Witness::Fork {
                left_tree: Witness::Pruned {
                    digest: l1_digest.clone(),
                }
                .into(),
                right_tree: Witness::Node {
                    label: l2,
                    sub_witness: Witness::Known().into(),
                }
                .into(),
            }
            .into(),
            right_tree: Witness::Node {
                label: l3.clone(),
                sub_witness: Witness::Known().into(),
            }
            .into(),
        };

        assert_eq!(
            Ok(root_digest.clone()),
            recompute_digest(&partial_tree_no_l1, &witness_no_l1)
        )
    }
    {
        let partial_tree_no_l2 = LabeledTree::SubTree(flatmap! {
            l1.clone() => LabeledTree::Leaf(Vec::from(v1)),
            l3.clone() => LabeledTree::Leaf(Vec::from(v3))
        });
        let witness_no_l2 = Witness::Fork {
            left_tree: Witness::Fork {
                left_tree: Witness::Node {
                    label: l1,
                    sub_witness: Witness::Known().into(),
                }
                .into(),
                right_tree: Witness::Pruned {
                    digest: l2_digest.clone(),
                }
                .into(),
            }
            .into(),
            right_tree: Witness::Node {
                label: l3.clone(),
                sub_witness: Witness::Known().into(),
            }
            .into(),
        };

        assert_eq!(
            Ok(root_digest),
            recompute_digest(&partial_tree_no_l2, &witness_no_l2)
        )
    }

    // But pruning each individually without also pruning the `Fork` that holds them
    // results in an invalid witness.
    let partial_tree_l3_only = LabeledTree::SubTree(flatmap! {
        l3.clone() => LabeledTree::Leaf(Vec::from(v3))
    });
    let witness_l1_and_l2_pruned = Witness::Fork {
        left_tree: Witness::Fork {
            left_tree: Witness::Pruned { digest: l1_digest }.into(),
            right_tree: Witness::Pruned { digest: l2_digest }.into(),
        }
        .into(),
        right_tree: Witness::Node {
            label: l3,
            sub_witness: Witness::Known().into(),
        }
        .into(),
    };

    assert_eq!(
        Err(TreeHashError::NonMinimalWitness {
            offending_path: vec![]
        }),
        recompute_digest(&partial_tree_l3_only, &witness_l1_and_l2_pruned)
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

#[test_strategy::proptest]
fn recompute_digest_for_mixed_hash_tree_iteratively_and_recursively_produces_same_digest(
    #[strategy(arbitrary::arbitrary_well_formed_mixed_hash_tree())] tree: MixedHashTree,
) {
    let rec_or_error = mixed_hash_tree_digest_recursive(&tree);
    // ignore the error case, since the iterative algorithm is infallible
    if let Ok(rec) = rec_or_error {
        let iter = tree.digest();
        assert_eq!(rec, iter);
    }
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
        sparse_labeled_tree_from_paths(&[]),
        Ok(LabeledTree::Leaf(()))
    );
}

#[test]
fn sparse_labeled_tree_shallow_path() {
    assert_eq!(
        sparse_labeled_tree_from_paths(&[Path::from(Label::from("0"))]),
        Ok(LabeledTree::SubTree(flatmap! {
            Label::from("0") => LabeledTree::Leaf(())
        }))
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

    assert_eq!(Ok(labeled_tree), sparse_labeled_tree_from_paths(&[path]));
}

#[test]
fn sparse_labeled_tree_one_path_max_depth() {
    let path = Path::from_iter(vec![
        Label::from("dummy_label");
        MAX_HASH_TREE_DEPTH as usize - 1
    ]);

    let result = sparse_labeled_tree_from_paths(&[path]);

    let mut expected_tree = LabeledTree::Leaf(());
    for _ in 0..MAX_HASH_TREE_DEPTH - 1 {
        expected_tree = LabeledTree::SubTree(flatmap!(Label::from("dummy_label") => expected_tree));
    }

    assert_eq!(result, Ok(expected_tree));
}

#[test]
fn sparse_labeled_tree_many_paths_max_depth() {
    const TREE_WIDTH: usize = 100;
    let subpath = vec![Label::from("dummy_label"); MAX_HASH_TREE_DEPTH as usize - 2];

    let mut paths = Vec::with_capacity(TREE_WIDTH);
    for i in 0..TREE_WIDTH {
        paths.push(Path::from_iter(
            [Label::from("a".repeat(i))].iter().chain(subpath.iter()),
        ));
    }
    let result = sparse_labeled_tree_from_paths(&paths[..]);

    let mut expected_subtree = LabeledTree::Leaf(());
    for _ in 0..MAX_HASH_TREE_DEPTH - 2 {
        expected_subtree =
            LabeledTree::SubTree(flatmap!(Label::from("dummy_label") => expected_subtree));
    }
    let mut flatmap = FlatMap::with_capacity(TREE_WIDTH);
    for i in 0..TREE_WIDTH {
        flatmap
            .try_append(Label::from("a".repeat(i)), expected_subtree.clone())
            .expect("failed to append");
    }
    let expected_tree = LabeledTree::SubTree(flatmap);

    assert_eq!(result, Ok(expected_tree));
}

#[test]
fn sparse_labeled_tree_one_path_too_deep() {
    for depth in [
        MAX_HASH_TREE_DEPTH as u16,
        MAX_HASH_TREE_DEPTH as u16 + 1,
        10 * MAX_HASH_TREE_DEPTH as u16,
    ] {
        let path = Path::from_iter(vec![Label::from("dummy_label"); depth as usize]);
        assert_eq!(
            Err(TooLongPathError),
            sparse_labeled_tree_from_paths(&[path])
        );
    }
}

#[test]
fn sparse_labeled_tree_many_paths_max_depth_one_too_deep() {
    const TREE_WIDTH: usize = 100;
    let ok_subpath = vec![Label::from("dummy_label"); MAX_HASH_TREE_DEPTH as usize - 2];
    let too_long_subpath = vec![Label::from("dummy_label"); MAX_HASH_TREE_DEPTH as usize - 1];

    let rng = &mut reproducible_rng();
    let target_index = rng.random_range(0..TREE_WIDTH);

    let mut paths = Vec::with_capacity(TREE_WIDTH);

    let get_subpath = |i| {
        let path = if i == target_index {
            too_long_subpath.clone()
        } else {
            ok_subpath.clone()
        };
        let path: Vec<_> = [Label::from("a".repeat(i))]
            .iter()
            .chain(path.iter())
            .cloned()
            .collect();
        path
    };

    for i in 0..TREE_WIDTH {
        paths.push(Path::from_iter(get_subpath(i)));
    }

    assert_eq!(
        Err(TooLongPathError),
        sparse_labeled_tree_from_paths(&paths[..])
    );
}

#[test]
fn sparse_labeled_tree_one_path_max_depth_does_not_panic_on_drop() {
    let path = Path::from_iter(vec![
        Label::from("dummy_label");
        MAX_HASH_TREE_DEPTH as usize - 1
    ]);
    let tree = sparse_labeled_tree_from_paths(&[path]);
    drop(tree);
}

#[test]
fn sparse_labeled_tree_many_paths_max_depth_does_not_panic_on_drop() {
    const TREE_WIDTH: usize = 100;
    let subpath = vec![Label::from("dummy_label"); MAX_HASH_TREE_DEPTH as usize - 2];

    let mut paths = Vec::with_capacity(TREE_WIDTH);
    for i in 0..TREE_WIDTH {
        paths.push(Path::from_iter(
            [Label::from("a".repeat(i))].iter().chain(subpath.iter()),
        ));
    }

    let tree = sparse_labeled_tree_from_paths(&paths[..]);
    drop(tree);
}

#[test]
fn sparse_labeled_tree_duplicate_paths() {
    let (segment1, segment2, segment3) = (Label::from("0"), Label::from("1"), Label::from("2"));

    let paths = vec![
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

    assert_eq!(Ok(labeled_tree), sparse_labeled_tree_from_paths(&paths));
}

#[test]
fn sparse_labeled_tree_path_prefixes_another_path() {
    let (segment1, segment2, segment3, segment4) = (
        Label::from("0"),
        Label::from("1"),
        Label::from("2"),
        Label::from("3"),
    );

    let labeled_tree = Ok(LabeledTree::SubTree(flatmap! {
        segment1.clone() => LabeledTree::SubTree(flatmap!{
            segment2.clone() => LabeledTree::SubTree(flatmap!{
                segment3.clone() => LabeledTree::Leaf(())
            })
        })
    }));

    let paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
    ];

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&paths));

    let paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
    ];

    assert_eq!(labeled_tree, sparse_labeled_tree_from_paths(&paths));
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

    let paths = vec![
        Path::from_iter(vec![&segment1, &segment2, &segment3, &segment4]),
        Path::from_iter(vec![&segment1, &segment2, &segment3]),
        Path::from_iter(vec![&segment5, &segment6]),
        Path::from_iter(vec![&segment5, &segment7, &segment8]),
        Path::from_iter(vec![&segment5, &segment7]),
    ];

    assert_eq!(Ok(labeled_tree), sparse_labeled_tree_from_paths(&paths));
}

/// Recursive implementation of `prune_labeled_tree()`.
fn prune_labeled_tree_impl<T: Clone, U>(
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
            if let LabeledTree::SubTree(children) = &tree {
                let mut children: BTreeMap<_, _> = children.iter().collect();
                let mut res = BTreeMap::new();
                for (k, sel_v) in selection_children.iter() {
                    path.push(k.to_owned());
                    let (k, v) = children.remove_entry(k).ok_or_else(|| {
                        TreeHashError::InconsistentPartialTree {
                            offending_path: path.to_owned(),
                        }
                    })?;
                    res.insert(k, prune_labeled_tree_impl(v.clone(), sel_v, path)?);
                    path.pop();
                }
                Ok(LabeledTree::SubTree(FlatMap::from_key_values(
                    res.into_iter().map(|(l, t)| (l.clone(), t)).collect(),
                )))
            } else {
                err_inconsistent_partial_tree(path.to_owned())
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
fn prune_labeled_tree<T: Clone, U>(
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
        let paths: Vec<_> = paths.iter().map(|p| p.to_owned().to_owned()).collect();
        let selection = sparse_labeled_tree_from_paths(&paths)
            .expect("Failed to convert paths to a labeled tree");
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
        witness_gen.witness(partial_tree).unwrap()
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
        other => panic!("Expected a Witness::Pruned, got {other:?}"),
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
        other => panic!("Expected a Witness::Pruned, got {other:?}"),
    }
}

#[test]
fn prune_witness_prune_nothing() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = &fixture.labeled_tree;
    let witness = fixture.witness_for(partial_tree);

    assert_eq!(
        err_inconsistent_partial_tree(vec![]),
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

    assert_eq!(err_inconsistent_partial_tree(fixture.p22.to_vec()), res);
}

#[test]
fn prune_witness_prune_leaf_from_already_pruned_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p22]));

    assert_eq!(err_inconsistent_partial_tree(fixture.p2.to_vec()), res);
}

#[test]
fn prune_witness_prune_already_pruned_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree =
        fixture.partial_tree(&[&fixture.p11, &fixture.p21, &fixture.p22, &fixture.p23]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree(&[&fixture.p3]));

    assert_eq!(err_inconsistent_partial_tree(fixture.p3.to_vec()), res);
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

    assert_eq!(err_inconsistent_partial_tree(fixture.p23.to_vec()), res);
}

#[test]
fn prune_witness_prune_inexistent_leaf_from_single_node_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree_12());

    assert_eq!(err_inconsistent_partial_tree(fixture.p12.to_vec()), res);
}

#[test]
fn prune_witness_prune_inexistent_leaf_from_empty_subtree() {
    let fixture = LabeledTreeFixture::new();
    let partial_tree = fixture.partial_tree(&[&fixture.p11, &fixture.p3]);
    let witness = fixture.witness_for(&partial_tree);

    let res = prune_witness(&witness, &fixture.partial_tree_31());

    assert_eq!(err_inconsistent_partial_tree(fixture.p3.to_vec()), res);
}

#[test]
fn prune_witness_exceed_recursion_depth() {
    const DUMMY_LABEL: &str = "dummy label";
    fn witness_of_depth(depth: u8) -> Witness {
        assert!(depth > 0);
        let mut result = Box::new(Witness::Known());
        if depth > 1 {
            result = Box::new(Witness::Node {
                label: DUMMY_LABEL.into(),
                sub_witness: result,
            });
        }
        for _ in 2..depth {
            result = Box::new(Witness::Fork {
                left_tree: result,
                right_tree: Box::new(Witness::Pruned {
                    digest: Digest([0u8; 32]),
                }),
            });
        }
        *result
    }

    fn labeled_tree(depth: u8) -> LabeledTree<Vec<u8>> {
        let mut result = LabeledTree::Leaf("dummy value".into());
        if depth > 1 {
            result = LabeledTree::SubTree(flatmap!(DUMMY_LABEL.into() => result));
        }
        result
    }

    for depth in [1, 2, MAX_HASH_TREE_DEPTH - 1, MAX_HASH_TREE_DEPTH] {
        let witness = witness_of_depth(depth);
        assert_matches!(
            prune_witness(&witness, &labeled_tree(depth)),
            Ok(Witness::Pruned { .. })
        );
        assert_matches!(recompute_digest(&labeled_tree(depth), &witness), Ok(_));
    }
    // failing tests reach the recursion limit
    for depth in [MAX_HASH_TREE_DEPTH + 1, MAX_HASH_TREE_DEPTH + 10] {
        let witness = witness_of_depth(depth);
        assert_matches!(
            serde_cbor::from_slice::<Witness>(
                serde_cbor::to_vec(&witness)
                    .expect("failed to serialize witness")
                    .as_slice()
            ),
            Err(e) if format!("{e:?}").contains("RecursionLimitExceeded")
        );
        assert_matches!(
            prune_witness(&witness, &labeled_tree(depth)),
            Err(TreeHashError::TooDeepRecursion { .. })
        );
        assert_matches!(
            recompute_digest(&labeled_tree(depth), &witness),
            Err(TreeHashError::TooDeepRecursion { .. })
        );
    }
}

/// Ensures that an invalid witness, with a partially pruned node (leaf pruned
/// but node/label not pruned) causes both `prune_witness()` and
/// `recompute_digest()` to fail with an error.
#[test]
fn prune_witness_prune_partially_pruned_node() {
    let label = Label::from("label");
    let value = "value";

    // A `LabeledTree` consisting of a single label and value:
    //
    // ```
    // (root)
    //    +-- label
    //         \__ "value"
    // ```
    let labeled_tree = LabeledTree::SubTree(flatmap! {
        label.clone() => LabeledTree::Leaf(value.into())
    });

    // An invalid witness with only the leaf pruned, but not the node/label.
    //
    // ```
    // (root)
    //    +-- label
    //         \__ [Pruned]
    // ```
    //
    // A valid witness would need to have the label and a `Known` node under it.
    //
    // More generally, we should never accept a witness having `Pruned` under a
    // `Node`: either both are pruned (and we have a single `Pruned` node) or
    // there's a `Known` or `Fork` under the `Node`.
    let invalid_witness = Witness::Node {
        label: label.clone(),
        sub_witness: Box::new(Witness::Pruned {
            digest: compute_leaf_digest(value.as_bytes()),
        }),
    };

    // Inconsistency at `/label`.
    let expected_err = TreeHashError::InconsistentPartialTree {
        offending_path: vec![label],
    };
    assert_eq!(
        Err(expected_err.clone()),
        prune_witness(&invalid_witness, &labeled_tree)
    );
    assert_eq!(
        Err(expected_err),
        recompute_digest(&labeled_tree, &invalid_witness)
    );
}

/// Ensures that a witness with a pruned leaf causes both `prune_witness()` and
/// `recompute_digest()` to fail if trying to prune the leaf again.
#[test]
fn prune_witness_prune_already_pruned_leaf_only() {
    let value = "value";

    // A `LabeledTree` consisting of a single label and value:
    //
    // ```
    // (root)
    //    \__ "value"
    // ```
    let labeled_tree = LabeledTree::Leaf(value.into());

    // An witness with the leaf already pruned.
    //
    // ```
    // (root)
    //    \__ [Pruned]
    // ```
    let witness = Witness::Pruned {
        digest: compute_leaf_digest(value.as_bytes()),
    };

    // Inconsistency in the root.
    let expected_err = TreeHashError::InconsistentPartialTree {
        offending_path: vec![],
    };
    assert_eq!(
        Err(expected_err.clone()),
        prune_witness(&witness, &labeled_tree)
    );
    assert_eq!(Err(expected_err), recompute_digest(&labeled_tree, &witness));
}

#[test]
fn sub_witness_test() {
    let l1 = Label::from("1");
    let l2 = Label::from("2");
    let l3 = Label::from("3");

    let witness = Witness::make_fork(
        Witness::make_fork(
            Witness::make_pruned(compute_leaf_digest(b"")),
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
    let pruned = Witness::make_pruned(compute_leaf_digest(b""));
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
            Witness::make_pruned(compute_leaf_digest(b"")),
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
    let pruned = Witness::make_pruned(compute_leaf_digest(b""));
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

#[test]
fn labeled_tree_lookup_lower_bound() {
    use LabeledTree::{Leaf, SubTree};
    let b_leaf = Leaf(b"leaf_b".to_vec());
    let c_leaf = Leaf(b"leaf_c".to_vec());
    let a_subtree = SubTree(flatmap! {
            Label::from("b") => b_leaf.clone()
    });

    let t: LabeledTree<Vec<u8>> = SubTree(flatmap! {
        Label::from("sig") => SubTree(flatmap!{
                Label::from("a") => a_subtree.clone(),
                Label::from("c") => c_leaf.clone(),
        })
    });

    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..], &b"a"[..]], &b"b"[..]),
        LookupLowerBoundStatus::Found(&Label::from("b"), &b_leaf)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..], &b"a"[..]], &b"c"[..]),
        LookupLowerBoundStatus::Found(&Label::from("b"), &b_leaf)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..], &b"a"[..]], &b"a"[..]),
        LookupLowerBoundStatus::LabelNotFound
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..]], &b"d"[..]),
        LookupLowerBoundStatus::Found(&Label::from("c"), &c_leaf)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..]], &b"c"[..]),
        LookupLowerBoundStatus::Found(&Label::from("c"), &c_leaf)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..]], &b"b"[..]),
        LookupLowerBoundStatus::Found(&Label::from("a"), &a_subtree)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..]], &b"a"[..]),
        LookupLowerBoundStatus::Found(&Label::from("a"), &a_subtree)
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..]], &b"0"[..]),
        LookupLowerBoundStatus::LabelNotFound
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..], &b"missing"[..]], &b"0"[..]),
        LookupLowerBoundStatus::PrefixNotFound
    );
    assert_eq!(
        lookup_lower_bound(&t, &[&b"sig"[..], &b"c"[..]], &b"0"[..]),
        LookupLowerBoundStatus::PrefixNotFound
    );
}

#[test]
fn mixed_hash_tree_lookup() {
    use LookupStatus::{Absent, Found, Unknown};
    use MixedHashTree::{Empty, Leaf};

    let t = mfork(
        mlabeled(&Label::from("1"), mleaf("test1")),
        mlabeled(&Label::from("3"), mleaf("test3")),
    );
    assert_eq!(t.lookup(&[b"0"]), Absent);
    assert_eq!(t.lookup(&[b"1"]), Found(&mleaf("test1")));
    assert_eq!(t.lookup(&[b"2"]), Absent);
    assert_eq!(t.lookup(&[b"3"]), Found(&mleaf("test3")));
    assert_eq!(t.lookup(&[b"4"]), Absent);
    assert_eq!(t.lookup(&[&b"3"[..], &b"nope"[..]]), Absent);

    let t = mfork(
        mpruned(&Digest([0u8; 32])),
        mlabeled(&Label::from("3"), mleaf("test3")),
    );
    assert_eq!(t.lookup(&[b"2"]), Unknown);
    assert_eq!(t.lookup(&[b"3"]), Found(&mleaf("test3")));
    assert_eq!(t.lookup(&[b"4"]), Absent);

    let t = mfork(
        mlabeled(&Label::from("3"), mleaf("test3")),
        mpruned(&Digest([0u8; 32])),
    );
    assert_eq!(t.lookup(&[b"2"]), Absent);
    assert_eq!(t.lookup(&[b"3"]), Found(&mleaf("test3")));
    assert_eq!(t.lookup(&[b"4"]), Unknown);

    assert_eq!(Empty.lookup::<&[u8]>(&[]), Found(&Empty));
    assert_eq!(Empty.lookup(&[b"1"]), Absent);
    assert_eq!(Empty.lookup(&[b"1", b"2"]), Absent);

    let tree = mfork(
        mlabeled(&Label::from("1"), Empty),
        mfork(
            mpruned(&Digest([1; 32])),
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
        ),
    );

    assert_eq!(tree.lookup(&[b"0"]), Absent);
    assert_eq!(tree.lookup(&[b"1"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"2"]), Unknown);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Absent);

    let tree = mfork(
        mlabeled(&Label::from("1"), Empty),
        mfork(
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
            mpruned(&Digest([1; 32])),
        ),
    );

    assert_eq!(tree.lookup(&[b"0"]), Absent);
    assert_eq!(tree.lookup(&[b"1"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"2"]), Absent);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Unknown);

    let tree = mfork(
        mpruned(&Digest([0; 32])),
        mfork(
            mpruned(&Digest([1; 32])),
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
        ),
    );

    assert_eq!(tree.lookup(&[b"2"]), Unknown);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Absent);

    let tree = mfork(
        mpruned(&Digest([0; 32])),
        mfork(
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
            mpruned(&Digest([1; 32])),
        ),
    );

    assert_eq!(tree.lookup(&[b"2"]), Unknown);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Unknown);

    let tree = mfork(
        mfork(
            mpruned(&Digest([1; 32])),
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
        ),
        mlabeled(&Label::from("7"), Empty),
    );

    assert_eq!(tree.lookup(&[b"2"]), Unknown);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Absent);
    assert_eq!(tree.lookup(&[b"7"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"8"]), Absent);

    let tree = mfork(
        mfork(
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
            mpruned(&Digest([1; 32])),
        ),
        mlabeled(&Label::from("7"), Empty),
    );

    assert_eq!(tree.lookup(&[b"2"]), Absent);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Unknown);
    assert_eq!(tree.lookup(&[b"7"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"8"]), Absent);

    let tree = mfork(
        mfork(
            mpruned(&Digest([1; 32])),
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
        ),
        mpruned(&Digest([0; 32])),
    );

    assert_eq!(tree.lookup(&[b"2"]), Unknown);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Unknown);

    let tree = mfork(
        mfork(
            mfork(
                mlabeled(&Label::from("3"), Leaf(vec![1, 2, 3, 4, 5, 6])),
                mlabeled(&Label::from("5"), Empty),
            ),
            mpruned(&Digest([1; 32])),
        ),
        mpruned(&Digest([0; 32])),
    );

    assert_eq!(tree.lookup(&[b"2"]), Absent);
    assert_eq!(tree.lookup(&[b"3"]), Found(&Leaf(vec![1, 2, 3, 4, 5, 6])));
    assert_eq!(tree.lookup(&[b"4"]), Absent);
    assert_eq!(tree.lookup(&[b"5"]), Found(&Empty));
    assert_eq!(tree.lookup(&[b"6"]), Unknown);
}

#[test]
fn labeled_tree_conversion() {
    use MixedHashTreeConversionError::Pruned;
    type R = Result<LabeledTree<Vec<u8>>, MixedHashTreeConversionError>;

    assert_eq!(gmpruned([0; 32]).try_into() as R, Err(Pruned));
    assert_eq!(
        mfork(gmpruned([0; 32]), gmpruned([0; 32])).try_into() as R,
        Err(Pruned)
    );

    assert_eq!(
        gmlabeled("a", gmpruned([0; 32])).try_into() as R,
        Ok(LabeledTree::SubTree(flatmap! {}))
    );

    assert_eq!(
        mfork(
            gmlabeled("a", gmpruned([0; 32])),
            gmlabeled("b", gmpruned([0; 32])),
        )
        .try_into() as R,
        Ok(LabeledTree::SubTree(flatmap! {}))
    );

    assert_eq!(
        mfork(
            gmlabeled("a", gmpruned([0; 32])),
            gmlabeled("b", gmpruned([0; 32])),
        )
        .try_into() as R,
        Ok(LabeledTree::SubTree(flatmap! {}))
    );

    assert_eq!(
        mfork(
            gmlabeled("a", mleaf("abcd")),
            gmlabeled("b", gmpruned([0; 32]))
        )
        .try_into() as R,
        Ok(LabeledTree::SubTree(
            flatmap! { Label::from("a") => LabeledTree::Leaf(b"abcd".to_vec()) }
        ))
    );

    assert_eq!(
        mfork(
            gmlabeled("a", gmpruned([0; 32])),
            gmlabeled("b", mleaf("abcd")),
        )
        .try_into() as R,
        Ok(LabeledTree::SubTree(
            flatmap! { Label::from("b") => LabeledTree::Leaf(b"abcd".to_vec()) }
        ))
    );

    assert_eq!(
        mfork(gmlabeled("a", mleaf("abcd")), gmpruned([0; 32])).try_into() as R,
        Ok(LabeledTree::SubTree(
            flatmap! { Label::from("a") => LabeledTree::Leaf(b"abcd".to_vec()) }
        ))
    );

    assert_eq!(
        mfork(gmpruned([0; 32]), gmlabeled("b", mleaf("abcd")),).try_into() as R,
        Ok(LabeledTree::SubTree(
            flatmap! { Label::from("b") => LabeledTree::Leaf(b"abcd".to_vec()) }
        ))
    );
}

#[test]
fn hash_tree_builders_debug_output_gets_truncated_on_deep_trees() {
    const DUMMY_LABEL: &str = "dummy label";
    const MAX_DEPTH: usize = 50;
    const TRUNCATION_MSG: &str = "... Further levels of the tree are truncated";

    let hash_tree_with_depth = |depth| -> HashTreeBuilderImpl {
        let mut builder = HashTreeBuilderImpl::default();
        for _ in 0..depth - 1 {
            builder.start_subtree();
            builder.new_edge(Label::from(DUMMY_LABEL.as_bytes()));
        }

        builder.start_leaf();
        builder.write_leaf(b"dummy leaf");
        builder.finish_leaf();

        for _ in 0..depth - 1 {
            builder.finish_subtree();
        }

        builder
    };

    // trees of depth less than or equal to `MAX_DEPTH` should not be truncated
    for depth in 1..=MAX_DEPTH {
        let output = format!("{:?}", hash_tree_with_depth(depth));
        assert!(!output.contains(TRUNCATION_MSG), "{output:?}");
    }

    // trees of depth higher than `MAX_DEPTH` should be truncated
    for depth in [MAX_DEPTH + 1, MAX_DEPTH + 100, MAX_DEPTH + 1000] {
        let output = format!("{:?}", hash_tree_with_depth(depth));
        assert!(output.contains(TRUNCATION_MSG), "{output:?}");
        assert_eq!(
            output.matches(DUMMY_LABEL).count(),
            // both hash and labeled tree are printed
            MAX_DEPTH * 2,
            "{output:?}"
        );
    }
}

#[test]
fn labeled_tree_leaf_count() {
    /// Counts the number of leaves and empty subtree nodes in a labeled tree.
    fn count_leaves_and_empty_subtrees<T>(tree: &LabeledTree<T>) -> u64 {
        match tree {
            LabeledTree::SubTree(children) if children.is_empty() => {
                // Pruning treats empty subtree hashes in the same way as leaves
                // in that their hash is computed and plugged into the witness if
                // they are present in the labeled tree, and left in place otherwise.
                // Hence we also count them here.
                1
            }
            LabeledTree::SubTree(children) if !children.is_empty() => children
                .iter()
                .map(|(_, tree)| count_leaves_and_empty_subtrees(tree))
                .sum(),
            LabeledTree::SubTree(_) => unreachable!(),
            LabeledTree::Leaf(_) => 1,
        }
    }

    let tree = LabeledTree::Leaf(());
    assert_eq!(count_leaves_and_empty_subtrees(&tree), 1);

    let tree: LabeledTree<()> = LabeledTree::SubTree(FlatMap::new());
    assert_eq!(count_leaves_and_empty_subtrees(&tree), 1);

    // Construct a more complex labeled tree of the form
    //
    // + -- 1 -- Leaf(())
    // |
    // | -- 2 -- Leaf(())
    // |
    // | -- 3 -- EMPTY_SUBTREE
    // |
    // | -- 4 -- + -- 5 -- Leaf(())
    //           |
    //           | -- 6 -- EMPTY_SUBTREE
    //           |
    //           | -- 7 -- + -- 8 -- Leaf(())
    //           |
    //           | -- 9 -- + -- 10 -- Leaf(())
    //                     |
    //                     | -- 11 -- Leaf(())
    //
    let tree = LabeledTree::SubTree(FlatMap::from_key_values(vec![
        ("1".into(), LabeledTree::Leaf(())),
        ("2".into(), LabeledTree::Leaf(())),
        ("3".into(), LabeledTree::SubTree(FlatMap::new())),
        (
            "4".into(),
            LabeledTree::SubTree(FlatMap::from_key_values(vec![
                ("5".into(), LabeledTree::Leaf(())),
                ("6".into(), LabeledTree::SubTree(FlatMap::new())),
                (
                    "7".into(),
                    LabeledTree::SubTree(FlatMap::from_key_values(vec![(
                        "8".into(),
                        LabeledTree::Leaf(()),
                    )])),
                ),
                (
                    "9".into(),
                    LabeledTree::SubTree(FlatMap::from_key_values(vec![
                        ("10".into(), LabeledTree::Leaf(())),
                        ("11".into(), LabeledTree::Leaf(())),
                    ])),
                ),
            ])),
        ),
    ]));

    // The tree above has 6 leaves and 2 empty subtress. So we expect
    // count_leaves to return 8.
    assert_eq!(count_leaves_and_empty_subtrees(&tree), 8);
}

#[test]
fn witness_for_a_labeled_tree_does_not_contain_private_data() {
    /// the maximum depth of the generated random [`LabeledTree`]
    const RANDOM_TREE_MAX_DEPTH: u32 = 10;
    /// The probability of generating a subtree from the root node, which
    /// continuously decreases with larger tree depth
    const RANDOM_TREE_DESIRED_SIZE: u32 = 1000;

    let rng = &mut reproducible_rng();

    // Minimum number of leaves in the generated random `LabeledTree`
    for min_leaves in [0, 5, 10, 15, 20] {
        let labeled_tree = new_random_labeled_tree(
            rng,
            RANDOM_TREE_MAX_DEPTH,
            RANDOM_TREE_DESIRED_SIZE,
            min_leaves,
        );
        witness_for_a_labeled_tree_does_not_contain_private_data_impl(&labeled_tree, rng);
    }
}

fn witness_for_a_labeled_tree_does_not_contain_private_data_impl<R: RngCore + CryptoRng>(
    labeled_tree: &LabeledTree<Vec<u8>>,
    rng: &mut R,
) {
    let builder = hash_tree_builder_from_labeled_tree(labeled_tree);

    // split the tree into paths with exactly one leaf or empty subtree at the end
    let leaf_partial_trees = partial_trees_to_leaves_and_empty_subtrees(labeled_tree);
    assert!(!leaf_partial_trees.is_empty());
    let full_tree_witness = builder
        .witness_generator()
        .unwrap()
        .witness(labeled_tree)
        .expect("Failed to generate a witness");
    let root_hash = recompute_digest(labeled_tree, &full_tree_witness)
        .expect("Failed to compute the root hash");

    if leaf_partial_trees.len() == 1 {
        assert!(
            witness_contains_only_nodes_and_known(&full_tree_witness),
            "{full_tree_witness:?}"
        );
        return;
    }

    // test witness generated from a single leaf for each leaf
    for i in 0..leaf_partial_trees.len() {
        witness_for_a_labeled_tree_does_not_contain_private_data_multileaf(
            labeled_tree,
            &[i],
            &leaf_partial_trees[..],
            &full_tree_witness,
            &root_hash,
            &builder,
            rng,
        );
    }

    const NUM_ITERATIONS: usize = 10;
    let num_selected_leaves = leaf_partial_trees.len() / 2;
    for _ in 0..NUM_ITERATIONS {
        // `NUMBER_OF_RANDOM_LEAVES` random indexes
        let mut indexes =
            rand::seq::index::sample(rng, leaf_partial_trees.len(), num_selected_leaves).into_vec();
        indexes.sort_unstable();
        witness_for_a_labeled_tree_does_not_contain_private_data_multileaf(
            labeled_tree,
            &indexes[..],
            &leaf_partial_trees[..],
            &full_tree_witness,
            &root_hash,
            &builder,
            rng,
        );

        // `NUMBER_OF_RANDOM_LEAVES` *consecutive* random indexes
        let start: usize = rng.random_range(0..num_selected_leaves);
        let indexes: Vec<_> = (start..start + num_selected_leaves).collect();
        witness_for_a_labeled_tree_does_not_contain_private_data_multileaf(
            labeled_tree,
            &indexes[..],
            &leaf_partial_trees[..],
            &full_tree_witness,
            &root_hash,
            &builder,
            rng,
        );
    }
}

/// Combines paths to multiple leaves/empty subtrees in the test.
fn witness_for_a_labeled_tree_does_not_contain_private_data_multileaf<R: RngCore + CryptoRng>(
    labeled_tree: &LabeledTree<Vec<u8>>,
    leaf_indexes: &[usize],
    leaf_partial_trees: &[LabeledTree<Vec<u8>>],
    full_tree_witness: &Witness,
    root_hash: &Digest,
    builder: &HashTreeBuilderImpl,
    rng: &mut R,
) {
    for w in leaf_indexes.windows(2) {
        assert_ne!(w[0], w[1], "Leaf indexes must be unique");
        assert!(
            w[0] < w[1],
            "Leaf indexes must be sorted in ascending order: {w:?}"
        );
    }

    // aggregate paths to leaves/empty subtrees indexed by `leaf_indexes` to a tree
    let mut aggregated_partial_tree = leaf_partial_trees[leaf_indexes[0]].clone();
    for i in leaf_indexes[1..].iter() {
        merge_path_into_labeled_tree(&mut aggregated_partial_tree, &leaf_partial_trees[*i]);
    }

    // pruning from the full tree the same subtree twice should return an error
    let pruned_witness = prune_witness(full_tree_witness, &aggregated_partial_tree)
        .expect("Failed to prune one leaf from a full tree witness");

    let mut pruned_full_tree = labeled_tree.clone();
    for i in leaf_indexes.iter() {
        pruned_full_tree =
            labeled_tree_without_leaf_or_empty_subtree(&pruned_full_tree, &leaf_partial_trees[*i]);
    }

    assert_eq!(
        recompute_digest(&pruned_full_tree, &pruned_witness,).expect("Failed to recompute_digest"),
        *root_hash,
    );

    assert_matches!(
        prune_witness(&pruned_witness, &aggregated_partial_tree),
        Err(TreeHashError::InconsistentPartialTree { offending_path }) // we might prune more than just the `Leaf`
        if labeled_tree_contains_prefix(&aggregated_partial_tree, &offending_path[..])
    );

    for single_path in partial_trees_to_leaves_and_empty_subtrees(&aggregated_partial_tree) {
        assert_matches!(
            prune_witness(&pruned_witness, &single_path),
            Err(TreeHashError::InconsistentPartialTree { offending_path })
            // we might prune more than just the `Leaf`
            if labeled_tree_contains_prefix(&single_path, &offending_path[..])
        );
    }

    // generate a witness for the aggregated tree
    let mut witness = builder
        .witness_generator()
        .unwrap()
        .witness(&aggregated_partial_tree)
        .expect("Failed to generate a witness");
    let num_known_nodes =
        check_leaves_and_empty_subtrees_are_known(&aggregated_partial_tree, &witness);
    let num_leaves = get_num_leaves_and_empty_subtrees(&aggregated_partial_tree);
    assert_eq!(num_leaves, leaf_indexes.len());
    assert_eq!(num_known_nodes, num_leaves);

    let pruned_witness = prune_witness(&witness, &aggregated_partial_tree);
    // completely pruned the witness should yield the correct root hash
    assert_matches!(
        &pruned_witness,
        Ok(Witness::Pruned { digest }) if digest == root_hash
    );

    // pruning a witness twice should return an error
    assert_matches!(
        prune_witness(&pruned_witness.expect("Failed to prune witness"), &aggregated_partial_tree),
        Err(TreeHashError::InconsistentPartialTree { offending_path }) if offending_path.is_empty()
    );

    // if we replace any `Witness::Known` with `Witness::Pruned` node, `prune_witness` should error
    let mut expected_offending_paths = vec![];

    for _ in 0..num_leaves {
        expected_offending_paths.push(replace_random_known_with_dummy_pruned(&mut witness, rng));
        assert_matches!(
            prune_witness(&witness, &aggregated_partial_tree),
            Err(TreeHashError::InconsistentPartialTree { offending_path })
            if expected_offending_paths.contains(&offending_path)
        );
    }
}

#[test]
fn pruning_depth_0_tree_works_correctly() {
    fn depth_0_inputs() -> Vec<(LabeledTree<Vec<u8>>, Digest)> {
        vec![
            (
                LabeledTree::Leaf(b"dummy leaf".to_vec()),
                compute_leaf_digest(&b"dummy leaf".to_vec()[..]),
            ),
            (LabeledTree::SubTree(FlatMap::new()), empty_subtree_hash()),
        ]
    }
    use rand::Rng;
    let rng = &mut reproducible_rng();
    const RANDOM_TREE_MAX_DEPTH: u32 = 10;

    for (labeled_tree, expected_hash) in depth_0_inputs() {
        let builder = hash_tree_builder_from_labeled_tree(&labeled_tree);

        let witness = builder
            .witness_generator()
            .unwrap()
            .witness(&labeled_tree)
            .expect("Failed to generate a witness");
        assert_eq!(&witness, &Witness::Known());
        assert_eq!(recompute_digest(&labeled_tree, &witness), Ok(expected_hash));

        // generate 10 random invalid trees and check that we cannot 1) generate
        // a witness and 2) recompute the hash using the wrong tree
        for _ in 0..10 {
            let random_tree_desired_size: u32 = rng.random_range(1..100);
            let min_leaves = rng.random_range(0..10);
            let other_labeled_tree = new_random_labeled_tree(
                rng,
                RANDOM_TREE_MAX_DEPTH,
                random_tree_desired_size,
                min_leaves,
            );
            if other_labeled_tree == labeled_tree {
                continue;
            }

            let other_has_depth_gt_0 = matches!(&other_labeled_tree, LabeledTree::SubTree(children) if !children.is_empty());
            if other_has_depth_gt_0 {
                let computed_witness = builder
                    .witness_generator()
                    .unwrap()
                    .witness(&other_labeled_tree);
                let expected_witness = if matches!(&labeled_tree, LabeledTree::Leaf(_)) {
                    Witness::Pruned {
                        digest: builder.as_hash_tree().unwrap().digest().clone(),
                    }
                } else {
                    Witness::Known()
                };
                // any attempt to generate a witness should result in the same witness
                assert_eq!(
                    computed_witness.as_ref(),
                    Ok(&expected_witness),
                    "labeled_tree={labeled_tree:?}, other_labeled_tree={other_labeled_tree:?}"
                );
                // A labeled tree with depth > 0 can't be plugged in to
                // `witness`, which equals `Witness::Known`.
                // Therefore, any attempt to `recompute_digest` or `prune_witness` with any
                // other tree of depth > 0 should error.
                assert_eq!(
                    recompute_digest(&other_labeled_tree, &witness),
                    Err(TreeHashError::InconsistentPartialTree {
                        offending_path: vec![]
                    }),
                    "witness={witness:?}, other_labeled_tree={other_labeled_tree:?}"
                );
                assert_eq!(
                    prune_witness(&witness, &other_labeled_tree),
                    Err(TreeHashError::InconsistentPartialTree {
                        offending_path: vec![]
                    })
                );
            }
        }
    }
}

#[test]
fn pruning_witness_pruned_in_the_root_fails_for_any_labeled_tree() {
    use rand::Rng;
    let rng = &mut reproducible_rng();
    const RANDOM_TREE_MAX_DEPTH: u32 = 10;
    let random_tree_desired_size: u32 = rng.random_range(1..100);
    let min_leaves = rng.random_range(0..10);
    const WITNESS: Witness = Witness::Pruned {
        digest: Digest([0u8; Sha256::DIGEST_LEN]),
    };
    for _ in 0..10 {
        let labeled_tree = new_random_labeled_tree(
            rng,
            RANDOM_TREE_MAX_DEPTH,
            random_tree_desired_size,
            min_leaves,
        );
        assert_eq!(
            recompute_digest(&labeled_tree, &WITNESS),
            Err(TreeHashError::InconsistentPartialTree {
                offending_path: vec![]
            })
        );
        assert_eq!(
            prune_witness(&WITNESS, &labeled_tree),
            Err(TreeHashError::InconsistentPartialTree {
                offending_path: vec![]
            })
        );
    }
}

#[test]
fn witness_for_a_leaf_returns_pruned_for_a_subtree() {
    // For the trees
    //
    //    +-- label_b
    //           \__ leaf
    //
    // should return the following Witness
    //    +-- Pruned
    //    +-- label_b
    //           \__ Pruned

    let partial_tree = LabeledTree::SubTree(flatmap!(
        Label::from("label_b") => LabeledTree::Leaf(Vec::from("v"))
    ));

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();

    let res = witness_generator.witness(&partial_tree);
    let root_nodes = builder
        .as_hash_tree()
        .expect("failed to generate hash tree");

    let expected_result = Ok(Witness::Fork {
        left_tree: Box::new(Witness::Pruned {
            digest: root_nodes.left_tree().digest().clone(),
        }),
        right_tree: Box::new(Witness::Node {
            label: Label::from("label_b"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.right_tree().node_tree().digest().clone(),
            }),
        }),
    });
    assert_eq!(res, expected_result);
}

#[test]
fn witness_for_a_subtree_returns_pruned_for_a_leaf() {
    // For the tree
    //
    //    +-- label_a
    //           \__ label_b
    //                  \__ leaf
    //
    // should return the following Witness
    //    +-- label_a
    //           \__ Pruned
    //    +-- Pruned

    let partial_tree = LabeledTree::SubTree(flatmap!(
        Label::from("label_a") => LabeledTree::SubTree(flatmap!(
        Label::from("label_b") => LabeledTree::Leaf(Vec::from("v"))
    ))));

    let builder = tree_with_a_subtree();
    let witness_generator = builder.witness_generator().unwrap();

    let res = witness_generator.witness(&partial_tree);
    let root_nodes = builder
        .as_hash_tree()
        .expect("failed to generate hash tree");

    let expected_result = Ok(Witness::Fork {
        left_tree: Box::new(Witness::Node {
            label: Label::from("label_a"),
            sub_witness: Box::new(Witness::Pruned {
                digest: root_nodes.left_tree().node_tree().digest().clone(),
            }),
        }),
        right_tree: Box::new(Witness::Pruned {
            digest: root_nodes.right_tree().digest().clone(),
        }),
    });
    assert_eq!(res, expected_result);
}

#[test]
fn labeled_tree_does_not_produce_stack_overflow_for_deep_trees() {
    let mut tree = LabeledTree::Leaf(vec![0u8; 32]);
    for _ in 0..100_000 {
        tree = LabeledTree::SubTree(flatmap! {
            Label::from("a") => tree
        });
    }
    println!("dropping tree");
    std::mem::drop(tree);
    println!("tree dropped");
}

#[test]
fn witness_generator_exceeding_recursion_depth_should_error() {
    let mut labeled_tree = LabeledTree::Leaf(vec![0u8; 32]);
    for _ in 1..MAX_HASH_TREE_DEPTH {
        labeled_tree = LabeledTree::SubTree(flatmap! {
            Label::from("a") => labeled_tree
        });
    }

    // valid tree depth succeeds
    let builder: HashTreeBuilderImpl = hash_tree_builder_from_labeled_tree(&labeled_tree);
    let witness_generator = builder.witness_generator().unwrap();

    let res_w = witness_generator.witness(&labeled_tree);
    assert_matches!(res_w, Ok(_));
    let res_mht = witness_generator.mixed_hash_tree(&labeled_tree);
    assert_matches!(res_mht, Ok(_));

    labeled_tree = LabeledTree::SubTree(flatmap! {
        Label::from("a") => labeled_tree
    });

    // too deep recursion errors
    let builder: HashTreeBuilderImpl = hash_tree_builder_from_labeled_tree(&labeled_tree);
    let witness_generator = builder.witness_generator().unwrap();

    let res_w = witness_generator.witness(&labeled_tree);
    assert_eq!(
        res_w,
        Err(WitnessGenerationError::TooDeepRecursion(
            MAX_HASH_TREE_DEPTH + 1
        ))
    );
    let res_mht = witness_generator.mixed_hash_tree(&labeled_tree);
    assert_eq!(
        res_mht,
        Err(WitnessGenerationError::TooDeepRecursion(
            MAX_HASH_TREE_DEPTH + 1
        ))
    );
}

#[test]
fn filtered_mixed_hash_tree() {
    let label_a = Label::from("label_a");
    let label_a_3 = Label::from("label_a_3");
    let label_a_3_2 = Label::from("label_a_3_2");
    let label_b = Label::from("label_b");
    let label_b_2 = Label::from("label_b_2");
    let label_b_4 = Label::from("label_b_4");
    let label_b_4_3 = Label::from("label_b_4_3");
    let label_c = Label::from("label_c");

    let subtree_a_3_map = flatmap!(
        label_a_3_2 => LabeledTree::Leaf(Vec::from("contents_a_3_2")));
    let subtree_a_map = flatmap!(
        label_a_3 => LabeledTree::SubTree(subtree_a_3_map),
    );
    let subtree_b_4_map = flatmap!(
        label_b_4_3 => LabeledTree::Leaf(Vec::from("contents_b_4_3")));
    let subtree_b_map = flatmap!(
        label_b_2 => LabeledTree::SubTree(FlatMap::new()),
        label_b_4.clone() => LabeledTree::SubTree(subtree_b_4_map.clone()),
    );
    let root_map = flatmap!(
        label_a.clone() => LabeledTree::SubTree(subtree_a_map.clone()),
        label_b.clone() => LabeledTree::SubTree(subtree_b_map),
        label_c => LabeledTree::Leaf(Vec::from("contents_c")),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_three_levels();
    let witness_generator = builder.witness_generator().unwrap();
    let mixed_hash_tree = witness_generator.mixed_hash_tree(&partial_tree).unwrap();
    let digest = mixed_hash_tree.digest();
    assert_eq!(*witness_generator.hash_tree().digest(), digest);

    let filter_builder = mixed_hash_tree.filter_builder();
    assert_eq!(filter_builder.digest(), &digest);

    let partial_tree = sparse_labeled_tree_from_paths(&[
        Path::from(vec![
            "label_a".into(),
            "label_a_3".into(),
            "label_a_3_2".into(),
        ]),
        Path::from(vec!["label_b".into(), "label_b_4".into()]),
    ])
    .unwrap();

    let filtered_hash_tree = filter_builder.filtered(&partial_tree).unwrap();

    assert_eq!(digest, filtered_hash_tree.digest());

    let subtree_b_map_filtered = flatmap!(
        label_b_4 => LabeledTree::SubTree(subtree_b_4_map),
    );
    let smaller_root_map = flatmap!(
        label_a => LabeledTree::SubTree(subtree_a_map),
        label_b => LabeledTree::SubTree(subtree_b_map_filtered),
    );
    let smaller_partial_tree = LabeledTree::SubTree(smaller_root_map);

    let expected_hash_tree = witness_generator
        .mixed_hash_tree(&smaller_partial_tree)
        .unwrap();
    assert_eq!(expected_hash_tree, filtered_hash_tree);

    let too_long_partial_tree = sparse_labeled_tree_from_paths(&[Path::from(vec![
        "label_a".into(),
        "label_a_3".into(),
        "label_a_3_2".into(),
        "too_long".into(),
    ])])
    .unwrap();

    assert_eq!(
        filter_builder.filtered(&too_long_partial_tree),
        Err(MixedHashTreeFilterError::PathTooLong)
    );
}

#[test]
fn pruned_mixed_hash_tree() {
    let label_a = Label::from("label_a");
    let label_a_3 = Label::from("label_a_3");
    let label_a_3_2 = Label::from("label_a_3_2");
    let label_b = Label::from("label_b");
    let label_b_2 = Label::from("label_b_2");
    let label_b_4 = Label::from("label_b_4");
    let label_b_4_3 = Label::from("label_b_4_3");
    let label_c = Label::from("label_c");

    let subtree_a_3_map = flatmap!(
        label_a_3_2 => LabeledTree::Leaf(Vec::from("contents_a_3_2")));
    let subtree_a_map = flatmap!(
        label_a_3.clone() => LabeledTree::SubTree(subtree_a_3_map),
    );
    let subtree_b_4_map = flatmap!(
        label_b_4_3 => LabeledTree::Leaf(Vec::from("contents_b_4_3")));
    let subtree_b_map = flatmap!(
        label_b_2.clone() => LabeledTree::SubTree(FlatMap::new()),
        label_b_4 => LabeledTree::SubTree(subtree_b_4_map.clone()),
    );
    let root_map = flatmap!(
        label_a.clone() => LabeledTree::SubTree(subtree_a_map.clone()),
        label_b.clone() => LabeledTree::SubTree(subtree_b_map),
        label_c => LabeledTree::Leaf(Vec::from("contents_c")),
    );
    let partial_tree = LabeledTree::SubTree(root_map);

    let builder = tree_with_three_levels();
    let witness_generator = builder.witness_generator().unwrap();
    let mixed_hash_tree = witness_generator.mixed_hash_tree(&partial_tree).unwrap();
    let digest = mixed_hash_tree.digest();
    assert_eq!(*witness_generator.hash_tree().digest(), digest);

    let filter_builder = mixed_hash_tree.filter_builder();
    assert_eq!(filter_builder.digest(), &digest);

    let dropped_paths = sparse_labeled_tree_from_paths(&[
        Path::from(vec![
            "label_a".into(),
            "label_a_3".into(),
            "label_a_3_2".into(),
        ]),
        Path::from(vec!["label_b".into(), "label_b_4".into()]),
        Path::from(vec!["label_c".into()]),
    ])
    .unwrap();

    let filtered_hash_tree = filter_builder.pruned(&dropped_paths).unwrap();

    assert_eq!(digest, filtered_hash_tree.digest());

    let subtree_a_map_filtered = flatmap!(
        label_a_3 => LabeledTree::SubTree(FlatMap::new()),
    );

    let subtree_b_map_filtered = flatmap!(
        label_b_2 => LabeledTree::SubTree(FlatMap::new()),
    );
    let smaller_root_map = flatmap!(
        label_a => LabeledTree::SubTree(subtree_a_map_filtered),
        label_b => LabeledTree::SubTree(subtree_b_map_filtered),
    );
    let smaller_partial_tree = LabeledTree::SubTree(smaller_root_map);

    let expected_hash_tree = witness_generator
        .mixed_hash_tree(&smaller_partial_tree)
        .unwrap();
    assert_eq!(expected_hash_tree, filtered_hash_tree);

    let too_long_partial_tree = sparse_labeled_tree_from_paths(&[Path::from(vec![
        "label_a".into(),
        "label_a_3".into(),
        "label_a_3_2".into(),
        "too_long".into(),
    ])])
    .unwrap();

    assert_eq!(
        filter_builder.pruned(&too_long_partial_tree),
        Err(MixedHashTreeFilterError::PathTooLong)
    );
}
