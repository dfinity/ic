use super::*;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_crypto_tree_hash::{Label, LabeledTree, flatmap};

pub fn v(v: Vec<u8>) -> LabeledTree<Vec<u8>> {
    LabeledTree::<Vec<u8>>::Leaf(v)
}

pub fn l(v: &[u8]) -> Label {
    Label::from(v.to_vec())
}

macro_rules! subtree {
    ( $($key:expr => $value:expr),* ) => { LabeledTree::<Vec<u8>>::SubTree(flatmap!($(l($key) => $value),*)) };
}

macro_rules! subtree_empty_values {
    ( $($key:expr),* ) => { LabeledTree::<Vec<u8>>::SubTree(flatmap!($(l($key) => v(vec![])),*)) };
}

#[test]
fn get_num_leaves_works_correctly() {
    assert_eq!(get_num_leaves(&subtree!()), 0);
    assert_eq!(get_num_leaves(&subtree_empty_values!(b"a")), 1);
    assert_eq!(get_num_leaves(&subtree_empty_values!(b"a", b"b")), 2);

    assert_eq!(
        get_num_leaves(&subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"d" => v(vec![]),
            b"e" => subtree_empty_values!(b"f", b"g")
        )),
        5
    );
}

#[test]
fn try_remove_leaf_removes_leaves_correctly() {
    let rng = &mut ReproducibleRng::new();

    let mut empty_tree = subtree!();
    try_remove_leaf(&mut empty_tree, rng);
    assert_eq!(empty_tree, subtree!());

    let mut one_leaf_tree = subtree_empty_values!(b"1");
    try_remove_leaf(&mut one_leaf_tree, rng);
    assert_eq!(one_leaf_tree, empty_tree);

    let mut five_leaf_tree = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(b"f" => subtree_empty_values!(b"g")),
        b"h" => subtree_empty_values!(b"i", b"j")
    );

    assert_eq!(get_num_leaves(&five_leaf_tree), 5);

    for i in 1..=5 {
        try_remove_leaf(&mut five_leaf_tree, rng);
        assert_eq!(get_num_leaves(&five_leaf_tree), 5 - i);
    }

    try_remove_leaf(&mut five_leaf_tree, rng);
    assert_eq!(get_num_leaves(&five_leaf_tree), 0);

    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree!(),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree!()),
            b"h" => subtree!()
        )
    );
}

#[test]
fn remove_leaf_removes_leaves_correctly() {
    let mut one_leaf_tree = subtree_empty_values!(b"1");
    remove_leaf(&mut one_leaf_tree, 0);
    assert_eq!(one_leaf_tree, subtree!());

    let mut five_leaf_tree = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(b"f" => subtree_empty_values!(b"g")),
        b"h" => subtree_empty_values!(b"i", b"j")
    );

    assert_eq!(get_num_leaves(&five_leaf_tree), 5);

    remove_leaf(&mut five_leaf_tree, 3);
    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree_empty_values!(b"g")),
            b"h" => subtree_empty_values!(b"j")
        )
    );

    remove_leaf(&mut five_leaf_tree, 2);
    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree!()),
            b"h" => subtree_empty_values!(b"j")
        )
    );

    remove_leaf(&mut five_leaf_tree, 0);
    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree_empty_values!(b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree!()),
            b"h" => subtree_empty_values!(b"j")
        )
    );

    remove_leaf(&mut five_leaf_tree, 1);
    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree_empty_values!(b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree!()),
            b"h" => subtree!()
        )
    );

    remove_leaf(&mut five_leaf_tree, 0);
    assert_eq!(
        five_leaf_tree,
        subtree!(
            b"a" => subtree!(),
            b"d" => subtree!(),
            b"e" => subtree!(b"f" => subtree!()),
            b"h" => subtree!()
        )
    );
}

#[test]
fn paths_to_empty_subtrees_returns_correct_paths() {
    let empty_tree = subtree!();
    let empty_tree_paths = paths_to_empty_subtrees(&empty_tree);
    assert_eq!(empty_tree_paths.len(), 0);

    let two_empty_subtrees = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(
            b"f" => subtree_empty_values!(b"g"),
            b"h" => subtree!()
        ),
        b"i" => subtree_empty_values!(b"j", b"k")
    );

    let two_empty_subtrees_paths = paths_to_empty_subtrees(&two_empty_subtrees);
    assert_eq!(
        two_empty_subtrees_paths,
        vec![vec![&l(b"d")], vec![&l(b"e"), &l(b"h")]]
    );
}

#[test]
fn try_remove_empty_subtree_removes_empty_substrees_correctly() {
    let rng = &mut ReproducibleRng::new();

    let mut empty_tree = subtree!();
    try_remove_empty_subtree(&mut empty_tree, rng);
    assert_eq!(paths_to_empty_subtrees(&empty_tree).len(), 0);
    assert_eq!(empty_tree, subtree!());

    let mut two_empty_subtrees = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(
            b"f" => subtree_empty_values!(b"g"),
            b"h" => subtree!()
        ),
        b"i" => subtree_empty_values!(b"j", b"k")
    );

    try_remove_empty_subtree(&mut two_empty_subtrees, rng);
    assert_eq!(paths_to_empty_subtrees(&two_empty_subtrees).len(), 1);

    try_remove_empty_subtree(&mut two_empty_subtrees, rng);
    assert_eq!(paths_to_empty_subtrees(&two_empty_subtrees).len(), 0);

    assert_eq!(
        paths_to_empty_subtrees(&two_empty_subtrees),
        Vec::<Vec::<&Label>>::default()
    );
}

#[test]
fn remove_empty_subtree_in_path_removes_correct_empty_substrees() {
    let mut two_empty_subtrees = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(
            b"f" => subtree_empty_values!(b"g"),
            b"h" => subtree!()
        ),
        b"i" => subtree_empty_values!(b"j", b"k")
    );

    remove_empty_subtree_in_path(&mut two_empty_subtrees, &[l(b"d")]);
    assert_eq!(
        &two_empty_subtrees,
        &subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            ),
            b"i" => subtree_empty_values!(b"j", b"k")
        )
    );

    remove_empty_subtree_in_path(&mut two_empty_subtrees, &[l(b"e"), l(b"h")]);
    assert_eq!(
        &two_empty_subtrees,
        &subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g")
            ),
            b"i" => subtree_empty_values!(b"j", b"k")
        )
    );
}

#[test]
fn add_subtree_and_leaf_works_correctly() {
    let rng = &mut ReproducibleRng::new();
    let mut tree = subtree!();
    for i in 1..100 {
        add_leaf(&mut tree, rng);
        assert_eq!(get_num_leaves(&tree), i, "{tree:?}");
        add_empty_subtree(&mut tree, rng);
        assert_eq!(all_subtrees(&tree).len(), i + 1, "{tree:?}");
    }
}

#[test]
fn all_subtrees_finds_all_subtrees_correctly() {
    assert_eq!(all_subtrees(&subtree!()), vec![Vec::<&Label>::new()]);

    assert_eq!(
        all_subtrees(&subtree!(b"a" => subtree_empty_values!(b"b", b"c"))),
        vec![vec![], vec![&l(b"a")]]
    );

    assert_eq!(
        all_subtrees(&subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            ),
            b"i" => subtree_empty_values!(b"j", b"k")
        )),
        vec![
            vec![],
            vec![&l(b"a")],
            vec![&l(b"d")],
            vec![&l(b"e")],
            vec![&l(b"e"), &l(b"f")],
            vec![&l(b"e"), &l(b"h")],
            vec![&l(b"i")]
        ]
    );
}

#[test]
fn add_subtree_in_path_works_correctly() {
    let mut tree = subtree!();

    add_subtree_in_path(&mut tree, &[], l(b"d"), subtree!());
    assert_eq!(&tree, &subtree!(b"d" => subtree!()));

    add_subtree_in_path(&mut tree, &[], l(b"e"), subtree!());
    assert_eq!(&tree, &subtree!(b"d" => subtree!(), b"e" => subtree!()));

    add_subtree_in_path(&mut tree, &[l(b"e")], l(b"f"), subtree!());
    assert_eq!(
        &tree,
        &subtree!(
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree!()
            )
        )
    );

    add_subtree_in_path(&mut tree, &[l(b"e"), l(b"f")], l(b"g"), v(vec![]));
    assert_eq!(
        &tree,
        &subtree!(
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g")
            )
        )
    );

    add_subtree_in_path(&mut tree, &[l(b"e")], l(b"h"), subtree!());
    assert_eq!(
        &tree,
        &subtree!(
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            )
        )
    );

    add_subtree_in_path(&mut tree, &[], l(b"a"), subtree!());
    assert_eq!(
        &tree,
        &subtree!(
            b"a" => subtree!(),
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            )
        )
    );

    add_subtree_in_path(&mut tree, &[l(b"a")], l(b"b"), v(vec![]));
    assert_eq!(
        &tree,
        &subtree!(
            b"a" => subtree_empty_values!(b"b"),
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            )
        )
    );

    add_subtree_in_path(&mut tree, &[l(b"a")], l(b"c"), v(vec![]));

    assert_eq!(
        &tree,
        &subtree!(
            b"a" => subtree_empty_values!(b"b", b"c"),
            b"d" => subtree!(),
            b"e" => subtree!(
                b"f" => subtree_empty_values!(b"g"),
                b"h" => subtree!()
            )
        )
    );
}

#[test]
fn modify_leaf_modifies_correct_leaf() {
    let mut tree = subtree!(
        b"a" => subtree!(b"b" => v(vec![0]), b"c" => v(vec![1])),
        b"d" => subtree!(),
        b"e" => v(vec![2]),
        b"f" => subtree!(
            b"g" => subtree!(b"h" => v(vec![3]))
        )
    );

    let num_leaves = get_num_leaves(&tree);
    assert_eq!(num_leaves, 4);

    let modify_buffer = |buffer: &mut Vec<u8>| {
        for b in buffer.iter_mut() {
            *b += 1;
        }
        *buffer = [0]
            .iter()
            .chain(buffer.iter())
            .cloned()
            .collect::<Vec<u8>>()
    };

    let modify_leaf_at_index = |t: &mut LabeledTree<Vec<u8>>, index| {
        modify_leaf(t, index, &modify_buffer);
    };

    let mut leaf_values: Vec<Vec<u8>> = (0..=3).map(|v| vec![v]).collect();

    for i in 0..num_leaves {
        modify_leaf_at_index(&mut tree, i);
        modify_buffer(&mut leaf_values[i]);
        assert_eq!(
            tree,
            subtree!(
                b"a" => subtree!(b"b" => v(leaf_values[0].clone()), b"c" => v(leaf_values[1].clone())),
                b"d" => subtree!(),
                b"e" => v(leaf_values[2].clone()),
                b"f" => subtree!(
                    b"g" => subtree!(b"h" => v(leaf_values[3].clone()))
                )
            )
        );
    }
}

#[test]
fn get_num_labels_works_correctly() {
    let rng = &mut ReproducibleRng::new();
    let mut tree = subtree!();
    for i in 0..100 {
        add_leaf(&mut tree, rng);
        assert_eq!(get_num_labels(&tree), 2 * i + 1, "{tree:?}");
        add_empty_subtree(&mut tree, rng);
        assert_eq!(get_num_labels(&tree), 2 * i + 2, "{tree:?}");
    }
}

#[test]
fn modify_label_modifies_correct_label() {
    let mut tree = subtree!(
        b"a" => subtree_empty_values!(b"b", b"c"),
        b"d" => subtree!(),
        b"e" => subtree!(
            b"f" => subtree_empty_values!(b"g")
        )
    );

    let modify_buffer = |buffer: &mut Vec<u8>| {
        for b in buffer.iter_mut() {
            *b += 1;
        }
        *buffer = b"a"
            .iter()
            .chain(buffer.iter())
            .cloned()
            .collect::<Vec<u8>>()
    };

    let modify_label_at_index = |t: &mut LabeledTree<Vec<u8>>, index| {
        modify_label(t, index, &modify_buffer);
    };

    let mut labels: Vec<Vec<u8>> = (b'a'..=b'g').map(|label| vec![label]).collect();

    for i in 0..labels.len() {
        modify_label_at_index(&mut tree, i);
        modify_buffer(&mut labels[i]);
        assert_eq!(
            tree,
            subtree!(
                &labels[0][..] => subtree_empty_values!(&labels[1][..], &labels[2][..]),
                &labels[3][..] => subtree!(),
                &labels[4][..] => subtree!(
                    &labels[5][..] => subtree_empty_values!(&labels[6][..])
                )
            )
        );
    }
}

#[test]
fn cmp_paths_works_correctly_for_1_depth_trees() {
    let equal_trees_in_root = [
        subtree!(),
        LabeledTree::Leaf(vec![]),
        LabeledTree::Leaf(vec![0u8]),
    ];

    for t1 in equal_trees_in_root.iter() {
        for t2 in equal_trees_in_root.iter() {
            assert_eq!(cmp_paths(t1, t2), Ordering::Equal);
        }
    }
}

#[test]
fn cmp_paths_works_correctly() {
    let tree = subtree!(b"a" => subtree_empty_values!(b"b"));
    assert_eq!(cmp_paths(&tree, &tree), Ordering::Equal);
    assert_eq!(
        cmp_paths(&subtree_empty_values!(b"a"), &tree),
        Ordering::Less
    );
    assert_eq!(
        cmp_paths(&tree, &subtree_empty_values!(b"a")),
        Ordering::Greater
    );

    assert_eq!(
        cmp_paths(&subtree!(b"a" => subtree!()), &tree),
        Ordering::Less
    );
    assert_eq!(
        cmp_paths(&tree, &subtree!(b"a" => subtree!())),
        Ordering::Greater
    );

    assert_eq!(
        cmp_paths(
            &tree,
            &subtree!(b"a" => subtree!(b"b" => subtree_empty_values!(b"c")))
        ),
        Ordering::Less
    );
    assert_eq!(
        cmp_paths(
            &subtree!(b"a" => subtree!(b"b" => subtree_empty_values!(b"c"))),
            &tree
        ),
        Ordering::Greater
    );

    assert_eq!(
        cmp_paths(&tree, &subtree!(b"a" => subtree_empty_values!(b"c"))),
        Ordering::Less
    );
    assert_eq!(
        cmp_paths(&subtree!(b"a" => subtree_empty_values!(b"c")), &tree),
        Ordering::Greater
    );
}

#[test]
#[should_panic = "bug: path with >1 argument lhs=FlatMap { keys: [a], values: [Leaf([])] } rhs=FlatMap { keys: [a, b], values: [Leaf([]), Leaf([])] }"]
fn cmp_paths_panics_if_first_argument_is_not_a_path() {
    let path = subtree_empty_values!(b"a");
    let not_path = subtree_empty_values!(b"a", b"b");
    cmp_paths(&path, &not_path);
}

#[test]
#[should_panic = "bug: path with >1 argument lhs=FlatMap { keys: [a, b], values: [Leaf([]), Leaf([])] } rhs=FlatMap { keys: [a], values: [Leaf([])] }"]
fn cmp_paths_panics_if_second_argument_is_not_a_path() {
    let path = subtree_empty_values!(b"a");
    let not_path = subtree_empty_values!(b"a", b"b");
    cmp_paths(&not_path, &path);
}
