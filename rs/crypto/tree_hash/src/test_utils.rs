use crate::*;

/// Returns complete partial trees for each leaf and empty subtree in `tree`.
///
/// For example, for `tree` of form
///
/// ```text
/// + -- 1 -- Leaf(())
/// |
/// | -- 2 -- Leaf(())
/// |
/// | -- 3 -- EMPTY_SUBTREE
/// |
/// | -- 4 -- + -- 5 -- Leaf(())
///           |
///           | -- 6 -- EMPTY_SUBTREE
/// ```
///
/// the result would contain
///
///  ```text
/// + -- 1 -- Leaf(())
///
/// + -- 2 -- Leaf(())
///
/// + -- 3 -- EMPTY_SUBTREE
///
/// + -- 4 -- + -- 5 -- Leaf(())
///
/// + -- 4 -- + -- 6 -- EMPTY_SUBTREE
/// ```
pub fn partial_trees_to_leaves_and_empty_subtrees(
    tree: &LabeledTree<Vec<u8>>,
) -> Vec<LabeledTree<Vec<u8>>> {
    let mut result = vec![];
    partial_trees_to_leaves_and_empty_subtrees_impl(tree, &mut vec![], &mut result);
    result
}

fn partial_trees_to_leaves_and_empty_subtrees_impl<'a>(
    tree: &'a LabeledTree<Vec<u8>>,
    curr_path: &mut Vec<&'a Label>,
    result: &mut Vec<LabeledTree<Vec<u8>>>,
) {
    match tree {
        LabeledTree::SubTree(children) if !children.is_empty() => {
            for (label, child) in children.iter() {
                curr_path.push(label);
                partial_trees_to_leaves_and_empty_subtrees_impl(child, curr_path, result);
                curr_path.pop();
            }
        }
        LabeledTree::SubTree(_) | LabeledTree::Leaf(_) => {
            let path_tree = curr_path.iter().rev().fold(tree.clone(), |acc, &label| {
                LabeledTree::SubTree(flatmap!(label.clone() => acc))
            });
            result.push(path_tree);
        }
    }
}

/// Merges a path (i.e., a one node wide [`LabeledTree`]  containing exactly one
/// [`LabeledTree::Leaf`]) into the `agg` by appending the missing node/subtree
/// from `path`.
///
/// Panics if the appended label from `path` is not larger than the largest
/// label in the respective subtree.
pub fn merge_path_into_labeled_tree<T: core::fmt::Debug + std::cmp::PartialEq + Clone>(
    agg: &mut LabeledTree<T>,
    path: &LabeledTree<T>,
) {
    match (agg, path) {
        (LabeledTree::SubTree(subtree_agg), LabeledTree::SubTree(subtree_path)) => {
            assert_eq!(
                subtree_path.len(),
                1,
                "`path` should always contain only exactly one label/tree pair in each subtree"
            );
            let (path_label, subpath) = subtree_path
                .iter()
                .next()
                .expect("should containt exactly one child");
            // if the left subtree contains the label from the right subtree, go one level deeper,
            // otherwise append the right subtree to the left subtree
            if let Some(subagg) = subtree_agg.get_mut(path_label) {
                merge_path_into_labeled_tree(subagg, subpath);
            } else {
                subtree_agg
                    .try_append(path_label.clone(), subpath.clone())
                    .expect(
                        "bug: the path label is unsorted w.r.t. to the tree and cannot be appended",
                    );
            }
        }
        _ => panic!("Trying to merge into existing tree path"),
    }
}
