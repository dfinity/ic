//! Test that the test utils work correctly
use super::*;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use proptest::prelude::*;
use std::fmt::Debug;

/// Verify that select_n behaves as expected:
/// * The length of the returned options should be the same as the length of the
///   available items.
/// * The number of selected options should be as requested.
fn test_select_n<T: Clone + PartialEq + Debug>(seed: Randomness, size: NumberOfNodes, items: &[T]) {
    let selection = select_n(seed, size, items);
    let num_elements = selection.len();
    let num_selected_elements = selection.iter().filter_map(|x| x.as_ref()).count();
    assert_eq!(
        num_elements,
        items.len(),
        "Incorrect number of elements: Got: {} Expected: {}",
        num_elements,
        items.len()
    );
    assert_eq!(
        num_selected_elements,
        size.get() as usize,
        "Incorrect number of non-empty elements: Got: {} Expected: {}",
        num_selected_elements,
        size.get()
    );
    items
        .iter()
        .zip(selection.iter())
        .for_each(|(left, right)| {
            if let Some(right) = right.as_ref() {
                assert_eq!(*left, *right);
            }
        });
}

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        #[test]
        fn proptest_select_n(seed: [u8;32], size in 0 as NodeIndex..10, items in proptest::collection::vec(any::<NodeIndex>(), 10..20)) {
            test_select_n(Randomness::from(seed), NumberOfNodes::from(size), &items);
        }
}
