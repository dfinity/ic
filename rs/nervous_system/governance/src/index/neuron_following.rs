use ic_stable_structures::{Memory, StableBTreeMap, Storable};
use num_traits::bounds::{LowerBounded, UpperBounded};
use std::{
    cmp::Ord,
    collections::{BTreeMap, BTreeSet},
};

/// An index to make it easy to look up neuron followers by (category, followee).
///
/// The category concept corresponds to Topic in NNS and FunctionId in SNS.
/// The index does not understand the semantics of the Category - even though NNS/SNS
/// both have blanket category, the index does not have special treatment for it.
///
/// The index does not try to understand or enforce what kind of following is allowed:
/// it will not validate against self-following.
pub trait NeuronFollowingIndex<NeuronId, Category> {
    /// Adds one follower-followee-category tuple into the index.
    /// Returns whether the tuple was newly added.
    #[must_use]
    fn add_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool;

    /// Removes one follower-followee-category tuple from the index.
    /// Returns whether the tuple was present.
    #[must_use]
    fn remove_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool;

    /// Gets all followees for a neuron and a category.
    fn get_followers_by_followee_and_category(
        &self,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> Vec<NeuronId>;
}

/// Adds a neuron's followees for each category and returns whether all of the followees
/// are newly added.
/// If the return value is non-empty, it signals a potential problem related to how the
/// caller uses the index - the primary neuron followee is probably inconsistent with
/// the index.
#[must_use]
pub fn add_neuron_followees<NeuronId, Category>(
    index: &mut dyn NeuronFollowingIndex<NeuronId, Category>,
    follower_neuron_id: &NeuronId,
    category_followee_pairs: BTreeSet<(Category, NeuronId)>,
) -> Vec<(Category, NeuronId)>
where
    Category: Copy,
{
    category_followee_pairs
        .into_iter()
        .filter_map(|(category, followee_neuron_id)| {
            let changed = index.add_neuron_followee_for_category(
                follower_neuron_id,
                &followee_neuron_id,
                category,
            );
            if changed {
                None
            } else {
                Some((category, followee_neuron_id))
            }
        })
        .collect()
}

/// Removes a neuron's followees for each category and returns whether all of the followees
/// were present in the index.
/// If the return value is non-empty, it signals a potential problem related to how the caller
/// uses the index - the primary neuron followee is probably inconsistent with
/// the index.
#[must_use]
pub fn remove_neuron_followees<NeuronId, Category>(
    index: &mut dyn NeuronFollowingIndex<NeuronId, Category>,
    follower_neuron_id: &NeuronId,
    category_followee_pairs: BTreeSet<(Category, NeuronId)>,
) -> Vec<(Category, NeuronId)>
where
    Category: Copy,
{
    category_followee_pairs
        .into_iter()
        .filter_map(|(category, followee_neuron_id)| {
            let changed = index.remove_neuron_followee_for_category(
                follower_neuron_id,
                &followee_neuron_id,
                category,
            );
            if changed {
                None
            } else {
                Some((category, followee_neuron_id))
            }
        })
        .collect()
}

/// Updates the neuron's followees per category, and returns the followees that were
/// already absent from the old followees set and the ones already present from the new
/// followees set.
/// If either of the return value is non-empty, it signals a potential problem related
/// to how the index is used - the primary neuron followee is probably inconsistent with
/// the index.
#[must_use]
pub fn update_neuron_category_followees<NeuronId, Category>(
    index: &mut dyn NeuronFollowingIndex<NeuronId, Category>,
    follower_neuron_id: &NeuronId,
    category: Category,
    old_followee_neuron_ids: BTreeSet<NeuronId>,
    new_followee_neuron_ids: BTreeSet<NeuronId>,
) -> (Vec<NeuronId>, Vec<NeuronId>)
where
    NeuronId: Clone + Ord,
    Category: Copy + Ord,
{
    // Using set difference to reduce the amount of read/write, which is especially important for stable storage.
    let already_absent_old = remove_neuron_followees(
        index,
        follower_neuron_id,
        old_followee_neuron_ids
            .difference(&new_followee_neuron_ids)
            .cloned()
            .map(|old_followee_neuron_id| (category, old_followee_neuron_id))
            .collect(),
    )
    .into_iter()
    .map(|(_category, old_followee_neuron_id)| old_followee_neuron_id)
    .collect();

    let already_present_new = add_neuron_followees(
        index,
        follower_neuron_id,
        new_followee_neuron_ids
            .difference(&old_followee_neuron_ids)
            .cloned()
            .map(|new_followee_neuron_id| (category, new_followee_neuron_id))
            .collect(),
    )
    .into_iter()
    .map(|(_category, new_followee_neuron_ids)| new_followee_neuron_ids)
    .collect();

    (already_absent_old, already_present_new)
}

/// An in-memory implementation of the neuron following index.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct HeapNeuronFollowingIndex<NeuronId, Category> {
    category_to_followee_to_followers: BTreeMap<Category, BTreeMap<NeuronId, BTreeSet<NeuronId>>>,
}

impl<NeuronId, Category> HeapNeuronFollowingIndex<NeuronId, Category> {
    pub fn new(
        category_to_followee_to_followers: BTreeMap<
            Category,
            BTreeMap<NeuronId, BTreeSet<NeuronId>>,
        >,
    ) -> Self {
        Self {
            category_to_followee_to_followers,
        }
    }

    /// Returns the number of entries (category, followee, follower) in the index. This is for
    /// validation purpose: this should be equal to the size of the followee collection within the
    /// primary storage.
    pub fn num_entries(&self) -> usize {
        self.category_to_followee_to_followers
            .values()
            .map(|neuron_followers_map| {
                neuron_followers_map
                    .values()
                    .map(|followers| followers.len())
                    .sum::<usize>()
            })
            .sum()
    }

    pub fn into_inner(self) -> BTreeMap<Category, BTreeMap<NeuronId, BTreeSet<NeuronId>>> {
        self.category_to_followee_to_followers
    }
}

impl<NeuronId, Category> NeuronFollowingIndex<NeuronId, Category>
    for HeapNeuronFollowingIndex<NeuronId, Category>
where
    NeuronId: Eq + Ord + Clone,
    Category: Eq + Ord + Copy,
{
    fn add_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool {
        self.category_to_followee_to_followers
            .entry(category)
            .or_default()
            .entry(followee_neuron_id.clone())
            .or_default()
            .insert(follower_neuron_id.clone())
    }

    fn remove_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool {
        self.category_to_followee_to_followers
            .get_mut(&category)
            .and_then(|followee_to_followers| followee_to_followers.get_mut(followee_neuron_id))
            .map(|followers_set| followers_set.remove(follower_neuron_id))
            .unwrap_or(false)
    }

    fn get_followers_by_followee_and_category(
        &self,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> Vec<NeuronId> {
        self.category_to_followee_to_followers
            .get(&category)
            .and_then(|followers_map| followers_map.get(followee_neuron_id).cloned())
            .unwrap_or_default()
            .into_iter()
            .collect()
    }
}

/// A stable memory implementation of the index.
pub struct StableNeuronFollowingIndex<NeuronId, Category, M>
where
    NeuronId: Storable + Clone + Default + Ord,
    Category: Storable + Copy + Default + Ord,
    M: Memory,
{
    // The composite key cannot be easily flattened since (A, B, C) does not
    // implement Storable even if A, B and C all do.
    category_followee_follower_to_null: StableBTreeMap<((Category, NeuronId), NeuronId), (), M>,
}

impl<NeuronId, Category, M> StableNeuronFollowingIndex<NeuronId, Category, M>
where
    NeuronId: Storable + Default + Clone + Ord,
    Category: Storable + Default + Copy + Ord,
    M: Memory,
{
    pub fn new(memory: M) -> Self {
        Self {
            category_followee_follower_to_null: StableBTreeMap::init(memory),
        }
    }

    /// Returns the number of entries (category, followee, follower) in the index. This is for
    /// validation purpose: this should be equal to the size of the followee collection within the
    /// primary storage.
    pub fn num_entries(&self) -> usize {
        self.category_followee_follower_to_null.len() as usize
    }

    /// Returns whether the (category, followee, follower) entry exists in the index. This is for
    /// validation purpose: each such pair in the primary storage should exist in the index.
    pub fn contains_entry(
        &self,
        category: Category,
        followee_id: &NeuronId,
        follower_id: &NeuronId,
    ) -> bool {
        let key = ((category, followee_id.clone()), follower_id.clone());
        self.category_followee_follower_to_null.contains_key(&key)
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        super::validate_stable_btree_map(&self.category_followee_follower_to_null);
    }
}

impl<NeuronId, Category, M> NeuronFollowingIndex<NeuronId, Category>
    for StableNeuronFollowingIndex<NeuronId, Category, M>
where
    NeuronId: Storable + Clone + Default + LowerBounded + UpperBounded + Ord,
    Category: Storable + Copy + Default + Ord,
    M: Memory,
{
    fn add_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool {
        self.category_followee_follower_to_null
            .insert(
                (
                    (category, followee_neuron_id.clone()),
                    follower_neuron_id.clone(),
                ),
                (),
            )
            .is_none()
    }

    fn remove_neuron_followee_for_category(
        &mut self,
        follower_neuron_id: &NeuronId,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> bool {
        self.category_followee_follower_to_null
            .remove(&(
                (category, followee_neuron_id.clone()),
                follower_neuron_id.clone(),
            ))
            .is_some()
    }

    fn get_followers_by_followee_and_category(
        &self,
        followee_neuron_id: &NeuronId,
        category: Category,
    ) -> Vec<NeuronId> {
        let partial_key = (category, followee_neuron_id.clone());
        self.category_followee_follower_to_null
            .range((partial_key.clone(), NeuronId::min_value())..)
            .take_while(|(k, _)| k.0 == partial_key)
            .map(|(k, _)| k.1)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_stable_structures::storable::Bound;
    use ic_stable_structures::{Storable, VectorMemory};
    use maplit::btreeset;
    use std::borrow::Cow;

    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default)]
    struct TestNeuronId([u8; 32]);

    impl Storable for TestNeuronId {
        fn to_bytes(&self) -> Cow<'_, [u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            TestNeuronId(<[u8; 32]>::from_bytes(bytes))
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: 32,
            is_fixed_size: true,
        };
    }

    impl LowerBounded for TestNeuronId {
        fn min_value() -> Self {
            TestNeuronId([0u8; 32])
        }
    }

    impl UpperBounded for TestNeuronId {
        fn max_value() -> Self {
            TestNeuronId([u8::MAX; 32])
        }
    }

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default)]
    enum Topic {
        #[default]
        Unspecified = 0,
        Topic1 = 1,
        Topic2 = 2,
    }

    impl From<i32> for Topic {
        fn from(i: i32) -> Self {
            match i {
                0 => Topic::Unspecified,
                1 => Topic::Topic1,
                2 => Topic::Topic2,
                _ => panic!("Invalid value for Topic enum"),
            }
        }
    }

    impl Storable for Topic {
        fn to_bytes(&self) -> Cow<'_, [u8]> {
            Cow::Owned((*self as i32).to_be_bytes().to_vec())
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            i32::from_be_bytes(bytes.as_ref().try_into().unwrap()).into()
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: std::mem::size_of::<i32>() as u32,
            is_fixed_size: true,
        };
    }

    fn get_stable_index() -> StableNeuronFollowingIndex<TestNeuronId, Topic, VectorMemory> {
        StableNeuronFollowingIndex::<TestNeuronId, Topic, VectorMemory>::new(VectorMemory::default())
    }

    fn get_heap_index() -> HeapNeuronFollowingIndex<TestNeuronId, Topic> {
        HeapNeuronFollowingIndex::<TestNeuronId, Topic>::new(BTreeMap::new())
    }

    // The following test helpers will be run by both implementations.
    fn test_add_single_followee_helper(mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id = TestNeuronId([2u8; 32]);

        // 1 -> 2
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );

        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id, Topic::Topic2),
            vec![]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&follower_id, Topic::Topic1),
            vec![]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id, Topic::Topic1),
            vec![follower_id]
        );
    }

    fn test_add_multiple_followees_helper(
        mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>,
    ) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id_1 = TestNeuronId([2u8; 32]);
        let followee_id_2 = TestNeuronId([3u8; 32]);

        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id_2.clone())],
            ),
            vec![]
        );
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &followee_id_1,
                btreeset![(Topic::Topic1, followee_id_2.clone())],
            ),
            vec![]
        );

        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_2, Topic::Topic1),
            vec![follower_id, followee_id_1]
        );
    }

    fn test_add_remove_followees_helper(mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>) {
        let neuron_id_1 = TestNeuronId([1u8; 32]);
        let neuron_id_2 = TestNeuronId([2u8; 32]);
        let neuron_id_3 = TestNeuronId([3u8; 32]);

        // Add: 1->3
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &neuron_id_1,
                btreeset![(Topic::Topic1, neuron_id_3.clone()),],
            ),
            vec![]
        );
        // Add: 2->3
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &neuron_id_2,
                btreeset![(Topic::Topic1, neuron_id_3.clone())],
            ),
            vec![]
        );

        // 1 and 2 both follow 3
        assert_eq!(
            index.get_followers_by_followee_and_category(&neuron_id_3, Topic::Topic1),
            vec![neuron_id_1.clone(), neuron_id_2.clone()]
        );

        // Remove: 1->3
        assert_eq!(
            remove_neuron_followees(
                &mut index,
                &neuron_id_1,
                btreeset![(Topic::Topic1, neuron_id_3.clone()),],
            ),
            vec![]
        );

        // Now only 2->3
        assert_eq!(
            index.get_followers_by_followee_and_category(&neuron_id_3, Topic::Topic1),
            vec![neuron_id_2]
        );
    }

    fn test_update_single_topic_followees_helper(
        mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>,
    ) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id_1 = TestNeuronId([2u8; 32]);
        let followee_id_2 = TestNeuronId([3u8; 32]);

        // Topic1: follower->1.2
        // Topic2: follower->2
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![
                    (Topic::Topic1, followee_id_1.clone()),
                    (Topic::Topic1, followee_id_2.clone()),
                    (Topic::Topic2, followee_id_2.clone()),
                ],
            ),
            vec![]
        );

        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_2, Topic::Topic1),
            vec![follower_id.clone()]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_1, Topic::Topic1),
            vec![follower_id.clone()]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_2, Topic::Topic2),
            vec![follower_id.clone()]
        );

        // Update for follower to follow 1 only on topic1
        assert_eq!(
            update_neuron_category_followees(
                &mut index,
                &follower_id,
                Topic::Topic1,
                btreeset![followee_id_1.clone(), followee_id_2.clone()],
                btreeset![followee_id_1.clone()],
            ),
            (vec![], vec![])
        );

        // After the update:
        // Nobody follows the follower.
        assert_eq!(
            index.get_followers_by_followee_and_category(&follower_id, Topic::Topic1),
            vec![]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&follower_id, Topic::Topic2),
            vec![]
        );
        // Follower follows 1 on topic1.
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_1, Topic::Topic1),
            vec![follower_id.clone()]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_1, Topic::Topic2),
            vec![]
        );
        // Follower follows 2 on topic2.
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_2, Topic::Topic1),
            vec![]
        );
        assert_eq!(
            index.get_followers_by_followee_and_category(&followee_id_2, Topic::Topic2),
            vec![follower_id.clone()]
        );
    }

    fn test_add_existing_followee_helper(
        mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>,
    ) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id = TestNeuronId([2u8; 32]);

        // First add is valid.
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );
        // Second add is invalid.
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![(Topic::Topic1, followee_id)]
        );
    }

    fn test_remove_absent_followee_helper(
        mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>,
    ) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id = TestNeuronId([2u8; 32]);

        // Adding first.
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );

        // First remove is valid
        assert_eq!(
            remove_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );
        // Second remove is invalid.
        assert_eq!(
            remove_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![(Topic::Topic1, followee_id)]
        );
    }

    fn test_update_followee_invalid_helper(
        mut index: impl NeuronFollowingIndex<TestNeuronId, Topic>,
    ) {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id_1 = TestNeuronId([2u8; 32]);
        let followee_id_2 = TestNeuronId([3u8; 32]);
        let followee_id_3 = TestNeuronId([4u8; 32]);
        // Adding follower->1,2.
        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![
                    (Topic::Topic1, followee_id_1.clone()),
                    (Topic::Topic1, followee_id_2.clone())
                ],
            ),
            vec![]
        );

        // Updating the followee from [1] to [2,3] is invalid - previous followees include 2.
        // We do not assert the actual following result since it's undefined behavior.
        assert_eq!(
            update_neuron_category_followees(
                &mut index,
                &follower_id,
                Topic::Topic1,
                btreeset![followee_id_1],
                btreeset![followee_id_2.clone(), followee_id_3],
            ),
            (vec![], vec![followee_id_2])
        );
    }

    #[test]
    fn test_add_single_followee_heap() {
        test_add_single_followee_helper(get_heap_index());
    }

    #[test]
    fn test_add_single_followee_stable() {
        test_add_single_followee_helper(get_stable_index());
    }

    #[test]
    fn test_add_multiple_followees_heap() {
        test_add_multiple_followees_helper(get_heap_index());
    }

    #[test]
    fn test_add_multiple_followees_stable() {
        test_add_multiple_followees_helper(get_stable_index());
    }

    #[test]
    fn test_add_remove_followees_heap() {
        test_add_remove_followees_helper(get_heap_index());
    }

    #[test]
    fn test_add_remove_followees_stable() {
        test_add_remove_followees_helper(get_stable_index());
    }

    #[test]
    fn test_update_single_topic_followees_heap() {
        test_update_single_topic_followees_helper(get_heap_index());
    }

    #[test]
    fn test_update_single_topic_followees_stable() {
        test_update_single_topic_followees_helper(get_stable_index());
    }

    #[test]
    fn test_add_existing_followee_heap() {
        test_add_existing_followee_helper(get_heap_index());
    }

    #[test]
    fn test_add_existing_followee_stable() {
        test_add_existing_followee_helper(get_stable_index());
    }

    #[test]
    fn test_remove_absent_followee_heap() {
        test_remove_absent_followee_helper(get_heap_index());
    }

    #[test]
    fn test_remove_absent_followee_stable() {
        test_remove_absent_followee_helper(get_stable_index());
    }
    #[test]

    fn test_update_followee_invalid_heap() {
        test_update_followee_invalid_helper(get_heap_index());
    }

    #[test]
    fn test_update_followee_invalid_stable() {
        test_update_followee_invalid_helper(get_stable_index());
    }

    #[test]
    fn test_stable_neuron_index_num_entries() {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id = TestNeuronId([2u8; 32]);
        let mut index = get_stable_index();

        assert_eq!(index.num_entries(), 0);

        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );

        assert_eq!(index.num_entries(), 1);
    }

    #[test]
    fn test_stable_neuron_index_contains_entry() {
        let follower_id = TestNeuronId([1u8; 32]);
        let followee_id = TestNeuronId([2u8; 32]);
        let mut index = get_stable_index();

        assert_eq!(
            add_neuron_followees(
                &mut index,
                &follower_id,
                btreeset![(Topic::Topic1, followee_id.clone())],
            ),
            vec![]
        );

        assert!(index.contains_entry(Topic::Topic1, &followee_id, &follower_id));
        assert!(!index.contains_entry(Topic::Topic1, &follower_id, &followee_id));
    }
}
