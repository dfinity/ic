//! Contains implementations of the Collection trait for (non-map) collection types in the standard
//! library, to wit, Vec, BTreeSet, HashSet.
use super::*;
use std::{
    collections::{BTreeSet, HashSet, btree_set, hash_set},
    ops::Deref,
};

type BTreeSetIterator<'a, Element> = btree_set::Iter<'a, Element>;
type HashSetIterator<'a, Element> = hash_set::Iter<'a, Element>;

impl<'a, Element> Collection<'a, Element> for Vec<Element>
where
    Element: Debug + 'a,
{
    type EigenIterator = std::slice::Iter<'a, Element>;

    fn iter(&'a self) -> std::slice::Iter<'a, Element> {
        self.deref().iter()
    }
}

impl<'a, Element> Collection<'a, Element> for HashSet<Element>
where
    Element: Ord + Debug + 'a,
{
    type EigenIterator = HashSetIterator<'a, Element>;

    fn iter(&'a self) -> HashSetIterator<'a, Element> {
        HashSet::iter(self)
    }
}

impl<'a, Element> Collection<'a, Element> for BTreeSet<Element>
where
    Element: Ord + Debug + 'a,
{
    type EigenIterator = BTreeSetIterator<'a, Element>;

    fn iter(&'a self) -> BTreeSetIterator<'a, Element> {
        BTreeSet::iter(self)
    }
}
