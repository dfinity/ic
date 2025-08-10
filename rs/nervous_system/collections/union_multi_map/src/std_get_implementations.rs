//! Contains implementations of the Get trait for the map types in the standar library, to wit,
//! BTreeMap and Hashmap.
use super::*;
use std::{
    cmp::Eq,
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

mod std_collection_implementations;

impl<'a, Key, Value, ValuesCollection> Get<'a, Key, Value, ValuesCollection::EigenIterator>
    for HashMap<Key, ValuesCollection>
where
    Key: Hash + Eq + Debug + 'a,
    Value: Debug + 'a,
    ValuesCollection: Collection<'a, Value>,
{
    fn get(&'a self, key: &Key) -> Option<ValuesCollection::EigenIterator> {
        HashMap::get(self, key).map(|values| values.iter())
    }
}

impl<'a, Key, Value, ValuesCollection> Get<'a, Key, Value, ValuesCollection::EigenIterator>
    for BTreeMap<Key, ValuesCollection>
where
    Key: Ord + Debug + 'a,
    Value: Debug + 'a,
    ValuesCollection: Collection<'a, Value>,
{
    fn get(&'a self, key: &Key) -> Option<ValuesCollection::EigenIterator> {
        BTreeMap::get(self, key).map(|values| values.iter())
    }
}

pub trait Collection<'a, Element>
where
    Element: Debug + 'a,
{
    type EigenIterator: Iterator<Item = &'a Element>;
    fn iter(&'a self) -> Self::EigenIterator;
}
