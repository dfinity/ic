use std::{fmt::Debug, marker::PhantomData};

mod std_get_implementations;

/// Here, we use the term "multi-map" to refer to a map whose Value type is a collection. E.g.
/// HashMap<u64, Vec<String>>.
///
/// If you have several of these, you could form a "union" of them by doing something like
///
/// ```rust
/// let mut union = HashMap::new();
/// for m in maps {
///     for (k, v) in m {
///         union.entry(k).or_default().append(&mut v);
///     }
/// }
/// ```
///
/// But this requires scanning all the input maps, and either consuming them, or copying them
/// (doubling the space required).
///
/// This avoids the (upfront) computational resource cost by providing a union view.
///
/// To support different kinds of input maps and Value collection types, this talks to the
/// constituent maps via a new trait: Get. All combinations of
///
///     {BTreeMap, HashMap} x {Vec, BTreeSet, HashSet}
///
/// implement Get. The only restriction (which could be removed later) is that the Key and Value
/// types must be Debug.
#[derive(Debug)]
pub struct UnionMultiMap<'a, Map, Key, Value, ValuesIterator>
where
    Map: Get<'a, Key, Value, ValuesIterator> + Debug,
    Key: Debug,
    Value: Debug + 'a,
    ValuesIterator: Iterator<Item = &'a Value>,
{
    layers: Vec<&'a Map>,
    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
    _values_iterator: PhantomData<ValuesIterator>,
}

impl<'a, Map, Key, Value, ValuesIterator> UnionMultiMap<'a, Map, Key, Value, ValuesIterator>
where
    Map: Get<'a, Key, Value, ValuesIterator> + Debug,
    Key: Debug,
    Value: Debug + 'a,
    ValuesIterator: Iterator<Item = &'a Value>,
{
    pub fn new(layers: Vec<&'a Map>) -> Self {
        let _key = Default::default();
        let _value = Default::default();
        let _values_iterator = Default::default();

        Self {
            layers,
            _key,
            _value,
            _values_iterator,
        }
    }

    pub fn get(
        &self,
        key: &Key,
    ) -> Option<impl Iterator<Item = &'a Value> + use<'a, Map, Key, Value, ValuesIterator>> {
        let relevant_layers = self
            .layers
            .iter()
            .filter_map(|layer| layer.get(key))
            .collect::<Vec<_>>();
        if relevant_layers.is_empty() {
            return None;
        }

        Some(relevant_layers.into_iter().flatten())
    }
}

pub trait Get<'a, Key, Value: 'a, ValuesIterator>
where
    ValuesIterator: Iterator<Item = &'a Value>,
{
    fn get(&'a self, key: &Key) -> Option<ValuesIterator>;
}
