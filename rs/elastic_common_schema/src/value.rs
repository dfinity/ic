//! Values that can be used in extra fields
//!
//! Because we want to be able to map from a string to an arbitrary value
//! that can be serialized.

use std::{
    cmp::{Ord, Ordering},
    collections::{BTreeMap, HashMap},
    iter::FromIterator,
    ops::{Deref, DerefMut},
};

use serde::Serialize;
use slog_derive::SerdeValue;

/// Contain values that can be stored in the `ExtraValues` map.
//
// slog::SerdeValue requires 'static lifetime (i.e., owned)
// for everything, as logging may be in a separate thread. Rather
// than take references here and then convert in to owned values
// as necessary it's vastly simpler to store owned values
// directly.
#[derive(Clone, Debug, Serialize, SerdeValue)]
#[serde(untagged)]
pub enum Value {
    Integer(i128),
    Text(String),
    Map(BTreeMap<Value, Value>),
    Array(Vec<Value>),
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Value) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    /// Each type compares with itself. Different types compare as
    /// Integer < Text < Map < Array.
    fn cmp(&self, other: &Value) -> Ordering {
        use self::Value::*;
        match (self, other) {
            (Integer(a), Integer(b)) => a.abs().cmp(&b.abs()),
            (Integer(_), _) | (_, Integer(_)) => Ordering::Less,
            (Text(a), Text(b)) => a.cmp(b),
            (Text(_), _) | (_, Text(_)) => Ordering::Less,
            (Array(a), Array(b)) => a.cmp(b),
            (Array(_), _) | (_, Array(_)) => Ordering::Less,
            (Map(a), Map(b)) => a.cmp(b),
        }
    }
}

macro_rules! impl_from {
    ($variant:path, $for_type:ty) => {
        impl From<$for_type> for Value {
            fn from(v: $for_type) -> Value {
                $variant(v.into())
            }
        }
    };
}

impl_from!(Value::Integer, i8);
impl_from!(Value::Integer, i16);
impl_from!(Value::Integer, i32);
impl_from!(Value::Integer, i64);
impl_from!(Value::Integer, i128);
impl_from!(Value::Integer, u8);
impl_from!(Value::Integer, u16);
impl_from!(Value::Integer, u32);
impl_from!(Value::Integer, u64);
impl_from!(Value::Text, &str);
impl_from!(Value::Text, String);

// TODO: figure out if these impls should be more generic or removed.
impl_from!(Value::Array, Vec<Value>);
impl_from!(Value::Map, BTreeMap<Value, Value>);

impl FromIterator<Value> for Value {
    fn from_iter<T: IntoIterator<Item = Value>>(iter: T) -> Self {
        Self::Array(iter.into_iter().collect())
    }
}

impl<'a> FromIterator<&'a Value> for Value {
    fn from_iter<T: IntoIterator<Item = &'a Value>>(iter: T) -> Self {
        Self::Array(iter.into_iter().cloned().collect())
    }
}

/// Additional values that can be logged.
///
/// [Custom Fields] explains how ECS supports custom fields -- broadly, this
/// is useful, you can add what you want, but there is a risk of clashing with
/// new fields in the future.
///
/// One way to mitigate this is to make sure the field names feature
/// capitilisation, as that's guaranteed not to appear in future versions of
/// the standard.
///
/// This supports extra fields by adding a type that maps from arbitrary
/// values to arbitrary values (the `Values` enum).
///
/// To use this in your struct, add a field at the bottom, conventionally
/// called `extra_fields`, of this type, and instruct Serde to flatten it and
/// ignore it if it's empty.
///
/// ```ignore
///     ...
///     #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
///     extra_fields: ExtraValues
/// }
/// ```
///
/// To use this as a client (assuming `ev` is an `ecs::Event` with an
/// `extra_values` field):
///
/// # To add key/value pairs of strings
///
/// ```ignore
/// // Note the uppercase in `Key` to distinguish from official fields
/// ev.extra_values.insert("Key".into(), "bar".into());
/// ```
///
/// Result:
///
/// ```ignore
///   "Key": "bar"
/// ```
///
/// # To add a map of keys to strings
///
/// ```ignore
/// let mut map: BTreeMap<Value, Value> = BTreeMap::new();
/// map.insert("foo".into(), "bar".into());
/// map.insert("fred".into(), "barney".into());
/// // Note the uppercase in `Key` to distinguish from official fields
/// ev.extra_values.insert("Key".into(), map.into());
/// ```
///
/// Result:
///
/// ```json
///   "Key": {
///     "foo": "bar",
///     "fred": "barney"
///   }
/// ```
///
/// [Custom Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-custom-fields-in-ecs.html
#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct ExtraValues(pub HashMap<&'static str, Value>);

impl Deref for ExtraValues {
    type Target = HashMap<&'static str, Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ExtraValues {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ExtraValues {
    pub fn new() -> Self {
        Self(HashMap::<&'static str, Value>::new())
    }
}
