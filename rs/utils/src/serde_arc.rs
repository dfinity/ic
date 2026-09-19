//! Functions for serializing and deserializing `Arc`s with serde.
//!
//! There can be tricky correctness issues when serializing an `Arc`, so please
//! provide some justification whenever using this module.
//!
//! # Warning
//!
//! Serializing `Arc`s will not preserve identity. The warnings in the [serde documentation of the `rc`](https://serde.rs/feature-flags.html#-features-rc)
//! feature apply when using this crate.
//!
//! If the data behind the `Arc` exhibits interior mutability (e.g. a `Mutex`),
//! then serializing the `Arc` will create a new value which is not kept in sync
//! with the original value. And serializing any value which contains multiple
//! references to that `Arc` will result in multiple copies of the `Mutex` which
//! are not kept in sync with each other.
//!
//! Even if the data in the `Arc` is read-only, there may be performance issues
//! with serializing because the referenced data will be duplicated for each
//! reference.
//!
//! # Examples
//!
//! ```
//! use std::sync::Arc;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Foo {
//!     /// It is same to serialize this `Arc` field because ...
//!     #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
//!     #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
//!     foo: Arc<u32>
//! }
//! ```
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize_arc<T: Serialize + ?Sized, S: Serializer>(
    data: &Arc<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    T::serialize(data, serializer)
}

pub fn deserialize_arc<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Arc<T>, D::Error> {
    T::deserialize(deserializer).map(Arc::new)
}

pub fn deserialize_arc_str<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Arc<str>, D::Error> {
    let s = String::deserialize(deserializer)?;
    Ok(Arc::from(s))
}

/// Serializes an optional `Arc` as the plain `Option` it wraps, i.e. exactly as
/// the same field without the `Arc` would be serialized.
pub fn serialize_option_arc<T: Serialize, S: Serializer>(
    data: &Option<Arc<T>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match data {
        Some(data) => serializer.serialize_some(data.as_ref()),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_option_arc<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Arc<T>>, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.map(Arc::new))
}

/// Like [`serialize_option_arc`], but for a byte vector, which is serialized as
/// a byte string rather than as a sequence -- i.e. exactly as an
/// `Option<Vec<u8>>` annotated with `#[serde(with = "serde_bytes")]` would be.
pub fn serialize_option_arc_bytes<S: Serializer>(
    data: &Option<Arc<Vec<u8>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match data {
        Some(bytes) => serializer.serialize_some(serde_bytes::Bytes::new(bytes)),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_option_arc_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Arc<Vec<u8>>>, D::Error> {
    Ok(Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?
        .map(|bytes| Arc::new(bytes.into_vec())))
}
