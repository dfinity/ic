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
//! references to that `Arc` will result in multple copies of the `Mutex` which
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

pub fn serialize_arc<T: Serialize, S: Serializer>(
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
