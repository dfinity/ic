//! A `Thunk<T>` represents delayed initialization of a value of type `T`.
//! That is, an initialization function of type `FnOnce() -> T` can be used
//! to create a `Thunk<T>` object, and only called once when the thunk is
//! evaluated. Evaluating the same thunk more than once will return the
//! same value as its first evaluation, but will not result in calling
//! the initialization function more than once.
//!
//! An alternative way of initializing a thunk is to use `From<T>` trait.
//!
//! To evaluate a thunk, we can either use the `into_inner` function or
//! `AsRef<T>` trait.
//!
//! The serialization of a `Thunk<T>` object will force an evaluation.
//!
//! Implementation wise, `Thunk` is just a thin wrapper around
//! `once_cell::Lazy` type, providing `From`, `Serialize`, and `Deserialize`
//! trait implementations.
use once_cell::sync::Lazy;
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

/// A lazily initialized value of type `T` that is only initialized upon
/// first evaluation.
pub struct Thunk<T> {
    thunk: Lazy<T, Box<dyn FnOnce() -> T + Send>>,
}

impl<T> Thunk<T> {
    /// Return a `Thunk<T>` object with an initialization function `init`
    /// that will not be called until the thunk is evaluated.
    pub fn new(init: Box<dyn FnOnce() -> T + Send>) -> Self {
        Thunk {
            thunk: Lazy::new(init),
        }
    }

    /// Convert a `Thunk<T>` object into its inner value of type `T`.
    /// It will force an evaluation if necessary.
    pub fn into_inner(self) -> T {
        self.thunk.into_inner()
    }
}

impl<T: Send + 'static> From<T> for Thunk<T> {
    fn from(value: T) -> Self {
        Thunk::new(Box::new(move || value))
    }
}

impl<T> AsRef<T> for Thunk<T> {
    fn as_ref(&self) -> &T {
        &*self.thunk
    }
}

impl<T: Serialize> Serialize for Thunk<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: &T = self.as_ref();
        value.serialize(serializer)
    }
}

impl<'a, T: Send + Deserialize<'a> + 'static> Deserialize<'a> for Thunk<T> {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let value = T::deserialize(deserializer)?;
        Ok(Thunk::from(value))
    }
}
