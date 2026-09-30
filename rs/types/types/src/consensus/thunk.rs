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
//! Implementation wise, `Thunk` is a thin wrapper around `std::sync::OnceLock`
//! holding the value, plus the (boxed) initialization function that is consumed
//! on first evaluation. It provides `From`, `Serialize`, and `Deserialize`
//! trait implementations.
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use std::sync::{Mutex, OnceLock};

type Init<T> = Box<dyn FnOnce() -> T + Send>;

/// A lazily initialized value of type `T` that is only initialized upon
/// first evaluation.
pub struct Thunk<T> {
    /// The evaluated value, if the thunk has been forced.
    value: OnceLock<T>,
    /// The initialization function; `None` once it has been consumed.
    init: Mutex<Option<Init<T>>>,
}

impl<T> Thunk<T> {
    /// Return a `Thunk<T>` object with an initialization function `init`
    /// that will not be called until the thunk is evaluated.
    pub fn new(init: Init<T>) -> Self {
        Thunk {
            value: OnceLock::new(),
            init: Mutex::new(Some(init)),
        }
    }

    /// Evaluate the thunk if it hasn't been evaluated yet and return a
    /// reference to the value.
    fn force(&self) -> &T {
        self.value.get_or_init(|| {
            let init = self
                .init
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("Thunk initialization function was already consumed");
            init()
        })
    }

    /// Convert a `Thunk<T>` object into its inner value of type `T`.
    /// It will force an evaluation if necessary.
    pub fn into_inner(self) -> T {
        // Force the thunk to ensure that `into_inner` succeeds.
        self.force();
        match self.value.into_inner() {
            Some(value) => value,
            None => {
                unreachable!("Forced thunk is not evaluated. This cannot happen.")
            }
        }
    }
}

impl<T: Send + 'static> From<T> for Thunk<T> {
    fn from(value: T) -> Self {
        Thunk::new(Box::new(move || value))
    }
}

impl<T> AsRef<T> for Thunk<T> {
    fn as_ref(&self) -> &T {
        self.force()
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
