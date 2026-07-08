use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
/// A helper struct used for introducing new fields to structs which need to be backwards compatible.
/// The main difference w.r.t. an [`Option`] is that its [`Hash`] implementation ignores the `None`
/// variant, which means that the hash of the struct without the field would be the same as the hash
/// of the struct with the field present but set to `None`.
///
/// Lifecycle of adding a new field to a struct in a backwards compatible way:
/// 1. Add a new field to the struct with type `BackwardsCompatibleOption<T, false>`. At this point
///    the field is *NOT* allowed to have any value other than `None`.
/// 2. When the change is deployed to all replicas, we can switch the type to
///    `BackwardsCompatibleOption<T, true>` and the field can begin to be populated.
/// 3. When the change is deployed to all replicas, we can replace the type with `T`.
pub struct BackwardsCompatibleOption<T, const SETTABLE: bool>(Option<T>);

impl<T: Default> Default for BackwardsCompatibleOption<T, false> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T: Default> Default for BackwardsCompatibleOption<T, true> {
    fn default() -> Self {
        Self(Some(T::default()))
    }
}

impl<T: Hash, const SETTABLE: bool> Hash for BackwardsCompatibleOption<T, SETTABLE> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(value) = &self.0 {
            value.hash(state);
        }
    }
}

impl<T> BackwardsCompatibleOption<T, true> {
    pub const fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T, const SETTABLE: bool> BackwardsCompatibleOption<T, SETTABLE> {
    pub const fn new_for_test_only(value: Option<T>) -> Self {
        Self(value)
    }

    pub const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }

    pub fn try_from_proto<Proto: TryInto<T, Error = ProxyDecodeError>>(
        proto: Option<Proto>,
    ) -> Result<Self, ProxyDecodeError> {
        match proto {
            Some(value) => Ok(Self(Some(value.try_into()?))),
            None => Ok(Self(None)),
        }
    }
}
