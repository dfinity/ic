use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
/// A helper struct for introducing new fields to structs that must stay backwards compatible.
/// Compared to [`Option`], its [`Hash`] implementation:
///  - ignores `None` (so adding an unset field preserves the surrounding struct hash), and
///  - hashes `Some(v)` like `v` (so later replacing it with `T` preserves hashes).
///
/// Lifecycle of adding a new field to a struct in a backwards compatible way:
/// 1. Add a new field to the struct with type `BackwardsCompatible<T, false>`. At this point the
///    field is *NOT* allowed to have any value other than `None`.
/// 2. When the change is deployed to all replicas, we can switch the type to
///    `BackwardsCompatible<T, true>` and the field can begin to be populated.
/// 3. When the change is deployed to all replicas, we can replace the type with `T`.
pub struct BackwardsCompatible<T, const SETTABLE: bool>(Option<T>);

impl<T: Default> Default for BackwardsCompatible<T, false> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T: Default> Default for BackwardsCompatible<T, true> {
    fn default() -> Self {
        Self(Some(T::default()))
    }
}

impl<T: Hash, const SETTABLE: bool> Hash for BackwardsCompatible<T, SETTABLE> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(value) = &self.0 {
            value.hash(state);
        }
    }
}

impl<T> BackwardsCompatible<T, true> {
    pub const fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T, const SETTABLE: bool> BackwardsCompatible<T, SETTABLE> {
    #[doc(hidden)]
    pub const fn new_for_test_only(value: Option<T>) -> Self {
        Self(value)
    }

    /// Allows to access the inner value, if set. Note that this could still be `Some(T)` even if
    /// `SETTABLE` is `false` in case the replica version was rolled back from a version that
    /// populated the field.
    pub const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Converts an optional protobuf value into a `BackwardsCompatible` value. Even if `SETTABLE`
    /// is `false`, if the protobuf value is `Some`, the inner value will be converted and stored in
    /// the `BackwardsCompatible` value. This is to allow for the case where a replica version that
    /// populated the field is rolled back to a version that does not populate the field.
    pub fn try_from_proto<Proto: TryInto<T, Error = ProxyDecodeError>>(
        proto: Option<Proto>,
    ) -> Result<Self, ProxyDecodeError> {
        match proto {
            Some(value) => Ok(Self(Some(value.try_into()?))),
            None => Ok(Self(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{DefaultHasher, Hash, Hasher};

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn none_variant_is_ignored_in_hash() {
        let none = BackwardsCompatible::<u64, false>::new_for_test_only(None);

        // Hashing the `None` variant must not write anything to the hasher, so
        // the result must be identical to that of a fresh, untouched hasher.
        assert_eq!(hash_of(&none), DefaultHasher::new().finish());
    }

    #[test]
    fn some_variant_hashes_like_inner_value() {
        let value = 42_u64;
        let some = BackwardsCompatible::<u64, true>::new(value);

        assert_eq!(hash_of(&some), hash_of(&value));
    }

    #[derive(Hash)]
    struct WithoutField {
        a: u64,
        b: String,
    }
    #[derive(Hash)]
    struct WithUnsettableField {
        a: u64,
        b: String,
        unsettable_field: BackwardsCompatible<u32, false>,
    }
    #[derive(Hash)]
    struct WithSettableField {
        a: u64,
        b: String,
        settable_field: BackwardsCompatible<u32, true>,
    }

    #[test]
    fn adding_none_field_preserves_struct_hash() {
        let without = WithoutField {
            a: 7,
            b: "ic".to_string(),
        };
        let with = WithUnsettableField {
            a: 7,
            b: "ic".to_string(),
            unsettable_field: BackwardsCompatible::default(),
        };

        // The whole point of the type: introducing a `None` field leaves the
        // hash of the surrounding struct unchanged.
        assert_eq!(hash_of(&without), hash_of(&with));
    }

    #[test]
    fn adding_some_field_changes_struct_hash() {
        let without = WithoutField {
            a: 7,
            b: "ic".to_string(),
        };
        let with = WithSettableField {
            a: 7,
            b: "ic".to_string(),
            settable_field: BackwardsCompatible::default(),
        };

        // Introducing a `Some` field changes the hash of the surrounding struct.
        assert_ne!(hash_of(&without), hash_of(&with));
    }

    #[test]
    fn default_is_none_when_not_settable() {
        let opt = BackwardsCompatible::<u64, false>::default();

        assert_eq!(opt.as_ref(), None);
    }

    #[test]
    fn default_is_some_default_when_settable() {
        let opt = BackwardsCompatible::<u64, true>::default();

        assert_eq!(opt.as_ref(), Some(&u64::default()));
    }

    #[test]
    fn new_wraps_value_in_some() {
        let opt = BackwardsCompatible::<u64, true>::new(123);

        assert_eq!(opt.as_ref(), Some(&123));
    }

    #[derive(Debug, PartialEq)]
    struct Value(u64);

    struct ValidProto(u64);
    impl TryFrom<ValidProto> for Value {
        type Error = ProxyDecodeError;
        fn try_from(proto: ValidProto) -> Result<Self, Self::Error> {
            Ok(Value(proto.0))
        }
    }

    struct InvalidProto;
    impl TryFrom<InvalidProto> for Value {
        type Error = ProxyDecodeError;
        fn try_from(_: InvalidProto) -> Result<Self, Self::Error> {
            Err(ProxyDecodeError::MissingField("Value"))
        }
    }

    #[test]
    fn try_from_proto_maps_none_to_none() {
        let opt_settable = BackwardsCompatible::<Value, true>::try_from_proto(None::<ValidProto>)
            .expect("conversion of `None` should never fail");
        let opt_not_settable =
            BackwardsCompatible::<Value, false>::try_from_proto(None::<ValidProto>)
                .expect("conversion of `None` should never fail");

        // `None` maps to `None` regardless of whether the field is settable or not.
        assert_eq!(opt_settable.as_ref(), None);
        assert_eq!(opt_not_settable.as_ref(), None);
    }

    #[test]
    fn try_from_proto_maps_some_to_converted_value() {
        let opt_settable = BackwardsCompatible::<Value, true>::try_from_proto(Some(ValidProto(9)))
            .expect("conversion should succeed");
        let opt_not_settable =
            BackwardsCompatible::<Value, false>::try_from_proto(Some(ValidProto(9)))
                .expect("conversion should succeed");

        // `Some(proto)` maps to `Some(converted_value)` regardless of whether the field is
        // settable or not.
        assert_eq!(opt_settable.as_ref(), Some(&Value(9)));
        assert_eq!(opt_not_settable.as_ref(), Some(&Value(9)));
    }

    #[test]
    fn try_from_proto_propagates_conversion_error() {
        let result_settable =
            BackwardsCompatible::<Value, true>::try_from_proto(Some(InvalidProto));
        let result_not_settable =
            BackwardsCompatible::<Value, false>::try_from_proto(Some(InvalidProto));

        // Conversion errors are propagated regardless of whether the field is settable or not.
        assert!(matches!(
            result_settable,
            Err(ProxyDecodeError::MissingField("Value"))
        ));
        assert!(matches!(
            result_not_settable,
            Err(ProxyDecodeError::MissingField("Value"))
        ));
    }
}
