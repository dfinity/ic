use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// A helper struct for introducing new fields to structs that must stay backwards compatible.
/// Its inner value can be read with [`as_ref`](BackwardsCompatible::as_ref).
///
/// Compared to [`Option`], its [`Hash`] implementation:
///  - ignores `None` (so adding an unset field preserves the surrounding struct hash), and
///  - hashes `Some(v)` like `v` (so later replacing it with `T` preserves hashes).
///
/// The purpose of this is to have a compatible `Hash` implementation across versions of a struct,
/// so that replicas running different versions of the code can still agree on the hash of a struct
/// instance.
///
/// IMPORTANT: there should be only one field of type `BackwardsCompatible` in a struct. Otherwise,
/// two different instances of the struct could have the same hash. For example:
///
/// #[derive(Hash)]
/// struct S { a: BackwardsCompatible<u8, false>, b: BackwardsCompatible<u8, false> }
///
/// S { a: Some(1), b: None }
/// S { a: None, b: Some(1) }
///
/// would have the same hash.
///
/// Lifecycle of adding a new field to a struct in a backwards compatible way:
/// 1. Add a new field to the struct with type `BackwardsCompatible<T, false>`. At this point the
///    field is *NOT* allowed to be instantiated with any value other than `None`. Though, it still
///    "understands" it: if it receives a protobuf containing a set value, it will still convert it
///    and store it in the `BackwardsCompatible` value.
/// 2. When the change is deployed to all replicas, we can switch the type to
///    `BackwardsCompatible<T, true>` and the field can begin to be populated.
/// 3. When the change is deployed to all replicas, we can replace the type with `T`.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
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

impl<T> BackwardsCompatible<T, false> {
    pub const fn empty() -> Self {
        Self(None)
    }
}

impl<T> BackwardsCompatible<T, true> {
    pub const fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T, const SETTABLE: bool> BackwardsCompatible<T, SETTABLE> {
    /// Creates a new `BackwardsCompatible` value with the given inner value. This is only intended
    /// for use in unit tests, where we would want to be able to fill a field that would not be
    /// settable yet in production.
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
    use ic_exhaustive_derive::ExhaustiveSet;

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

    #[derive(Clone, Debug, Default, PartialEq, Hash, ExhaustiveSet)]
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

    /// Verifies, over every value produced by [`ExhaustiveSet`], that a `BackwardsCompatible` field
    /// hashes identically across the representations it takes on throughout its lifecycle. This is
    /// what lets replicas running different versions of the code agree on the hash of a struct.
    mod hash_compatibility {
        use super::*;
        use crate::exhaustive::ExhaustiveSet;
        use ic_crypto_test_utils_reproducible_rng::reproducible_rng;

        /// Every value the *unsettable* field can be generated with (its `ExhaustiveSet` is exactly
        /// `[None]`) hashes identically to:
        ///  - *having nothing* — an absent field contributes nothing to the hash
        ///  - the *settable* field (`<_, true>`) holding the same value
        ///  - the *settable* field deserialized from the serialized unsettable field
        ///
        /// This is what lets step 1 of the lifecycle be deployed without changing any hash.
        #[test]
        fn unsettable_values_hash_like_nothing_and_settable() {
            let mut rng = reproducible_rng();
            for unsettable in BackwardsCompatible::<Value, false>::exhaustive_set(&mut rng) {
                // Same hash as having nothing: hashing the field leaves the hasher untouched.
                assert_eq!(hash_of(&unsettable), DefaultHasher::new().finish());

                let same_value_but_settable = BackwardsCompatible::<Value, true>::new_for_test_only(
                    unsettable.as_ref().cloned(),
                );
                // Same hash as the settable representation of the same value.
                assert_eq!(hash_of(&unsettable), hash_of(&same_value_but_settable));

                let deserialized_settable = BackwardsCompatible::<Value, true>::try_from_proto(
                    unsettable.as_ref().cloned().map(|v| ValidProto(v.0)),
                )
                .unwrap();
                // Same hash as the settable representation of the same value, even when
                // deserialized from a protobuf.
                assert_eq!(hash_of(&unsettable), hash_of(&deserialized_settable));
            }
        }

        /// Every value the *settable* field can be generated with (its `ExhaustiveSet` is every
        /// `Some(v)`) hashes identically to:
        ///  - the *unsettable* field (`<_, false>`) holding the same value (so a rollback still
        ///    agrees)
        ///  - the *settable* field deserialized from the serialized settable field (so a
        ///    rollback still agrees)
        ///  - the bare `T` it is eventually replaced with
        ///  - the bare `T` deserialized from the serialized settable field
        ///
        /// This is what lets steps 2 and 3 of the lifecycle be deployed without changing any hash.
        #[test]
        fn settable_values_hash_like_unsettable_and_bare() {
            let mut rng = reproducible_rng();
            for settable in BackwardsCompatible::<Value, true>::exhaustive_set(&mut rng) {
                let same_value_but_unsettable =
                    BackwardsCompatible::<Value, false>::new_for_test_only(
                        settable.as_ref().cloned(),
                    );
                // Same hash as the unsettable representation of the same value.
                assert_eq!(hash_of(&settable), hash_of(&same_value_but_unsettable));
                let deserialized_unsettable = BackwardsCompatible::<Value, false>::try_from_proto(
                    settable.as_ref().cloned().map(|v| ValidProto(v.0)),
                )
                .unwrap();
                // Same hash as the unsettable representation of the same value, even when
                // deserialized from a protobuf.
                assert_eq!(hash_of(&settable), hash_of(&deserialized_unsettable));

                let bare = settable
                    .as_ref()
                    .cloned()
                    .expect("the settable `ExhaustiveSet` only contains populated values");
                // Same hash as the bare `T`.
                assert_eq!(hash_of(&settable), hash_of(&bare));
                let deserialized_bare = Value::try_from(ValidProto(bare.0)).unwrap();
                // Same hash as the bare `T`, even when deserialized from a protobuf.
                assert_eq!(hash_of(&settable), hash_of(&deserialized_bare));
            }
        }
    }
}
