use ic_protobuf::proxy::ProxyDecodeError;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// A helper struct for introducing new fields to structs that must stay backwards compatible.
/// Its inner value can be read with [`as_ref`](BackwardsCompatible::as_ref).
///
/// Compared to [`Option`], its [`Hash`] implementation:
///  - ignores `None` (so adding an unset field preserves the surrounding struct hash), and
///  - hashes `Some(v)` like `v` (so later replacing it with `T` preserves hashes).
/// The purpose of this is to have a compatible `Hash` implementation across versions of a struct,
/// so that replicas running different versions of the code can still agree on the hash of a struct
/// instance.
///
/// IMPORTANT: there should be only one field of type `BackwardsCompatible` in a struct. Otherwise,
/// two different instances of the struct could have the same hash. For example:
/// ```
/// #[derive(Hash)]
/// struct S { a: BackwardsCompatible<u8, false>, b: BackwardsCompatible<u8, false> }
///
/// S { a: Some(1), b: None }
/// S { a: None, b: Some(1) }
/// ```
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

    #[derive(Debug, PartialEq, Hash)]
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

    /// Showcases the full backwards-compatible rollout *and* rollback of a new struct field, as
    /// documented on [`BackwardsCompatible`]. Each `V0`..`V3` struct models a replica version;
    /// during a rollout/rollback adjacent versions run side by side, so for the same logical state
    /// they must agree on the struct hash and must be able to exchange the field over the wire
    /// without losing it.
    mod rollout {
        use super::*;

        // Base fields shared by every version; only the new field evolves across versions.
        const A: u64 = 7;
        const B: &str = "ic";

        // Protobuf-like wire format exchanged between replicas. Like a freshly added proto field,
        // `new_field` is optional.
        struct Wire {
            a: u64,
            b: String,
            new_field: Option<ValidProto>,
        }

        // Before the field existed.
        #[derive(Hash)]
        struct V0 {
            a: u64,
            b: String,
        }

        // Step 1: field added as `<_, false>` — understood on the wire, but never populated.
        #[derive(Hash)]
        struct V1 {
            a: u64,
            b: String,
            new_field: BackwardsCompatible<Value, false>,
        }

        // Step 2: field switched to `<_, true>` — now allowed to be populated.
        #[derive(Hash)]
        struct V2 {
            a: u64,
            b: String,
            new_field: BackwardsCompatible<Value, true>,
        }

        // Step 3: field replaced with the bare type `T` — now mandatory.
        #[derive(Hash)]
        struct V3 {
            a: u64,
            b: String,
            new_field: Value,
        }

        impl V0 {
            fn to_wire(&self) -> Wire {
                // V0 knows nothing about the field...
                Wire {
                    a: self.a,
                    b: self.b.clone(),
                    new_field: None,
                }
            }
            fn from_wire(wire: Wire) -> Self {
                // ...and ignores it on the way in.
                Self {
                    a: wire.a,
                    b: wire.b,
                }
            }
        }

        impl V1 {
            fn to_wire(&self) -> Wire {
                Wire {
                    a: self.a,
                    b: self.b.clone(),
                    new_field: self.new_field.as_ref().map(|v| ValidProto(v.0)),
                }
            }
            fn from_wire(wire: Wire) -> Result<Self, ProxyDecodeError> {
                Ok(Self {
                    a: wire.a,
                    b: wire.b,
                    new_field: BackwardsCompatible::try_from_proto(wire.new_field)?,
                })
            }
        }

        impl V2 {
            fn to_wire(&self) -> Wire {
                Wire {
                    a: self.a,
                    b: self.b.clone(),
                    new_field: self.new_field.as_ref().map(|v| ValidProto(v.0)),
                }
            }
            fn from_wire(wire: Wire) -> Result<Self, ProxyDecodeError> {
                Ok(Self {
                    a: wire.a,
                    b: wire.b,
                    new_field: BackwardsCompatible::try_from_proto(wire.new_field)?,
                })
            }
        }

        impl V3 {
            fn to_wire(&self) -> Wire {
                Wire {
                    a: self.a,
                    b: self.b.clone(),
                    new_field: Some(ValidProto(self.new_field.0)),
                }
            }
            fn from_wire(wire: Wire) -> Result<Self, ProxyDecodeError> {
                let new_field = wire
                    .new_field
                    .map(Value::try_from)
                    .transpose()?
                    .ok_or(ProxyDecodeError::MissingField("V3::new_field"))?;
                Ok(Self {
                    a: wire.a,
                    b: wire.b,
                    new_field,
                })
            }
        }

        #[test]
        fn full_rollout_and_rollback_preserve_cross_version_hashes() {
            let v0 = V0 {
                a: A,
                b: B.to_string(),
            };
            let v1_unset = V1 {
                a: A,
                b: B.to_string(),
                new_field: BackwardsCompatible::empty(),
            };

            // === Rollout step 1 — introduce the field as `<_, false>` (V0 <-> V1) ===
            // Adding an unset backwards-compatible field must not change the struct hash, so V0 and
            // V1 replicas agree while both are in the fleet.
            assert_eq!(hash_of(&v0), hash_of(&v1_unset));
            // The (absent) field round-trips: a V0 wire decodes into an unset V1 with an equal hash.
            let v1_from_v0 = V1::from_wire(v0.to_wire()).unwrap();
            assert_eq!(v1_from_v0.new_field.as_ref(), None);
            assert_eq!(hash_of(&v1_from_v0), hash_of(&v0));

            // === Rollout step 2 — make the field settable `<_, true>` (V1 <-> V2) ===
            // A pure type change; in production the field is still unset, so the switch is
            // hash-neutral. We build the V2 state by decoding a V1 wire, exactly like a replica
            // migrating its own state across the upgrade.
            let v2_unset = V2::from_wire(v1_unset.to_wire()).unwrap();
            assert_eq!(v2_unset.new_field.as_ref(), None);
            assert_eq!(hash_of(&v1_unset), hash_of(&v2_unset));

            // === All replicas at V2 — start populating the field ===
            let v2_set = V2 {
                a: A,
                b: B.to_string(),
                new_field: BackwardsCompatible::new(Value(42)),
            };
            // Populating the field now genuinely changes the hash (it is no longer `None`).
            assert_ne!(hash_of(&v2_unset), hash_of(&v2_set));

            // === Rollout step 3 — replace with the bare type `T` (V2 <-> V3) ===
            // `Some(v)` hashes like `v`, so a populated V2 and a mandatory-field V3 agree.
            let v3 = V3 {
                a: A,
                b: B.to_string(),
                new_field: Value(42),
            };
            assert_eq!(hash_of(&v2_set), hash_of(&v3));
            // The value round-trips from V2 to V3.
            let v3_from_v2 = V3::from_wire(v2_set.to_wire()).unwrap();
            assert_eq!(v3_from_v2.new_field, Value(42));
            assert_eq!(hash_of(&v3_from_v2), hash_of(&v2_set));

            // Trying to rollout to V3 with an unset field fails, as expected.
            let v3_from_v2_unset = V3::from_wire(v2_unset.to_wire());
            assert!(matches!(
                v3_from_v2_unset,
                Err(ProxyDecodeError::MissingField("V3::new_field"))
            ));

            // ============================= Rollback =============================

            // --- Rollback step 3 -> 2 (V3 -> V2) ---
            // A replica downgraded from V3 ingests the now-optional value and still agrees on hash.
            let v2_from_v3 = V2::from_wire(v3.to_wire()).unwrap();
            assert_eq!(v2_from_v3.new_field.as_ref(), Some(&Value(42)));
            assert_eq!(hash_of(&v2_from_v3), hash_of(&v3));

            // --- Rollback step 2 -> 1 (V2 -> V1), field already populated (the crux) ---
            // A `<_, false>` field cannot *produce* a value, but it still *understands* one decoded
            // from a newer replica, and hashes it identically. This is what makes rolling back a
            // populated fleet safe.
            let v1_from_v2_set = V1::from_wire(v2_set.to_wire()).unwrap();
            assert_eq!(v1_from_v2_set.new_field.as_ref(), Some(&Value(42)));
            assert_eq!(hash_of(&v1_from_v2_set), hash_of(&v2_set));
            // Sanity check also for the V2 unset case
            let v1_from_v2_unset = V1::from_wire(v2_unset.to_wire()).unwrap();
            assert_eq!(v1_from_v2_unset.new_field.as_ref(), None);
            assert_eq!(hash_of(&v1_from_v2_unset), hash_of(&v2_unset));

            // --- Rollback step 1 -> 0 (V1 -> V0), only safe while the field is unset ---
            let v0_from_v1 = V0::from_wire(v1_unset.to_wire());
            assert_eq!(hash_of(&v0_from_v1), hash_of(&v0));

            // --- Safety floor: once populated, rolling back to V0 would diverge ---
            // A no-field V0 replica cannot match a populated field. This is exactly why the field
            // is rolled out as "understood" (step 1) everywhere before any value is produced, and
            // why the safe rollback floor rises to V1 once the field is populated.
            assert_ne!(hash_of(&v0), hash_of(&v1_from_v2_set));
        }
    }
}
