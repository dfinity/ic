use crate::{
    common::LOG_PREFIX,
    pb::v1::{
        registry_stable_storage::Version as ReprVersion, ChangelogEntry, RegistryStableStorage,
    },
};
use ic_certified_map::RbTree;
use ic_registry_transport::{
    pb::v1::{
        registry_mutation::Type, RegistryAtomicMutateRequest, RegistryDelta, RegistryMutation,
        RegistryValue,
    },
    Error,
};
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use prost::Message;
use std::{
    cmp::max,
    collections::{BTreeMap, VecDeque},
    fmt,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

/// The maximum size a registry delta, used to ensure that response payloads
/// stay under `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64`.
///
/// We reserve ⅓ of the response buffer capacity for encoding overhead.
pub const MAX_REGISTRY_DELTAS_SIZE: usize =
    2 * MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize / 3;

/// The type for the registry map.
///
/// The Deque part is mostly future proofing for when we have garbage collection
/// so that we're able to call pop_front().
pub type RegistryMap = BTreeMap<Vec<u8>, VecDeque<RegistryValue>>;
pub type Version = u64;
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
pub struct EncodedVersion([u8; 8]);

impl EncodedVersion {
    pub const fn as_version(&self) -> Version {
        Version::from_be_bytes(self.0)
    }
}

impl fmt::Debug for EncodedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_version())
    }
}

impl From<Version> for EncodedVersion {
    fn from(v: Version) -> Self {
        Self(v.to_be_bytes())
    }
}

impl From<EncodedVersion> for Version {
    fn from(v: EncodedVersion) -> Self {
        v.as_version()
    }
}

impl AsRef<[u8]> for EncodedVersion {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The main struct for the Registry.
///
/// The registry is a versioned key value store.
///
/// TODO(NNS1-487): Garbage collection.
#[derive(PartialEq, Default, Clone, Debug)]
pub struct Registry {
    /// Global counter that is incremented each time a mutation is applied to
    /// the registry. Each set of changes is tagged with this version.
    version: Version,

    /// Registry contents represented as a versioned key/value store, where
    /// value versions are stored in a deque in ascending order (latest version
    /// is stored at the back of the deque).
    pub(crate) store: RegistryMap,

    /// All the mutations applied to the registry.
    ///
    /// We keep them explicitly for certification purposes and as a stable
    /// representation that allows us change the index structure in future.
    ///
    /// Each entry contains a blob which is a serialized
    /// RegistryAtomicMutateRequest.  We keep the serialized version around to
    /// make sure that hash trees stay the same even if protobuf schema evolves.
    pub(crate) changelog: RbTree<EncodedVersion, Vec<u8>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the deltas applied since `version`, exclusive; optionally
    /// limited to the subsequent `max_versions` (i.e. changes applied in
    /// versions `(version, version + max_versions]`).
    pub fn get_changes_since(
        &self,
        version: u64,
        max_versions: Option<usize>,
    ) -> Vec<RegistryDelta> {
        let max_version = match max_versions {
            Some(max_versions) => version.saturating_add(max_versions as u64),
            None => u64::MAX,
        };

        self.store
            .iter()
            // For every key create a delta with values versioned `(version, max_version]`.
            .map(|(key, values)| RegistryDelta {
                key: key.clone(),
                values: values
                    .iter()
                    .rev()
                    .skip_while(|value| value.version > max_version)
                    .take_while(|value| value.version > version)
                    .cloned()
                    .collect(),
            })
            // Drop empty deltas.
            .filter(|delta| !delta.values.is_empty())
            .collect()
    }

    /// Returns the highest version of value such that it is lower than or equal
    /// to 'version', or None if it does not exist or if the most recent update
    /// whose version is less than or equal to 'version' is a deletion marker.
    pub fn get(&self, key: &[u8], version: Version) -> Option<&RegistryValue> {
        let value = self
            .store
            .get(key)?
            .iter()
            .rev()
            // Get the first one versioned at or below `version`.
            .find(|value| value.version <= version)?;
        if value.deletion_marker {
            return None;
        }
        Some(value)
    }

    /// Computes the number of deltas with version greater than `since_version`
    /// that fit into the specified byte limit.
    ///
    /// This function is used to determine the number of deltas to include into
    /// a response to avoid the going beyond the max response size limit.
    pub fn count_fitting_deltas(&self, since_version: Version, max_bytes: usize) -> usize {
        self.changelog()
            .iter()
            .skip(since_version as usize)
            .scan(0, |size, (key, value)| {
                *size += value.len() + key.as_ref().len();
                Some(*size)
            })
            .take_while(|size| *size <= max_bytes)
            .count()
    }

    /// Returns the last RegistryValue, if any, for the given key.
    ///
    /// As we keep track of deletions in the registry, this value
    /// might be the tombstone, that is, RegistryValue with 'deleted'
    /// field equal true, and value being completely bogus. Thus,
    /// when calling 'get_last' you must check the 'deleted' marker,
    /// otherwise you might deal with garbage.
    fn get_last(&self, key: &[u8]) -> Option<&RegistryValue> {
        self.store.get(key).and_then(VecDeque::back)
    }

    /// Increments the latest version of the registry.
    fn increment_version(&mut self) -> Version {
        self.version += 1;
        self.version
    }

    pub fn latest_version(&self) -> Version {
        self.version
    }

    fn apply_mutations_as_version(
        &mut self,
        mut mutations: Vec<RegistryMutation>,
        version: Version,
    ) {
        // We sort entries by key to eliminate the difference between changelog
        // produced by the new version of the registry canister starting from v1
        // and the changelog recovered from the stable representation of the
        // original version that didn't support certification.
        mutations.sort_by(|l, r| l.key.cmp(&r.key));
        for m in mutations.iter_mut() {
            // We normalize all the INSERT/UPDATE/UPSERT operations to be just
            // UPSERTs. This serves 2 purposes:
            //
            // 1. This significantly simplifies reconstruction of the changelog
            //    when we deserialize the registry from the original stable
            //    representation.
            //
            // 2. This will play nicely with garbage collection: if an old
            //    INSERT entry is removed, the newly connected clients won't
            //    fail because of an UPDATE in the first survived entry with the
            //    same key.
            m.mutation_type = match Type::try_from(m.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => Type::Upsert,
                Type::Delete => Type::Delete,
            } as i32;
        }

        let req = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        self.changelog_insert(version, &req);

        for mutation in req.mutations {
            (*self.store.entry(mutation.key).or_default()).push_back(RegistryValue {
                version,
                value: mutation.value,
                deletion_marker: mutation.mutation_type == Type::Delete as i32,
            });
        }
    }

    /// Applies the given mutations, without any check corresponding
    /// to the mutation_type.
    ///
    /// This should be called only after having made sure that all
    /// preconditions are satisfied.
    fn apply_mutations(&mut self, mutations: Vec<RegistryMutation>) {
        if mutations.is_empty() {
            // We should not increment the version if there is no
            // mutation, so that we keep the invariant that the
            // global version is the max of all versions in the store.
            return;
        }
        self.increment_version();
        self.apply_mutations_as_version(mutations, self.version);
    }

    /// Verifies the implicit precondition corresponding to the mutation_type
    /// field.
    fn verify_mutation_type(&self, mutations: &[RegistryMutation]) -> Vec<Error> {
        mutations
            .iter()
            .map(|m| {
                let key = &m.key;
                let latest = self
                    .get_last(key)
                    .filter(|registry_value| !registry_value.deletion_marker);
                match (Type::try_from(m.mutation_type).ok(), latest) {
                    (None, _) => Err(Error::MalformedMessage(format!(
                        "Unknown mutation type {} for key {:?}.",
                        m.mutation_type, m.key
                    ))),
                    (Some(Type::Insert), None) => Ok(()),
                    (Some(Type::Insert), Some(_)) => Err(Error::KeyAlreadyPresent(key.to_vec())),
                    (Some(Type::Update), None) => Err(Error::KeyNotPresent(key.to_vec())),
                    (Some(Type::Update), Some(_)) => Ok(()),
                    (Some(Type::Delete), None) => Err(Error::KeyNotPresent(key.to_vec())),
                    (Some(Type::Delete), Some(_)) => Ok(()),
                    (Some(Type::Upsert), None) => Ok(()),
                    (Some(Type::Upsert), Some(_)) => Ok(()),
                }
            })
            .flat_map(Result::err)
            .collect()
    }

    /// Checks that invariants would hold after applying mutations, and applies the mutations if they do
    pub fn maybe_apply_mutation_internal(&mut self, mutations: Vec<RegistryMutation>) {
        println!(
            "{}Received a mutate call containing a list of {} mutations",
            LOG_PREFIX,
            mutations.len()
        );
        self.verify_mutations_internal(&mutations);
        self.apply_mutations(mutations);
    }

    /// Checks that invariants would hold after applying the mutations
    pub(crate) fn verify_mutations_internal(&self, mutations: &Vec<RegistryMutation>) {
        let errors = self.verify_mutation_type(mutations.as_slice());
        if !errors.is_empty() {
            panic!(
                "{}Verification of the mutation type failed with the following errors: [{}].",
                LOG_PREFIX,
                errors
                    .iter()
                    .map(|e| format!("{}", e))
                    .collect::<Vec::<String>>()
                    .join(", ")
            );
        }

        self.check_global_state_invariants(mutations.as_slice());
    }

    /// Serializes the registry contents using the specified version of stable
    /// representation.
    fn serializable_form_at(&self, repr_version: ReprVersion) -> RegistryStableStorage {
        match repr_version {
            ReprVersion::Version1 => RegistryStableStorage {
                version: repr_version as i32,
                deltas: vec![],
                changelog: self
                    .changelog
                    .iter()
                    .map(|(encoded_version, bytes)| ChangelogEntry {
                        version: encoded_version.as_version(),
                        encoded_mutation: bytes.clone(),
                    })
                    .collect(),
            },
            ReprVersion::Unspecified => RegistryStableStorage {
                version: repr_version as i32,
                deltas: self
                    .store
                    .iter()
                    .map(|(key, values)| RegistryDelta {
                        key: key.clone(),
                        values: values.iter().cloned().collect(),
                    })
                    .collect(),
                changelog: vec![],
            },
        }
    }

    pub fn serializable_form(&self) -> RegistryStableStorage {
        self.serializable_form_at(ReprVersion::Version1)
    }

    pub fn changelog(&self) -> &RbTree<EncodedVersion, Vec<u8>> {
        &self.changelog
    }

    /// Inserts a changelog entry at the given version, while enforcing the
    /// [`MAX_REGISTRY_DELTAS_SIZE`] limit.
    fn changelog_insert(&mut self, version: u64, req: &RegistryAtomicMutateRequest) {
        let version = EncodedVersion::from(version);
        let bytes = pb_encode(req);

        let delta_size = version.as_ref().len() + bytes.len();
        if delta_size > MAX_REGISTRY_DELTAS_SIZE {
            panic!(
                "{}Transaction rejected because delta would be too large: {} vs {}.",
                LOG_PREFIX, delta_size, MAX_REGISTRY_DELTAS_SIZE
            );
        }

        self.changelog.insert(version, bytes);
    }

    /// Sets the content of the registry from its serialized representation.
    ///
    /// Panics if not currently empty: this is only meant to be used in
    /// canister_post_upgrade.
    ///
    /// In post_upgrade, one should do as much verification as possible, and
    /// panic for anything unexpected. Indeed, panicking here keeps the
    /// pre-upgrade state unchanged, and gives the developer an opportunity
    /// to try upgrading to a different wasm binary. As a corollary, any
    /// lossy way of handling unexpected data must be banned in
    /// post_upgrade.
    pub fn from_serializable_form(&mut self, stable_repr: RegistryStableStorage) {
        assert!(self.store.is_empty());
        assert!(self.changelog.is_empty());
        assert_eq!(self.version, 0);

        let repr_version = ReprVersion::try_from(stable_repr.version).unwrap_or_else(|_| {
            panic!(
                "Version {} of stable registry representation is not supported by this canister",
                stable_repr.version
            )
        });

        match repr_version {
            ReprVersion::Version1 => {
                let mut current_version = 0;
                for entry in stable_repr.changelog {
                    // Code to fix ICSUP-2589.
                    // This fills in missing versions with empty entries so that clients see an
                    // unbroken sequence.
                    // If the current version is different from the previous version + 1, we
                    // need to add empty records to fill out the missing versions, to keep
                    // the invariants that are present in the
                    // client side.
                    for i in current_version + 1..entry.version {
                        let mutations = vec![RegistryMutation {
                            mutation_type: Type::Upsert as i32,
                            key: "_".into(),
                            value: "".into(),
                        }];
                        self.apply_mutations_as_version(mutations, i);
                        self.version = i;
                    }
                    // End code to fix ICSUP-2589

                    let req = RegistryAtomicMutateRequest::decode(&entry.encoded_mutation[..])
                        .unwrap_or_else(|err| {
                            panic!("Failed to decode mutation@{}: {}", entry.version, err)
                        });
                    self.apply_mutations_as_version(req.mutations, entry.version);
                    self.version = entry.version;
                    current_version = self.version;
                }
            }
            ReprVersion::Unspecified => {
                let mut mutations_by_version = BTreeMap::<Version, Vec<RegistryMutation>>::new();
                for delta in stable_repr.deltas.into_iter() {
                    self.version = max(
                        self.version,
                        delta
                            .values
                            .last()
                            .map(|registry_value| registry_value.version)
                            .unwrap_or(0),
                    );

                    for v in delta.values.iter() {
                        mutations_by_version
                            .entry(v.version)
                            .or_default()
                            .push(RegistryMutation {
                                mutation_type: if v.deletion_marker {
                                    Type::Delete
                                } else {
                                    Type::Upsert
                                } as i32,
                                key: delta.key.clone(),
                                value: v.value.clone(),
                            })
                    }

                    self.store.insert(delta.key, VecDeque::from(delta.values));
                }
                // We iterated over keys in ascending order, so the mutations
                // must also be sorted by key, resulting in canonical encoding.
                for (v, mutations) in mutations_by_version.into_iter() {
                    self.changelog_insert(
                        v,
                        &RegistryAtomicMutateRequest {
                            mutations,
                            preconditions: vec![],
                        },
                    );
                }
            }
        }
    }
}

fn pb_encode(msg: &impl prost::Message) -> Vec<u8> {
    let mut buf = vec![];
    msg.encode(&mut buf).unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_registry_transport::{delete, insert, update, upsert};
    use rand::{Rng, SeedableRng};
    use rand_distr::{Alphanumeric, Distribution, Poisson, Uniform};

    /// Simulate a round-trip through stable memory, which is an essential part
    /// of the upgrade process.
    ///
    /// This should bring back the registry in a state indistinguishable
    /// from the one before calling this method.
    fn serialize_then_deserialize(registry: Registry) {
        let mut serialized_v0 = Vec::new();
        registry
            .serializable_form_at(ReprVersion::Unspecified)
            .encode(&mut serialized_v0)
            .expect("Error encoding registry");
        let mut serialized_v1 = Vec::new();
        registry
            .serializable_form_at(ReprVersion::Version1)
            .encode(&mut serialized_v1)
            .expect("Error encoding registry");

        let restore_from_v0 = RegistryStableStorage::decode(serialized_v0.as_slice())
            .expect("Error decoding registry");
        let mut restored = Registry::new();
        restored.from_serializable_form(restore_from_v0);
        assert_eq!(restored, registry);

        let restore_from_v1 = RegistryStableStorage::decode(serialized_v1.as_slice())
            .expect("Error decoding registry");
        let mut restored = Registry::new();
        restored.from_serializable_form(restore_from_v1);
        assert_eq!(restored, registry);
    }

    fn apply_mutations_skip_invariant_checks(
        registry: &mut Registry,
        mutations: Vec<RegistryMutation>,
    ) -> Vec<Error> {
        let errors = registry.verify_mutation_type(&mutations);
        if errors.is_empty() {
            registry.apply_mutations(mutations);
        }
        errors
    }

    /// Shorthand for asserting equality with the empty vector.
    macro_rules! assert_empty {
        ($v:expr) => {
            assert_eq!($v, vec![])
        };
    }

    #[test]
    fn test_get() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, &value)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![update(&key, &value2)]
        ));
        let result2 = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result2.unwrap().value);
        assert_eq!(registry.latest_version(), result2.unwrap().version);
        let result = registry.get(&key, registry.latest_version() - 1);
        assert_eq!(value, result.unwrap().value);
        assert_eq!(registry.latest_version() - 1, result.unwrap().version);

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_get_after_delete() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, &value)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![update(&key, &value2)]
        ));
        let result2 = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result2.unwrap().value);
        assert_eq!(registry.latest_version(), result2.unwrap().version);
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key)]
        ));
        // The definition of get says that we should get None if the last version is has
        // a deletion marker set.
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(None, result);
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, &value)]
        ));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value, result.unwrap().value);
        assert_eq!(registry.latest_version(), result.unwrap().version);

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_get_changes_since() {
        let mut registry = Registry::new();
        let key1 = vec![1, 2, 3, 4];
        let key2 = vec![5, 6, 7, 8];
        let value1 = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];
        // On the first mutation we insert key1
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key1, &value1)]
        ));
        // On the second mutation we insert key2 an update key 1
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key2, &value1), update(&key1, &value2)],
        ));
        // On the third mutation we update key 2 and delete key one.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key1), update(&key2, &value2)],
        ));
        // On the forth mutation we insert key one again
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key1, &value1)]
        ));

        // Fetching all the mutations since 0 should get
        // a total of 2 keys:
        // key 1 with three values (@1 value1, @2 value2, @3 delete, @4 value1)
        // key 2 with three values (@2 value1, @3 value2)
        let deltas = registry.get_changes_since(0, None);
        // Assert that we got the right thing, and test a few values
        assert_eq!(deltas.len(), 2);
        let key1_values = &deltas.first().unwrap().values;
        let key2_values = &deltas.get(1).unwrap().values;
        assert_eq!(key1_values.len(), 4);
        assert_eq!(key2_values.len(), 2);
        assert_eq!(key1_values[0].value, value1);
        assert_eq!(key1_values[0].version, 4);
        assert!(key1_values[1].deletion_marker);
        assert_eq!(key1_values[1].version, 3);

        assert_eq!(deltas, registry.get_changes_since(0, Some(4)));
        assert_eq!(deltas, registry.get_changes_since(0, Some(9)));

        // Fetch all mutations for 2 versions after version 1 (i.e. versions 2 and 3).
        let deltas = registry.get_changes_since(1, Some(2));
        // Assert that we got the right thing, and test the values.
        assert_eq!(deltas.len(), 2);
        let key1_values = &deltas.first().unwrap().values;
        let key2_values = &deltas.get(1).unwrap().values;
        assert_eq!(key1_values.len(), 2);
        assert_eq!(key2_values.len(), 2);
        assert!(key1_values[0].deletion_marker);
        assert_eq!(key1_values[0].version, 3);
        assert_eq!(key1_values[1].value, value2);
        assert_eq!(key1_values[1].version, 2);
        assert_eq!(key2_values[0].value, value2);
        assert_eq!(key2_values[0].version, 3);
        assert_eq!(key2_values[1].value, value1);
        assert_eq!(key2_values[1].version, 2);

        // Now try getting a couple of other versions
        // Version 4 should be empty (versions to get changes from are exclusive)
        let deltas = registry.get_changes_since(4, None);
        assert_eq!(deltas.len(), 0);
        // Changes since version 3 for should include key 1
        let deltas = registry.get_changes_since(3, None);
        assert_eq!(deltas.len(), 1);
        // Changes since version 2 for should include both keys
        let deltas = registry.get_changes_since(2, None);
        assert_eq!(deltas.len(), 2);

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_insert() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];
        // Inserting a non-existing key should succeed.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, &value)]
        ));
        // Inserting an existing (non-deleted) key should fail.
        assert_eq!(
            registry.verify_mutation_type(&[insert(&key, &value)]),
            vec![Error::KeyAlreadyPresent(key.clone())]
        );
        // After deleting the key, it should be possible to insert
        // it again.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, value2)]
        ));

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_update() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        // Updating without the key existing should fail.
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];

        assert_eq!(
            registry.verify_mutation_type(&[update(&key, &value)]),
            vec![Error::KeyNotPresent(key.clone())]
        );
        // After a regular insert the update should succeed.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, &value)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![update(&key, &value2)]
        ));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result.unwrap().value);
        // After the key is deleted the update should fail.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key)]
        ));
        assert_eq!(
            apply_mutations_skip_invariant_checks(&mut registry, vec![update(&key, &value)]),
            vec![Error::KeyNotPresent(key)]
        );

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_count_fitting_deltas() {
        let mut registry = Registry::new();

        let mutation1 = upsert([90; 50], [1; 50]);
        let mutation2 = upsert([90; 100], [1; 100]);
        let mutation3 = upsert([89; 200], [1; 200]);

        for mutation in [&mutation1, &mutation2, &mutation3] {
            assert_empty!(apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![mutation.clone()]
            ));
        }

        assert_eq!(registry.count_fitting_deltas(0, 100), 0);
        assert_eq!(registry.count_fitting_deltas(0, 150), 1);
        assert_eq!(registry.count_fitting_deltas(0, 400), 2);
        assert_eq!(registry.count_fitting_deltas(0, 2000000), 3);

        assert_eq!(registry.count_fitting_deltas(1, 150), 0);
        assert_eq!(registry.count_fitting_deltas(1, 400), 1);
        assert_eq!(registry.count_fitting_deltas(1, 2000000), 2);

        assert_eq!(registry.count_fitting_deltas(2, 300), 0);
        assert_eq!(registry.count_fitting_deltas(2, 1000), 1);

        assert_eq!(registry.count_fitting_deltas(3, 2000000), 0);
        assert_eq!(registry.count_fitting_deltas(4, 2000000), 0);
    }

    #[test]
    fn test_count_fitting_deltas_max_size() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let max_value = vec![0; max_mutation_value_size(version, key)];

        let mutation1 = upsert([90; 50], [1; 50]);
        let mutation2 = upsert(key, max_value);
        let mutation3 = upsert([89; 200], [1; 200]);

        for mutation in [&mutation1, &mutation2, &mutation3] {
            assert_empty!(apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![mutation.clone()]
            ));
        }

        assert_eq!(registry.count_fitting_deltas(0, 100), 0);
        assert_eq!(
            registry.count_fitting_deltas(0, MAX_REGISTRY_DELTAS_SIZE),
            1
        );

        assert_eq!(
            registry.count_fitting_deltas(1, MAX_REGISTRY_DELTAS_SIZE - 1),
            0
        );
        assert_eq!(
            registry.count_fitting_deltas(1, MAX_REGISTRY_DELTAS_SIZE),
            1
        );

        assert_eq!(registry.count_fitting_deltas(2, 300), 0);
        assert_eq!(registry.count_fitting_deltas(2, 1000), 1);

        assert_eq!(registry.count_fitting_deltas(3, 2000000), 0);
    }

    #[test]
    fn test_upsert() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        // Upserting without the key existing should succeed.
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];

        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![upsert(&key, &value)]
        ));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value, result.unwrap().value);
        // Afterwards, another upsert should update the value
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![upsert(&key, &value2)]
        ));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result.unwrap().value);
        // After the key is deleted the upsert should succeed.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![upsert(&key, &value)]
        ));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value, result.unwrap().value);

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_delete() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];
        // Deleting a non-existing key should fail.
        assert_eq!(
            apply_mutations_skip_invariant_checks(&mut registry, vec![delete(&key)]),
            vec![Error::KeyNotPresent(key.clone())]
        );
        // After inserting the key, delete should succeed.
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(&key, value)]
        ));
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(&key)]
        ));
        // After a key has been deleted delete should fail.
        assert_eq!(
            apply_mutations_skip_invariant_checks(&mut registry, vec![delete(&key)]),
            vec![Error::KeyNotPresent(key)]
        );

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_transactional_behavior() {
        let mut registry = Registry::new();
        // Single mutation, all good
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(b"shakira", b"colombia")]
        ));
        // Two mutations, all good
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(b"rihanna", b"barbados"), insert(b"m.i.a", b"uk")],
        ));
        // two insertions, but the second one is already present -- should do nothing
        assert_eq!(
            apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![insert(b"beyonce", b"us"), insert(b"m.i.a", b"sri lanka")]
            ),
            vec![Error::KeyAlreadyPresent(b"m.i.a".to_vec())]
        );
        // We should still be at version 2, since the last transaction returned an error
        assert_eq!(registry.latest_version(), 2);
        assert_eq!(registry.get(b"shakira", 2).unwrap().value, b"colombia");
        assert_eq!(registry.get(b"rihanna", 2).unwrap().value, b"barbados");
        assert_eq!(registry.get(b"m.i.a", 2).unwrap().value, b"uk");
        assert_eq!(registry.get(b"beyonce", 2), None);
    }

    #[test]
    fn test_transactional_behavior_with_deletes() {
        let mut registry = Registry::new();
        // Single mutation, all good
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(b"shakira", b"colombia")]
        ));
        // Two mutations, all good
        apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![insert(b"rihanna", b"barbados"), insert(b"m.i.a", b"uk")],
        );
        // two insertions, but the second one is already present -- should do nothing
        assert_empty!(apply_mutations_skip_invariant_checks(
            &mut registry,
            vec![delete(b"rihanna")]
        ));
        // We should be at version 3
        assert_eq!(registry.latest_version(), 3);
        assert_eq!(registry.get(b"rihanna", 3), None);
    }

    /// A generator of byte vectors where the length is
    /// geometrically-distributed and the content uniformly distributed.
    ///
    /// This is in a sense the most natural distribution over byte vectors:
    /// since the length is unbounded, the length should be the most natural
    /// distribution over all non-negative integers that has a finite mean:
    /// the geometric one is perfect.
    ///
    /// Then, give the length, the uniform distribution is the most natural
    /// choice for the content.
    struct RandomByteVectorGenerator {
        mean_length: f32,
    }
    impl Distribution<Vec<u8>> for RandomByteVectorGenerator {
        fn sample<R>(&self, rng: &mut R) -> Vec<u8>
        where
            R: Rng + ?Sized,
        {
            let mut val = Vec::<u8>::new();
            let p = 1.0 / (self.mean_length + 1.0);
            while rng.gen::<f32>() > p {
                val.push(rng.gen());
            }
            val
        }
    }

    fn average<Iter: Iterator<Item = usize>>(iter: Iter) -> f32 {
        let sum_and_count = iter.fold((0, 0), |(sum, n), item| (sum + item, n + 1));
        sum_and_count.0 as f32 / sum_and_count.1 as f32
    }

    #[test]
    fn test_serialize_deserialize_with_random_content_10_keys() {
        let registry = initialize_random_registry(1, 10, 25.0, 300);
        serialize_then_deserialize(registry)
    }

    #[test]
    fn test_serialize_deserialize_with_random_content_100_keys() {
        let registry = initialize_random_registry(2, 100, 8.0, 2000);
        serialize_then_deserialize(registry)
    }

    #[test]
    fn test_serialize_deserialize_with_random_content_1000_keys() {
        let registry = initialize_random_registry(3, 1000, 13.0, 1500);
        serialize_then_deserialize(registry)
    }

    #[test]
    fn test_icsup_2589() {
        let mut rng = rand::rngs::SmallRng::from_entropy();
        let registry = initialize_random_registry(3, 1000, 13.0, 150);

        let mut serializable_form = registry.serializable_form_at(ReprVersion::Version1);
        // Remove half of the entries, but retain the first and the last entry.
        let initial_len = registry.changelog().iter().count();
        serializable_form
            .changelog
            .retain(|entry| entry.version == 1 || rng.gen() || entry.version == initial_len as u64);
        let len_after_random_trim = serializable_form.changelog.len();
        assert!(len_after_random_trim < initial_len);

        let mut serialized_v1 = Vec::new();
        serializable_form
            .encode(&mut serialized_v1)
            .expect("Error encoding registry");

        let restore_from_v1 = RegistryStableStorage::decode(serialized_v1.as_slice())
            .expect("Error decoding registry");

        assert_eq!(restore_from_v1.changelog.len(), len_after_random_trim);
        let mut restored = Registry::new();

        // The restore should add the missing versions.
        restored.from_serializable_form(restore_from_v1);
        assert_eq!(restored.changelog().iter().count(), initial_len);
    }

    #[test]
    fn test_changelog_insert_max_size_delta() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let max_value = vec![0; max_mutation_value_size(version, key)];
        let mutations = vec![upsert(key, max_value)];
        let req = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        registry.changelog_insert(version, &req);

        // We should have one changelog entry.
        assert_eq!(1, registry.changelog().iter().count());
        assert!(registry
            .changelog()
            .get(EncodedVersion::from(version).as_ref())
            .is_some());
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_changelog_insert_delta_too_large() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let too_large_value = vec![0; max_mutation_value_size(version, key) + 1];
        let mutations = vec![upsert(key, too_large_value)];
        let req = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };

        registry.changelog_insert(1, &req);
    }

    #[test]
    fn test_apply_mutations_max_size_delta() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let max_value = vec![0; max_mutation_value_size(version, key)];
        let mutations = vec![upsert(key, &max_value)];
        apply_mutations_skip_invariant_checks(&mut registry, mutations);

        assert_eq!(registry.latest_version(), version);
        assert_eq!(
            registry.get(key, version),
            Some(&RegistryValue {
                value: max_value,
                version,
                deletion_marker: false
            })
        );
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_apply_mutations_delta_too_large() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let too_large_value = vec![0; max_mutation_value_size(version, key) + 1];
        let mutations = vec![upsert(key, too_large_value)];

        apply_mutations_skip_invariant_checks(&mut registry, mutations);
    }

    /// Common implementation for `from_serializable_form()` tests.
    ///
    /// In order to avoid panicking, "manually" constructs a registry containing
    /// a single mutation / mutate request that is zero or more bytes above
    /// `MAX_REGISTRY_DELTAS_SIZE`. Then serializes it using the given version
    /// and tests deserialization.
    fn test_from_serializable_form_impl(bytes_above_max_size: usize, repr_version: ReprVersion) {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let value = vec![0; max_mutation_value_size(version, key) + bytes_above_max_size];
        let mutation = upsert(key, value);
        let mutations = vec![mutation.clone()];
        let req = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        // Circumvent `changelog_insert()` to insert potentially oversized mutations.
        registry
            .changelog
            .insert(EncodedVersion::from(version), pb_encode(&req));

        (*registry.store.entry(mutation.key).or_default()).push_back(RegistryValue {
            version,
            value: mutation.value,
            deletion_marker: mutation.mutation_type == Type::Delete as i32,
        });
        registry.version = version;

        // Serialize.
        let stable_repr = registry.serializable_form_at(repr_version);

        // Deserialize.
        let mut deserialized = Registry::new();
        deserialized.from_serializable_form(stable_repr);

        assert_eq!(deserialized, registry);
    }

    #[test]
    fn test_from_serializable_form_version_unspecified_max_size_delta() {
        test_from_serializable_form_impl(0, ReprVersion::Unspecified)
    }

    #[test]
    fn test_from_serializable_form_version1_max_size_delta() {
        test_from_serializable_form_impl(0, ReprVersion::Version1)
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_from_serializable_form_version_unspecified_delta_too_large() {
        test_from_serializable_form_impl(1, ReprVersion::Unspecified)
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_from_serializable_form_version1_delta_too_large() {
        test_from_serializable_form_impl(1, ReprVersion::Version1)
    }

    #[allow(unused_must_use)] // Required because insertion errors are ignored.
    fn initialize_random_registry(
        seed: u64,
        num_keys: usize,
        mean_value_length: f32,
        num_updates: usize,
    ) -> Registry {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
        // First generate a bunch of keys
        // How long should they be, roughly?
        // We're not trying to prevent collisions here -- we just want enough diversity.
        // A Poisson distribution plus an offset of one byte sounds pretty natural.
        let mean_key_length_in_bytes = (num_keys as f64).log2() / 8.0;
        let key_length_generator = Poisson::new(mean_key_length_in_bytes).unwrap();
        // In theory the registry allows keys to be arbitrary collections of
        // bytes. In practice the replica expects keys to only ever be String.
        let keys: Vec<String> = (1..num_keys)
            .map(|_| {
                let len = key_length_generator.sample(&mut rng) as usize;
                (&mut rng)
                    .sample_iter(Alphanumeric)
                    .take(len)
                    .map(char::from)
                    .collect()
            })
            .collect();
        // First let's insert them all to avoid having to deal with insert v. update
        let mut registry = Registry::new();
        let gen = RandomByteVectorGenerator {
            mean_length: mean_value_length,
        };
        for k in &keys {
            apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![insert(k.as_bytes(), gen.sample(&mut rng))],
            );
        }
        // Now let's do some mutations.
        // Each mutation will be on a random key, so that not all keys have the same
        // number of RegistryValues.
        let key_index_distr = Uniform::new(0, keys.len());
        for _ in 0..num_updates {
            apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![update(
                    &keys[key_index_distr.sample(&mut rng)],
                    gen.sample(&mut rng),
                )],
            );
        }
        // Let's print out some stats to make sure we have the diversity we want
        let changes = registry.get_changes_since(0, None);
        let num_registry_values: usize = changes.iter().map(|delta| delta.values.len()).sum();
        eprintln!(
            "\
Populated a registry with random content.

Number of keys: {} (desired: {})
Average key length: {},
Number of RegistryValues: {},
Average number of RegistryValue per key: {},
Average length of the values: {} (desired: {})",
            changes.len(),
            num_keys,
            average(changes.iter().map(|delta| delta.key.len())),
            num_registry_values,
            num_registry_values as f32 / changes.len() as f32,
            average(
                changes
                    .iter()
                    .flat_map(|delta| delta.values.iter())
                    .map(|registry_value| registry_value.value.len())
            ),
            mean_value_length
        );
        registry
    }

    /// Computes the mutation value size (given the version and key) that will
    /// result in a delta of exactly `MAX_REGISTRY_DELTAS_SIZE` bytes.
    fn max_mutation_value_size(version: u64, key: &[u8]) -> usize {
        fn delta_size(version: u64, key: &[u8], value_size: usize) -> usize {
            let req = RegistryAtomicMutateRequest {
                mutations: vec![upsert(key, vec![0; value_size])],
                preconditions: vec![],
            };

            let version = EncodedVersion::from(version);
            let bytes = pb_encode(&req);

            version.as_ref().len() + bytes.len()
        }

        // Start off with an oversized delta.
        let too_large_delta_size = delta_size(version, key, MAX_REGISTRY_DELTAS_SIZE);

        // Compoute the value size that will give us a delta of exactly
        // MAX_REGISTRY_DELTAS_SIZE.
        let max_value_size = 2 * MAX_REGISTRY_DELTAS_SIZE - too_large_delta_size;

        // Ensure we actually get a MAX_REGISTRY_DELTAS_SIZE delta.
        assert_eq!(
            MAX_REGISTRY_DELTAS_SIZE,
            delta_size(version, key, max_value_size)
        );

        max_value_size
    }
}
