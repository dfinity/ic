use ic_registry_transport::{
    pb::v1::{
        registry_mutation::Type, Precondition, RegistryAtomicMutateRequest,
        RegistryAtomicMutateResponse, RegistryDelta, RegistryError, RegistryMutation,
        RegistryValue,
    },
    Error,
};

use crate::{
    common::LOG_PREFIX,
    pb::v1::{
        registry_stable_storage::Version as ReprVersion, ChangelogEntry, RegistryStableStorage,
    },
};
use prost::Message;
use std::cmp::max;
use std::collections::{BTreeMap, VecDeque};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

/// The type for the registry map.
///
/// The Deque part is mostly future proofing for when we have garbage collection
/// so that we're able to call pop_front().
pub type RegistryMap = BTreeMap<Vec<u8>, VecDeque<RegistryValue>>;
pub type Version = u64;

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
    changelog: Vec<(Version, Vec<u8>)>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the deltas applied since 'version', exclusive.
    pub fn get_changes_since(&self, version: u64) -> Vec<RegistryDelta> {
        self.store
            .iter()
            // For every key create a delta with values versioned above `version`
            .map(|(key, values)| RegistryDelta {
                key: key.clone(),
                values: values
                    .iter()
                    .rev()
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

    /// Verifies the given explicit precondition.
    ///
    /// The semantic we want to achieve is:
    /// Key K has not been updated since the last time I read the registry,
    /// which was at version V.
    ///
    /// If the key does not exist, this method will return an error, unless
    /// the expected version in the precondition is 0. Using version 0 is
    /// useful with UPSERTs.
    fn verify_explicit_precondition(&self, precondition: &Precondition) -> Result<(), Error> {
        match self.get_last(&precondition.key) {
            None => {
                if precondition.expected_version == 0 {
                    Ok(())
                } else {
                    Err(Error::KeyNotPresent(precondition.key.clone()))
                }
            }
            Some(value) => {
                // Check if the expected version is in the future, then we can't
                // attest anything.
                if self.version < precondition.expected_version {
                    Err(Error::VersionBeyondLatest(precondition.key.clone()))
                } else if value.version > precondition.expected_version {
                    Err(Error::VersionNotLatest(precondition.key.clone()))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Verifies the implicit precondition corresponding to the mutation_type
    /// field.
    fn verify_implicit_precondition(&self, mutation: &RegistryMutation) -> Result<(), Error> {
        let key = &mutation.key;
        let latest = self
            .get_last(&key)
            .filter(|registry_value| !registry_value.deletion_marker);
        match (Type::from_i32(mutation.mutation_type), latest) {
            (None, _) => Err(Error::MalformedMessage(format!(
                "Unknown mutation type {} for key {:?}.",
                mutation.mutation_type, mutation.key
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
    }

    /// Collects violations for all the preconditions for the given
    /// RegistryAtomicMutateRequest: the explicit ones in field
    /// `preconditions`, and the ones that originate from the
    /// `mutation_type` fields in the mutations.
    fn get_precondition_violations(&self, request_pb: &RegistryAtomicMutateRequest) -> Vec<Error> {
        let errors_explicit_preconditions_iter = request_pb
            .preconditions
            .iter()
            .map(|p| self.verify_explicit_precondition(p));
        let errors_implicit_preconditions_iter = request_pb
            .mutations
            .iter()
            .map(|m| self.verify_implicit_precondition(m));
        errors_explicit_preconditions_iter
            .chain(errors_implicit_preconditions_iter)
            .flat_map(Result::err)
            .collect()
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
            // UPSERTs.  This serves 2 purposes:
            //
            // 1. This significantly simplifies reconstruction of the changelog
            //    when we deserialize the registry from the original stable
            //    representation.
            //
            // 2. This will play nicely with garbage collection: if an old
            //    INSERT entry is removed, the newly connected clients won't
            //    fail because of an UPDATE in the first survived entry with the
            //    same key.
            m.mutation_type = match Type::from_i32(m.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => Type::Upsert,
                Type::Delete => Type::Delete,
            } as i32;
        }

        let req = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        let bytes = pb_encode(&req);

        self.changelog.push((version, bytes));

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

    /// Checks that invariants hold after applying mutations
    pub fn maybe_apply_mutation_internal(&mut self, mutations: Vec<RegistryMutation>) {
        println!(
            "{}Received a mutate call containing a list of {} mutations",
            LOG_PREFIX,
            mutations.len()
        );

        let request_pb = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        let errors = self.get_precondition_violations(&request_pb);
        if !errors.is_empty() {
            panic!(
                "{}Transaction rejected because of the following errors: [{}].",
                LOG_PREFIX,
                errors
                    .iter()
                    .map(|e| format!("{}", e))
                    .collect::<Vec::<String>>()
                    .join(", ")
            );
        }

        self.check_global_invariants(&request_pb.mutations);
        self.apply_mutations(request_pb.mutations);
    }

    pub fn maybe_apply_mutations(
        &mut self,
        request_pb: RegistryAtomicMutateRequest,
    ) -> RegistryAtomicMutateResponse {
        println!(
            "{}Received a mutate call containing a list of {} mutations",
            LOG_PREFIX,
            request_pb.mutations.len()
        );

        let errors = self.get_precondition_violations(&request_pb);
        if !errors.is_empty() {
            println!(
                "{}Transaction rejected because of the following errors: [{}].",
                LOG_PREFIX,
                errors
                    .iter()
                    .map(|e| format!("{}", e))
                    .collect::<Vec::<String>>()
                    .join(", ")
            );
            return RegistryAtomicMutateResponse {
                errors: errors.into_iter().map(RegistryError::from).collect(),
                version: self.latest_version(),
            };
        }

        self.apply_mutations(request_pb.mutations);

        RegistryAtomicMutateResponse {
            errors: vec![],
            version: self.version,
        }
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
                    .map(|(version, bytes)| ChangelogEntry {
                        version: *version,
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

    pub fn changelog(&self) -> &[(Version, Vec<u8>)] {
        &self.changelog[..]
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

        let repr_version = ReprVersion::from_i32(stable_repr.version).unwrap_or_else(|| {
            panic!(
                "Version {} of stable registry representation is not supported by this canister",
                stable_repr.version
            )
        });

        match repr_version {
            ReprVersion::Version1 => {
                for entry in stable_repr.changelog {
                    let req = RegistryAtomicMutateRequest::decode(&entry.encoded_mutation[..])
                        .unwrap_or_else(|err| {
                            panic!("Failed to decode mutation@{}: {}", entry.version, err)
                        });
                    self.apply_mutations_as_version(req.mutations, entry.version);
                    self.version = entry.version;
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
                self.changelog = mutations_by_version
                    .into_iter()
                    .map(|(v, mutations)| {
                        (
                            v,
                            pb_encode(&RegistryAtomicMutateRequest {
                                mutations,
                                preconditions: vec![],
                            }),
                        )
                    })
                    .collect()
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
    use ic_registry_transport::{delete, insert, pb::v1::RegistryMutation, update, upsert};
    use rand::Rng;
    use rand_core::SeedableRng;
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

    /// Shorthand to try a mutation with preconditions.
    fn try_mutate_with_preconditions(
        registry: &mut Registry,
        mutations: &[RegistryMutation],
        preconditions: &[Precondition],
    ) -> Vec<Error> {
        registry
            .maybe_apply_mutations(RegistryAtomicMutateRequest {
                preconditions: preconditions.to_vec(),
                mutations: mutations.to_vec(),
            })
            .errors
            .into_iter()
            .map(Error::from)
            .collect()
    }

    /// Shorthand to try a mutation with no preconditions.
    fn try_mutate(registry: &mut Registry, mutations: &[RegistryMutation]) -> Vec<Error> {
        try_mutate_with_preconditions(registry, mutations, &[])
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
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        assert_empty!(try_mutate(&mut registry, &[update(&key, &value2)]));
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
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        assert_empty!(try_mutate(&mut registry, &[update(&key, &value2)]));
        let result2 = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result2.unwrap().value);
        assert_eq!(registry.latest_version(), result2.unwrap().version);
        assert_empty!(try_mutate(&mut registry, &[delete(&key)]));
        // The definition of get says that we should get None if the last version is has
        // a deletion marker set.
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(None, result);
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value, result.unwrap().value);
        assert_eq!(registry.latest_version(), result.unwrap().version);

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_get_all_changes_since() {
        let mut registry = Registry::new();
        let key1 = vec![1, 2, 3, 4];
        let key2 = vec![5, 6, 7, 8];
        let value1 = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];
        // On the first mutation we insert key1
        assert_empty!(try_mutate(&mut registry, &[insert(&key1, &value1)]));
        // On the second mutation we insert key2 an update key 1
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(&key2, &value1), update(&key1, &value2)]
        ));
        // On the third mutation we update key 2 and delete key one.
        assert_empty!(try_mutate(
            &mut registry,
            &[delete(&key1), update(&key2, &value2)]
        ));
        // On the forth mutation we insert key one again
        assert_empty!(try_mutate(&mut registry, &[insert(&key1, &value1)]));

        // Fetching all the mutations since 0 should get
        // a total of 2 keys:
        // key 1 with three values (@1 value1, @2 value2, @3 delete, @4 value1)
        // key 2 with three values (@2 value1, @3 value2)
        let mut deltas = registry.get_changes_since(0);
        // Sort the keys as they might not come sorted from the hashmap.
        deltas.sort_by(|a, b| a.key.cmp(&b.key));
        // Assert that we got the right thing, and test a few values
        assert_eq!(deltas.len(), 2);
        let key1_values = &deltas.get(0).unwrap().values;
        let key2_values = &deltas.get(1).unwrap().values;
        assert_eq!(key1_values.len(), 4);
        assert_eq!(key2_values.len(), 2);
        assert_eq!(key1_values[0].value, value1);
        assert_eq!(key1_values[0].version, 4);
        assert_eq!(key1_values[1].deletion_marker, true);
        assert_eq!(key1_values[1].version, 3);

        // Now try getting a couple of other versions
        // Version 4 should be empty (versions to get changes from are exclusive)
        let deltas = registry.get_changes_since(4);
        assert_eq!(deltas.len(), 0);
        // Changes since version 3 for should include key 1
        let deltas = registry.get_changes_since(3);
        assert_eq!(deltas.len(), 1);
        // Changes since version 2 for should include both keys
        let deltas = registry.get_changes_since(2);
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
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        // Inserting an existing (non-deleted) key should fail.
        assert_eq!(
            try_mutate(&mut registry, &[insert(&key, &value)]),
            vec![Error::KeyAlreadyPresent(key.clone())]
        );
        // After deleting the key, it should be possible to insert
        // it again.
        assert_empty!(try_mutate(&mut registry, &[delete(&key)]));
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value2)]));

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
            try_mutate(&mut registry, &[update(&key, &value)]),
            vec![Error::KeyNotPresent(key.clone())]
        );
        // After a regular insert the update should succeed.
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        assert_empty!(try_mutate(&mut registry, &[update(&key, &value2)]));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result.unwrap().value);
        // After the key is deleted the update should fail.
        assert_empty!(try_mutate(&mut registry, &[delete(&key)]));
        assert_eq!(
            try_mutate(&mut registry, &[update(&key, &value)]),
            vec![Error::KeyNotPresent(key)]
        );

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_upsert() {
        let mut registry = Registry::new();
        let key = vec![1, 2, 3, 4];
        // Upserting without the key existing should succeed.
        let value = vec![5, 6, 7, 8];
        let value2 = vec![9, 10, 11, 12];

        assert_empty!(try_mutate(&mut registry, &[upsert(&key, &value)]));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value, result.unwrap().value);
        // Afterwards, another upsert should update the value
        assert_empty!(try_mutate(&mut registry, &[upsert(&key, &value2)]));
        let result = registry.get(&key, registry.latest_version());
        assert_eq!(value2, result.unwrap().value);
        // After the key is deleted the upsert should succeed.
        assert_empty!(try_mutate(&mut registry, &[delete(&key)]));
        assert_empty!(try_mutate(&mut registry, &[upsert(&key, &value)]));
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
            try_mutate(&mut registry, &[delete(&key)]),
            vec![Error::KeyNotPresent(key.clone())]
        );
        // After inserting the key, delete should succeed.
        assert_empty!(try_mutate(&mut registry, &[insert(&key, &value)]));
        assert_empty!(try_mutate(&mut registry, &[delete(&key)]));
        // After a key has been deleted delete should fail.
        assert_eq!(
            try_mutate(&mut registry, &[delete(&key)]),
            vec![Error::KeyNotPresent(key)]
        );

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_verify_precondition_version_0() {
        let mut registry = Registry::new();

        assert_empty!(try_mutate_with_preconditions(
            &mut registry,
            &[upsert(b"spices", b"scary,sporty,baby,ginger,posh")],
            &[Precondition {
                key: b"spices".to_vec(),
                expected_version: 0 as u64,
            }]
        ));
        // but update should still fail
        assert_eq!(
            try_mutate_with_preconditions(
                &mut registry,
                &[update(b"real_spices", b"melanie,emma,mel,geri,victoria")],
                &[Precondition {
                    key: b"real_spices".to_vec(),
                    expected_version: 0 as u64,
                }]
            ),
            vec![Error::KeyNotPresent(b"real_spices".to_vec())]
        );
    }

    #[test]
    fn test_verify_precondition_scenario_with_deletion() {
        let mut registry = Registry::new();

        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"spices", b"scary,sporty,baby,ginger,posh")]
        ));
        assert_empty!(try_mutate(&mut registry, &[delete(b"spices")]));
        let new_val = b"scary,sporty,baby,posh";
        let latest_rv = registry.latest_version();
        let (val, version) = registry
            .get(b"spices", latest_rv)
            .map(|x| (x.value.clone(), x.version))
            .unwrap_or((new_val.to_vec(), latest_rv as u64));
        assert_eq!(version, latest_rv);
        assert_eq!(val, new_val);
        assert_empty!(try_mutate_with_preconditions(
            &mut registry,
            &[upsert(b"spices", &val)],
            &[Precondition {
                key: b"spices".to_vec(),
                expected_version: version,
            }]
        ));
    }

    #[test]
    fn test_verify_precondition() {
        let mut registry = Registry::new();
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"day_of_the_week", b"monday")]
        ));

        // Version matches
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 1 as u64,
            }),
            Ok(())
        );
        // Version too small
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 0 as u64,
            }),
            Err(Error::VersionNotLatest(b"day_of_the_week".to_vec()))
        );
        // Reading from the future should err, because we can't attest that
        // the value will not change.
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 200 as u64,
            }),
            Err(Error::VersionBeyondLatest(b"day_of_the_week".to_vec()))
        );
        // Mutate
        assert_empty!(try_mutate(
            &mut registry,
            &[update(b"day_of_the_week", b"tuesday")]
        ));
        // Version matches
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 2 as u64,
            }),
            Ok(())
        );
        // Version too small
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 1 as u64,
            }),
            Err(Error::VersionNotLatest(b"day_of_the_week".to_vec()))
        );
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"day_of_the_week".to_vec(),
                expected_version: 3 as u64,
            }),
            Err(Error::VersionBeyondLatest(b"day_of_the_week".to_vec()))
        );

        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_verify_precondition_key_does_not_exist() {
        let registry = Registry::new();
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"month_of_the_year".to_vec(),
                expected_version: 55 as u64
            }),
            Err(Error::KeyNotPresent(b"month_of_the_year".to_vec()))
        );
        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_preconditions_on_deleted_keys_are_legal() {
        let mut registry = Registry::new();
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"world_population", b"8 billion")]
        ));
        assert_empty!(try_mutate(&mut registry, &[delete(b"world_population")])); // humanity has ended
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"world_population".to_vec(),
                expected_version: 3 as u64
            }),
            Err(Error::VersionBeyondLatest(b"world_population".to_vec()))
        );
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"world_population".to_vec(),
                expected_version: 2 as u64
            }),
            Ok(())
        );
        assert_eq!(
            registry.verify_explicit_precondition(&Precondition {
                key: b"world_population".to_vec(),
                expected_version: 1 as u64
            }),
            Err(Error::VersionNotLatest(b"world_population".to_vec()))
        );
        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_verify_preconditions() {
        let mut registry = Registry::new();
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"polar_bears", b"endangered")]
        ));
        assert_empty!(try_mutate(
            &mut registry,
            &[
                update(b"polar_bears", b"extinct"),
                insert(b"pinguins", b"vulnerable")
            ]
        ));

        // First precondition is violated, second is satisfied
        assert_eq!(
            registry.get_precondition_violations(&RegistryAtomicMutateRequest {
                preconditions: vec![
                    Precondition {
                        key: b"polar_bears".to_vec(),
                        expected_version: 1 as u64
                    },
                    Precondition {
                        key: b"pinguins".to_vec(),
                        expected_version: 2 as u64
                    }
                ],
                mutations: vec![]
            }),
            vec![Error::VersionNotLatest(b"polar_bears".to_vec())]
        );
        serialize_then_deserialize(registry);
    }

    #[test]
    fn test_transactional_behavior() {
        let mut registry = Registry::new();
        // Single mutation, all good
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"shakira", b"colombia")]
        ));
        // Two mutations, all good
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"rihanna", b"barbados"), insert(b"m.i.a", b"uk")]
        ));
        // two insertions, but the second one is already present -- should do nothing
        assert_eq!(
            try_mutate(
                &mut registry,
                &[insert(b"beyonce", b"us"), insert(b"m.i.a", b"sri lanka")]
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
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"shakira", b"colombia")]
        ));
        // Two mutations, all good
        assert_empty!(try_mutate(
            &mut registry,
            &[insert(b"rihanna", b"barbados"), insert(b"m.i.a", b"uk")]
        ));
        // two insertions, but the second one is already present -- should do nothing
        assert_empty!(try_mutate(&mut registry, &[delete(b"rihanna")]));
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
    impl rand_distr::Distribution<Vec<u8>> for RandomByteVectorGenerator {
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
            try_mutate(
                &mut registry,
                &[insert(k.as_bytes(), &gen.sample(&mut rng))],
            );
        }
        // Now let's do some mutations.
        // Each mutation will be on a random key, so that not all keys have the same
        // number of RegistryValues.
        let key_index_distr = Uniform::new(0, keys.len());
        for _ in 0..num_updates {
            assert_empty!(try_mutate(
                &mut registry,
                &[update(
                    &keys[key_index_distr.sample(&mut rng)],
                    &gen.sample(&mut rng)
                )]
            ));
        }
        // Let's print out some stats to make sure we have the diversity we want
        let changes = registry.get_changes_since(0);
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
                    .map(|delta| delta.values.iter())
                    .flatten()
                    .map(|registry_value| registry_value.value.len())
            ),
            mean_value_length
        );
        registry
    }
}
