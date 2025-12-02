use crate::{
    common::LOG_PREFIX,
    pb::v1::{
        ChangelogEntry, RegistryStableStorage, registry_stable_storage::Version as ReprVersion,
    },
    storage::{chunkify_composite_mutation_if_too_large, with_chunks},
};
use ic_certified_map::RbTree;
use ic_nervous_system_time_helpers::now_nanoseconds;
use ic_registry_canister_api::{Chunk, GetChunkRequest};
use ic_registry_canister_chunkify::dechunkify_registry_value;
use ic_registry_transport::{
    Error,
    pb::v1::{
        HighCapacityRegistryAtomicMutateRequest, HighCapacityRegistryDelta,
        HighCapacityRegistryMutation, HighCapacityRegistryValue, RegistryAtomicMutateRequest,
        RegistryMutation, RegistryValue, high_capacity_registry_mutation,
        high_capacity_registry_value, registry_mutation::Type,
    },
};
use ic_types::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use prost::Message;
use std::{
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

pub type Version = u64;
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct EncodedVersion([u8; std::mem::size_of::<Version>()]);

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
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Registry {
    /// Global counter that is incremented each time a mutation is applied to
    /// the registry. Each set of changes is tagged with this version.
    version: Version,

    /// Registry contents represented as a versioned key/value store, where
    /// value versions are stored in a deque in ascending order (latest version
    /// is stored at the back of the deque).
    pub(crate) store: BTreeMap<Vec<u8>, VecDeque<HighCapacityRegistryValue>>,

    /// All the mutations applied to the registry.
    ///
    /// We keep them explicitly for certification purposes and as a stable
    /// representation that allows us change the index structure in future.
    ///
    /// Each entry contains a blob which is a serialized
    /// HighCapacityRegistryAtomicMutateRequest. The serialized version is
    /// retained to ensure that hash trees stay the same even if the protobuf
    /// schema evolves.
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
    ) -> Vec<HighCapacityRegistryDelta> {
        let max_version = match max_versions {
            Some(max_versions) => version.saturating_add(max_versions as u64),
            None => u64::MAX,
        };

        self.store
            .iter()
            // For every key create a delta with values versioned `(version, max_version]`.
            .map(|(key, values)| HighCapacityRegistryDelta {
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

    /// Returns the most recent value associated with key that is not newer than
    /// version. (If the key was never set, or absent due to deletion, None is
    /// returned).
    pub fn get_high_capacity(
        &self,
        key: &[u8],
        version: Version,
    ) -> Option<&HighCapacityRegistryValue> {
        let result = self
            .store
            .get(key)?
            .iter()
            .rev()
            .find(|value| value.version <= version)?;

        let is_delete = match &result.content {
            Some(high_capacity_registry_value::Content::DeletionMarker(_)) => true,

            None
            | Some(high_capacity_registry_value::Content::Value(_))
            | Some(high_capacity_registry_value::Content::LargeValueChunkKeys(_)) => false,
        };

        if is_delete {
            return None;
        }

        Some(result)
    }

    pub fn get_chunk(&self, request: GetChunkRequest) -> Result<Chunk, String> {
        let GetChunkRequest { content_sha256 } = request;

        let Some(content_sha256) = content_sha256 else {
            return Err("Request does not specify content_sha256.".to_string());
        };

        let content = crate::storage::with_chunks(|chunks| chunks.get_chunk(&content_sha256))
            .ok_or_else(|| format!("No chunk with SHA256 = {content_sha256:X?}"))?;

        Ok(Chunk {
            content: Some(content),
        })
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

    pub(crate) fn get(&self, key: &[u8], version: Version) -> Option<RegistryValue> {
        let HighCapacityRegistryValue {
            version,
            content,
            timestamp_nanoseconds,
        } = self.get_high_capacity(key, version)?;

        let value = content
            .clone()
            .map(|content| with_chunks(|chunks| dechunkify_registry_value(content, chunks)))
            .unwrap_or_else(|| Some(vec![]));

        let value = value?;

        let version = *version;
        Some(RegistryValue {
            version,
            value,
            deletion_marker: false,
            timestamp_nanoseconds: *timestamp_nanoseconds,
        })
    }

    /// Returns the last RegistryValue, if any, for the given key.
    ///
    /// As we keep track of deletions in the registry, this value
    /// might be the tombstone, that is, RegistryValue with 'deleted'
    /// field equal true, and value being completely bogus. Thus,
    /// when calling 'get_last' you must check the 'deleted' marker,
    /// otherwise you might deal with garbage.
    fn get_last(&self, key: &[u8]) -> Option<&HighCapacityRegistryValue> {
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
        mut composite_mutation: HighCapacityRegistryAtomicMutateRequest,
        version: Version,
    ) {
        // We sort entries by key to eliminate the difference between changelog
        // produced by the new version of the registry canister starting from v1
        // and the changelog recovered from the stable representation of the
        // original version that didn't support certification.
        composite_mutation
            .mutations
            .sort_by(|l, r| l.key.cmp(&r.key));

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
        for m in composite_mutation.mutations.iter_mut() {
            m.mutation_type = match Type::try_from(m.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => Type::Upsert,
                Type::Delete => Type::Delete,
            } as i32;
        }

        // Populate self.store (which is secondary to self.changelog).
        let timestamp_nanoseconds = composite_mutation.timestamp_nanoseconds;
        for prime_mutation in composite_mutation.mutations.clone() {
            let HighCapacityRegistryMutation {
                mutation_type,
                content,
                key,
            } = prime_mutation;

            // Convert to high_capacity_registry_value::Content.
            let mutation_type = Type::try_from(mutation_type).unwrap_or_else(|err| {
                panic!("Unable to convert mutation_type ({mutation_type}): {err}");
            });
            let content = if mutation_type.is_delete() {
                high_capacity_registry_value::Content::DeletionMarker(true)
            } else {
                high_capacity_registry_value::Content::from(content)
            };
            let content = Some(content);

            let registry_value = HighCapacityRegistryValue {
                version,
                content,
                timestamp_nanoseconds,
            };

            self.store.entry(key).or_default().push_back(registry_value);
        }

        // Populate self.changelog (this is our primary data).
        self.changelog_insert(version, composite_mutation);
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

        let mutations = RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        };
        let mut mutations = chunkify_composite_mutation_if_too_large(mutations);
        mutations.timestamp_nanoseconds = now_nanoseconds();

        self.increment_version();
        self.apply_mutations_as_version(mutations, self.version);
    }

    /// Some mutation_type(s) require that the key/value is currently (i.e.
    /// right before the mutation is performed) present, while other(s) require
    /// that the key/value is currently absent. This enforces those requirements.
    fn verify_mutation_type(&self, mutations: &[RegistryMutation]) -> Vec<Error> {
        mutations
            .iter()
            .map(|new_mutation| {
                let RegistryMutation {
                    key,
                    mutation_type,
                    value: _,
                } = new_mutation;

                let mutation_type = Type::try_from(*mutation_type).map_err(|err| {
                    Error::MalformedMessage(format!("Unable to convert mutation_type: {err}",))
                })?;
                let presence_requirement = mutation_type.presence_requirement();

                let is_record_currently_present = self
                    .get_last(key)
                    .map(HighCapacityRegistryValue::is_present)
                    .unwrap_or(false);

                presence_requirement.verify(is_record_currently_present, key)
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

    #[cfg(any(test, feature = "canbench-rs", feature = "test"))]
    pub fn apply_mutations_for_test(&mut self, mutations: Vec<RegistryMutation>) {
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
                    .map(|e| format!("{e}"))
                    .collect::<Vec::<String>>()
                    .join(", ")
            );
        }

        self.check_global_state_invariants(mutations.as_slice());
    }

    pub fn serializable_form(&self) -> RegistryStableStorage {
        RegistryStableStorage {
            version: ReprVersion::Version1 as i32,
            changelog: self
                .changelog
                .iter()
                .map(|(encoded_version, bytes)| ChangelogEntry {
                    version: encoded_version.as_version(),
                    encoded_mutation: bytes.clone(),
                })
                .collect(),
        }
    }

    pub fn changelog(&self) -> &RbTree<EncodedVersion, Vec<u8>> {
        &self.changelog
    }

    /// Inserts a changelog entry at the given version, while enforcing the
    /// [`MAX_REGISTRY_DELTAS_SIZE`] limit.
    fn changelog_insert(&mut self, version: u64, req: HighCapacityRegistryAtomicMutateRequest) {
        let version = EncodedVersion::from(version);
        let bytes = req.encode_to_vec();

        // Once chunking is enabled, you would need a really degenerate
        // composite/atomic mutation to reach this panic, but it is still
        // possible (e.g. by touching a huge number of keys). Therefore, this
        // should remain in place, even though it is not as easy to make overly
        // large atomic/composite mutations anymore.
        let delta_size = version.as_ref().len() + bytes.len();
        if delta_size > MAX_REGISTRY_DELTAS_SIZE {
            panic!(
                "{LOG_PREFIX}Transaction rejected because delta would be too large: {delta_size} vs {MAX_REGISTRY_DELTAS_SIZE}."
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
                        let prime_mutation = HighCapacityRegistryMutation {
                            mutation_type: Type::Upsert as i32,
                            key: b"_".to_vec(),
                            content: Some(high_capacity_registry_mutation::Content::Value(vec![])),
                        };

                        let composite_mutation = HighCapacityRegistryAtomicMutateRequest {
                            mutations: vec![prime_mutation],
                            preconditions: vec![],
                            timestamp_nanoseconds: 0,
                        };

                        self.apply_mutations_as_version(composite_mutation, i);
                        self.version = i;
                    }
                    // End code to fix ICSUP-2589

                    let mutation = HighCapacityRegistryAtomicMutateRequest::decode(
                        &entry.encoded_mutation[..],
                    )
                    .unwrap_or_else(|err| {
                        panic!("Failed to decode mutation@{}: {}", entry.version, err)
                    });
                    self.apply_mutations_as_version(mutation, entry.version);
                    self.version = entry.version;
                    current_version = self.version;
                }
            }

            ReprVersion::Unspecified => {
                panic!(
                    "Restoring from the legacy representation is no longer supported. \
                     If this is needed again for whatever reason, use git history to \
                     add this feature/ability back to the canister. It was removed to \
                     reduce cruft (i.e. the usual reason), and because it really looked \
                     like it could not possibly be needed in practice anymore."
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flags::{
            temporarily_disable_chunkifying_large_values,
            temporarily_enable_chunkifying_large_values,
        },
        storage::MAX_CHUNKABLE_ATOMIC_MUTATION_LEN,
    };
    use ic_nervous_system_string::clamp_debug_len;
    use ic_registry_canister_chunkify::dechunkify;
    use ic_registry_transport::{
        delete, insert,
        pb::v1::{high_capacity_registry_mutation, registry_mutation},
        update, upsert,
    };
    use rand::{Rng, SeedableRng};
    use rand_distr::{Alphanumeric, Distribution, Poisson, Uniform};

    const DELETION_MARKER: Option<high_capacity_registry_value::Content> =
        Some(high_capacity_registry_value::Content::DeletionMarker(true));

    /// Simulate a round-trip through stable memory, which is an essential part
    /// of the upgrade process.
    ///
    /// This should bring back the registry in a state indistinguishable
    /// from the one before calling this method.
    fn serialize_then_deserialize(registry: Registry) {
        let serialized = registry.serializable_form().encode_to_vec();

        let mut restored = Registry::new();
        restored.from_serializable_form(
            RegistryStableStorage::decode(serialized.as_slice()).expect("Error decoding registry"),
        );

        assert_eq!(restored, registry);
    }

    /// Warning: You almost certainly want to assert that the return value is
    /// empty. (This is an easy oversight to commit, since it is easy to
    /// overlook the fact that this even has a return value in the first place.)
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
        ($v:expr_2021) => {
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
        let result2 = registry.get(&key, registry.latest_version()).unwrap();
        assert_eq!(value2, result2.value);
        assert_eq!(registry.latest_version(), result2.version);
        let result = registry.get(&key, registry.latest_version() - 1).unwrap();
        assert_eq!(value, result.value);
        assert_eq!(registry.latest_version() - 1, result.version);

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
        let result2 = registry.get(&key, registry.latest_version()).unwrap();
        assert_eq!(value2, result2.value);
        assert_eq!(registry.latest_version(), result2.version);
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
        let result = registry.get(&key, registry.latest_version()).unwrap();
        assert_eq!(value, result.value);
        assert_eq!(registry.latest_version(), result.version);

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
        assert_eq!(
            key1_values[0].content,
            Some(high_capacity_registry_value::Content::Value(value1.clone()))
        );
        assert_eq!(key1_values[0].version, 4);
        assert_eq!(key1_values[1].content, DELETION_MARKER);
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
        assert_eq!(key1_values[0].content, DELETION_MARKER);
        assert_eq!(key1_values[0].version, 3);
        assert_eq!(
            key1_values[1].content,
            Some(high_capacity_registry_value::Content::Value(value2.clone()))
        );
        assert_eq!(key1_values[1].version, 2);
        assert_eq!(
            key2_values[0].content,
            Some(high_capacity_registry_value::Content::Value(value2.clone()))
        );
        assert_eq!(key2_values[0].version, 3);
        assert_eq!(
            key2_values[1].content,
            Some(high_capacity_registry_value::Content::Value(value1.clone()))
        );
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
    fn test_verify_mutation_type_delete() {
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];

        let mut registry = Registry::new();

        assert_eq!(
            registry.verify_mutation_type(&[delete(&key)]),
            vec![Error::KeyNotPresent(key.clone())]
        );

        apply_mutations_skip_invariant_checks(&mut registry, vec![insert(&key, &value)]);

        assert_eq!(registry.verify_mutation_type(&[delete(&key)]), vec![],);
    }

    #[test]
    fn test_verify_mutation_type_upsert() {
        let key = vec![1, 2, 3, 4];
        let value = vec![5, 6, 7, 8];

        let mut registry = Registry::new();

        assert_eq!(
            registry.verify_mutation_type(&[upsert(&key, &value)]),
            vec![],
        );

        apply_mutations_skip_invariant_checks(&mut registry, vec![insert(&key, &value)]);

        assert_eq!(
            registry.verify_mutation_type(&[upsert(&key, &value)]),
            vec![],
        );
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
        let _restore_on_drop = temporarily_enable_chunkifying_large_values();

        let mut registry = Registry::new();

        // This seems large, but this will get chunkified down to approximately
        // dozens of bytes. As a result, for the purposes of
        // count_fitting_deltas, this is actually small.
        let chunkified_mutation = upsert(b"this_is_chunkified", [43; 2_000_000]);

        // This mutation is engineered so that the encoded_len of the
        // HighCapacityRegistryAtomicMutateRequest is exactly
        // MAX_REGISTRY_DELTAS_SIZE - 100.
        //
        // The point at which chunkification kicks in is close to (but less
        // than) MAX_REGISTRY_DELTAS_SIZE. Furthermore, EXACT point is not so
        // precisely defined. Therefore, to COMFORTABLY avoid chunkification,
        // ` - 100` is applied here.
        let version = 1;
        let key = b"this_is_large_but_not_chunkified";
        let large_but_not_chunkified_mutation =
            upsert(key, vec![42; max_mutation_value_size(version, key) - 100]);

        let not_large_mutation = upsert(b"this_is_small_but_not_completely_negligible", [44; 200]);

        for mutation in [
            chunkified_mutation,
            large_but_not_chunkified_mutation,
            not_large_mutation,
        ] {
            assert_empty!(apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![mutation]
            ));
        }

        // The first mutation (chunkified_mutation) takes up more than 32 bytes,
        // because, that is how long a SHA-256 hash is, but it should not take
        // up much more space than that.
        assert_eq!(registry.count_fitting_deltas(0, 30), 0);
        assert_eq!(registry.count_fitting_deltas(0, 250), 1);

        // The second mutation (large_but_not_chunkified_mutation) was
        // specifically engineered to take up exactly MAX_REGISTRY_DELTAS_SIZE -
        // 100 bytes.
        assert_eq!(
            registry.count_fitting_deltas(1, MAX_REGISTRY_DELTAS_SIZE - 101),
            0,
        );
        assert_eq!(
            registry.count_fitting_deltas(1, MAX_REGISTRY_DELTAS_SIZE - 100),
            1,
        );

        // Like the first mutation, but this one does not get chunkified.
        assert_eq!(registry.count_fitting_deltas(2, 200), 0);
        assert_eq!(registry.count_fitting_deltas(2, 300), 1);

        // Because there are no versions after 3 (yet)!
        assert_eq!(registry.count_fitting_deltas(3, 999_999_999_999), 0);

        assert_eq!(
            registry.count_fitting_deltas(0, 100 + MAX_REGISTRY_DELTAS_SIZE + 300),
            3,
        );
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
            while rng.r#gen::<f32>() > p {
                val.push(rng.r#gen());
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

        let mut serializable_form = registry.serializable_form();
        // Remove half of the entries, but retain the first and the last entry.
        let initial_len = registry.changelog().iter().count();
        serializable_form.changelog.retain(|entry| {
            entry.version == 1 || rng.r#gen() || entry.version == initial_len as u64
        });
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
        let req = HighCapacityRegistryAtomicMutateRequest::from(RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        });
        registry.changelog_insert(version, req);

        // We should have one changelog entry.
        assert_eq!(1, registry.changelog().iter().count());
        assert!(
            registry
                .changelog()
                .get(EncodedVersion::from(version).as_ref())
                .is_some()
        );
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_changelog_insert_delta_too_large() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        // This is not very realistic, because if a mutation is this large, it
        // would get chunked before changelog_insert sees it. Nevertheless, this
        // test is still valuable, because it shows that if (for whatever
        // reason) changelog_insert sees a mutation that is too large, it
        // refuses to add the mutation, which protects the system from storing
        // mutations that are too large to later be read (due to ICP's message
        // size limits). See the next test for a more realistic version of this
        // test.
        let too_large_value = vec![0; max_mutation_value_size(version, key) + 1];
        let mutations = vec![HighCapacityRegistryMutation::from(upsert(
            key,
            too_large_value,
        ))];
        let req = HighCapacityRegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
            // max_mutation_value_size assumes that this field holds the maximum
            // value. Therefore, in order for `req`'s encoded_len to be exactly
            // 1 greater than what changelog_insert allows, we need this field
            // to have the maximum value.
            timestamp_nanoseconds: u64::MAX,
        };

        registry.changelog_insert(1, req);
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_changelog_insert_delta_too_large_but_no_prime_mutation_large() {
        let mut registry = Registry::new();

        // This is just (slightly) more elaborate+realistic version of the data
        // in the previous test (test_changelog_insert_delta_too_large), but we
        // are essentially doing the same thing: creating a mutation that should
        // be rejected due to being too large.
        let mutations = (0..1000)
            .map(|i| {
                let i = i % (u8::MAX as u64 + 1);
                HighCapacityRegistryMutation {
                    key: format!("key_{i}").into_bytes(),
                    mutation_type: registry_mutation::Type::Insert as i32,
                    content: Some(high_capacity_registry_mutation::Content::Value(vec![
                        i as u8;
                        2_000
                    ])),
                }
            })
            .collect();
        let req = HighCapacityRegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
            // Since the `too_large_value` is built with serializing maximum
            // timestamp length to 10 bytes the tipping point of `+ 1` will be
            // there only if we account the timestamp of full serialized 10
            // bytes.
            timestamp_nanoseconds: u64::MAX,
        };

        registry.changelog_insert(1, req);
    }

    #[test]
    fn test_apply_mutations_max_size_delta() {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let max_value = vec![0; max_mutation_value_size(version, key)];
        let mutations = vec![upsert(key, &max_value)];
        apply_mutations_skip_invariant_checks(&mut registry, mutations);
        let got = registry.get(key, version).unwrap();

        assert_eq!(registry.latest_version(), version);
        assert_eq!(
            got,
            RegistryValue {
                value: max_value,
                version,
                deletion_marker: false,
                timestamp_nanoseconds: got.timestamp_nanoseconds,
            }
        );
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_apply_mutations_delta_too_large() {
        let _restore_on_drop = temporarily_disable_chunkifying_large_values();

        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let too_large_value = vec![0; max_mutation_value_size(version, key) + 1];
        let mutations = vec![upsert(key, too_large_value)];

        apply_mutations_skip_invariant_checks(&mut registry, mutations);
    }

    // This is like the previous test (test_apply_mutations_delta_too_large),
    // except that chunking is enabled. As a result, there is supposed to be no
    // panic.
    #[test]
    fn test_apply_mutations_delta_not_too_large_when_chunking_is_enabled() {
        let _restore_on_drop = temporarily_enable_chunkifying_large_values();

        let mut registry = Registry::new();

        let key = b"key";
        let too_large_value = vec![0; MAX_REGISTRY_DELTAS_SIZE];
        let mutations = vec![upsert(key, too_large_value)];

        apply_mutations_skip_invariant_checks(&mut registry, mutations);
    }

    // This is like the previous test
    // (test_apply_mutations_delta_not_too_large_when_chunking_is_enabled),
    // except that the mutation is approx close to 10 MiB limit, as opposed to
    // 1.3 MiB. Since these numbers are in the same regime (i.e. they are both
    // chunkable), the outcome should be (more or less) the same: the mutation
    // gets successfully applied (or at least, without panic).
    #[test]
    fn test_apply_mutations_delta_near_max_chunkable_len_when_chunking_is_enabled() {
        let _restore_on_drop = temporarily_enable_chunkifying_large_values();

        let mut registry = Registry::new();

        let key = b"key";
        let too_large_value = vec![0; MAX_CHUNKABLE_ATOMIC_MUTATION_LEN - 150];
        let mutations = vec![upsert(key, too_large_value)];

        apply_mutations_skip_invariant_checks(&mut registry, mutations);
    }

    #[test]
    #[should_panic(expected = "Mutation too large. First key =")]
    fn test_apply_mutations_too_large_even_when_chunking_is_enabled() {
        let _restore_on_drop = temporarily_enable_chunkifying_large_values();

        let mut registry = Registry::new();

        let key = b"key";
        let too_large_value = vec![0; MAX_CHUNKABLE_ATOMIC_MUTATION_LEN];
        let mutations = vec![upsert(key, too_large_value)];

        apply_mutations_skip_invariant_checks(&mut registry, mutations);
    }

    /// Common implementation for `from_serializable_form()` tests.
    ///
    /// In order to avoid panicking, "manually" constructs a registry containing
    /// a single mutation / mutate request that is zero or more bytes above
    /// `MAX_REGISTRY_DELTAS_SIZE`. Then serializes it using the given version
    /// and tests deserialization.
    fn test_from_serializable_form_impl(bytes_above_max_size: usize) {
        let mut registry = Registry::new();
        let version = 1;
        let key = b"key";

        let value = vec![0; max_mutation_value_size(version, key) + bytes_above_max_size];
        let mutation = HighCapacityRegistryMutation::from(upsert(key, value));
        let mutations = vec![mutation.clone()];
        let req = HighCapacityRegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
            timestamp_nanoseconds: now_nanoseconds(),
        };
        // Circumvent `changelog_insert()` to insert potentially oversized mutations.
        registry
            .changelog
            .insert(EncodedVersion::from(version), req.encode_to_vec());

        let content = match mutation.content.unwrap() {
            high_capacity_registry_mutation::Content::Value(vec) => {
                high_capacity_registry_value::Content::Value(vec)
            }
            _garbage => panic!(
                "Transcribing to a HighCapacity object somehow  did not result in an \
                 inline Value (which is impossible, unless of course, bugs)."
            ),
        };
        (*registry.store.entry(mutation.key).or_default()).push_back(HighCapacityRegistryValue {
            version,
            content: Some(content),
            timestamp_nanoseconds: req.timestamp_nanoseconds,
        });
        registry.version = version;

        // Serialize.
        let stable_repr = registry.serializable_form();

        // Deserialize.
        let mut deserialized = Registry::new();
        deserialized.from_serializable_form(stable_repr);

        assert_eq!(deserialized, registry);
    }

    #[test]
    fn test_from_serializable_form_version1_max_size_delta() {
        test_from_serializable_form_impl(0)
    }

    #[test]
    #[should_panic(expected = "[Registry] Transaction rejected because delta would be too large")]
    fn test_from_serializable_form_version1_delta_too_large() {
        test_from_serializable_form_impl(1)
    }

    // This is a little more realistic than the previous two tests
    // (test_from_serializable_form_version1_(max_size_delta|delta_too_large))
    // in the way that the original Registry gets populated. More precisely,
    // instead of directly manipulating members, apply_mutations is called (via
    // apply_mutations_skip_invariant_checks, like many other tests).
    #[test]
    fn test_from_serializable_form_with_chunking() {
        // Step 1: Prepare the world.

        let _restore_on_drop = temporarily_enable_chunkifying_large_values();
        let mut original_registry = Registry::new();

        // Add a chunkable singleton "composite" mutation to original_registry.
        {
            let errors = apply_mutations_skip_invariant_checks(
                &mut original_registry,
                vec![insert(b"this_gets_chunked_42", vec![42; 3_000_000])],
            );
            assert_eq!(errors, vec![]);
        }

        // Add a chunkable non-singleton composite mutation.
        let mutations = (0_u64..100)
            .map(|i| {
                let key = format!("also_gets_chunked_{i}");
                let i = (i % (u8::MAX as u64 + 1)) as u8;
                insert(key, vec![i; 14_000])
            })
            .collect();
        {
            let errors = apply_mutations_skip_invariant_checks(&mut original_registry, mutations);
            assert_eq!(errors, vec![]);
        }

        // Double check that the above mutations ended up chunkified.
        assert_eq!(
            original_registry.changelog.iter().count(),
            2,
            "{}",
            clamp_debug_len(
                &original_registry
                    .changelog
                    .iter()
                    .map(|(version, mutation)| (*version, mutation.clone()))
                    .collect::<Vec<_>>(),
                100,
            ),
        );
        for (version, composite_mutation) in original_registry.changelog.iter() {
            let composite_mutation =
                HighCapacityRegistryAtomicMutateRequest::decode(&**composite_mutation).unwrap();
            for mutation in &composite_mutation.mutations {
                match &mutation.content {
                    Some(high_capacity_registry_mutation::Content::LargeValueChunkKeys(_ok)) => (),
                    garbage => panic!(
                        "Not a LargeValueChunkKey! {}\nversion={:?}",
                        clamp_debug_len(garbage, 100),
                        version,
                    ),
                }
            }
        }

        // This is thrown in "for good measure", just so that not all mutations
        // NEED to be high-capacity/chunked. Otherwise, this is not a very
        // interesting mutation, and is already covered by previous test(s).
        apply_mutations_skip_invariant_checks(
            &mut original_registry,
            vec![insert(b"no_need_for_chunking_here_57", vec![57; 1024])],
        );

        // Step 2: Run the code under test: Serialize original_registry into a
        // blob. Then, deserialize it into restored_registry, like what happens
        // in a canister upgrade (during pre- and post- ugprade). In short, do a
        // serialization+deserialization round trip.
        let mut restored_registry = Registry::new();
        restored_registry.from_serializable_form(original_registry.serializable_form());

        // Step 3: Verify result(s).
        assert_eq!(restored_registry, original_registry);
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
        let r#gen = RandomByteVectorGenerator {
            mean_length: mean_value_length,
        };
        for k in &keys {
            apply_mutations_skip_invariant_checks(
                &mut registry,
                vec![insert(k.as_bytes(), r#gen.sample(&mut rng))],
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
                    r#gen.sample(&mut rng),
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
                    .map(|registry_value| {
                        let content = registry_value.content.as_ref().unwrap();
                        match content {
                            high_capacity_registry_value::Content::Value(value) => value.len(),
                            _ => 0,
                        }
                    })
            ),
            mean_value_length
        );
        registry
    }

    /// Computes the mutation value size (given the version and key) that will
    /// result in a delta of exactly `MAX_REGISTRY_DELTAS_SIZE` bytes.
    fn max_mutation_value_size(version: u64, key: &[u8]) -> usize {
        fn delta_size(version: u64, key: &[u8], value_size: usize) -> usize {
            let req = HighCapacityRegistryAtomicMutateRequest {
                mutations: vec![HighCapacityRegistryMutation::from(upsert(
                    key,
                    vec![0; value_size],
                ))],
                preconditions: vec![],
                timestamp_nanoseconds: now_nanoseconds(),
            };

            let version = EncodedVersion::from(version);
            let bytes = req.encode_to_vec();

            version.as_ref().len() + bytes.len()
        }

        // Start off with an oversized delta.
        let too_large_delta_size = delta_size(version, key, MAX_REGISTRY_DELTAS_SIZE);

        // Compute the value size that will give us a delta of exactly
        // MAX_REGISTRY_DELTAS_SIZE.
        let max_value_size = 2 * MAX_REGISTRY_DELTAS_SIZE - too_large_delta_size;

        // Ensure we actually get a MAX_REGISTRY_DELTAS_SIZE delta.
        assert_eq!(
            MAX_REGISTRY_DELTAS_SIZE,
            delta_size(version, key, max_value_size)
        );

        max_value_size
    }

    #[test]
    fn test_big_mutation_survives_upgrade() {
        let _restore_on_drop = temporarily_enable_chunkifying_large_values();
        const MOD: u64 = u8::MAX as u64 + 1;

        // Step 1: Prepare the world

        // Step 1.1: Populate original Registry.
        let original_value = (0_u64..5_000_000)
            .map(|i| {
                let result = 57 * i + 42;
                (result % MOD) as u8
            })
            .collect::<Vec<u8>>();
        let mutation = RegistryMutation {
            mutation_type: Type::Insert as i32,
            key: b"this is key".to_vec(),
            value: original_value.clone(),
        };
        let mut original_registry = Registry::new();
        let timestamp_before_applying_mutation = now_nanoseconds();
        apply_mutations_skip_invariant_checks(&mut original_registry, vec![mutation]);
        let timestamp_after_applying_mutation = now_nanoseconds();

        // Step 1.2: Verify contents of original Registry.

        // Step 1.2.1: Verify original_registry.store.
        let store = &original_registry.store;
        assert_eq!(store.len(), 1, "{store:#?}");
        let history: &VecDeque<HighCapacityRegistryValue> =
            store.get(&b"this is key".to_vec()).unwrap();
        assert_eq!(history.len(), 1, "{history:#?}");
        let registry_value = history.front().unwrap();
        let large_value_chunk_keys = match registry_value.content.as_ref().unwrap() {
            high_capacity_registry_value::Content::LargeValueChunkKeys(ok) => ok.clone(),
            _ => panic!("{registry_value:#?}"),
        };
        assert_eq!(
            large_value_chunk_keys.chunk_content_sha256s.len(),
            3,
            "{large_value_chunk_keys:#?}"
        );
        let reconstituted_monolithic_blob_from_store =
            with_chunks(|chunks| dechunkify(&large_value_chunk_keys, chunks));
        assert_eq!(
            reconstituted_monolithic_blob_from_store.len(),
            original_value.len()
        );
        // assert_eq is intentionally NOT used here, because it would generate lots of spam.
        assert!(reconstituted_monolithic_blob_from_store == original_value);
        assert_eq!(
            registry_value,
            &HighCapacityRegistryValue {
                content: Some(high_capacity_registry_value::Content::LargeValueChunkKeys(
                    large_value_chunk_keys,
                )),
                version: 1,
                // This part is tested later since its hard to get the exact
                // timestamp before the actual function call.
                timestamp_nanoseconds: registry_value.timestamp_nanoseconds,
            },
        );

        assert!(
            timestamp_before_applying_mutation <= registry_value.timestamp_nanoseconds
                && registry_value.timestamp_nanoseconds <= timestamp_after_applying_mutation
        );

        // Step 1.2.2: Verify original_registry.changelog.
        let changelog = &original_registry.changelog;

        assert_eq!(
            changelog.iter().collect::<Vec<_>>().len(),
            1,
            "{changelog:#?}"
        );

        let composite_mutation = HighCapacityRegistryAtomicMutateRequest::decode(
            changelog
                .get(EncodedVersion::from(1).as_ref())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let mutations = &composite_mutation.mutations;
        assert_eq!(mutations.len(), 1, "{composite_mutation:#?}");
        let prime_mutation = mutations.first().unwrap();
        let large_value_chunk_keys = match &prime_mutation.content {
            Some(high_capacity_registry_mutation::Content::LargeValueChunkKeys(ok)) => ok,
            _ => panic!("{prime_mutation:#?}"),
        };
        assert_eq!(
            large_value_chunk_keys.chunk_content_sha256s.len(),
            3,
            "{large_value_chunk_keys:?}"
        );
        let reconstituted_monolithic_blob =
            with_chunks(|chunks| dechunkify(large_value_chunk_keys, chunks));
        assert_eq!(reconstituted_monolithic_blob.len(), original_value.len());
        // assert_eq is not used here, because it would generate a MBs of spam.
        assert!(reconstituted_monolithic_blob == original_value);

        assert_eq!(
            composite_mutation,
            HighCapacityRegistryAtomicMutateRequest {
                preconditions: vec![],
                // This part is tested later since its hard to get the exact
                // timestamp before the actual function call.
                timestamp_nanoseconds: composite_mutation.timestamp_nanoseconds,
                mutations: vec![HighCapacityRegistryMutation {
                    key: b"this is key".to_vec(),
                    mutation_type: Type::Upsert as i32,
                    content: Some(
                        high_capacity_registry_mutation::Content::LargeValueChunkKeys(
                            large_value_chunk_keys.clone(),
                        )
                    ),
                }],
            },
        );
        assert!(
            timestamp_before_applying_mutation <= composite_mutation.timestamp_nanoseconds
                && composite_mutation.timestamp_nanoseconds <= timestamp_after_applying_mutation
        );

        // Step 2: Call code under test. Simulate (Registry) canister upgrade.
        let mut upgraded_registry = Registry::new();
        upgraded_registry.from_serializable_form(original_registry.serializable_form());

        // Step 3: Verify result(s): Verify that upgrade resulted in no data loss.
        assert_eq!(upgraded_registry, original_registry);
    }
}
