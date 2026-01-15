use ic_interfaces_registry::{RegistryDataProvider, RegistryRecord};
use ic_registry_common_proto::pb::local_store::v1::{
    ChangelogEntry as PbChangelogEntry, Delta as PbDelta, KeyMutation as PbKeyMutation,
    MutationType,
};
use ic_sys::fs::{sync_path, write_protobuf_simple, write_protobuf_using_tmp_file};
use ic_types::RegistryVersion;
use ic_types::registry::RegistryDataProviderError;
use prost::Message;
use std::{
    io::{self},
    path::{Path, PathBuf},
};
pub trait LocalStore: LocalStoreWriter + LocalStoreReader {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct KeyMutation {
    /// The key of the entry.
    pub key: String,

    /// The value of this key value pair. `None` means that the value has been
    /// deleted at the corresponding version.
    pub value: Option<Vec<u8>>,
}

/// A ChangelogEntry is a list of mutations that, when applied to a registry at
/// version v, produce the registry at version v+1.
pub type ChangelogEntry = Vec<KeyMutation>;

/// A changelog is a sequence of ChangelogEntries. Applied consecutively to a
/// registry, the registry will be at version v + l, if v is the previous latest
/// version and l is the length of the Changelog.
pub type Changelog = Vec<ChangelogEntry>;

pub trait LocalStoreReader: Send + Sync {
    /// For a given version `version`, returns a (possibly empty) Changelog
    /// `cl` where the subsequence `cl[0..i]`, `0 <= i <= len(ds)`, applied
    /// to a registry at latest version `v` represents the registry at
    /// version `v+i+1`.
    fn get_changelog_since_version(&self, version: RegistryVersion) -> io::Result<Changelog>;
}

pub trait LocalStoreWriter: Send + Sync {
    /// Store the changelog at the given version.
    ///
    /// Preconditions:
    /// (1) For a given `version` > 1, a changelog_entry for `version-1`
    /// must exist in the store.
    /// (2) The given change log entry must be nonempty list of KeyMutations.
    fn store(&self, version: RegistryVersion, v: ChangelogEntry) -> io::Result<()>;

    /// Clears the Local Store.
    ///
    /// Note: This clears registry versions, stored in directories.
    fn clear(&self) -> io::Result<()>;
}

#[derive(Clone, Debug)]
pub struct LocalStoreImpl {
    /// Directory with one .pb file per registry version.
    path: PathBuf,
}

impl LocalStoreImpl {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: PathBuf::from(path.as_ref()),
        }
    }

    /// Efficiently creates a `LocalStore` from a `Changelog`.
    pub fn from_changelog<P: AsRef<Path>>(changelog: Changelog, path: P) -> io::Result<Self> {
        let store = Self {
            path: PathBuf::from(path.as_ref()),
        };

        let mut last_parent_dir = None;
        for (v, changelog_entry) in changelog.into_iter().enumerate() {
            let version = (v + 1) as u64;
            let path = store.get_path(version);

            // Create the parent directories if we haven't already.
            let parent_dir = path.parent().expect(
                "get_path returns a non-empty path whose parent isn't the root or prefix, see the definition of v_path in get_path."
            );
            match last_parent_dir.as_ref() {
                // First parent dir: create and remember it.
                None => {
                    std::fs::create_dir_all(parent_dir)?;
                    last_parent_dir = Some(parent_dir.to_path_buf());
                }

                // New parent dir: sync the last parent dir, create the new one and remember it.
                Some(last_parent_dir_) if last_parent_dir_ != parent_dir => {
                    sync_path(last_parent_dir_)?;
                    std::fs::create_dir_all(parent_dir)?;
                    last_parent_dir = Some(parent_dir.to_path_buf());
                }

                // Same parent dir as last file: do nothing.
                _ => {}
            }

            let changelog_entry = changelog_entry_to_protobuf(changelog_entry);
            write_protobuf_simple(&path, &changelog_entry).unwrap();
        }
        // Also sync the last parent dir.
        if let Some(last_parent_dir) = last_parent_dir {
            sync_path(&last_parent_dir)?;
        }

        Ok(store)
    }

    // precondition: version > 0
    // there exists no path for a version 0, as version 0 represents the empty
    // registry.
    fn get_path(&self, version: u64) -> PathBuf {
        assert!(version > 0);

        let path_str = format!("{version:016x}.pb");
        // 00 01 02 03 04 / 05 / 06 / 07.pb
        let v_path = &[
            &path_str[0..10],
            &path_str[10..12],
            &path_str[12..14],
            &path_str[14..19],
        ]
        .iter()
        .collect::<PathBuf>();
        self.path.join(v_path.as_path())
    }

    fn read_changelog_entry<P: AsRef<Path>>(p: P) -> io::Result<PbChangelogEntry> {
        let bytes = std::fs::read(p)?;
        PbChangelogEntry::decode(bytes.as_slice()).map_err(io::Error::other)
    }

    // precondition: version > 0
    fn write_changelog_entry_<F>(&self, version: u64, pb: PbChangelogEntry, f: F) -> io::Result<()>
    where
        F: Fn(&Path, PbChangelogEntry) -> io::Result<()>,
    {
        if version == 0 {
            panic!("Version must be > 0.")
        }
        if version > 1 && !self.get_path(version - 1).exists() {
            return Err(io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Version {} does not exist.", version - 1),
            ));
        }
        // version == 1 || version-1 exists
        let path = self.get_path(version);
        std::fs::create_dir_all(path.parent().expect(
            "get_path returns a non-empty path
        whose parent isn't the root or prefix, see the definition of v_path in get_path.",
        ))?;
        f(path.as_path(), pb)
    }

    fn write_changelog_entry(&self, version: u64, pb: PbChangelogEntry) -> io::Result<()> {
        self.write_changelog_entry_(version, pb, |p, m| write_protobuf_using_tmp_file(p, &m))
    }
}

impl LocalStore for LocalStoreImpl {}

impl LocalStoreReader for LocalStoreImpl {
    fn get_changelog_since_version(&self, version: RegistryVersion) -> io::Result<Changelog> {
        let start = version.get() + 1;
        (start..)
            .map(|i| self.get_path(i))
            .take_while(|p| p.exists())
            .try_fold(vec![], |mut res, p| {
                res.push(changelog_entry_try_from_proto(Self::read_changelog_entry(
                    p,
                )?)?);
                Ok(res)
            })
    }
}

impl LocalStoreWriter for LocalStoreImpl {
    // precondition: version > 0
    fn store(&self, version: RegistryVersion, ce: ChangelogEntry) -> io::Result<()> {
        let pb_ce = changelog_entry_to_protobuf(ce);
        self.write_changelog_entry(version.get(), pb_ce)
    }

    fn clear(&self) -> io::Result<()> {
        std::fs::read_dir(self.path.as_path())?.try_for_each(|de| {
            let path = de?.path();
            if path.is_dir() {
                std::fs::remove_dir_all(path)
            } else {
                Ok(())
            }
        })
    }
}

impl RegistryDataProvider for LocalStoreImpl {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        let changelog = self.get_changelog_since_version(version).map_err(|e| {
            RegistryDataProviderError::Transfer {
                source: format!("Error when reading changelog from local storage: {e:?}"),
            }
        })?;
        let res: Vec<_> = changelog
            .iter()
            .enumerate()
            .flat_map(|(i, cle)| cle.iter().map(move |km| (i, km)))
            .map(|(i, km)| RegistryRecord {
                version: version + RegistryVersion::from((i as u64) + 1),
                key: km.key.clone(),
                value: km.value.clone(),
            })
            .collect();
        Ok(res)
    }
}

fn changelog_entry_try_from_proto(value: PbChangelogEntry) -> Result<ChangelogEntry, io::Error> {
    if value.key_mutations.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Empty changelog Entry.",
        ));
    }
    value
        .key_mutations
        .iter()
        .try_fold(vec![], |mut res, mutation| {
            res.push(key_mutation_try_from_proto(mutation)?);
            Ok(res)
        })
}

fn key_mutation_try_from_proto(value: &PbKeyMutation) -> Result<KeyMutation, io::Error> {
    let mut_type = match MutationType::try_from(value.mutation_type).ok() {
        Some(v) => v,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid mutation type.",
            ));
        }
    };
    let res = match mut_type {
        MutationType::InvalidState => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid mutation type.",
            ));
        }
        MutationType::Unset => {
            if !value.value.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-empty value for UNSET.",
                ));
            }
            KeyMutation {
                key: value.key.clone(),
                value: None,
            }
        }
        MutationType::Set => KeyMutation {
            key: value.key.clone(),
            value: Some(value.value.clone()),
        },
    };
    Ok(res)
}

/// Translate a compact protobuf message to a changelog.
///
/// The original use case is auxiliary services and utilities that interact with
/// the mainnet-registry and ship with a hardcoded prefix. As the registry is
/// designed as an append-only store, this has the benefit that the prefix does
/// not need to be re-fetched. Further, all mainnet configuration information is
/// already available (provided the software is received through an
/// authenticated channel).
pub fn compact_delta_to_changelog(source: &[u8]) -> std::io::Result<(RegistryVersion, Changelog)> {
    PbDelta::decode(source)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Protobuf encoding for registry delta failed: {e:?}"),
            )
        })
        .and_then(|delta| {
            let changelog =
                delta
                    .changelog
                    .into_iter()
                    .try_fold(vec![], |mut changelog, entry| {
                        changelog.push(changelog_entry_try_from_proto(entry)?);
                        Ok::<_, std::io::Error>(changelog)
                    })?;
            Ok((RegistryVersion::from(delta.registry_version), changelog))
        })
}

/// Inverse of [compact_delta_to_changelog].
///
/// # Panics
///
/// This function panics if any of the changelog entries is empty.
pub fn changelog_to_compact_delta(
    registry_version: RegistryVersion,
    changelog: Changelog,
) -> std::io::Result<Vec<u8>> {
    let changelog = changelog
        .into_iter()
        .map(changelog_entry_to_protobuf)
        .collect::<Vec<_>>();
    let delta = PbDelta {
        registry_version: registry_version.get(),
        changelog,
    };
    let mut buf = vec![];
    delta
        .encode(&mut buf)
        .expect("Encoding protobuf message failed!");
    Ok(buf)
}

fn changelog_entry_to_protobuf(ce: ChangelogEntry) -> PbChangelogEntry {
    assert!(!ce.is_empty());
    let key_mutations = ce
        .iter()
        .map(|km| {
            let mutation_type = if km.value.is_some() {
                MutationType::Set as i32
            } else {
                MutationType::Unset as i32
            };
            PbKeyMutation {
                key: km.key.clone(),
                value: km.value.clone().unwrap_or_default(),
                mutation_type,
            }
        })
        .collect();
    PbChangelogEntry { key_mutations }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use tempfile::TempDir;

    #[test]
    fn empty_changelog_after_clear() {
        let tempdir = TempDir::new().unwrap();
        let store = LocalStoreImpl::new(tempdir.path());
        let mut rng = rand::thread_rng();
        let changelog = get_random_changelog(1, &mut rng);

        store
            .store(RegistryVersion::from(1), changelog[0].clone())
            .unwrap();

        store.clear().unwrap();

        assert!(
            store
                .get_changelog_since_version(RegistryVersion::from(0))
                .unwrap()
                .is_empty()
        );

        let changelog = get_random_changelog(1, &mut rng);
        store
            .store(RegistryVersion::from(1), changelog[0].clone())
            .unwrap();

        assert_eq!(
            store
                .get_changelog_since_version(RegistryVersion::from(0))
                .unwrap(),
            changelog
        );
    }

    #[test]
    #[should_panic(expected = "Version must be > 0")]
    fn storing_at_version_0_fails() {
        let tempdir = TempDir::new().unwrap();
        let store = LocalStoreImpl::new(tempdir.path());
        let mut rng = rand::thread_rng();
        let changelog = get_random_changelog(1, &mut rng);

        store
            .store(RegistryVersion::from(0), changelog[0].clone())
            .unwrap()
    }

    #[test]
    fn can_extend_and_restore() {
        let tempdir = TempDir::new().unwrap();
        let store = LocalStoreImpl::new(tempdir.path());
        let mut rng = rand::thread_rng();

        let mut changelog = get_random_changelog(200, &mut rng);
        changelog.iter().enumerate().for_each(|(i, c)| {
            store
                .store(RegistryVersion::from((i + 1) as u64), c.clone())
                .unwrap()
        });

        for i in (0..changelog.len()).step_by(10) {
            let cl = store
                .get_changelog_since_version(RegistryVersion::from(i as u64))
                .unwrap();
            assert_eq!(&changelog[i..], cl.as_slice());
        }

        let mut new_changelog = get_random_changelog(100, &mut rng);
        new_changelog.iter().enumerate().for_each(|(i, c)| {
            store
                .store(RegistryVersion::from((i + 201) as u64), c.clone())
                .unwrap()
        });

        changelog.append(&mut new_changelog);
        for i in (0..changelog.len()).step_by(10) {
            let cl = store
                .get_changelog_since_version(RegistryVersion::from(i as u64))
                .unwrap();
            assert_eq!(&changelog[i..], cl.as_slice());
        }
    }

    fn get_random_changelog(n: usize, rng: &mut ThreadRng) -> Changelog {
        // some pseudo random entries
        (0..n)
            .map(|_i| {
                let k = rng.r#gen::<usize>() % 64 + 2;
                (0..(k + 2)).map(|k| key_mutation(k, rng)).collect()
            })
            .collect()
    }

    fn key_mutation(k: usize, rng: &mut ThreadRng) -> KeyMutation {
        let s = rng.next_u64() & 64;
        let set: bool = rng.r#gen();
        KeyMutation {
            key: k.to_string(),
            value: if set {
                Some((0..s as u8).collect())
            } else {
                None
            },
        }
    }

    #[test]
    fn mainnet_delta_can_be_read() {
        let changelog = get_mainnet_delta();
        assert_eq!(changelog.len(), 0x6dc1);
    }

    fn get_mainnet_delta() -> Changelog {
        compact_delta_to_changelog(ic_registry_local_store_artifacts::MAINNET_DELTA_00_6D_C1)
            .expect("")
            .1
    }
}
