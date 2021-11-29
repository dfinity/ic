use anyhow::{bail, Result};
use ic_registry_client::client::RegistryVersion;
use serde_json::Value;
use std::{collections::HashSet, fs::File, io::BufReader, path::PathBuf};
use structopt::StructOpt;
use thiserror::Error;
use url::Url;

pub type Projection = Vec<String>;

#[derive(Debug, StructOpt)]
pub struct CliArgs {
    #[structopt(subcommand)]
    source: CommandArg,
}

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "ic-regedit", about = "Registry (Local Store) Editor.")]
pub enum CommandArg {
    Snapshot {
        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[structopt(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Comma-separated list of key prefixes. If provided, only which the
        /// content of the registry should be filtered by.
        ///
        /// Note: This flag should only be used when inspecting a registry
        /// version on the console as the resulting snapshot is
        /// incomplete.
        #[structopt(short, long)]
        keys: Option<String>,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        local_store_path: PathBuf,
    },
    ShowDiff {
        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[structopt(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        local_store_path: PathBuf,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        snapshot_file: PathBuf,
    },
    ApplyUpdate {
        /// Amend the latest version of the local-store, i.e. overwrite the
        /// latest version.
        #[structopt(long)]
        amend: bool,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        local_store_path: PathBuf,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        snapshot_file: PathBuf,
    },
    CanisterSnapshot {
        /// Url to a node hosting the registry canister (may not be specified
        /// together with --local-store).
        #[structopt(long, parse(try_from_str = url::Url::parse))]
        url: Url,

        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[structopt(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Comma-separated list of key prefixes by which the content of the
        /// registry should be filtered by.
        ///
        /// Note: This flag should only be used when inspecting a registry
        /// version on the console as the resulting snapshot is
        /// incomplete.
        #[structopt(short, long)]
        keys: Option<String>,
    },
    CanisterShowDiff {
        /// Url to a node hosting the registry canister (may not be specified
        /// together with --local-store).
        #[structopt(long, parse(try_from_str = url::Url::parse))]
        url: Url,

        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[structopt(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Path to the local store (may not be specified together with --url).
        #[structopt(parse(from_os_str))]
        snapshot_file: PathBuf,
    },
}

impl CliArgs {
    pub fn validate(self) -> Result<Command> {
        let res = match self.source {
            CommandArg::Snapshot {
                local_store_path,
                version,
                keys,
            } => {
                let version: VersionSpec = version.into();
                let source = SourceSpec::LocalStore(Self::is_dir(local_store_path)?);
                let projection = Self::keys_to_projection(keys);
                Command::Snapshot {
                    registry_spec: RegistrySpec { version, source },
                    projection,
                }
            }
            CommandArg::ShowDiff {
                local_store_path,
                version,
                snapshot_file,
            } => {
                let version: VersionSpec = version.into();
                let source = SourceSpec::LocalStore(Self::is_dir(local_store_path)?);
                let snapshot = Self::read_json_value(snapshot_file)?;

                Command::ShowDiff {
                    registry_spec: RegistrySpec { version, source },
                    snapshot,
                }
            }
            CommandArg::ApplyUpdate {
                local_store_path,
                snapshot_file,
                amend,
            } => {
                let local_store_path = Self::is_dir(local_store_path)?;
                let snapshot = Self::read_json_value(snapshot_file)?;

                Command::ApplyUpdate {
                    local_store_path,
                    snapshot,
                    amend,
                }
            }
            CommandArg::CanisterSnapshot { url, version, keys } => {
                let version: VersionSpec = version.into();
                let source = SourceSpec::Canister(url);
                let projection = Self::keys_to_projection(keys);
                Command::Snapshot {
                    registry_spec: RegistrySpec { version, source },
                    projection,
                }
            }
            CommandArg::CanisterShowDiff {
                url,
                version,
                snapshot_file,
            } => {
                let version: VersionSpec = version.into();
                let source = SourceSpec::Canister(url);
                let snapshot = Self::read_json_value(snapshot_file)?;

                Command::ShowDiff {
                    registry_spec: RegistrySpec { version, source },
                    snapshot,
                }
            }
        };
        Ok(res)
    }

    /// Normalize the provided keys argument to a projection. I.e. if the
    /// argument is `None`, this corresponds to any set containing the empty
    /// string.
    fn keys_to_projection(keys: Option<String>) -> Vec<String> {
        Self::shortest_prefix_free_set(
            keys.map(|s| s.split(',').map(|s| s.into()).collect::<Vec<_>>())
                .unwrap_or_else(universal_projection),
        )
    }

    fn shortest_prefix_free_set(projection: Vec<String>) -> Vec<String> {
        let mut res: Vec<_> = vec![];
        let projection: HashSet<_> = projection.into_iter().collect();
        // after each iteration, is `key` added to the result or, if `key`
        // is a prefix of an existing entry of `res`, that entry is replaced by
        // `key`.
        for key in projection {
            if let Some(p) = res.iter_mut().find(|s: &&mut String| s.starts_with(&key)) {
                *p = key;
            } else {
                res.push(key);
            }
        }
        res
    }

    fn is_dir(p: PathBuf) -> Result<PathBuf> {
        if !p.is_dir() {
            bail!(ArgError::NotADirectory(p));
        }
        Ok(p)
    }

    fn read_json_value(p: PathBuf) -> Result<Value> {
        use ArgError::*;
        let json_error = |e| JsonError(p.clone(), e);
        let f = File::open(&p).map_err(IoError)?;
        let rdr = BufReader::new(f);
        let value: Value = serde_json::from_reader(rdr).map_err(json_error)?;
        Ok(value)
    }
}

pub fn universal_projection() -> Vec<String> {
    vec!["".into()]
}

#[derive(Debug, Error)]
pub enum ArgError {
    #[error("`{0:?}` is not a directory.")]
    NotADirectory(PathBuf),

    #[error("IoError: {0:?}")]
    IoError(std::io::Error),

    #[error("JsonError when reading file `{0:?}`: {1:?}")]
    JsonError(PathBuf, serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct RegistrySpec {
    pub version: VersionSpec,
    pub source: SourceSpec,
}

#[derive(Debug, Clone)]
pub enum SourceSpec {
    LocalStore(PathBuf),
    Canister(Url),
}

#[derive(Debug, Clone)]
pub enum Command {
    Snapshot {
        registry_spec: RegistrySpec,
        projection: Projection,
    },
    ShowDiff {
        registry_spec: RegistrySpec,
        snapshot: Value,
    },
    ApplyUpdate {
        local_store_path: PathBuf,
        snapshot: Value,
        amend: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionSpec {
    RelativeToLatest(u64),
    Absolute(RegistryVersion),
}

impl From<Option<i64>> for VersionSpec {
    fn from(v: Option<i64>) -> Self {
        let v = v.unwrap_or(0);
        if v <= 0 {
            Self::RelativeToLatest(-v as u64)
        } else {
            Self::Absolute(RegistryVersion::from(v as u64))
        }
    }
}
