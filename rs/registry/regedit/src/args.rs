use anyhow::{Context, Result, bail};
use clap::Parser;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_from_der;
use ic_registry_client::client::RegistryVersion;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use serde_json::Value;
use std::fmt;
use std::{collections::HashSet, fs::File, io::BufReader, path::PathBuf};
use thiserror::Error;
use url::Url;

pub type Projection = Vec<String>;

#[derive(Debug, Parser)]
pub struct CliArgs {
    #[clap(subcommand)]
    source: CommandArg,
}

#[derive(Clone, Debug, Parser)]
#[clap(name = "ic-regedit", about = "Registry (Local Store) Editor.", version)]
pub enum CommandArg {
    Snapshot {
        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[clap(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Comma-separated list of key prefixes. If provided, only which the
        /// content of the registry should be filtered by.
        ///
        /// Note: This flag should only be used when inspecting a registry
        /// version on the console as the resulting snapshot is
        /// incomplete.
        #[clap(short, long)]
        keys: Option<String>,

        /// Path to the local store (may not be specified together with --url).
        local_store_path: PathBuf,
    },
    CanisterToProto {
        /// Url to a node hosting the registry canister (may not be specified
        /// together with --local-store).
        #[clap(long)]
        url: Url,

        /// Path to the local store (may not be specified together with --url).
        path: PathBuf,

        /// The registry version where the delta starts. (default: 0)
        #[clap(short, long, allow_hyphen_values = true)]
        start_version: Option<u64>,

        /// The registry version where the delta ends. (default: latest registry version)
        #[clap(short, long, allow_hyphen_values = true)]
        latest_version: Option<u64>,

        /// Optional path to the threshold public key of the root subnet
        /// (a.k.a. NNS public key). One way to get this key is via
        /// "ic-admin --nns-url https://nns.ic0.app  get-subnet-public-key"
        nns_public_key: Option<PathBuf>,
    },
    ShowDiff {
        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[clap(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Path to the local store (may not be specified together with --url).
        local_store_path: PathBuf,

        /// Path to the local store (may not be specified together with --url).
        snapshot_file: PathBuf,
    },
    ApplyUpdate {
        /// Amend the latest version of the local-store, i.e. overwrite the
        /// latest version.
        #[clap(long)]
        amend: bool,

        /// Path to the local store (may not be specified together with --url).
        local_store_path: PathBuf,

        /// Path to the local store (may not be specified together with --url).
        snapshot_file: PathBuf,
    },
    CanisterSnapshot {
        /// Url to a node hosting the registry canister (may not be specified
        /// together with --local-store).
        #[clap(long)]
        url: Url,

        /// Optional path to the threshold public key of the root subnet
        /// (a.k.a. NNS public key). One way to get this key is via
        /// "ic-admin --nns-url https://nns.ic0.app  get-subnet-public-key"
        #[clap(long)]
        nns_public_key: Option<PathBuf>,

        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[clap(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Comma-separated list of key prefixes by which the content of the
        /// registry should be filtered by.
        ///
        /// Note: This flag should only be used when inspecting a registry
        /// version on the console as the resulting snapshot is
        /// incomplete.
        #[clap(short, long)]
        keys: Option<String>,
    },
    CanisterShowDiff {
        /// Url to a node hosting the registry canister (may not be specified
        /// together with --local-store).
        #[clap(long)]
        url: Url,

        /// Optional path to the threshold public key of the root subnet
        /// (a.k.a. NNS public key). One way to get this key is via
        /// "ic-admin --nns-url https://nns.ic0.app  get-subnet-public-key"
        nns_public_key: Option<PathBuf>,

        /// The registry version of the snapshot. (default: latest available
        /// version.)
        #[clap(short, long, allow_hyphen_values = true)]
        version: Option<i64>,

        /// Path to the local store (may not be specified together with --url).
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
            CommandArg::CanisterToProto {
                start_version,
                latest_version,
                url,
                nns_public_key,
                path,
            } => {
                let nns_key_material = get_key_material(nns_public_key)?;
                let source_spec = SourceSpec::Canister(url, nns_key_material);

                Command::CanisterToProto {
                    start_version: start_version.unwrap_or_default().into(),
                    latest_version: latest_version.map(RegistryVersion::from),
                    source_spec,
                    path,
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
            CommandArg::CanisterSnapshot {
                url,
                nns_public_key,
                version,
                keys,
            } => {
                let version: VersionSpec = version.into();
                let nns_key_material = get_key_material(nns_public_key)?;
                let source = SourceSpec::Canister(url, nns_key_material);
                let projection = Self::keys_to_projection(keys);
                Command::Snapshot {
                    registry_spec: RegistrySpec { version, source },
                    projection,
                }
            }
            CommandArg::CanisterShowDiff {
                url,
                nns_public_key,
                version,
                snapshot_file,
            } => {
                let version: VersionSpec = version.into();
                let nns_key_material = get_key_material(nns_public_key)?;
                let source = SourceSpec::Canister(url, nns_key_material);
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

#[derive(Clone, Debug)]
pub struct RegistrySpec {
    pub version: VersionSpec,
    pub source: SourceSpec,
}

#[derive(Clone, Debug)]
pub enum SourceSpec {
    LocalStore(PathBuf),
    Canister(Url, Option<ThresholdSigPublicKey>),
}

#[derive(Clone, Debug)]
pub enum Command {
    Snapshot {
        registry_spec: RegistrySpec,
        projection: Projection,
    },
    CanisterToProto {
        start_version: RegistryVersion,
        latest_version: Option<RegistryVersion>,
        source_spec: SourceSpec,
        path: PathBuf,
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

#[derive(Clone, Eq, PartialEq, Debug)]
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

// This code is taken from rs/prep/src/prep_state_directory.rs
fn parse_threshold_sig_key<P: AsRef<std::path::Path> + fmt::Debug>(pem_file: P) -> Result<Vec<u8>> {
    let buf =
        std::fs::read(&pem_file).with_context(|| format!("failed to read from {:?}", &pem_file))?;
    let s = String::from_utf8_lossy(&buf);
    let lines: Vec<_> = s.trim_end().lines().collect();
    let n = lines.len();

    if n < 3 {
        bail!("input file is too short: {:?}", &pem_file);
    }

    if !lines[0].starts_with("-----BEGIN PUBLIC KEY-----") {
        bail!(
            "PEM file doesn't start with BEGIN PUBLIC KEY block: {:?}",
            &pem_file
        );
    }
    if !lines[n - 1].starts_with("-----END PUBLIC KEY-----") {
        bail!(
            "PEM file doesn't end with END PUBLIC KEY block: {:?}",
            &pem_file
        );
    }

    let decoded = base64::decode(lines[1..n - 1].join(""))
        .with_context(|| format!("failed to decode base64 from: {:?}", &pem_file))?;

    Ok(decoded)
}

fn get_key_material(nns_public_key: Option<PathBuf>) -> Result<Option<ThresholdSigPublicKey>> {
    if let Some(nns_pk) = nns_public_key {
        let encoded_nns_pk = parse_threshold_sig_key(nns_pk)?;
        return Ok(Some(threshold_sig_public_key_from_der(
            encoded_nns_pk.as_slice(),
        )?));
    }
    Ok(None)
}
