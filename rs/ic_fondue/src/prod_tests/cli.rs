use anyhow::{bail, Result};
use humantime::parse_duration;
use ic_types::ReplicaVersion;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use structopt::StructOpt;
use url::Url;

const RND_SEED_DEFAULT: u64 = 42;

#[derive(StructOpt, Debug)]
#[structopt(name = "prod-test-driver", about = "Production Test Driver.")]
pub struct CliArgs {
    #[structopt(
        long = "log-base-dir",
        about = "If set, specifies where to write demultiplexed test-specific logs."
    )]
    log_base_dir: Option<PathBuf>,

    #[structopt(
        long = "log-level",
        about = "One of TRACE, DEBUG, INFO, WARN, or ERROR. (Default: Info)"
    )]
    log_level: Option<String>,

    #[structopt(long = "rand-seed", about = "A 64-bit wide random seed.")]
    rand_seed: Option<u64>,

    #[structopt(
        long = "job-id",
        about = r#"
A unique string identifying this test run. On CI, this could be the
CI-Job-Number, e.g.

If not provided, a default of the form `$HOSTNAME-<timestamp>` is used, where
`<timestamp>` is the time at which the test driver was started."#
    )]
    job_id: Option<String>,

    #[structopt(
        long = "initial-replica-version",
        about = r#"
The initial replica version. This version must match the version of the guest os
image that the IC is bootstrapped with. If not provided, the default version is
used."#
    )]
    initial_replica_version: String,

    #[structopt(
        long = "ic-os-img-sha256",
        about = r#"The sha256 hash sum of the IC-OS image."#
    )]
    ic_os_img_sha256: String,

    #[structopt(
        long = "ic-os-img-url",
        about = r#"The URL of the IC-OS disk image used by default for all IC nodes
        version."#,
        parse(try_from_str = url::Url::parse)
    )]
    ic_os_img_url: Url,

    #[structopt(
        long = "boundary-node-img-sha256",
        about = r#"The SHA-256 hash of the Boundary Node disk image"#
    )]
    boundary_node_img_sha256: String,

    #[structopt(
        long = "boundary-node-img-url",
        about = r#"The URL of the Boundary Node disk image"#,
        parse(try_from_str = url::Url::parse)
    )]
    boundary_node_img_url: Url,

    #[structopt(
        long = "farm-base-url",
        about = r#"The base URL of the Farm-service to be used for resource
        management. (default: https://farm.dfinity.systems)"#,
        parse(try_from_str = url::Url::parse)
    )]
    farm_base_url: Option<Url>,

    #[structopt(
        long = "result-file",
        parse(from_os_str),
        help = "If set, specifies where to write results of executed tests."
    )]
    pub result_file: Option<PathBuf>,

    #[structopt(
        long = "nns-canister-path",
        parse(from_os_str),
        help = r#"Path to directory containing wasm-files of NNS canisters.
        Required for tests that install NNS canisters."#
    )]
    pub nns_canister_path: Option<PathBuf>,

    #[structopt(long = "suite", help = r#"Mandatory name of a test suite to run."#)]
    pub suite: String,

    #[structopt(
        long = "include-pattern",
        help = r#"If set, only tests matching this regex will be excercised
        and all others will be ignored. Note: when `include-pattern` is set,
        `ignore-pattern` and `skip-pattern` are not effective."#
    )]
    pub include_pattern: Option<String>,

    #[structopt(
        long = "ignore-pattern",
        help = r#"If set, all tests matching this regex will be ignored,
        i.e. completely omitted by the framework."#
    )]
    pub ignore_pattern: Option<String>,

    #[structopt(
        long = "skip-pattern",
        help = r#"If set, all tests matching this regex will be skipped,
        i.e. included in a summary, but not exercised."#
    )]
    pub skip_pattern: Option<String>,

    #[structopt(
        long = "authorized-ssh-accounts",
        parse(from_os_str),
        help = r#"Path to directory containing ssh public/private key pairs
        (file/file.pub) that are installed on the IC-OS by default."#
    )]
    pub authorized_ssh_accounts: Option<PathBuf>,

    #[structopt(
        long = "journalbeat-hosts",
        help = r#"A comma-separated list of hostname/port-pairs that journalbeat
        should use as target hosts. (e.g. "host1.target.com:443,host2.target.com:443")"#
    )]
    pub journalbeat_hosts: Option<String>,

    #[structopt(
        long = "log-debug-overrides",
        help = r#"A string containing debug overrides in terms of ic.json5.template 
        (e.g. "ic_consensus::consensus::batch_delivery,ic_artifact_manager::processors")"#
    )]
    pub log_debug_overrides: Option<String>,

    #[structopt(
    long = "pot-timeout",
    default_value = "600s",
    parse(try_from_str = parse_duration),
    help = r#"Amount of time to wait before releasing resources allocated for a pot."#
    )]
    pub pot_timeout: Duration,

    #[structopt(
        long = "working-dir",
        about = "Path to a working directory of the test driver."
    )]
    working_dir: PathBuf,
}

impl CliArgs {
    pub fn validate(self) -> Result<ValidatedCliArgs> {
        let lvl_str = self.log_level.unwrap_or_else(|| "info".to_string());
        let log_level = if let Ok(v) = slog::Level::from_str(&lvl_str) {
            v
        } else {
            bail!("Invalid log level: '{}'!", lvl_str);
        };

        let initial_replica_version =
            if let Ok(v) = ReplicaVersion::try_from(self.initial_replica_version) {
                v
            } else {
                bail!("Invalid initial replica version id: {}",)
            };

        let nns_canister_path = if let Some(p) = self.nns_canister_path {
            if !p.is_dir() {
                bail!("nns-canister-path is not a directory");
            }
            Some(p)
        } else {
            None
        };

        if !is_sha256_hex(&self.ic_os_img_sha256) {
            bail!("Invalid base image hash: {:?}", self.ic_os_img_sha256)
        }

        let include_pattern = parse_pattern(self.include_pattern)?;
        let ignore_pattern = parse_pattern(self.ignore_pattern)?;
        let skip_pattern = parse_pattern(self.skip_pattern)?;

        let authorized_ssh_accounts = match self.authorized_ssh_accounts {
            Some(path) => is_valid_ssh_key_dir(path)?,
            None => vec![],
        };

        let journalbeat_hosts = parse_journalbeat_hosts(self.journalbeat_hosts)?;

        let log_debug_overrides = parse_log_debug_overrides(self.log_debug_overrides)?;

        Ok(ValidatedCliArgs {
            log_base_dir: self.log_base_dir,
            log_level,
            rand_seed: self.rand_seed.unwrap_or(RND_SEED_DEFAULT),
            job_id: self.job_id,
            initial_replica_version,
            ic_os_img_sha256: self.ic_os_img_sha256,
            ic_os_img_url: self.ic_os_img_url,
            boundary_node_img_sha256: self.boundary_node_img_sha256,
            boundary_node_img_url: self.boundary_node_img_url,
            farm_base_url: self.farm_base_url,
            result_file: self.result_file,
            nns_canister_path,
            suite: self.suite,
            include_pattern,
            ignore_pattern,
            skip_pattern,
            authorized_ssh_accounts,
            journalbeat_hosts,
            log_debug_overrides,
            pot_timeout: self.pot_timeout,
            working_dir: self.working_dir,
        })
    }
}

fn parse_pattern(p: Option<String>) -> Result<Option<Regex>, regex::Error> {
    match p.map(|p| Regex::new(&p)) {
        None => Ok(None),
        Some(Ok(r)) => Ok(Some(r)),
        Some(Err(e)) => Err(e),
    }
}

#[derive(Debug)]
pub struct ValidatedCliArgs {
    pub log_base_dir: Option<PathBuf>,
    pub log_level: slog::Level,
    pub rand_seed: u64,
    pub job_id: Option<String>,
    pub initial_replica_version: ReplicaVersion,
    pub ic_os_img_sha256: String,
    pub ic_os_img_url: Url,
    pub boundary_node_img_sha256: String,
    pub boundary_node_img_url: Url,
    pub farm_base_url: Option<Url>,
    pub result_file: Option<PathBuf>,
    pub nns_canister_path: Option<PathBuf>,
    pub suite: String,
    pub include_pattern: Option<Regex>,
    pub ignore_pattern: Option<Regex>,
    pub skip_pattern: Option<Regex>,
    pub authorized_ssh_accounts: Vec<AuthorizedSshAccount>,
    pub journalbeat_hosts: Vec<String>,
    pub log_debug_overrides: Vec<String>,
    pub pot_timeout: Duration,
    pub working_dir: PathBuf,
}

pub type PrivateKeyFileContent = Vec<u8>;
pub type PublicKeyFileContent = Vec<u8>;

/// The key pair of an authorized ssh account.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizedSshAccount {
    pub name: String,
    pub private_key: PrivateKeyFileContent,
    pub public_key: PublicKeyFileContent,
}

fn is_sha256_hex(s: &str) -> bool {
    let l = s.len();
    l == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_ssh_key_dir<P: AsRef<Path>>(p: P) -> Result<Vec<AuthorizedSshAccount>> {
    let mut res: Vec<AuthorizedSshAccount> = vec![];
    // directory exists
    if !p.as_ref().is_dir() {
        bail!("Not a directory!")
    }
    let entries = std::fs::read_dir(p.as_ref())?;
    let entries = entries
        .into_iter()
        .map(|file| {
            let path = file?.path();
            if std::fs::metadata(&path)?.len() == 0 {
                bail!("Found empty file!")
            }
            Ok(path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for pub_path in entries {
        // for each x.pub, x exists
        let pub_filename = pub_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if let Some(filename) = pub_filename.strip_suffix(".pub") {
            let pk_path = p.as_ref().join(filename);
            if !pk_path.is_file() {
                bail!("Private key file does not exist")
            }
            let private_key = std::fs::read(pk_path)?;
            let public_key = std::fs::read(&pub_path)?;
            res.push(AuthorizedSshAccount {
                name: filename.to_string(),
                private_key,
                public_key,
            })
        }
    }
    Ok(res)
}

/// Checks whether the input string as the form [hostname:port{,hostname:port}]
fn parse_journalbeat_hosts(s: Option<String>) -> Result<Vec<String>> {
    const HOST_START: &str = r#"^(([[:alnum:]]|[[:alnum:]][[:alnum:]\-]*[[:alnum:]])\.)*"#;
    const HOST_STOP: &str = r#"([[:alnum:]]|[[:alnum:]][[:alnum:]\-]*[[:alnum:]])"#;
    const PORT: &str = r#":[[:digit:]]{2,5}$"#;
    let s = match s {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let rgx = format!("{}{}{}", HOST_START, HOST_STOP, PORT);
    let rgx = Regex::new(&rgx).unwrap();
    let mut res = vec![];
    for target in s.trim().split(',') {
        if !rgx.is_match(target) {
            bail!("Invalid journalbeat host: '{}'", s);
        }
        res.push(target.to_string());
    }
    Ok(res)
}

fn parse_log_debug_overrides(s: Option<String>) -> Result<Vec<String>> {
    let s = match s {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let rgx = r#"^([\w]+::)+[\w]+$"#.to_string();
    let rgx = Regex::new(&rgx).unwrap();
    let mut res = vec![];
    for target in s.trim().split(',') {
        if !rgx.is_match(target) {
            bail!("Invalid log_debug_overrides: '{}'", s);
        }
        res.push(target.to_string());
    }
    Ok(res)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::{is_valid_ssh_key_dir, parse_journalbeat_hosts};
    use std::{fs::OpenOptions, path::Path, process::Command};

    #[test]
    fn valid_key_dir_is_valid_key_dir() {
        let tempdir = tempfile::tempdir().expect("Could not create a temp dir");
        let path = tempdir.path();
        create_key(path, "admin");
        create_key(path, "root");

        let r = is_valid_ssh_key_dir(path).unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn empty_pk_file_fails() {
        let tempdir = tempfile::tempdir().expect("Could not create a temp dir");
        let path = tempdir.path();
        create_key(path, "admin");
        create_key(path, "root");

        let touched_file = path.join("root");
        std::fs::remove_file(&touched_file).unwrap();
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .open(touched_file)
            .unwrap();

        assert!(is_valid_ssh_key_dir(path).is_err());
    }

    // ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_DIR/admin"
    fn create_key<P: AsRef<Path>>(p: P, key_name: &str) {
        let filename = p.as_ref().join(key_name);
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(filename)
            .output()
            .expect("Could not execute ssh-keygen");
    }

    #[test]
    fn invalid_journalbeat_hostnames_are_rejected() {
        let invalid_hostnames = &[
            "sub.domain.tld:1a23",
            "sub.domain-.tld:123",
            "sub.domain-.tld:aaa",
            "sub.domain-.tld:1a2",
            "sub.-domain.tld:123",
            "sub.-domain.tl.:123",
            ".:123",
            ":123",
            "sub.domain.tld:",
            "sub.domain.tld",
        ];

        for hostname in invalid_hostnames {
            let hostname = Some(hostname.to_string());
            assert!(parse_journalbeat_hosts(hostname).is_err())
        }

        for i in 0..invalid_hostnames.len() {
            let s = Some(invalid_hostnames[i..].join(","));
            assert!(parse_journalbeat_hosts(s).is_err())
        }
    }

    #[test]
    fn valid_journalbeat_hostnames_are_accepted() {
        let invalid_hostnames = &[
            "sub.domain.tld:123",
            "sub.domain.tld:12",
            "sub.domain.tld:123",
            "sub.domain.tld:1234",
            "sub.domain.tld:12345",
            "sub.do-main.tld:123",
            "sub.do--main.tld:123",
            "s-ub.domain.tl:123",
        ];

        for hostname in invalid_hostnames {
            let hostname = Some(hostname.to_string());
            assert!(parse_journalbeat_hosts(hostname).is_ok())
        }

        for i in 0..invalid_hostnames.len() {
            let s = Some(invalid_hostnames[i..].join(","));
            let res = parse_journalbeat_hosts(s).expect("Could not parse journalbeat hosts!");
            assert_eq!(res.len(), invalid_hostnames.len() - i);
        }
    }
}
