use anyhow::{bail, Result};
use clap::Parser;
use humantime::parse_duration;
use ic_types::ReplicaVersion;
use regex::Regex;
use std::{convert::TryFrom, path::PathBuf, str::FromStr, time::Duration};
use url::Url;

const RND_SEED_DEFAULT: u64 = 42;

#[derive(Parser, Debug)]
#[clap(name = "prod-test-driver", version)]
pub struct CliArgs {
    #[clap(subcommand)]
    pub action: DriverSubCommand,
}

#[derive(clap::Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DriverSubCommand {
    RunTests(RunTestsArgs),
    ProcessTestResults(ProcessTestsArgs),
}

#[derive(clap::Args, Debug)]
pub struct ProcessTestsArgs {
    #[clap(
        long = "working-dir",
        help = "Path to a working directory of the test driver."
    )]
    working_dir: PathBuf,

    #[clap(long = "test-result-dir", help = "Path to the test result directory.")]
    test_result_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct RunTestsArgs {
    #[clap(
        long = "log-base-dir",
        help = "If set, specifies where to write demultiplexed test-specific logs."
    )]
    log_base_dir: Option<PathBuf>,

    #[clap(
        long = "log-level",
        help = "One of TRACE, DEBUG, INFO, WARN, or ERROR. (Default: Info)"
    )]
    log_level: Option<String>,

    #[clap(long = "rand-seed", help = "A 64-bit wide random seed.")]
    rand_seed: Option<u64>,

    #[clap(
        long = "job-id",
        help = r#"
A unique string identifying this test run. On CI, this could be the
CI-Job-Number, e.g.

If not provided, a default of the form `$HOSTNAME-<timestamp>` is used, where
`<timestamp>` is the time at which the test driver was started."#
    )]
    job_id: Option<String>,

    #[clap(
        long = "initial-replica-version",
        help = r#"
The initial replica version. This version must match the version of the guest os
image that the IC is bootstrapped with. If not provided, the default version is
used."#
    )]
    initial_replica_version: String,

    #[clap(
        long = "ic-os-img-sha256",
        help = r#"The sha256 hash sum of the IC-OS image."#
    )]
    ic_os_img_sha256: String,

    #[clap(
            long = "ic-os-img-url",
            help = r#"The URL of the IC-OS disk image used by default for all IC nodes
            version."#,
            parse(try_from_str = url::Url::parse)
        )]
    ic_os_img_url: Url,

    #[clap(
        long = "boundary-node-img-sha256",
        help = r#"The SHA-256 hash of the Boundary Node disk image"#
    )]
    boundary_node_img_sha256: String,

    #[clap(
            long = "boundary-node-img-url",
            help = r#"The URL of the Boundary Node disk image"#,
            parse(try_from_str = url::Url::parse)
        )]
    boundary_node_img_url: Url,

    #[clap(
            long = "farm-base-url",
            help = r#"The base URL of the Farm-service to be used for resource
            management. (default: https://farm.dfinity.systems)"#,
            parse(try_from_str = url::Url::parse)
        )]
    farm_base_url: Option<Url>,

    #[clap(
        long = "result-file",
        parse(from_os_str),
        help = "If set, specifies where to write results of executed tests."
    )]
    result_file: Option<PathBuf>,

    #[clap(
        long = "nns-canister-path",
        parse(from_os_str),
        help = r#"Path to directory containing wasm-files of NNS canisters. 
Required for tests that install NNS canisters."#
    )]
    nns_canister_path: Option<PathBuf>,

    #[clap(long = "suite", help = r#"Mandatory name of a test suite to run."#)]
    suite: String,

    #[clap(
        long = "artifacts-path",
        parse(from_os_str),
        help = r#"Path containing test artifacts (additional binaries, canisters, etc.)."#
    )]
    artifacts_path: Option<PathBuf>,

    #[clap(
        long = "include-pattern",
        help = r#"If set, only tests matching this regex will be exercised 
and all others will be ignored. Note: when `include-pattern` is set, 
`ignore-pattern` and `skip-pattern` are not effective."#
    )]
    include_pattern: Option<String>,

    #[clap(
        long = "ignore-pattern",
        help = r#"If set, all tests matching this regex will be ignored, 
i.e. completely omitted by the framework."#
    )]
    ignore_pattern: Option<String>,

    #[clap(
        long = "skip-pattern",
        help = r#"If set, all tests matching this regex will be skipped, 
i.e. included in a summary, but not exercised."#
    )]
    skip_pattern: Option<String>,

    #[clap(
        long = "authorized-ssh-accounts",
        parse(from_os_str),
        help = r#"Path to directory containing ssh public/private key pairs
(file/file.pub) that are installed on the IC-OS by default."#
    )]
    authorized_ssh_accounts: Option<PathBuf>,

    #[clap(
        long = "journalbeat-hosts",
        help = r#"A comma-separated list of hostname/port-pairs that journalbeat 
should use as target hosts. (e.g. "host1.target.com:443,host2.target.com:443")"#
    )]
    journalbeat_hosts: Option<String>,

    #[clap(
        long = "log-debug-overrides",
        help = r#"A string containing debug overrides in terms of ic.json5.template  
(e.g. "ic_consensus::consensus::batch_delivery,ic_artifact_manager::processors")"#
    )]
    log_debug_overrides: Option<String>,

    #[clap(
        long = "pot-timeout",
        default_value = "600s",
        parse(try_from_str = parse_duration),
        help = r#"Amount of time to wait before releasing resources allocated for a pot."#
        )]
    pot_timeout: Duration,

    #[clap(
        long = "working-dir",
        help = "Path to a working directory of the test driver."
    )]
    working_dir: PathBuf,
}

impl ProcessTestsArgs {
    pub fn validate(self) -> Result<ValidatedCliProcessTestsArgs> {
        Ok(ValidatedCliProcessTestsArgs {
            working_dir: self.working_dir,
            test_result_dir: self.test_result_dir,
        })
    }
}

impl RunTestsArgs {
    pub fn validate(self) -> Result<ValidatedCliRunTestsArgs> {
        let lvl_str = self.log_level.unwrap_or_else(|| "info".to_string());
        let log_level = if let Ok(v) = slog::Level::from_str(&lvl_str) {
            v
        } else {
            bail!("Invalid log level: '{}'!", lvl_str);
        };

        let initial_replica_version = match ReplicaVersion::try_from(self.initial_replica_version) {
            Ok(v) => v,
            Err(e) => bail!("Invalid initial replica version id: {}", e),
        };

        let nns_canister_path = if let Some(p) = self.nns_canister_path {
            if !p.is_dir() {
                bail!("nns-canister-path is not a directory");
            }
            Some(p)
        } else {
            None
        };

        let artifacts_path = if let Some(p) = self.artifacts_path {
            if !p.is_dir() {
                bail!("artifacts-path is not a directory");
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

        let journalbeat_hosts = parse_journalbeat_hosts(self.journalbeat_hosts)?;

        let log_debug_overrides = parse_log_debug_overrides(self.log_debug_overrides)?;

        Ok(ValidatedCliRunTestsArgs {
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
            artifacts_path,
            suite: self.suite,
            include_pattern,
            ignore_pattern,
            skip_pattern,
            authorized_ssh_accounts: self.authorized_ssh_accounts,
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

#[derive(Clone, Debug)]
pub struct ValidatedCliProcessTestsArgs {
    pub working_dir: PathBuf,
    pub test_result_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ValidatedCliRunTestsArgs {
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
    pub artifacts_path: Option<PathBuf>,
    pub suite: String,
    pub include_pattern: Option<Regex>,
    pub ignore_pattern: Option<Regex>,
    pub skip_pattern: Option<Regex>,
    pub authorized_ssh_accounts: Option<PathBuf>,
    pub journalbeat_hosts: Vec<String>,
    pub log_debug_overrides: Vec<String>,
    pub pot_timeout: Duration,
    pub working_dir: PathBuf,
}

fn is_sha256_hex(s: &str) -> bool {
    let l = s.len();
    l == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
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
    use super::parse_journalbeat_hosts;

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
