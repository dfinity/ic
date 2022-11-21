use anyhow::{bail, Result};
use clap::Parser;
use humantime::parse_duration;
use regex::Regex;
use std::{path::PathBuf, str::FromStr, time::Duration};

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
    // These fields below are needed for creating slack alerts.
    #[clap(long = "ci-job-url")]
    ci_job_url: String,
    #[clap(long = "ci-project-url")]
    ci_project_url: String,
    #[clap(long = "ci-commit-sha")]
    ci_commit_sha: String,
    #[clap(long = "ci-commit-short-sha")]
    ci_commit_short_sha: String,
    #[clap(long = "ic-version-id")]
    ic_version_id: String,
}

#[derive(clap::Args, Debug)]
pub struct RunTestsArgs {
    #[clap(
        long = "log-level",
        help = "One of TRACE, DEBUG, INFO, WARN, or ERROR. (Default: Info)"
    )]
    log_level: Option<String>,

    #[clap(
        long = "no-propagate-test-logs",
        help = r#"If set, logs of tests will only be strored in the test.log
file of the respective test environment (and not be propagated to stdout, e.g.)."#
    )]
    no_propagate_test_logs: bool,

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

    #[clap(long = "suite", help = r#"Mandatory name of a test suite to run."#)]
    suite: String,

    #[clap(
        long = "include-pattern",
        help = r#"If set, only tests matching this regex will be exercised
 and all others will be ignored. Note: when `include-pattern` is set, `skip-pattern` is not effective."#
    )]
    include_pattern: Option<String>,

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

    // TODO: remove this arg, which is anyway ignored, as it is should be passed as /dependencies.
    #[clap(
        long = "replica-log-debug-overrides",
        help = r#"A string containing debug overrides in terms of ic.json5.template
 (e.g. "ic_consensus::consensus::batch_delivery,ic_artifact_manager::processors")"#
    )]
    _replica_log_debug_overrides: Option<String>,

    #[clap(
        long = "pot-timeout",
        default_value = "900s",
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
            ci_commit_sha: self.ci_commit_sha,
            ci_commit_short_sha: self.ci_commit_short_sha,
            ci_job_url: self.ci_job_url,
            ci_project_url: self.ci_project_url,
            ic_version_id: self.ic_version_id,
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

        let include_pattern = parse_pattern(self.include_pattern)?;
        let skip_pattern = parse_pattern(self.skip_pattern)?;

        Ok(ValidatedCliRunTestsArgs {
            log_level,
            propagate_test_logs: !self.no_propagate_test_logs,
            rand_seed: self.rand_seed.unwrap_or(RND_SEED_DEFAULT),
            job_id: self.job_id,
            suite: self.suite,
            include_pattern,
            skip_pattern,
            authorized_ssh_accounts: self.authorized_ssh_accounts,
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
    pub ci_job_url: String,
    pub ci_project_url: String,
    pub ci_commit_sha: String,
    pub ci_commit_short_sha: String,
    pub ic_version_id: String,
}

#[derive(Clone, Debug)]
pub struct ValidatedCliRunTestsArgs {
    pub log_level: slog::Level,
    pub propagate_test_logs: bool,
    pub rand_seed: u64,
    pub job_id: Option<String>,
    pub suite: String,
    pub include_pattern: Option<Regex>,
    pub skip_pattern: Option<Regex>,
    pub authorized_ssh_accounts: Option<PathBuf>,
    pub pot_timeout: Duration,
    pub working_dir: PathBuf,
}

pub fn bail_if_sha256_invalid(sha256: &str, opt_name: &str) -> Result<()> {
    let l = sha256.len();
    if !(l == 64 || sha256.chars().all(|c| c.is_ascii_hexdigit())) {
        bail!("option '{}': invalid sha256 value: {:?}", opt_name, sha256);
    }
    Ok(())
}

/// Checks whether the input string as the form [hostname:port{,hostname:port}]
pub fn parse_journalbeat_hosts(s: Option<String>) -> Result<Vec<String>> {
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

pub fn parse_replica_log_debug_overrides(s: Option<String>) -> Result<Vec<String>> {
    let s = match s {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    let rgx = r#"^([\w]+::)+[\w]+$"#.to_string();
    let rgx = Regex::new(&rgx).unwrap();
    let mut res = vec![];
    for target in s.trim().split(',') {
        if !rgx.is_match(target) {
            bail!("Invalid replica_log_debug_overrides: '{}'", s);
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
