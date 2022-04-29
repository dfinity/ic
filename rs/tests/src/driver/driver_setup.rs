use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use ic_nns_init::set_up_env_vars_for_all_canisters;
use ic_types::ReplicaVersion;
use rand_chacha::{rand_core, ChaCha8Rng};
use slog::{o, warn, Drain, Logger};
use slog_async::OverflowStrategy;
use std::ffi::OsStr;
use std::time::SystemTime;
use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

use super::cli::ValidatedCliArgs;
use super::farm::Farm;
use super::pot_dsl::{self};
use super::test_env::HasBaseLogDir;
use serde::{Deserialize, Serialize};

const ASYNC_CHAN_SIZE: usize = 8192;
const DEFAULT_FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub const SSH_AUTHORIZED_PUB_KEYS_DIR: &str = "ssh/authorized_pub_keys";
pub const SSH_AUTHORIZED_PRIV_KEYS_DIR: &str = "ssh/authorized_priv_keys";

#[derive(Deserialize, Serialize)]
pub struct IcSetup {
    pub farm_base_url: Url,
    pub ic_os_img_url: Url,
    pub ic_os_img_sha256: String,
    pub boundary_node_img_url: Url,
    pub boundary_node_img_sha256: String,
    pub journalbeat_hosts: Vec<String>,
    pub initial_replica_version: ReplicaVersion,
    pub log_debug_overrides: Vec<String>,
}

impl TestEnvAttribute for IcSetup {
    fn attribute_name() -> String {
        "ic_setup".to_string()
    }
}

pub fn initialize_env(env: &TestEnv, cli_args: ValidatedCliArgs) -> Result<()> {
    let farm_base_url = cli_args
        .farm_base_url
        .clone()
        .unwrap_or_else(|| Url::parse(DEFAULT_FARM_BASE_URL).expect("should not fail!"));
    if let Some(authorized_ssh_accounts) = cli_args.authorized_ssh_accounts.clone() {
        copy_ssh_keys(env, authorized_ssh_accounts)?;
    }
    IcSetup {
        farm_base_url,
        ic_os_img_url: cli_args.ic_os_img_url,
        ic_os_img_sha256: cli_args.ic_os_img_sha256,
        boundary_node_img_url: cli_args.boundary_node_img_url,
        boundary_node_img_sha256: cli_args.boundary_node_img_sha256,
        journalbeat_hosts: cli_args.journalbeat_hosts,
        initial_replica_version: cli_args.initial_replica_version,
        log_debug_overrides: cli_args.log_debug_overrides,
    }
    .write_attribute(env);
    if let Some(base_dir) = &cli_args.log_base_dir {
        env.write_base_log_dir(base_dir)?;
    }
    Ok(())
}

fn copy_ssh_keys(env: &TestEnv, authorized_ssh_accounts: PathBuf) -> Result<()> {
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);
    let ssh_authorized_priv_key_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    fs::create_dir_all(ssh_authorized_pub_keys_dir.clone())?;
    fs::create_dir_all(ssh_authorized_priv_key_dir.clone())?;
    for entry in fs::read_dir(authorized_ssh_accounts)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() == Some(OsStr::new("pub")) {
            let name = path.file_stem().unwrap();
            fs::copy(&path, ssh_authorized_pub_keys_dir.clone().join(name))?;
        } else {
            let name = path.file_name().unwrap();
            fs::copy(path.clone(), ssh_authorized_priv_key_dir.clone().join(name))?;
        }
    }
    Ok(())
}

pub fn create_driver_context_from_cli(
    cli_args: ValidatedCliArgs,
    env: TestEnv,
    hostname: Option<String>,
) -> DriverContext {
    let created_at = SystemTime::now();
    let job_id = cli_args.job_id.unwrap_or_else(|| {
        let datetime: DateTime<Utc> = DateTime::from(created_at);
        let job_id = hostname
            .map(|s| format!("{}-", s))
            .unwrap_or_else(|| "".to_string());
        format!(
            "{}{}",
            job_id,
            datetime.to_rfc3339_opts(SecondsFormat::Millis, true)
        )
    });

    let logger = env.logger();
    let farm_url = cli_args
        .farm_base_url
        .unwrap_or_else(|| Url::parse(DEFAULT_FARM_BASE_URL).expect("should not fail!"));
    let rng = rand_core::SeedableRng::seed_from_u64(cli_args.rand_seed);
    let farm = Farm::new(farm_url, logger.clone());

    // Setting the global env variables that point to the wasm files for NNS
    // canisters. This is a known hack inherited from the canister_test
    // framework.
    if let Some(p) = &cli_args.nns_canister_path {
        set_up_env_vars_for_all_canisters(p);
    } else {
        warn!(
            logger,
            "Path to nns canister not provided; tests might not be able to install them!"
        );
    }

    DriverContext {
        logger: logger.clone(),
        rng,
        created_at,
        job_id,
        farm,
        logs_base_dir: cli_args.log_base_dir,
        artifacts_path: cli_args.artifacts_path,
        pot_timeout: cli_args.pot_timeout,
        env,
        working_dir: cli_args.working_dir,
    }
}

pub fn mk_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(ASYNC_CHAN_SIZE)
        .build();
    slog::Logger::root(drain.fuse(), o!())
}

pub fn tee_logger(test_env: &TestEnv, logger: Logger) -> Logger {
    use crate::driver::test_env::HasTestPath;
    if let Some(base_dir) = test_env.base_log_dir() {
        let stdout_drain = slog::LevelFilter::new(logger.clone(), slog::Level::Warning);
        let test_path = test_env.test_path();
        let file_drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(
            File::create(set_up_filepath(&base_dir, &test_path))
                .expect("could not create a log file"),
        ))
        .build()
        .fuse();
        let file_drain = slog_async::Async::new(file_drain)
            .chan_size(ASYNC_CHAN_SIZE)
            .overflow_strategy(OverflowStrategy::Block)
            .build()
            .fuse();
        slog::Logger::root(slog::Duplicate(stdout_drain, file_drain).fuse(), o!())
    } else {
        logger
    }
}

fn set_up_filepath(base_dir: &Path, test_path: &pot_dsl::TestPath) -> PathBuf {
    let mut tp = test_path.clone();
    let filename = tp.pop();
    let mut path = tp.to_filepath(base_dir);
    fs::create_dir_all(&path).unwrap();
    path.push(filename);
    path.set_extension("log");
    path
}

#[derive(Clone)]
pub struct DriverContext {
    /// logger
    pub logger: Logger,
    pub rng: ChaCha8Rng,
    /// The instance at which the context was created.
    pub created_at: SystemTime,
    /// A unique id identifying this test run.
    pub job_id: String,
    /// Abstraction for the Farm service
    pub farm: Farm,
    pub logs_base_dir: Option<PathBuf>,
    pub artifacts_path: Option<PathBuf>,
    pub pot_timeout: Duration,
    pub env: TestEnv,
    pub working_dir: PathBuf,
}

impl DriverContext {
    pub fn logger(&self) -> slog::Logger {
        self.logger.clone()
    }
}
