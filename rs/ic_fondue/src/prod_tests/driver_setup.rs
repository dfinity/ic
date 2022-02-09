use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use ic_nns_init::set_up_env_vars_for_all_canisters;
use ic_types::ReplicaVersion;
use rand_chacha::{rand_core, ChaCha8Rng};
use slog::{o, warn, Drain, Logger};
use slog_async::OverflowStrategy;
use std::sync::Arc;
use std::time::SystemTime;
use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
use url::Url;

use super::cli::{AuthorizedSshAccount, ValidatedCliArgs};
use super::farm::Farm;
use super::pot_dsl;

const ASYNC_CHAN_SIZE: usize = 8192;
const FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub fn create_driver_context_from_cli(
    cli_args: ValidatedCliArgs,
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

    let farm_url = cli_args
        .farm_base_url
        .unwrap_or_else(|| Url::parse(FARM_BASE_URL).expect("should not fail!"));

    let rng = rand_core::SeedableRng::seed_from_u64(cli_args.rand_seed);
    let logger = mk_logger();
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

    let ssh_key_dir = Arc::new(
        setup_ssh_key_dir(&cli_args.authorized_ssh_accounts[..])
            .expect("Could not setup ssh key dir file."),
    );
    DriverContext {
        logger: logger.clone(),
        rng,
        created_at,
        job_id,
        initial_replica_version: cli_args.initial_replica_version,
        base_img_sha256: cli_args.base_img_sha256,
        base_img_url: cli_args.base_img_url,
        farm,
        logs_base_dir: cli_args.log_base_dir,
        authorized_ssh_accounts_dir: ssh_key_dir,
        authorized_ssh_accounts: cli_args.authorized_ssh_accounts,
        journalbeat_hosts: cli_args.journalbeat_hosts,
        log_debug_overrides: cli_args.log_debug_overrides,
        pot_timeout: cli_args.pot_timeout,
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

pub fn tee_logger(ctx: &DriverContext, test_path: &pot_dsl::TestPath) -> Logger {
    if let Some(base_dir) = ctx.logs_base_dir.clone() {
        let stdout_drain = slog::LevelFilter::new(ctx.logger.clone(), slog::Level::Warning);
        let file_drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(
            File::create(set_up_filepath(&base_dir, test_path))
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
        ctx.logger.clone()
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

/// Setup a directory containing files as consumed by the bootstrap script.
fn setup_ssh_key_dir(key_pairs: &[AuthorizedSshAccount]) -> Result<TempDir> {
    let tmp_dir = tempfile::tempdir()?;
    let path = tmp_dir.path();
    for key_pair_files in key_pairs {
        let pub_path = path.join(&key_pair_files.name);
        std::fs::write(pub_path, key_pair_files.public_key.as_slice())?;
    }
    Ok(tmp_dir)
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
    /// The initial replica version to be used.
    pub initial_replica_version: ReplicaVersion,
    pub base_img_sha256: String,
    pub base_img_url: Url,
    /// Abstraction for the Farm service
    pub farm: Farm,
    pub logs_base_dir: Option<PathBuf>,
    pub authorized_ssh_accounts_dir: Arc<TempDir>,
    pub authorized_ssh_accounts: Vec<AuthorizedSshAccount>,
    pub journalbeat_hosts: Vec<String>,
    pub log_debug_overrides: Vec<String>,
    pub pot_timeout: Duration,
}

impl DriverContext {
    pub fn logger(&self) -> slog::Logger {
        self.logger.clone()
    }
}
