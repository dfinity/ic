use crate::driver::test_env::TestEnv;
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use rand_chacha::{rand_core, ChaCha8Rng};
use slog::{o, Drain, Logger};
use std::ffi::OsStr;
use std::time::SystemTime;
use std::{fs, path::PathBuf, time::Duration};

use super::cli::ValidatedCliRunTestsArgs;
use super::farm::Farm;
use super::test_env_api::HasIcDependencies;

const ASYNC_CHAN_SIZE: usize = 8192;
pub const DEFAULT_FARM_BASE_URL: &str = "https://farm.dfinity.systems";

pub const SSH_AUTHORIZED_PUB_KEYS_DIR: &str = "ssh/authorized_pub_keys";
pub const SSH_AUTHORIZED_PRIV_KEYS_DIR: &str = "ssh/authorized_priv_keys";

pub fn initialize_env(env: &TestEnv, cli_args: ValidatedCliRunTestsArgs) -> Result<()> {
    if let Some(authorized_ssh_accounts) = cli_args.authorized_ssh_accounts {
        copy_ssh_keys(env, authorized_ssh_accounts)?;
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
    cli_args: ValidatedCliRunTestsArgs,
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
    let farm_url = env.get_farm_url().unwrap();
    let rng = rand_core::SeedableRng::seed_from_u64(cli_args.rand_seed);
    let farm = Farm::new(farm_url, logger.clone());

    DriverContext {
        logger: logger.clone(),
        propagate_test_logs: cli_args.propagate_test_logs,
        rng,
        created_at,
        job_id,
        farm,
        pot_timeout: cli_args.pot_timeout,
        env,
        working_dir: cli_args.working_dir,
    }
}

pub fn mk_stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(ASYNC_CHAN_SIZE)
        .build();
    slog::Logger::root(drain.fuse(), o!())
}

#[derive(Clone)]
pub struct DriverContext {
    /// logger
    pub logger: Logger,
    /// if set, test logs will be propagated to the parent logger, otherwise
    /// they will only be stored in the test.log file of the respective test
    /// environment
    pub propagate_test_logs: bool,
    pub rng: ChaCha8Rng,
    /// The instance at which the context was created.
    pub created_at: SystemTime,
    /// A unique id identifying this test run.
    pub job_id: String,
    /// Abstraction for the Farm service
    pub farm: Farm,
    pub pot_timeout: Duration,
    pub env: TestEnv,
    pub working_dir: PathBuf,
}

impl DriverContext {
    pub fn logger(&self) -> slog::Logger {
        self.logger.clone()
    }
}
