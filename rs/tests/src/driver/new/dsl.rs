#![allow(dead_code)]
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fs::File,
    os::unix::prelude::AsRawFd,
    panic::UnwindSafe,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::driver::{
    driver_setup::DEFAULT_FARM_BASE_URL,
    farm::{Farm, GroupSpec},
    new::task_scheduler::TaskSchedule,
    pot_dsl::{PotSetupFn, SysTestFn},
    test_env::TestEnv,
    test_setup::PotSetup,
};
use anyhow::{bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use slog::{o, Drain, Logger};
use url::Url;

const ASYNC_LOG_CHANNEL_SIZE: usize = 8192;

#[macro_export]
macro_rules! systest {
    ($a:path) => {
        ic_tests::driver::new::dsl::TestFunction::new(std::stringify!($a), $a)
    };
}

pub struct SystemTestGroup {
    setup: Option<Box<dyn PotSetupFn>>,
    tests: BTreeMap<String, Box<dyn SysTestFn>>,
}

impl Default for SystemTestGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemTestGroup {
    pub fn new() -> Self {
        Self {
            setup: Default::default(),
            tests: Default::default(),
        }
    }

    pub fn with_setup<F: PotSetupFn>(mut self, setup: F) -> Self {
        self.setup = Some(Box::new(setup));
        self
    }

    pub fn add_test(mut self, test: TestFunction) -> Self {
        if let e @ Entry::Vacant(_) = self.tests.entry(test.name.clone()) {
            e.or_insert(test.f);
        } else {
            panic!("redeclared test with name '{}'", test.name)
        }
        self
    }

    pub fn execute_from_args(self) -> Result<()> {
        let ctx = DriverContext::from_args()?;

        match ctx.driver_cmd {
            SystemTestsSubcommand::Run(_) => {
                println!("Run");
                let singleton =
                    |name: &str| vec![name.to_string()].into_iter().collect::<BTreeSet<_>>();
                let mut schedule = TaskSchedule::new();
                // the setup is always executed first
                schedule = schedule.append_set(singleton("::setup"));
                schedule = self.tests.keys().fold(schedule, |schedule, name| {
                    schedule.append_set(singleton(name))
                });
                schedule.execute();
            }
            SystemTestsSubcommand::InteractiveMode(_) => todo!(),
            // SpawnChild is an 'internal' command that is used to re-spawn the
            // binary.
            SystemTestsSubcommand::SpawnChild {
                task_name: _,
                cord: _,
                log_stream: _,
            } => {
                todo!()
            }
        }

        // the following code should be moved to the parent
        let farm_base_url = Url::parse(DEFAULT_FARM_BASE_URL).expect("can't fail");
        let farm = Farm::new(farm_base_url, ctx.logger.clone());

        // setup resource group
        let farm_group_name = exec_name_to_pot_name(std::env::args().next().unwrap());
        let pot_setup = PotSetup {
            farm_group_name,
            artifact_path: None,
            default_vm_resources: None,
            pot_timeout: Duration::from_secs(60 * 10), // ten minutes
        };

        let group_spec = GroupSpec {
            vm_allocation: None,
            required_host_features: vec![],
            preferred_network: None,
        };

        farm.create_group(
            &pot_setup.farm_group_name,
            pot_setup.pot_timeout,
            group_spec,
        )
        .unwrap();

        for (name, _t) in self.tests.iter() {
            println!("mock executing test: {}", name);
        }

        Ok(())
    }
}

pub struct TestFunction {
    name: String,
    f: Box<dyn SysTestFn>,
}

impl TestFunction {
    pub fn new<F: SysTestFn>(name: &str, f: F) -> Self {
        Self {
            name: name.to_string(),
            f: Box::new(f),
        }
    }
}

#[derive(Debug, Clone)]
struct DriverContext {
    pub constructed_at: SystemTime,
    pub exec_path: PathBuf,
    pub working_dir: PathBuf,
    pub driver_cmd: SystemTestsSubcommand,
    pub dependencies: Dependencies,
    pub logger: Logger,
}

impl DriverContext {
    fn from_args() -> Result<Self> {
        let constructed_at = SystemTime::now();
        let exec_path = PathBuf::from(std::env::args().next().unwrap());
        if !exec_path.is_file() {
            bail!("{:?} is not a file.", exec_path)
        }

        // The help message for the command line arguments of this binary should
        // *not* list the options that the binary uses to re-spawn itself. Thus,
        // we check whether we are a child-process separately.
        let dependencies = Dependencies::from_env().unwrap();

        let args = CliArgs::parse().validate()?;
        let logger = new_stdout_logger();

        Ok(Self {
            constructed_at,
            exec_path,
            working_dir: args.working_dir.working_dir,
            driver_cmd: args.action,
            dependencies,
            logger,
        })
    }

    pub fn setup_path(&self) -> PathBuf {
        self.working_dir.join("setup")
    }

    pub fn test_path(&self, test_name: &str) -> PathBuf {
        self.working_dir.join("tests").join(test_name)
    }

    pub fn canonical_group_instance_name(&self) -> String {
        let ts = self.constructed_at.duration_since(UNIX_EPOCH).unwrap();
        format!("{}_{}", self.exec_name(), ts.as_millis())
    }

    fn exec_name(&self) -> String {
        self.exec_path
            .file_name()
            .expect("could not extract filename")
            .to_str()
            .expect("could not convert os string to string")
            .to_owned()
    }
}

#[derive(Debug, Clone)]
enum DriverCmd {
    Run,
    ExecuteTask { task_name: String },
}

fn exec_name_to_pot_name(name: String) -> String {
    let now = SystemTime::now();
    let ts = now.duration_since(UNIX_EPOCH).unwrap().as_millis();
    format!("{}_{}", name, ts)
}

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[clap(flatten)]
    working_dir: WorkingDir,

    #[clap(subcommand)]
    pub action: SystemTestsSubcommand,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        // nothing to validate at the moment
        Ok(self)
    }
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum SystemTestsSubcommand {
    /// run all tests in this test group using the working directory specified
    Run(WorkingDir),
    /// Execute only the setup function and keep the system running until the
    /// ctrl+c is pressed.
    ///
    /// Not yet implemented!
    InteractiveMode(WorkingDir),

    #[clap(hide = true)]
    SpawnChild {
        task_name: String,
        cord: PathBuf,
        log_stream: PathBuf,
    },
}

#[derive(clap::Args, Clone, Debug)]
pub struct WorkingDir {
    #[clap(
        long = "working-dir",
        help = r#"
Path to a working directory of the test driver. The working directory contains
all test environments including the one of the setup."#
    )]
    working_dir: PathBuf,
}

#[derive(Clone, Debug)]
struct Dependencies(BTreeMap<String, Dependency>);

impl Dependencies {
    // This function is essentially the interface between bazel and the test
    // driver.

    // btw, bazel allows assembling json objects
    fn from_env() -> Result<Self> {
        Ok(Self(Default::default()))
    }
}

// this should be some internally stable representation of available
// dependencies
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Dependency {
    RemoteApi { url: Url },
    // for example, wasm files that are required by the test drivers are
    // certainly locally available
    LocalFile { path: PathBuf },
    // for example, disk image
    RemoteFile { url: Url, sha256: String },
}

/// create a logger that logs to a file; creates all parent directories if they
/// don't exist.
fn new_file_logger<P: AsRef<Path>>(p: P) -> Result<Logger> {
    std::fs::create_dir_all(p.as_ref().parent().expect("no parent"))?;
    let log_file = open_append_and_lock_exclusive(p)?;
    let file_drain = slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(log_file))
        .build()
        .fuse();
    Ok(slog::Logger::root(async_drain(file_drain), o!()))
}

fn multiplex_logger(l1: Logger, l2: Logger) -> Logger {
    slog::Logger::root(slog::Duplicate(l1, l2).fuse(), o!())
}

/// creates a slog::Logger that prints to standard out using an asynchronous drain
fn new_stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    slog::Logger::root(async_drain(drain), o!())
}

fn open_append_and_lock_exclusive<P: AsRef<Path>>(p: P) -> Result<File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    let fd = f.as_raw_fd();
    nix::fcntl::flock(fd, nix::fcntl::FlockArg::LockExclusiveNonblock)?;
    Ok(f)
}

fn async_drain<D>(d: D) -> slog::Fuse<slog_async::Async>
where
    D: slog::Drain<Err = slog::Never, Ok = ()> + Send + 'static,
{
    slog_async::Async::new(d)
        .chan_size(ASYNC_LOG_CHANNEL_SIZE)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse()
}

pub trait ChildFn: FnOnce(Logger) + UnwindSafe + Send + Sync + 'static {}
impl<T: FnOnce(Logger) + UnwindSafe + Send + Sync + 'static> ChildFn for T {}

// (TestEnv -> ()) -> (WorkingDir -> ())
fn lift<P, R, F: SysTestFn>(source_env: P, target_env: R, f: F) -> impl ChildFn
where
    P: AsRef<Path>,
    R: AsRef<Path>,
{
    let source_env_path = source_env.as_ref().to_owned();
    let target_env_path = target_env.as_ref().to_owned();
    move |logger: Logger| {
        let src_env = TestEnv::new(&source_env_path, logger.clone())
            .expect("could not create source environment");
        let test_env = src_env
            .fork(logger, target_env_path)
            .expect("could not create test env");
        (f)(test_env);
    }
}

fn get_test_env_from_working_dir<P: AsRef<Path>>(working_dir: P, task_name: &str) -> PathBuf {
    if task_name.contains('/') {
        panic!("Invalid character '/' in task name {:?}.", task_name);
    }

    working_dir.as_ref().join(pathify_test_name(task_name))
}

// currently, this is a dummy function. Eventually, this should turn the test
// name into a path-compatible string (e.g., by replacing :: with __ or similar)
fn pathify_test_name(p: &str) -> String {
    p.replace("::", "__")
}
