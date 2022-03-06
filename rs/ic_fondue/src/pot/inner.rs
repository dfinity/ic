//! A fondue [Pot] groups together an environment configuration
//! and tests to be executed in said environment, once it is set up.
//! A [Pot] consists in either an isolated test or a set of composable tests.
//!
//! * Isolated Tests receive a `m: impl Manager` and are allowed to interact
//!   with it in whatever way they see fit.
//!
//! * Composable Tests receive a `hd: Manager::Handle`, which should b a
//!   "read-only" view of the environment. This is what enables us to safely
//!   compose these tests: they should not be able to change the enviroment and
//!   from the test's perspective, it is indistinguishable whether or not its
//!   running under a shared env or not.
//!
//! Importantly, the order of execution of composable tests DOES NOT correspond
//! to the order they were declared, in fact, the [Config::rng_seed] will
//! dictate the execution order. This is a deliberate decision to maximise test
//! surface and to make sure that test authors do not rely on any assumptions
//! about the pre-state of a test.
//!
//! Additionally to receiving access to the [Manager] or the corrsponding
//! handle, tests also receive a [Context], which carries a logger, a PRNG and
//! the pipeline registry. Check [Context]'s documentation for more info.

use nix::unistd::Pid;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, RefUnwindSafe, UnwindSafe};
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, thread};

use super::log::mk_logger;
use crate::ic_instance::LegacyInternetComputer as InternetComputer;
use crate::ic_manager::*;
use crate::result::*;
use slog::{info, warn, Logger};

/// A [Context] carries auxiliary data to a test. Using the provided PRNG is
/// very important if we care about test reproducibility. The
/// [pipeline::Registry] enables the test to tap into the stream of events being
/// produced and analyzed by the environment and, finally, the logger is there
/// for convenience and consistency.
#[derive(Clone)]
pub struct Context {
    pub rng: ChaCha8Rng,
    pub logger: Logger,
    pub is_nns_installed: Arc<Mutex<bool>>,
}

#[allow(clippy::mutex_atomic)]
impl Context {
    pub fn new(rng: ChaCha8Rng, logger: Logger) -> Self {
        Self {
            rng,
            logger,
            is_nns_installed: Arc::new(Mutex::new(false)),
        }
    }
}

/// An [Pot] has an associated environment configuration
/// and a test. Each subsequent test can be either an isolated test
/// or a vector of composable tests.
///
/// A [Pot] carries a derived name which often includes a hash of the
/// configuration and a hash of the test names inside of it. Check
/// [crate::manager::Summarize] for additional info.
pub struct Pot {
    pub env: InternetComputer,
    pub test: Test,
    pub derived_name: String,
    pub experimental: bool,
}

/// Tests can be either isolated, or a sequence of composable tests.
/// The difference is that an isolated test is allowed to change its
/// environment and a composable test can only read from its environment
/// (with the exception of the setup).
pub enum Test {
    Isolated(IsolatedTest),
    Composable {
        /// The `before_tests` field gets executed once after the environment is
        /// setup and is allowed to make arbitrary changes in it. This
        /// is useful to be able to configure the environment a little
        /// more easily than having to rely solely on [Manager::EnvConfig]
        before_tests: Option<Setup>,
        tests: Vec<ComposableTest>,
    },
}

impl Test {
    pub fn test_names(&self) -> Vec<String> {
        match self {
            Test::Isolated(t) => vec![t.name.clone()],
            Test::Composable {
                before_tests: _,
                tests: ts,
            } => ts.iter().map(|t| t.name.clone()).collect(),
        }
    }

    /// Mark all tests as skipped.
    pub fn skip(&mut self) {
        use Test::*;
        match self {
            Isolated(t) => t.skip = true,
            Composable { tests: ts, .. } => ts.iter_mut().for_each(|t| t.skip = true),
        };
    }
}

pub type Setup = Box<dyn FondueTestFn<IcManager>>;
pub type IsolatedTest = FondueTest<IcManager>;
pub type ComposableTest = FondueTest<IcHandle>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PotResult {
    pub test_reports: Vec<TestResultNode>,
}

impl PotResult {
    pub fn is_success(&self) -> bool {
        infer_result(self.test_reports.as_slice()) == TestResult::Passed
    }
}

/// Pot configuration.
pub struct Config {
    /// Specifies the seed for the RNG used within tests for that run. This
    /// ensures that runs are as reproducible as possible.
    pub rng_seed: u64,

    /// Configures the time we are willing to wait for the system under test to
    /// come up.
    pub ready_timeout: std::time::Duration,

    /// Where do we want to log to
    pub log_target: Option<PathBuf>,

    /// What log level do we want to see.
    pub level: slog::Level,
}

impl Config {
    pub fn default() -> Self {
        Config {
            rng_seed: 42,
            ready_timeout: std::time::Duration::from_secs(30),
            log_target: None,
            level: slog::Level::Debug,
        }
    }

    pub fn trace(self) -> Self {
        Config {
            level: slog::Level::Trace,
            ..self
        }
    }

    pub fn random_rng_seed(self) -> Self {
        Config {
            rng_seed: rand::thread_rng().gen_range(0..999999),
            ..self
        }
    }
}

impl Pot {
    /// Runs a ic_fondue::pot::Pot until completion with default configuration.
    /// If you want the RNG to produce different runs, make sure to use
    /// `run_with` and specify the seeds manually.
    pub fn run(self, mancfg: IcManagerSettings) -> PotResult {
        self.run_with(&Config::default(), mancfg)
    }

    pub fn run_against_handle(mut self, cfg: &Config, handle: IcHandle) -> PotResult {
        let pot_name = self.derived_name;
        let logger = mk_logger(cfg.level, cfg.log_target.clone());
        info!(
            logger,
            "<<< POT RUN_ON_HANDLE {} {{pid: {:?}, seed: {}}} >>>",
            pot_name,
            Pid::this(),
            cfg.rng_seed,
        );

        let rng = rand_core::SeedableRng::seed_from_u64(cfg.rng_seed);
        let res = match self.test {
            Test::Isolated(_) => {
                println!("Cannot call run_remote on an isolated test");
                Vec::new()
            }
            Test::Composable {
                before_tests: _,
                tests: ref mut ts,
            } => run_composable_tests(handle, &Context::new(rng, logger.clone()), ts),
        };

        info!(logger, "<<< POT DONE >>>");

        PotResult { test_reports: res }
    }

    pub fn run_with(mut self, cfg: &Config, mancfg: IcManagerSettings) -> PotResult {
        let pot_name = self.derived_name;
        let logger = mk_logger(cfg.level, cfg.log_target.clone());
        info!(
            logger,
            "<<< POT START {} {{pid: {:?}, seed: {}}} >>>",
            pot_name,
            Pid::this(),
            cfg.rng_seed,
        );

        let man = IcManager::start(pot_name, mancfg, self.env, &logger);
        thread::spawn({
            let logger = logger.clone();
            let man = man.clone();
            move || {
                let res = man.wait_for_signal();
                if let Some(sig) = res {
                    warn!(logger, "Stopped with signal {:?}", sig);
                    drop(man);
                    std::process::exit(1);
                }
            }
        });

        let rng = rand_core::SeedableRng::seed_from_u64(cfg.rng_seed);
        let res = if self.experimental {
            self.test.skip();
            vec![]
        } else {
            run_test(&man, &Context::new(rng, logger.clone()), self.test)
        };

        info!(logger, "<<< POT DONE >>>");
        PotResult { test_reports: res }
    }

    /// Marks each step of a composable test to be skipped or not according
    /// to the filters at hand. A step is marked as skipped if its name
    /// does not contain `select` or its name contains `skip`
    pub fn apply_filter(&mut self, f: &Filter) {
        match self.test {
            Test::Isolated(ref mut it) => {
                it.skip = !f.matches(&it.name);
            }
            Test::Composable {
                before_tests: _,
                tests: ref mut ts,
            } => {
                for t in ts.iter_mut() {
                    t.skip = !f.matches(&t.name);
                }
            }
        }
    }
}

/// Filters the composable tests out of a pot.
#[derive(Debug, Clone)]
pub struct Filter {
    pub select: String,
    pub skip_filter: Option<String>,
}

impl Filter {
    pub fn matches(&self, s: &str) -> bool {
        s.contains(&self.select)
            && !self
                .skip_filter
                .clone()
                .map(|skip| s.contains(&skip))
                .unwrap_or(false)
    }
}

/// Builds a pot from a single isolated test
pub fn from_isolated<S: Into<String>>(
    name: S,
    env: &InternetComputer,
    t: impl FondueTestFn<IcManager>,
) -> Pot {
    let name_str = name.into();
    Pot {
        derived_name: format!("{}:{}", name_str, env.summarize()),
        env: env.clone(),
        test: Test::Isolated(FondueTest::new(name_str, t)),
        experimental: false,
    }
}

/// Builds a pot from an iterator of composable tests without a setup phase.
pub fn from_composable<S: Into<String>>(
    name: S,
    env: &InternetComputer,
    ts: impl Iterator<Item = ComposableTest>,
) -> Pot {
    from_composable_setup(name, env, None, ts, false)
}

/// Builds a pot from an iterator of composable tests with a setup phase
pub fn from_composable_setup<S: Into<String>>(
    name: S,
    env: &InternetComputer,
    before_tests: Option<Setup>,
    ts: impl Iterator<Item = ComposableTest>,
    experimental: bool,
) -> Pot {
    let tests: Vec<_> = ts.collect();
    Pot {
        derived_name: format!("{}:{}", name.into(), env.summarize()),
        env: env.clone(),
        test: Test::Composable {
            before_tests,
            tests,
        },
        experimental,
    }
}

// Because rust doesn't let me write trait aliases, I have to resort to ugly
// tricks not to write this monster of a trait everywhere. So much for a "strong
// type system" :)
pub trait FondueTestFn<M>: FnOnce(M, &Context) + UnwindSafe + Send + Sync + 'static {}
impl<M, T: FnOnce(M, &Context) + UnwindSafe + Send + Sync + 'static> FondueTestFn<M> for T {}

pub struct FondueTest<M> {
    pub name: String,
    pub skip: bool,
    pub should_panic: bool,
    pub test: Box<dyn FondueTestFn<M>>,
}

impl<M: RefUnwindSafe + UnwindSafe> FondueTest<M> {
    pub fn new<S: Into<String>>(name: S, test: impl FondueTestFn<M>) -> Self {
        FondueTest {
            name: name.into(),
            test: Box::new(test),
            skip: false,
            should_panic: false,
        }
    }

    pub fn with_name(self, name: &str) -> Self {
        FondueTest {
            name: String::from(name),
            ..self
        }
    }

    /// Returns a modified [FondueTest] with an applied suffix to its name.
    pub fn suffix_name<S: ToString>(self, suffix: S) -> Self {
        let mut aux = self.name;
        aux.push_str(&suffix.to_string());
        FondueTest { name: aux, ..self }
    }

    pub fn should_panic(self) -> Self {
        FondueTest {
            name: self.name,
            test: self.test,
            skip: self.skip,
            should_panic: true,
        }
    }

    pub fn run(self, man: M, ctx: &Context) -> TestResult {
        let name = self.name.clone();
        let should_panic = self.should_panic;

        if self.skip {
            info!(ctx.logger, "<<< POT::TEST SKIP {} >>>", name);
            return TestResult::Skipped;
        } else {
            info!(ctx.logger, "<<< POT::TEST START {} >>>", name);
        }

        let didnt_panic = catch_unwind(|| (self.test)(man, ctx)).is_ok();
        let res = if should_panic != didnt_panic {
            TestResult::Passed
        } else {
            TestResult::Failed
        };

        info!(ctx.logger, "<<< POT::TEST DONE {}: {:?} >>>", name, res);
        res
    }
}

/// If every step of a test is marked as `skip`, there's no need to run
/// anything. This function returns a `Some` with a skipped report for every
/// step of a test when they are all marked as `skip`.
pub fn should_skip(test: &Test) -> bool {
    match test {
        Test::Isolated(it) => it.skip,
        Test::Composable { tests, .. } => tests.iter().all(|t| t.skip),
    }
}

/// Runs a test and returns its result. In case of composable tests,
/// returns whether or not all of them were successful
pub fn run_test(man: &IcManager, ctx: &Context, test: Test) -> Vec<TestResultNode> {
    match test {
        Test::Isolated(t) => vec![run_isolated_test(man, ctx, t)],
        Test::Composable {
            before_tests: bef,
            tests: mut ts,
        } => {
            // We check whether there is a 'setup' phase that needs to be ran,
            // if so, we run it and make sure it succeeds.
            if let Some(setup) = bef {
                info!(ctx.logger, "Starting test setup");
                if !run_setup(man, ctx, setup) {
                    // When the setup fails, we report the individual test steps as being
                    // failed.
                    let mut igns = Vec::new();
                    for t in ts.iter() {
                        igns.push(TestResultNode {
                            name: t.name.clone(),
                            result: TestResult::Failed,
                            ..TestResultNode::default()
                        });
                    }
                    warn!(ctx.logger, "Test setup failed, aborting.");
                    return igns;
                }
            };
            // After the setup has been executed (if any!), we run the composable tests
            run_composable_tests(man.handle(), ctx, &mut ts)
        }
    }
}

/// An isolated test produces a single result
pub fn run_setup(man: &IcManager, ctx: &Context, setup: Setup) -> bool {
    catch_unwind(|| (setup)(man.clone(), ctx)).is_ok()
}

/// An isolated test produces a single result
pub fn run_isolated_test(man: &IcManager, ctx: &Context, test: IsolatedTest) -> TestResultNode {
    let name = test.name.clone();
    let result = test.run(man.clone(), ctx);
    let started_at = std::time::Instant::now();
    let duration = std::time::Instant::now().duration_since(started_at);

    TestResultNode {
        name,
        group_name: None,
        started_at,
        duration,
        result,
        children: vec![],
    }
}

/// Running composable tests consists in running them in
/// a given order; we use the provided rng to get this order
/// to ensure we can reproduce everything by running with the same seed.
///
/// We do return the results of each individual test here to enable
/// us to do some better reporting if we wanted to.
pub fn run_composable_tests(
    handle: IcHandle,
    ctx: &Context,
    tests: &mut Vec<ComposableTest>,
) -> Vec<TestResultNode> {
    let mut results = Vec::new();
    let mut rng = ctx.rng.clone();
    while let Some(test) = pop_random(tests, &mut rng) {
        let name = test.name.clone();
        let started_at = std::time::Instant::now();
        let result = test.run(handle.clone(), ctx);
        let duration = std::time::Instant::now().duration_since(started_at);

        results.push(TestResultNode {
            name,
            group_name: None,
            started_at,
            duration,
            result,
            children: vec![],
        });
    }
    results
}

/// Auxiliary function to pop a random element from a vector.
fn pop_random<A>(v: &mut Vec<A>, rng: &mut ChaCha8Rng) -> Option<A> {
    let v_len = v.len();
    if v_len <= 1 {
        v.pop()
    } else {
        let ix = rng.gen_range(0..v.len());
        let el = v.remove(ix);
        Some(el)
    }
}
