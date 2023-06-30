#![allow(dead_code)]
#[rustfmt::skip]

use std::path::PathBuf;

use crate::driver::{
    farm::{Farm, HostFeature},
    task_scheduler::TaskScheduler,
    test_env_api::{FarmBaseUrl, HasGroupSetup},
    {
        action_graph::ActionGraph,
        context::{GroupContext, ProcessContext},
        dsl::{SubprocessFn, TestFunction},
        event::TaskId,
        plan::{EvalOrder, Plan},
        report::Outcome,
        task::{DebugKeepaliveTask, EmptyTask},
        task_scheduler::TaskTable,
    },
};
use crate::driver::{
    pot_dsl::{PotSetupFn, SysTestFn},
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::HasIcDependencies,
    test_setup::GroupSetup,
};
use serde::{Deserialize, Serialize};

use anyhow::{bail, Result};
use clap::Parser;
use tokio::runtime::{Builder, Handle, Runtime};

use crate::driver::{
    constants::{kibana_link, GROUP_TTL, KEEPALIVE_INTERVAL},
    subprocess_task::SubprocessTask,
    task::{SkipTestTask, Task},
    timeout::TimeoutTask,
};
use std::{collections::BTreeMap, iter::once, time::Duration};

use slog::{debug, info, trace, Logger};

use super::report::{SystemGroupSummary, SystemTestGroupError};

const DEFAULT_TIMEOUT_PER_TEST: Duration = Duration::from_secs(60 * 10); // 10 minutes
const DEFAULT_OVERALL_TIMEOUT: Duration = Duration::from_secs(60 * 10); // 10 minutes
pub const MAX_RUNTIME_THREADS: usize = 16;
pub const MAX_RUNTIME_BLOCKING_THREADS: usize = 16;

const DEBUG_KEEPALIVE_TASK_NAME: &str = "debug_keepalive";
const REPORT_TASK_NAME: &str = "report";
const KEEPALIVE_TASK_NAME: &str = "keepalive";
const SETUP_TASK_NAME: &str = "setup";
const LIFETIME_GUARD_TASK_PREFIX: &str = "lifetime_guard_";

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[clap(flatten)]
    group_dir: GroupDir,

    #[clap(subcommand)]
    pub action: SystemTestsSubcommand,

    #[clap(
        long = "debug-keepalive",
        help = "If set, system under test is kept alive until bazel timeout or user interrupt."
    )]
    pub debug_keepalive: bool,

    #[clap(
        long = "no-delete-farm-group",
        help = "If set, Farm group is not deleted in the tear down."
    )]
    pub no_delete_farm_group: bool,

    #[clap(
        long = "no-summary-report",
        help = "If set, no summary/report events are produced by the test-driver."
    )]
    pub no_summary_report: bool,

    #[clap(
        long = "no-farm-keepalive",
        help = "If set, Farm group is not kept alive."
    )]
    pub no_farm_keepalive: bool,

    #[clap(
        long = "include-tests",
        help = "Execute only those test functions, which contain a substring and skip all the others."
    )]
    pub filter_tests: Option<String>,

    #[clap(long = "group-base-name", help = "Group base name.")]
    pub group_base_name: String,

    #[clap(
        long = "farm-base-url",
        help = "Use a custom url for the Farm webservice."
    )]
    pub farm_base_url: Option<url::Url>,
    #[clap(
        long = "set-required-host-features",
        help = "Require all host machines to have these features. Override others.",
        value_delimiter = ',',
        value_parser = CliArgs::parse_host_feature
    )]
    pub required_host_features: Option<Vec<HostFeature>>,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        // nothing to validate at the moment
        Ok(self)
    }

    /// A convenience method to get the task id of this subprocess, *if* it is in fact a
    /// subprocess.
    fn subproc_id(&self) -> Option<(TaskId, u64)> {
        match &self.action {
            SystemTestsSubcommand::SpawnChild { task_id, sock_id } => {
                Some((task_id.clone(), *sock_id))
            }
            _ => None,
        }
    }

    /// Convert stringified HostFeatures to HostFeatures.
    fn parse_host_feature(s: &str) -> Result<HostFeature, serde_json::Error> {
        let quoted_feature = format!("\"{}\"", s.trim());
        serde_json::from_str::<HostFeature>(&quoted_feature)
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct GroupDir {
    #[clap(
        long = "working-dir",
        help = r#"
Path to a working directory of the test driver. The working directory contains
all test environments including the one of the setup."#
    )]
    pub path: PathBuf,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum SystemTestsSubcommand {
    /// run all tests in this test group
    Run,

    /// Execute only the setup function and keep the system running until the
    /// ctrl+c is pressed.
    ///
    /// Not yet implemented!
    InteractiveMode,

    #[clap(hide = true)]
    SpawnChild { task_id: TaskId, sock_id: u64 },
}

#[derive(Deserialize, Serialize)]
struct SetupResult;

impl TestEnvAttribute for SetupResult {
    fn attribute_name() -> String {
        String::from("setup_succeeded")
    }
}

pub fn is_task_visible_to_user(task_id: &TaskId) -> bool {
    matches!(task_id, TaskId::Test(task_name) if task_name.ne(REPORT_TASK_NAME) && task_name.ne(KEEPALIVE_TASK_NAME) && !task_name.starts_with(LIFETIME_GUARD_TASK_PREFIX) && !task_name.starts_with("dummy("))
}

pub struct ComposeContext<'a> {
    rh: &'a Handle,
    group_ctx: GroupContext,
    empty_task_counter: u64,
    logger: Logger,
    timeout_per_test: Duration,
}

fn subproc(
    task_id: TaskId,
    target_fn: impl SubprocessFn,
    ctx: &mut ComposeContext,
) -> SubprocessTask {
    trace!(ctx.group_ctx.log(), "subproc(task_name={})", &task_id);
    SubprocessTask::new(task_id, ctx.rh.clone(), target_fn, ctx.group_ctx.clone())
}

fn timed(
    plan: Plan<Box<dyn Task>>,
    timeout: Duration,
    descriptor: Option<String>,
    ctx: &mut ComposeContext,
) -> Plan<Box<dyn Task>> {
    trace!(
        ctx.logger,
        "timed(plan={:?}, timeout={:?})",
        &plan,
        &timeout
    );
    let timeout_task = TimeoutTask::new(
        ctx.rh.clone(),
        timeout,
        TaskId::Timeout(descriptor.unwrap_or_else(|| plan.root_task_id().name())),
    );
    Plan::Supervised {
        supervisor: Box::from(timeout_task) as Box<dyn Task>,
        ordering: EvalOrder::Sequential, // the order is irrelevant since there is only one child
        children: vec![plan],
    }
}

fn compose(
    root_task: Option<Box<dyn Task>>,
    ordering: EvalOrder,
    children: Vec<Plan<Box<dyn Task>>>,
    ctx: &mut ComposeContext,
) -> Plan<Box<dyn Task>> {
    trace!(
        ctx.logger,
        "compose(root={:?}, ordering={:?}, children={:?})",
        &root_task,
        &ordering,
        &children
    );
    let root_task = match root_task {
        Some(task) => task,
        None => {
            let empty_task = Box::from(EmptyTask::new(TaskId::Test(format!(
                "dummy({})",
                ctx.empty_task_counter
            ))));
            ctx.empty_task_counter += 1;
            empty_task
        }
    };
    Plan::Supervised {
        supervisor: root_task,
        ordering,
        children,
    }
}

fn compose_par(
    root_task: Option<Box<dyn Task>>,
    first: Plan<Box<dyn Task>>,
    second: Plan<Box<dyn Task>>,
    ctx: &mut ComposeContext,
) -> Plan<Box<dyn Task>> {
    compose(root_task, EvalOrder::Parallel, vec![first, second], ctx)
}

fn compose_seq(
    root_task: Option<Box<dyn Task>>,
    first: Plan<Box<dyn Task>>,
    second: Plan<Box<dyn Task>>,
    ctx: &mut ComposeContext,
) -> Plan<Box<dyn Task>> {
    compose(root_task, EvalOrder::Sequential, vec![first, second], ctx)
}

fn get_setup_env(gctx: GroupContext) -> TestEnv {
    trace!(gctx.log(), "get_setup_env()");
    let process_ctx = ProcessContext::new(gctx, String::from(SETUP_TASK_NAME)).unwrap();
    process_ctx.group_context.create_setup_env().unwrap()
}

fn get_or_create_env(gctx: GroupContext, task_id: TaskId) -> Result<TestEnv> {
    trace!(gctx.log(), "create_env(task_id={})", &task_id);
    let process_ctx = ProcessContext::new(gctx, task_id.name()).unwrap();
    process_ctx.group_context.create_test_env(&task_id.name())
}

pub enum SystemTestSubGroup {
    Multiple {
        tasks: Vec<SystemTestSubGroup>,
        ordering: EvalOrder,
    },
    Singleton {
        task_fn: Box<dyn SysTestFn>,
        task_id: TaskId,
    },
}

impl Default for SystemTestSubGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemTestSubGroup {
    pub fn new() -> Self {
        Self::Multiple {
            tasks: vec![],
            ordering: EvalOrder::Parallel,
        }
    }

    pub fn add_test(self, test: TestFunction) -> Self {
        let task_is = TaskId::Test(String::from(test.name()));
        let singleton = Self::Singleton {
            task_fn: test.f(),
            task_id: task_is,
        };
        match self {
            Self::Multiple { tasks, .. } if tasks.is_empty() => {
                // This case is only to support the builder pattern
                singleton
            }
            Self::Multiple { tasks, ordering } => Self::Multiple {
                tasks: tasks.into_iter().chain(once(singleton)).collect(),
                ordering,
            },
            sub_group @ Self::Singleton { .. } => {
                Self::Multiple {
                    tasks: once(sub_group).chain(once(singleton)).collect(),
                    ordering: EvalOrder::Parallel, // TODO: generalize this
                }
            }
        }
    }

    pub fn into_plan(self, ctx: &mut ComposeContext) -> Plan<Box<dyn Task>> {
        match self {
            SystemTestSubGroup::Multiple { tasks, ordering } => compose(
                None,
                ordering,
                tasks
                    .into_iter()
                    .map(|sub_group| sub_group.into_plan(ctx))
                    .collect(),
                ctx,
            ),
            // If filtering flag `--include-tests` is set, then for all
            // skipped test function we execute a SkipTestTask
            SystemTestSubGroup::Singleton { task_fn, task_id } => {
                let logger = ctx.logger.clone();
                let group_ctx = ctx.group_ctx.clone();
                if let Some(ref filter) = group_ctx.filter_tests {
                    if let TaskId::Test(ref name) = task_id {
                        if !name.contains(filter) {
                            return Plan::Leaf {
                                task: Box::from(SkipTestTask::new(task_id.clone())),
                            };
                        }
                    }
                }
                let closure = {
                    let task_id = task_id.clone();
                    let group_ctx = ctx.group_ctx.clone();
                    move || {
                        debug!(logger, ">>> test_fn({})", &task_id);
                        let env = get_or_create_env(group_ctx, task_id).unwrap();
                        // This function will only be called after setup finishes
                        if SetupResult::try_read_attribute(&env).is_err() {
                            panic!("Failed to find SetupResult attribute after setup. Cancelling test function.");
                        }
                        task_fn(env)
                    }
                };
                timed(
                    Plan::Leaf {
                        task: Box::from(subproc(task_id, closure, ctx)),
                    },
                    ctx.timeout_per_test,
                    None,
                    ctx,
                )
            }
        }
    }
}

pub struct SystemTestGroup {
    setup: Option<Box<dyn PotSetupFn>>,
    tests: Vec<SystemTestSubGroup>,
    timeout_per_test: Option<Duration>,
    overall_timeout: Option<Duration>,
    with_farm: bool,
}

impl Default for SystemTestGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl Plan<Box<dyn Task>> {
    fn root_task_id(&self) -> TaskId {
        match self {
            Plan::Supervised { supervisor, .. } => supervisor.task_id(),
            Plan::Leaf { task } => task.task_id(),
        }
    }
}

impl SystemTestGroup {
    pub fn new() -> Self {
        Self {
            setup: Default::default(),
            tests: Default::default(),
            timeout_per_test: None,
            overall_timeout: None,
            with_farm: true,
        }
    }

    fn effective_timeout_per_test(&self) -> Duration {
        self.timeout_per_test.unwrap_or(DEFAULT_TIMEOUT_PER_TEST)
    }

    pub fn without_farm(mut self) -> Self {
        self.with_farm = false;
        self
    }

    pub fn with_overall_timeout(mut self, overall_timeout: Duration) -> Self {
        self.overall_timeout = Some(overall_timeout);
        self
    }

    pub fn with_setup<F: PotSetupFn>(mut self, setup: F) -> Self {
        self.setup = Some(Box::new(setup));
        self
    }

    pub fn add_test(mut self, test: TestFunction) -> Self {
        let task_id = TaskId::Test(String::from(test.name()));
        self.tests.push(SystemTestSubGroup::Singleton {
            task_fn: test.f(),
            task_id,
        });
        self
    }

    fn add_group(mut self, sub_group: SystemTestSubGroup, ordering: EvalOrder) -> Self {
        self.tests.push(match sub_group {
            SystemTestSubGroup::Multiple { tasks, .. } => {
                SystemTestSubGroup::Multiple { tasks, ordering }
            }
            _ => sub_group,
        });
        self
    }

    pub fn add_sequential(self, sub_group: SystemTestSubGroup) -> Self {
        self.add_group(sub_group, EvalOrder::Sequential)
    }

    pub fn add_parallel(self, sub_group: SystemTestSubGroup) -> Self {
        self.add_group(sub_group, EvalOrder::Parallel)
    }

    /// Add a subgroup with the specified minumal lifetime.
    ///
    /// Useful in experiments involving human interactions.
    pub fn add_group_with_minimal_lifetime(
        self,
        sub_group: SystemTestSubGroup,
        min_lifetime: Duration,
    ) -> Self {
        assert!(
            min_lifetime <= self.effective_timeout_per_test(),
            "min_lifetime of a SystemTestSubGroup cannot be greater than timeout_per_test"
        );
        if min_lifetime.is_zero() {
            // Optimization
            return self.add_group(sub_group, EvalOrder::Parallel);
        }
        let lifetime_guard_task = move |env: TestEnv| {
            info!(
                env.logger(),
                ">>> {LIFETIME_GUARD_TASK_PREFIX}task(min_lifetime={min_lifetime:?})"
            );
            std::thread::sleep(min_lifetime);
        };
        let lifetime_guard_task = TestFunction::new(
            &format!("{LIFETIME_GUARD_TASK_PREFIX}{}_sec", min_lifetime.as_secs()),
            lifetime_guard_task,
        );
        let lifetime_guard_sub_group = match sub_group {
            SystemTestSubGroup::Singleton { .. } => sub_group.add_test(lifetime_guard_task),
            SystemTestSubGroup::Multiple {
                tasks: _,
                ordering: EvalOrder::Parallel,
            } => sub_group.add_test(lifetime_guard_task),
            SystemTestSubGroup::Multiple {
                tasks: _,
                ordering: EvalOrder::Sequential,
            } => {
                todo!()
            }
        };
        self.add_group(lifetime_guard_sub_group, EvalOrder::Parallel)
    }

    /// Add a single task with the specified minimal lifetime.
    ///
    /// Useful in experiments involving human interactions.
    pub fn add_task_with_minimal_lifetime(
        self,
        task: TestFunction,
        min_lifetime: Duration,
    ) -> Self {
        let sub_group = SystemTestSubGroup::new().add_test(task);
        self.add_group_with_minimal_lifetime(sub_group, min_lifetime)
    }

    pub fn with_timeout_per_test(mut self, t: Duration) -> Self {
        self.timeout_per_test = Some(t);
        self
    }

    fn make_plan(self, rh: &Handle, group_ctx: GroupContext) -> Result<Plan<Box<dyn Task>>> {
        debug!(group_ctx.log(), "SystemTestGroup.make_plan");

        let mut compose_ctx = ComposeContext {
            rh,
            group_ctx: group_ctx.clone(),
            empty_task_counter: 0,
            logger: group_ctx.logger().clone(),
            timeout_per_test: self.effective_timeout_per_test(),
        };

        // The ID of the root task is needed outside this function for awaiting when the plan execution finishes.
        let keepalive_task_id = TaskId::Test(String::from(KEEPALIVE_TASK_NAME));
        let keepalive_task = if self.with_farm && !group_ctx.no_farm_keepalive {
            Box::from(subproc(
                keepalive_task_id.clone(),
                {
                    let logger = group_ctx.logger().clone();
                    let group_ctx = group_ctx.clone();
                    move || {
                        let group_ctx = group_ctx.clone();
                        debug!(logger, ">>> keepalive");
                        loop {
                            let group_ctx = group_ctx.clone();
                            if let Ok((group_setup, env)) =
                                get_or_create_env(group_ctx, keepalive_task_id.clone()).and_then(
                                    |env| GroupSetup::try_read_attribute(&env).map(|x| (x, env)),
                                )
                            {
                                let farm_url = env.get_farm_url().unwrap();
                                let farm = Farm::new(farm_url.clone(), env.logger());
                                let group_name = group_setup.farm_group_name;
                                if let Err(e) = farm.set_group_ttl(&group_name, GROUP_TTL) {
                                    panic!(
                                        "{}",
                                        format!(
                                            "Failed to keep group {} alive via endpoint {:?}: {:?}",
                                            group_name, farm_url, e
                                        )
                                    )
                                };
                                debug!(
                                    logger,
                                    "Group {} TTL set to +{:?} from now (Farm endpoint: {:?})",
                                    group_name,
                                    GROUP_TTL,
                                    farm_url
                                );
                            } else {
                                info!(logger, "Farm group not created yet.");
                            }
                            std::thread::sleep(KEEPALIVE_INTERVAL);
                        }
                    }
                },
                &mut compose_ctx,
            )) as Box<dyn Task>
        } else {
            Box::from(EmptyTask::new(keepalive_task_id)) as Box<dyn Task>
        };

        let setup_plan = {
            let logger = group_ctx.logger().clone();
            let group_ctx = group_ctx.clone();
            let setup_fn = self
                .setup
                .unwrap_or_else(|| panic!("setup function not specified for SystemTestGroup."));
            let setup_task = subproc(
                TaskId::Test(String::from(SETUP_TASK_NAME)),
                move || {
                    debug!(logger, ">>> setup_fn");
                    let env = get_setup_env(group_ctx);
                    setup_fn(env.clone());
                    SetupResult {}.write_attribute(&env);
                },
                &mut compose_ctx,
            );
            timed(
                Plan::Leaf {
                    task: Box::from(setup_task),
                },
                compose_ctx.timeout_per_test,
                None,
                &mut compose_ctx,
            )
        };

        // normal case: no debugkeepalive, overall timeout is active
        if !group_ctx.debug_keepalive {
            let plan = compose(
                Some(keepalive_task),
                EvalOrder::Sequential,
                vec![compose(
                    None,
                    EvalOrder::Sequential,
                    std::iter::once(setup_plan)
                        .chain(
                            self.tests
                                .into_iter()
                                .map(|sub_group| sub_group.into_plan(&mut compose_ctx)),
                        )
                        .collect(),
                    &mut compose_ctx,
                )],
                &mut compose_ctx,
            );

            let plan = Ok(compose(
                Some(Box::new(EmptyTask::new(TaskId::Test(
                    REPORT_TASK_NAME.to_string(),
                )))),
                EvalOrder::Sequential,
                vec![if let Some(overall_timeout) = self.overall_timeout {
                    timed(
                        plan,
                        overall_timeout,
                        Some(String::from("::group")),
                        &mut compose_ctx,
                    )
                } else {
                    plan
                }],
                &mut compose_ctx,
            ));
            return plan;
        }

        // otherwise: keepalive needs to be above report task. no overall timeout.
        let keepalive_plan: Plan<Box<dyn Task>> = Plan::Leaf {
            task: Box::new(DebugKeepaliveTask::new(
                TaskId::Test(String::from("debugKeepAliveTask")),
                group_ctx.log().clone(),
                compose_ctx.rh.clone(),
            )),
        };

        let plan = compose(
            Some(Box::new(EmptyTask::new(TaskId::Test(
                REPORT_TASK_NAME.to_string(),
            )))),
            EvalOrder::Sequential,
            vec![compose(
                None,
                EvalOrder::Sequential,
                std::iter::once(setup_plan)
                    .chain(
                        self.tests
                            .into_iter()
                            .map(|sub_group| sub_group.into_plan(&mut compose_ctx)),
                    )
                    .collect(),
                &mut compose_ctx,
            )],
            &mut compose_ctx,
        );

        Ok(compose(
            Some(keepalive_task),
            EvalOrder::Parallel,
            vec![plan, keepalive_plan],
            &mut compose_ctx,
        ))
    }

    pub fn execute(self) -> Result<Outcome> {
        // TODO: check preconditions:
        // 0. None of the test functions (modulo the setup function) have the literal name "setup"
        // 1. There exists at least one test after setup
        // 2. All sub-groups are non-empty
        // 3. The computed plan is sane (e.g., there are no timeout(timeout(x)) for some x)

        // Preconditions that are already being checked:
        // 1. CLI arguments are sane
        // 2. Test / setup functions are not specified more than once in the group
        let args = CliArgs::parse().validate()?;
        let is_parent_process = matches!(args.action, SystemTestsSubcommand::Run);

        let group_ctx = GroupContext::new(
            args.group_dir.path.clone(),
            args.subproc_id(),
            args.filter_tests,
            args.debug_keepalive,
            args.no_farm_keepalive,
            args.group_base_name,
        )?;
        if is_parent_process {
            let root_env = group_ctx.get_root_env().unwrap();
            FarmBaseUrl::new_or_default(args.farm_base_url).write_attribute(&root_env);
            if let Some(required_args) = args.required_host_features {
                required_args.write_attribute(&root_env);
            }
            if self.with_farm {
                root_env.create_group_setup(group_ctx.group_base_name.clone());
            }
            debug!(group_ctx.log(), "Created group context: {:?}", group_ctx);
        }
        let with_farm = self.with_farm;

        // create the runtime that lives until this variable is dropped.
        // Note: having only a runtime handle does not guarantee that the runtime is alive.
        let runtime: Runtime = {
            let cpus = num_cpus::get();
            info!(group_ctx.log(), "Number of CPUs {}", cpus);
            let workers = std::cmp::min(MAX_RUNTIME_THREADS, cpus);
            let blocking_threads = std::cmp::min(MAX_RUNTIME_BLOCKING_THREADS, cpus);
            info!(
                group_ctx.log(),
                "Set tokio runtime: worker_threads={}, blocking_threads={}",
                workers,
                blocking_threads
            );
            Builder::new_multi_thread()
                .worker_threads(workers)
                .max_blocking_threads(blocking_threads)
                .enable_all()
                .build()
                .unwrap()
        };

        let plan = self.make_plan(runtime.handle(), group_ctx.clone())?;
        if is_parent_process {
            info!(group_ctx.log(), "Generated plan: {:?}", plan);
        }

        let static_plan = plan.map(&|task| task.task_id());
        if is_parent_process {
            debug!(group_ctx.log(), "Generated static_plan: {:?}", &static_plan);
        }

        // create a task table, consuming the plan
        let mut table = TaskTable::new();
        let mut duplicate_tasks: Option<TaskId> = None;
        plan.flatten().into_iter().for_each(|task| {
            let tid = task.task_id();
            if table.insert(tid.clone(), task).is_some() {
                duplicate_tasks = Some(tid)
            }
        });
        if let Some(duplicate_task_id) = duplicate_tasks {
            bail!(SystemTestGroupError::PreconditionViolation {
                condition:
                    "Test function names must be unique across an entire SystemTestGroup instance"
                        .to_string(),
                counterexample: format!(
                    "test function name {} is specified more than once",
                    duplicate_task_id
                )
            })
        }
        if is_parent_process {
            debug!(group_ctx.log(), "Generated task table: {:?}", table);
        }

        // handle the sub-command
        match args.action {
            SystemTestsSubcommand::Run => {
                info!(
                    group_ctx.log(),
                    "Executing parent-process-specific code ..."
                );

                let action_graph = ActionGraph::from_plan(static_plan);
                info!(group_ctx.log(), "Generated action_graph");

                let mut task_scheduler = TaskScheduler {
                    scheduled_tasks: table,
                    action_graph,
                    running_tasks: BTreeMap::new(),
                    start_times: BTreeMap::new(),
                    end_times: BTreeMap::new(),
                    log: group_ctx.logger(),
                };
                info!(group_ctx.log(), "Generated task_scheduler");
                task_scheduler.execute(args.debug_keepalive);
                info!(group_ctx.log(), "Task scheduler has terminated.");

                // debug!(group_ctx.log(), "===== Debug Summary =====");
                // let ag_res = task_scheduler.action_graph;
                // for (node_index, (node, maybe_task_id)) in ag_res.task_iter().enumerate() {
                //     if maybe_task_id.is_some() {
                //         debug!(group_ctx.log(), "ag: node {:?}           task_id {:?}", node, maybe_task_id);
                //     }
                // }

                let report = task_scheduler.create_report();
                if !args.no_summary_report {
                    info!(group_ctx.log(), "JSON Report:\n{}", report);
                    info!(group_ctx.log(), "Report:\n{}", report.pretty_print());
                }

                if with_farm && !args.no_delete_farm_group {
                    Self::delete_farm_group(group_ctx.clone());
                }
                if report.failure.is_empty() {
                    Ok(Outcome::FromParentProcess(report))
                } else {
                    bail!(SystemTestGroupError::SystemTestFailure(report))
                }
            }
            SystemTestsSubcommand::InteractiveMode => {
                todo!()
            }
            SystemTestsSubcommand::SpawnChild { task_id, .. } => {
                info!(group_ctx.log(), "Executing sub-process-specific code ...");
                let my_task = table.get(&task_id).unwrap();
                my_task.execute().unwrap();
                Ok(Outcome::FromSubProcess)
            }
        }
    }

    pub fn execute_from_args(self) -> Result<()> {
        let outcome = self.execute();

        match outcome {
            Ok(Outcome::FromSubProcess) => Ok(()),
            Ok(Outcome::FromParentProcess(_)) => Ok(()),
            Err(e) => {
                // TODO: also print Kibana link in case of failure. This requires that the dyncamic
                // group name (e.g., distributed_mainnet_test_bin--1673213252002) is made available
                // to all SystemTestGroup instances, not only those used with Farm.
                bail!("Tests failed: {e:?}");
            }
        }
    }

    fn delete_farm_group(ctx: GroupContext) {
        info!(ctx.log(), "Deleting farm group.");
        let env = get_setup_env(ctx);
        let group_setup = GroupSetup::read_attribute(&env);
        let farm_url = env.get_farm_url().unwrap();
        let farm = Farm::new(farm_url, env.logger());
        let group_name = group_setup.farm_group_name;
        farm.delete_group(&group_name);
    }
}

fn print_report(ctx: &GroupContext, report: &SystemGroupSummary) {
    info!(ctx.log(), "JSON Report:\n{}", report);
    info!(ctx.log(), "\n{}", report.pretty_print());
    if let Ok(group_setup) = GroupSetup::try_read_attribute(&ctx.get_setup_env().unwrap()) {
        info!(
            ctx.log(),
            "See replica logs in Kibana: {}\n",
            kibana_link(&group_setup.farm_group_name)
        );
    };
}
