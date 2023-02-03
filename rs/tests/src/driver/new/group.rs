#![allow(dead_code)]
#[rustfmt::skip]

use std::path::PathBuf;

use crate::driver::{
    farm::Farm,
    new::{
        action_graph::ActionGraph,
        context::{GroupContext, ProcessContext},
        dsl::{SubprocessFn, TestFunction},
        event::{
            BroadcastingEventSubscriberFactory, Event, EventBroadcaster, EventPayload, TaskId,
        },
        plan::{EvalOrder, Plan},
        process::ProcessEventPayload,
        report::{
            FarmGroupReport, Outcome, SystemTestGroupError, SystemTestGroupReport,
            TargetFunctionFailure, TargetFunctionSuccess,
        },
        subprocess_ipc::LogServer,
        task::EmptyTask,
        task_scheduler::{new_task_scheduler, TaskTable},
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
use tokio::runtime::{Handle, Runtime};

use crate::driver::new::constants::{kibana_link, GROUP_TTL, KEEPALIVE_INTERVAL};
use crate::driver::new::{subprocess_task::SubprocessTask, task::Task, timeout::TimeoutTask};
use std::{
    iter::once,
    sync::Arc,
    time::{Duration, SystemTime},
};

use slog::{debug, info, trace, warn, Logger};

#[derive(Parser, Debug)]
pub struct CliArgs {
    #[clap(flatten)]
    group_dir: GroupDir,

    #[clap(subcommand)]
    pub action: SystemTestsSubcommand,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        // nothing to validate at the moment
        Ok(self)
    }

    /// A convenience method to get the task id of this subprocess, *if* it is in fact a
    /// subprocess.
    fn subproc_id(&self) -> Option<(TaskId, u32)> {
        match &self.action {
            SystemTestsSubcommand::SpawnChild {
                task_id,
                parent_pid,
            } => Some((task_id.clone(), *parent_pid)),
            _ => None,
        }
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
    path: PathBuf,
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
    SpawnChild { task_id: TaskId, parent_pid: u32 },
}

const DEFAULT_TIMEOUT_PER_TEST: Duration = Duration::from_secs(60 * 10); // 10 minutes
const DEFAULT_OVERALL_TIMEOUT: Duration = Duration::from_secs(60 * 10); // 10 minutes

const ROOT_TASK_NAME: &str = "root";
const KEEPALIVE_TASK_NAME: &str = "keepalive";
const SETUP_TASK_NAME: &str = "setup";
const LIFETIME_GUARD_TASK_PREFIX: &str = "lifetime_guard_";

#[derive(Deserialize, Serialize)]
struct SetupResult;

impl TestEnvAttribute for SetupResult {
    fn attribute_name() -> String {
        String::from("setup_succeeded")
    }
}

fn is_task_visible_to_user(task_id: &TaskId) -> bool {
    matches!(task_id, TaskId::Test(task_name) if task_name.ne(ROOT_TASK_NAME) && task_name.ne(KEEPALIVE_TASK_NAME) && !task_name.starts_with(LIFETIME_GUARD_TASK_PREFIX) && !task_name.starts_with("dummy("))
}

/// A shortcut to represent the type of an event subscriber
pub type Subs = Arc<dyn BroadcastingEventSubscriberFactory>;

pub struct ComposeContext<'a> {
    rh: &'a Handle,
    group_ctx: GroupContext,
    empty_task_counter: u64,
    subs: Subs,
    logger: Logger,
    timeout_per_test: Duration,
}

fn subproc(
    task_id: TaskId,
    target_fn: impl SubprocessFn,
    ctx: &mut ComposeContext,
) -> SubprocessTask {
    trace!(ctx.group_ctx.log(), "subproc(task_name={})", &task_id);
    SubprocessTask::new(
        task_id,
        ctx.rh.clone(),
        target_fn,
        ctx.group_ctx.clone(),
        ctx.subs.clone(),
    )
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
        ctx.subs.clone(),
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
            let empty_task = Box::from(EmptyTask::new(
                ctx.subs.clone(),
                TaskId::Test(format!("dummy({})", ctx.empty_task_counter)),
            ));
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
            SystemTestSubGroup::Singleton { task_fn, task_id } => {
                let logger = ctx.logger.clone();
                let task_id = task_id;
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
                let task = subproc(task_id, closure, ctx);
                timed(
                    Plan::Leaf {
                        task: Box::from(task),
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

    fn effective_overall_timeout(&self) -> Duration {
        self.overall_timeout.unwrap_or(DEFAULT_OVERALL_TIMEOUT)
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
        assert!(
            min_lifetime <= self.effective_overall_timeout(),
            "min_lifetime of a SystemTestSubGroup cannot be greater than overall_timeout"
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

    /// Add a single task with the specified minumal lifetime.
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

    fn make_plan(
        self,
        rh: &Handle,
        group_ctx: GroupContext,
        subs: Subs,
    ) -> Result<Plan<Box<dyn Task>>> {
        debug!(group_ctx.log(), "SystemTestGroup.make_plan");

        let effective_overall_timeout = self.effective_overall_timeout();

        let mut compose_ctx = ComposeContext {
            rh,
            group_ctx: group_ctx.clone(),
            empty_task_counter: 0,
            subs: subs.clone(),
            logger: group_ctx.logger().clone(),
            timeout_per_test: self.effective_timeout_per_test(),
        };

        // The ID of the root task is needed outside this function for awaiting when the plan execution finishes.
        let keepalive_task_id = TaskId::Test(String::from(KEEPALIVE_TASK_NAME));
        let keepalive_task = if self.with_farm {
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
                                info!(logger, "Farm group not created (did you forget to call env.ensure_group_setup_created()?)");
                            }
                            std::thread::sleep(KEEPALIVE_INTERVAL);
                        }
                    }
                },
                &mut compose_ctx,
            )) as Box<dyn Task>
        } else {
            Box::from(EmptyTask::new(subs.clone(), keepalive_task_id)) as Box<dyn Task>
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
        Ok(compose(
            Some(Box::new(EmptyTask::new(
                subs.clone(),
                TaskId::Test(ROOT_TASK_NAME.to_string()),
            ))),
            EvalOrder::Sequential,
            vec![timed(
                plan,
                effective_overall_timeout,
                Some(String::from("::group")),
                &mut compose_ctx,
            )],
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

        let group_ctx = GroupContext::new(args.group_dir.path.clone(), args.subproc_id())?;
        if is_parent_process {
            debug!(group_ctx.log(), "Created group context: {:?}", group_ctx);
        }

        let broadcaster = Arc::new(EventBroadcaster::start());
        if is_parent_process {
            debug!(group_ctx.log(), "Created broadcaster");
        }

        // create the runtime that lives until this variable is dropped.
        // Note: having only a runtime handle does not guarantee that the runtime is alive.
        let runtime = Runtime::new().unwrap();

        let subs: Arc<dyn BroadcastingEventSubscriberFactory> = broadcaster.clone(); // a shallow copy - the broadcaster is shared!
        let plan = self.make_plan(runtime.handle(), group_ctx.clone(), subs)?;
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

                let log_server = Arc::new(LogServer::new(
                    group_ctx.log_socket_path(),
                    broadcaster.create_broadcasting_subscriber(),
                    group_ctx.logger(),
                )?);

                let log_server_jh = std::thread::spawn({
                    let log_server = log_server.clone();
                    move || log_server.receive_all_events()
                });

                let action_graph = ActionGraph::from_plan(static_plan);
                info!(group_ctx.log(), "Generated action_graph");

                let scheduler = new_task_scheduler(table, action_graph, group_ctx.logger());
                info!(group_ctx.log(), "Generated task_scheduler");

                broadcaster.subscribe(Box::new(scheduler));
                info!(
                    group_ctx.log(),
                    "Scheduler is now subscribed to broadcaster"
                );

                // subscribe to the root task's terminal events
                // Note: synchronization is done via a zero-capacity crossbeam channel
                let (terminal_event_sender, terminal_event_receiver) =
                    crossbeam_channel::bounded(0);

                broadcaster.subscribe(Box::new({
                    let group_ctx = group_ctx.clone();
                    let mut report = SystemTestGroupReport::default();
                    let mut is_root_completed = false;
                    move |event| {
                        log_event(group_ctx.log(), &event);
                        if let EventPayload::TaskSpawned { ref task_id } = event.what {
                            // 1. Write down the start time of a freshly-spawned task
                            // Note: This will be needed to compute the task's duration
                            debug!(
                                group_ctx.log(),
                                "Reporting on newly spawned task {}", task_id
                            );
                            report.set_test_start_time(task_id.clone());
                        };
                        if let EventPayload::TaskFailed {
                            ref task_id,
                            ref msg,
                        } = event.what
                        {
                            report.set_test_end_time(task_id.clone());
                            // 2. Handle failed tasks
                            if let TaskId::Timeout(timed_task_name) = task_id {
                                // 2.1. When a timeout task of a timed task fails, the timed task should be marked as "timed out"
                                // Note: Timeout tasks have no other purpose whatsoever
                                // report.set_test_as_timed_out(TaskId::Test(timed_task_id.clone()));
                                let timed_task_id = TaskId::Test(timed_task_name.clone());
                                report.set_test_as_timed_out(timed_task_id);
                                // Set the group timeout flag
                                report.set_group_timed_out();
                            } else {
                                // 2.2. When a regular (i.e., not Timeout) tasks fails, Write down its end time.
                                if is_task_visible_to_user(task_id) {
                                    if report.is_test_timed_out(task_id) || report.is_group_timed_out() {
                                        // 2.3. Use information from step 2.1 to detect if this task has timed out
                                        debug!(
                                            group_ctx.log(),
                                            "Reporting on timed out task {}", task_id
                                        );
                                        report.add_fail(TargetFunctionFailure::TimedOut {
                                            task_id: task_id.clone(),
                                            timeout: report.get_test_duration(task_id),
                                        });
                                    } else {
                                        // 2.4. Otherwise, this is a regular failure (i.e., the test function panicked)
                                        debug!(
                                            group_ctx.log(),
                                            "Reporting on failed task {}", task_id
                                        );
                                        report.add_fail(TargetFunctionFailure::Panicked {
                                            task_id: task_id.clone(),
                                            message: msg.clone(),
                                            runtime: report.get_test_duration(task_id),
                                        });
                                    }
                                } else {
                                    debug!(
                                        group_ctx.log(),
                                        "Skip reporting about completed auxiliary task {}", task_id
                                    );
                                }
                            }
                        } else if let EventPayload::TaskSubReport { task_id, sub_report } = event.clone().what {
                            // 3. Handle the sub-report generated by this task
                            report.set_test_sub_report(task_id, sub_report);
                        } else if let EventPayload::TaskStopped { ref task_id } = event.what {
                            report.set_test_end_time(task_id.clone());
                            if is_task_visible_to_user(task_id) {
                                // 4. Handle successfully completed tasks
                                // Note: we omit tasks that the user is not aware of in the report
                                debug!(
                                    group_ctx.log(),
                                    "Reporting on successfully completed task {}", task_id
                                );
                                report.add_succ(TargetFunctionSuccess {
                                    task_id: task_id.clone(),
                                    runtime: report.get_test_duration(task_id),
                                });
                            }
                        } else if let EventPayload::TaskCaughtPanic { ref task_id, ref msg } = event.what {
                            report.set_assert_failure_message(task_id.clone(), msg);
                        }
                        // else { non-terminal event }
                        match event.what {
                            EventPayload::TaskFailed { ref task_id, .. }
                            | EventPayload::TaskStopped { ref task_id, .. }
                                if task_id.name().eq(ROOT_TASK_NAME) =>
                            {
                                debug!(group_ctx.log(), "Detected root completion {:?} (awaiting all running tasks to complete)", event);
                                is_root_completed = true;
                            }
                            _ => (),
                        };
                        if is_root_completed && report.all_tasks_finished() {
                            // No more running tasks ==> send the report
                            debug!(group_ctx.log(), "All events completed. Sending the report ...");
                            terminal_event_sender.send(report.clone()).unwrap();
                        }
                    }
                }));

                // bootstrap the test driver
                broadcaster.broadcast(Event {
                    when: SystemTime::now(),
                    what: EventPayload::StartSchedule,
                });

                // await root task's final event and produce appropriate return code
                let mut report = terminal_event_receiver.recv().unwrap();

                if let Err(e) = log_server.shutdown() {
                    warn!(
                        group_ctx.log(),
                        "Error when shutting down log server: {e:?}"
                    );
                }

                if let Err(e) = log_server_jh.join() {
                    warn!(
                        group_ctx.log(),
                        "Error receiving all events from subprocess: {e:?}"
                    );
                }

                if report.is_failure_free() {
                    let setup_env = group_ctx.get_setup_env()?;
                    debug!(
                        group_ctx.log(),
                        "Obtained setup_env from disk: {:?}", setup_env
                    );
                    match GroupSetup::try_read_attribute(&setup_env) {
                        Ok(group_setup) => {
                            debug!(group_ctx.log(), "Group setup: {:?}", group_setup);
                            report.farm_group_report = Some(FarmGroupReport { group_setup });
                        }
                        Err(error) => {
                            debug!(group_ctx.log(), "Could not read group setup: {:?}", error);
                        }
                    };
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

        // this logger is only used in the parent process
        let logger = super::logger::new_stdout_logger();

        match outcome {
            Ok(Outcome::FromSubProcess) => Ok(()),
            Ok(Outcome::FromParentProcess(report)) => {
                if let Some(ref farm_group_report) = report.farm_group_report {
                    info!(
                        &logger,
                        "\n{report}\nSee replica logs in Kibana: {}",
                        kibana_link(&farm_group_report.group_setup.farm_group_name)
                    );
                } else {
                    info!(&logger, "\n{report}");
                }
                Ok(())
            }
            Err(failure_mode) => {
                // TODO: also print Kibana link in case of failure. This requires that the dyncamic group name (e.g., distributed_mainnet_test_bin--1673213252002) is made available to all SystemTestGroup instances, not only those used with Farm.
                warn!(logger, "{failure_mode}");
                bail!("Tests failed.")
            }
        }
    }
}

#[inline]
fn log_event(log: &Logger, e: &Event) {
    match &e.what {
        EventPayload::ProcessEvent {
            task_id,
            process_event,
        } => match process_event {
            ProcessEventPayload::OutputLine { channel_name, line } => {
                info!(log, "[{task_id}|{channel_name:?}] {line}");
            }
            ProcessEventPayload::ChannelClosed { channel_name } => {
                info!(log, "[{task_id}|{channel_name:?} closed] ");
            }
            ProcessEventPayload::Exited(exit_status) => {
                info!(log, "[{task_id} existed: {exit_status:?}] ");
            }
        },
        e => debug!(log, "Event: {e:?}"),
    }
}
