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
            Outcome, SystemTestGroupError, SystemTestGroupReport, TargetFunctionFailure,
            TargetFunctionSuccess,
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

use anyhow::{bail, Result};
use clap::Parser;
use tokio::runtime::{Handle, Runtime};

use crate::driver::new::constants::{GROUP_TTL, KEEPALIVE_INTERVAL};
use crate::driver::new::{subprocess_task::SubprocessTask, task::Task, timeout::TimeoutTask};
use std::{
    iter::once,
    sync::Arc,
    time::{Duration, SystemTime},
};

use slog::{debug, info, warn, Logger};

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

const ROOT_TASK_NAME: &str = "root";
const SETUP_TASK_NAME: &str = "setup";

fn is_task_visible_to_user(task_id: &TaskId) -> bool {
    matches!(task_id, TaskId::Test(task_name) if task_name.ne(ROOT_TASK_NAME) && !task_name.starts_with("dummy("))
}

/// A shortcut to represent the type of an event subscriber
pub type Subs = Arc<dyn BroadcastingEventSubscriberFactory>;

pub struct ComposeContext {
    group_ctx: GroupContext,
    empty_task_counter: u64,
    subs: Subs,
    logger: Logger,
    timeout_per_test: Duration,
}

fn subproc(
    rh: &Handle,
    task_id: TaskId,
    target_fn: impl SubprocessFn,
    ctx: &mut ComposeContext,
) -> SubprocessTask {
    debug!(ctx.group_ctx.log(), "subproc(task_name={})", &task_id);
    SubprocessTask::new(
        task_id,
        rh.clone(),
        target_fn,
        ctx.group_ctx.clone(),
        ctx.subs.clone(),
    )
}

fn timed(
    rh: &Handle,
    plan: Plan<Box<dyn Task>>,
    timeout: Duration,
    ctx: &mut ComposeContext,
) -> Plan<Box<dyn Task>> {
    debug!(
        ctx.logger,
        "timed(plan={:?}, timeout={:?})", &plan, &timeout
    );
    let timeout_task = TimeoutTask::new(
        rh.clone(),
        timeout,
        ctx.subs.clone(),
        TaskId::Timeout(plan.root_task_id().name()),
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
    debug!(
        ctx.logger,
        "compose(root={:?}, ordering={:?}, children={:?})", &root_task, &ordering, &children
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
    info!(gctx.log(), "get_setup_env()");
    let process_ctx = ProcessContext::new(gctx, String::from(SETUP_TASK_NAME)).unwrap();
    process_ctx.group_context.create_setup_env().unwrap()
}

fn get_env(gctx: GroupContext, task_id: TaskId) -> Result<TestEnv> {
    info!(gctx.log(), "get_env(task_id={})", &task_id);
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
                    ordering: EvalOrder::Parallel, // TOOD: generalize this
                }
            }
        }
    }

    pub fn into_plan(self, rh: &Handle, ctx: &mut ComposeContext) -> Plan<Box<dyn Task>> {
        match self {
            SystemTestSubGroup::Multiple { tasks, ordering } => compose(
                None,
                ordering,
                tasks
                    .into_iter()
                    .map(|sub_group| sub_group.into_plan(rh, ctx))
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
                        // Assumption: this function will be called after setup finishes
                        let env = get_env(group_ctx, task_id).unwrap();
                        task_fn(env)
                    }
                };
                let task = subproc(rh, task_id, closure, ctx);
                timed(
                    rh,
                    Plan::Leaf {
                        task: Box::from(task),
                    },
                    ctx.timeout_per_test,
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
        }
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

    pub fn add_parallel(self, sub_group: SystemTestSubGroup) -> Self {
        self.add_group(sub_group, EvalOrder::Parallel)
    }

    pub fn add_sequential(self, sub_group: SystemTestSubGroup) -> Self {
        self.add_group(sub_group, EvalOrder::Sequential)
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
        info!(group_ctx.log(), "SystemTestGroup.make_plan");

        let mut compose_ctx = ComposeContext {
            group_ctx: group_ctx.clone(),
            empty_task_counter: 0,
            subs: subs.clone(),
            logger: group_ctx.logger().clone(),
            timeout_per_test: self.timeout_per_test.unwrap_or(DEFAULT_TIMEOUT_PER_TEST),
        };

        // The ID of the root task is needed outside this function for awaiting when the plan execution finishes.
        let root_task_id = TaskId::Test(String::from(ROOT_TASK_NAME));
        let root_task = Box::from(subproc(
            rh,
            root_task_id.clone(),
            {
                let logger = group_ctx.logger().clone();
                let group_ctx = group_ctx.clone();
                move || {
                    let group_ctx = group_ctx.clone();
                    debug!(logger, ">>> keepalive");
                    loop {
                        let group_ctx = group_ctx.clone();
                        let root_task_id = root_task_id.clone();
                        if let Ok((group_setup, env)) = get_env(group_ctx, root_task_id)
                            .and_then(|env| GroupSetup::try_read_attribute(&env).map(|x| (x, env)))
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
                            info!(
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
        )) as Box<dyn Task>;

        let setup_plan = {
            let logger = group_ctx.logger().clone();
            let group_ctx = group_ctx.clone();
            let setup_fn = self.setup.unwrap();
            let setup_task = subproc(
                rh,
                TaskId::Test(String::from(SETUP_TASK_NAME)),
                move || {
                    debug!(logger, ">>> setup_fn");
                    let env = get_setup_env(group_ctx);
                    setup_fn(env)
                },
                &mut compose_ctx,
            );
            timed(
                rh,
                Plan::Leaf {
                    task: Box::from(setup_task),
                },
                compose_ctx.timeout_per_test,
                &mut compose_ctx,
            )
        };

        let plan = compose(
            Some(root_task),
            EvalOrder::Sequential,
            std::iter::once(setup_plan)
                .chain(
                    self.tests
                        .into_iter()
                        .map(|sub_group| sub_group.into_plan(rh, &mut compose_ctx)),
                )
                .collect(),
            &mut compose_ctx,
        );
        Ok(plan)
    }

    pub fn execute(self) -> Result<Outcome> {
        // TODO: check preconditions:
        // 1. there exists at least one test after setup
        // 2. all sub-groups are non-empty

        let args = CliArgs::parse().validate()?;

        let group_ctx = GroupContext::new(args.group_dir.path.clone(), args.subproc_id())?;
        info!(group_ctx.log(), "Created group context: {:?}", group_ctx);

        let broadcaster = Arc::new(EventBroadcaster::start());
        info!(group_ctx.log(), "Created broadcaster");

        // create the runtime that lives until this variable is dropped.
        // Note: having only a runtime handle does not guarantee that the runtime is alive.
        let runtime = Runtime::new().unwrap();

        let subs: Arc<dyn BroadcastingEventSubscriberFactory> = broadcaster.clone(); // a shallow copy - the broadcaster is shared!
        let plan = self.make_plan(runtime.handle(), group_ctx.clone(), subs)?;
        info!(group_ctx.log(), "Generated plan: {:?}", plan);

        let static_plan = plan.map(&|task| task.task_id());
        info!(group_ctx.log(), "Generated static_plan: {:?}", static_plan);

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
        info!(group_ctx.log(), "Generated task table: {:?}", table);

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
                    move |event| {
                        log_event(group_ctx.log(), &event);
                        if let EventPayload::TaskSpawned { ref task_id } = event.what {
                            // 1. Write down the start time of a freshly-spawned task
                            // Note: This will be needed to compute the task's duration
                            report.set_test_start_time(task_id.clone());
                        };
                        if let EventPayload::TaskFailed {
                            ref task_id,
                            ref msg,
                        } = event.what
                        {
                            // 2. Handle failed tasks
                            if let TaskId::Timeout(timed_task_id) = task_id {
                                // 2.1. When a timeout task of a timed task fails, the timed task should be marked as "timed out"
                                // Note: Timeout tasks have no other purpose whatsoever
                                report.set_test_as_timed_out(TaskId::Test(timed_task_id.clone()));
                            } else {
                                // 2.2. When a regular (i.e., not Timeout) tasks fails, Write down its end time.
                                report.set_test_end_time(task_id.clone());
                                if is_task_visible_to_user(task_id) {
                                    if report.is_test_timed_out(task_id) {
                                        // 2.3. Use information from step 2.1 to detect if this task has timed out
                                        report.add_fail(TargetFunctionFailure::TimedOut {
                                            task_id: task_id.clone(),
                                            timeout: report.get_test_duration(task_id),
                                        });
                                    } else {
                                        // 2.4. Otherwise, this is a regular failure (i.e., the test function panicked)
                                        report.add_fail(TargetFunctionFailure::Panicked {
                                            task_id: task_id.clone(),
                                            message: msg.clone(),
                                            runtime: report.get_test_duration(task_id),
                                        });
                                    }
                                }
                            }
                        };
                        if let EventPayload::TaskStopped { ref task_id } = event.what {
                            if is_task_visible_to_user(task_id) {
                                // 3. Handle successfully completed tasks
                                // Note: we omit tasks that the user is not aware of in the report
                                report.set_test_end_time(task_id.clone());
                                report.add_succ(TargetFunctionSuccess {
                                    task_id: task_id.clone(),
                                    runtime: report.get_test_duration(task_id),
                                });
                            }
                        };
                        match event.what {
                            EventPayload::TaskFailed { ref task_id, .. }
                            | EventPayload::TaskStopped { ref task_id, .. }
                                if task_id.name().eq(ROOT_TASK_NAME) =>
                            {
                                debug!(group_ctx.log(), "Detected final event {:?}", event);
                                terminal_event_sender.send(report.clone()).unwrap();
                            }
                            _ => (),
                        };
                    }
                }));

                // bootstrap the test driver
                broadcaster.broadcast(Event {
                    when: SystemTime::now(),
                    what: EventPayload::StartSchedule,
                });

                // await root task's final event and produce appropriate return code
                let report = terminal_event_receiver.recv().unwrap();

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
                info!(&logger, "{report}");
                Ok(())
            }
            Err(failure_mode) => {
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
