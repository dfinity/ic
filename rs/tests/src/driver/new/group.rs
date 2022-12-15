#![allow(dead_code)]
#[rustfmt::skip]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    path::PathBuf,
};

use crate::driver::{
    new::{
        action_graph::ActionGraph,
        dsl::SubprocessFn,
        event::{BroadcastingEventSubscriberFactory, Event, EventBroadcaster, EventPayload},
        plan::{EvalOrder, Plan},
        task::EmptyTask,
        task_scheduler::{new_task_scheduler, TaskTable},
    },
    test_env::TestEnv,
};
use crate::driver::{
    new::{
        context::{GroupContext, ProcessContext},
        dsl::TestFunction,
    },
    pot_dsl::{PotSetupFn, SysTestFn},
};

use anyhow::{bail, Result};
use clap::Parser;
use tokio::runtime::{Handle, Runtime};

use crate::driver::new::{subprocess_task::SubprocessTask, task::Task, timeout::TimeoutTask};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use slog::{debug, info, Logger};

const PLAN_STRATEGY_FLAT: bool = true;

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
}

/// A shortcut to represent the type of an event subscriber
pub type Subs = Arc<dyn BroadcastingEventSubscriberFactory>;

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
    SpawnChild {
        task_name: String,
        cord: PathBuf,
        log_stream: PathBuf,
    },
}

const DEFAULT_TIMEOUT_PER_TEST: Duration = Duration::from_secs(60 * 10); // 10 minutes

pub struct SystemTestGroup {
    setup: Option<Box<dyn PotSetupFn>>,
    tests: BTreeMap<String, Box<dyn SysTestFn>>,
    timeout_per_test: Option<Duration>,
}

impl Default for SystemTestGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl Plan<Box<dyn Task>> {
    fn root_task_id(&self) -> String {
        match self {
            Plan::Supervised { supervisor, .. } => supervisor.task_id(),
            Plan::Leaf { task } => task.task_id(),
        }
    }
}

// The ID of the top-level supervisor task in the generated Plan<Task> structure.
const ROOT_TASK_ID: &str = "root_task";

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
        let test_name = String::from(test.name());

        if let e @ Entry::Vacant(_) = self.tests.entry(test_name.clone()) {
            e.or_insert_with(|| Box::new(test.f()));
        } else {
            panic!("redeclared test with name '{}'", test_name)
        }
        self
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

        let timeout_per_test = self.timeout_per_test.unwrap_or(DEFAULT_TIMEOUT_PER_TEST);

        struct ComposeContext {
            group_ctx: GroupContext,
            empty_root_task_counter: usize,
            subs: Subs,
            logger: Logger,
        }

        let mut compose_ctx = ComposeContext {
            group_ctx: group_ctx.clone(),
            empty_root_task_counter: 0,
            subs: subs.clone(),
            logger: group_ctx.logger().clone(),
        };

        fn subproc(
            rh: &Handle,
            task_name: &str,
            target_fn: impl SubprocessFn,
            ctx: &mut ComposeContext,
        ) -> SubprocessTask {
            debug!(ctx.group_ctx.log(), "SystemTestGroup.make_plan.subproc");
            SubprocessTask::new(
                task_name.to_string(),
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
            debug!(ctx.logger, "SystemTestGroup.make_plan.timed");
            let timeout_task = TimeoutTask::new(
                rh.clone(),
                timeout,
                ctx.subs.clone(),
                format!("timeout_of_{}", plan.root_task_id()),
            );
            Plan::Supervised {
                supervisor: Box::from(timeout_task) as Box<dyn Task>,
                ordering: EvalOrder::Sequential, // the order is irrelevant since there is only one child
                children: vec![plan],
            }
        }

        // The ID of the root task is needed outside this function for awaiting when the plan execution finishes.
        let root_task =
            Box::from(EmptyTask::new(subs.clone(), ROOT_TASK_ID.to_string())) as Box<dyn Task>;

        fn compose(
            root_task: Option<Box<dyn Task>>,
            ordering: EvalOrder,
            children: Vec<Plan<Box<dyn Task>>>,
            ctx: &mut ComposeContext,
        ) -> Plan<Box<dyn Task>> {
            let root_task = match root_task {
                Some(task) => task,
                None => {
                    let empty_root_task = Box::from(EmptyTask::new(
                        ctx.subs.clone(),
                        format!("empty_root_task_{}", ctx.empty_root_task_counter),
                    ));
                    ctx.empty_root_task_counter += 1;
                    empty_root_task
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
            debug!(ctx.logger, "SystemTestGroup.make_plan.compose_par");
            compose(root_task, EvalOrder::Parallel, vec![first, second], ctx)
        }

        fn compose_seq(
            root_task: Option<Box<dyn Task>>,
            first: Plan<Box<dyn Task>>,
            second: Plan<Box<dyn Task>>,
            ctx: &mut ComposeContext,
        ) -> Plan<Box<dyn Task>> {
            debug!(ctx.logger, "SystemTestGroup.make_plan.compose_seq");
            compose(root_task, EvalOrder::Sequential, vec![first, second], ctx)
        }

        fn get_env(gctx: GroupContext, task_id: String) -> TestEnv {
            info!(gctx.log(), "SystemTestGroup.make_plan.get_env");
            let process_ctx = ProcessContext::new(gctx, task_id).unwrap();
            process_ctx.group_context.create_setup_env().unwrap()
        }

        let setup_plan = {
            let logger = group_ctx.logger().clone();
            let task_name = "setup";
            let group_ctx = group_ctx.clone();
            let setup_fn = self.setup.unwrap();
            let setup_task = subproc(
                rh,
                task_name,
                move || {
                    debug!(logger, ">>> setup_fn");
                    let env = get_env(group_ctx, "setup".to_string());
                    setup_fn(env)
                },
                &mut compose_ctx,
            );
            timed(
                rh,
                Plan::Leaf {
                    task: Box::from(setup_task),
                },
                timeout_per_test,
                &mut compose_ctx,
            )
        };

        let plan = if PLAN_STRATEGY_FLAT {
            compose(
                Some(root_task),
                EvalOrder::Sequential,
                std::iter::once(setup_plan)
                    .chain(self.tests.into_iter().map(|(task_name, target_fn)| {
                        let logger = group_ctx.logger().clone();
                        let task_name = task_name;
                        let closure = {
                            let task_name = task_name.clone();
                            let group_ctx = group_ctx.clone();
                            move || {
                                debug!(logger, ">>> task_fn({})", task_name);
                                let env = get_env(group_ctx, task_name);
                                target_fn(env)
                            }
                        };
                        let task = subproc(rh, &task_name, closure, &mut compose_ctx);
                        timed(
                            rh,
                            Plan::Leaf {
                                task: Box::from(task),
                            },
                            timeout_per_test,
                            &mut compose_ctx,
                        )
                    }))
                    .collect::<Vec<Plan<Box<dyn Task>>>>(),
                &mut compose_ctx,
            )
        } else {
            let group_ctx = group_ctx.clone();
            let plan = self
                .tests
                .into_iter()
                .fold(setup_plan, |p, (task_name, target_fn)| {
                    let closure = {
                        let logger = group_ctx.logger().clone();
                        let group_ctx = group_ctx.clone();
                        let task_name = task_name.clone();
                        move || {
                            debug!(logger, ">>> task_fn({})", task_name);
                            let env = get_env(group_ctx, task_name);
                            target_fn(env)
                        }
                    };
                    let task = subproc(rh, &task_name, closure, &mut compose_ctx);
                    let new_plan = timed(
                        rh,
                        Plan::Leaf {
                            task: Box::from(task),
                        },
                        timeout_per_test,
                        &mut compose_ctx,
                    );
                    compose_seq(None, p, new_plan, &mut compose_ctx)
                });
            Plan::Supervised {
                supervisor: root_task,
                ordering: EvalOrder::Sequential, // the order is irrelevant since there is only one child
                children: vec![plan],
            }
        };

        Ok(plan)
    }

    pub fn execute_from_args(self) -> Result<()> {
        // Step 0
        let args = CliArgs::parse().validate()?;

        // Step 1
        let group_ctx = GroupContext::new(args.group_dir.path)?;
        info!(group_ctx.log(), "Created group context: {:?}", group_ctx);

        // Step 2
        let broadcaster = Arc::new(EventBroadcaster::start());
        info!(group_ctx.log(), "Created broadcaster");

        // Step 3 -- create the runtime that lives until this variable is dropped.
        // Note: having only a runtime handle does not guarantee that the runtime is alive.
        let runtime = Runtime::new().unwrap();

        // Step 4
        let subs: Arc<dyn BroadcastingEventSubscriberFactory> = broadcaster.clone(); // a shallow copy - the broadcaster is shared!
        let plan = self.make_plan(runtime.handle(), group_ctx.clone(), subs)?;
        info!(group_ctx.log(), "Generated plan: {:?}", plan);

        // Step 5
        let static_plan = plan.map(&|task| task.task_id());
        info!(group_ctx.log(), "Generated static_plan: {:?}", static_plan);

        // Step 6 -- create a task table, consuming the plan
        let mut table = TaskTable::new();
        plan.flatten().into_iter().for_each(|task| {
            table.insert(task.task_id(), task);
        });
        info!(group_ctx.log(), "Generated task table: {:?}", table);

        // Step 7 -- handle the sub-command
        match args.action {
            SystemTestsSubcommand::Run => {
                info!(
                    group_ctx.log(),
                    "Executing parent-process-specific code ..."
                );
                // Step A
                let action_graph = ActionGraph::from_plan(static_plan);
                info!(group_ctx.log(), "Generated action_graph");

                // Step B
                let scheduler = new_task_scheduler(table, action_graph, group_ctx.logger());
                info!(group_ctx.log(), "Generated task_scheduler");

                // Step C
                broadcaster.subscribe(Box::new(scheduler));
                info!(
                    group_ctx.log(),
                    "Scheduler is now subscribed to broadcaster"
                );

                // Step D -- subscribe to the root task's terminal events
                // Note: synchronization is done via a zero-capacity crossbeam channel
                let (terminal_event_sender, terminal_event_receiver) =
                    crossbeam_channel::bounded(0);

                #[derive(Clone, Debug)]
                struct SystemTestGroupReport {
                    num_failures: usize,
                }

                broadcaster.subscribe(Box::new({
                    let group_ctx = group_ctx.clone();
                    let mut report = SystemTestGroupReport { num_failures: 0 };
                    move |event| {
                        debug!(group_ctx.log(), "Considering event {:?}", event);
                        if let EventPayload::TaskFailed { .. } = event.what {
                            report.num_failures += 1;
                        };
                        match event.clone().what {
                            EventPayload::TaskFailed { task_id, .. }
                            | EventPayload::TaskStopped { task_id, .. }
                                if task_id == *ROOT_TASK_ID =>
                            {
                                debug!(group_ctx.log(), "Detected final event {:?}", event);
                                terminal_event_sender.send(report.clone()).unwrap();
                            }
                            _ => (),
                        };
                    }
                }));

                // Step E -- bootstrap the test driver
                broadcaster.broadcast(Event {
                    when: SystemTime::now(),
                    what: EventPayload::StartSchedule,
                });

                // Step F -- await root task's final event and produce appropriate return code
                let report = terminal_event_receiver.recv().unwrap();
                let msg = "Exiting parent process after receiving terminal event from root task";
                if report.num_failures > 0 {
                    info!(
                        group_ctx.log(),
                        "{} (exit code 1 as there were {} failure(s))", msg, report.num_failures
                    );
                    bail!(format!("{} tests failed", report.num_failures))
                } else {
                    info!(
                        group_ctx.log(),
                        "{} (all tasks succeeded ==> exit code 0)", msg
                    );
                    Ok(())
                }
            }
            SystemTestsSubcommand::InteractiveMode => {
                todo!()
            }
            SystemTestsSubcommand::SpawnChild {
                task_name,
                cord: _,
                log_stream: _,
            } => {
                info!(group_ctx.log(), "Executing sub-process-specific code ...");
                let my_task = table.get(&task_name).unwrap();
                my_task.execute().unwrap();
                Ok(())
            }
        }
    }
}
