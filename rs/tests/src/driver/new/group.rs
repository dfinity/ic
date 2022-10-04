#![allow(dead_code)]
#[rustfmt::skip]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    path::PathBuf,
};

use crate::driver::{
    new::{
        context::{Command, GroupContext, ProcessContext},
        dsl::TestFunction,
        task_scheduler::TaskSchedule,
    },
    pot_dsl::{PotSetupFn, SysTestFn},
};
use anyhow::Result;
use clap::Parser;

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
        let test_name = String::from(test.name());
        if let e @ Entry::Vacant(_) = self.tests.entry(test_name.clone()) {
            e.or_insert_with(|| Box::new(test.f()));
        } else {
            panic!("redeclared test with name '{}'", test_name)
        }
        self
    }

    fn consume_test(&mut self, test_name: &str) -> Box<dyn SysTestFn> {
        let abc = &mut self.tests;
        abc.remove(test_name).unwrap()
    }

    fn consume_setup(&mut self) -> Box<dyn PotSetupFn> {
        let abc = &mut self.setup;
        abc.take().unwrap()
    }

    pub fn execute_from_args(&mut self) -> Result<()> {
        println!("SystemTestGroup.execute_from_args");
        let args = CliArgs::parse().validate()?;
        println!("Parsed args as: {:?}", args);

        let ctx = GroupContext::new(args.group_dir.path)?;
        match args.action {
            SystemTestsSubcommand::Run => {
                println!("Run parent");
                // obtain driver context
                // the setup is always executed first
                let mut schedule = TaskSchedule::new(ctx).append("::setup");
                schedule = self
                    .tests
                    .keys()
                    .fold(schedule, |schedule, name| schedule.append(name));
                schedule.execute();
            }
            SystemTestsSubcommand::InteractiveMode => {
                todo!();
            }
            // SpawnChild is an 'internal' command that is used to re-spawn the
            // binary.
            SystemTestsSubcommand::SpawnChild {
                task_name,
                cord: _,
                log_stream: _,
            } => {
                let child_ctx = ProcessContext::new(
                    ctx,
                    Command::RunTask {
                        task_name: task_name.clone(),
                    },
                )?;
                // let env =
                match task_name.as_str() {
                    "::setup" => {
                        println!("Child: running setup");
                        // Step 1: create an independent driver context for this process
                        let env = child_ctx.create_setup_env()?;
                        // Step 2: call user-defined setup function
                        let setup_fn = self.consume_setup();
                        setup_fn(env);
                    }
                    test_name => {
                        println!("Child: running test");
                        // Step 1: create fresh test_env using setup_env as template
                        let env = child_ctx.create_test_env(test_name)?;
                        // Step 2: call user-defined test function
                        let test_fn = self.consume_test(test_name);
                        test_fn(env);
                    }
                };
            }
        }

        Ok(()) // FIXME: decide what the semantics should be for the result of this function
    }
}
