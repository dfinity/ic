#![allow(dead_code)]
#[rustfmt::skip]

use std::{
    collections::{btree_map::Entry, BTreeMap},
    path::PathBuf,
};

use std::fs;

use crate::driver::{
    driver_setup::IcSetup,
    new::{
        constants,
        context::{Command, GroupContext, ProcessContext},
        dsl::TestFunction,
        task_scheduler::TaskSchedule,
    },
    pot_dsl::{PotSetupFn, SysTestFn},
    test_setup::GroupSetup,
};
use crate::driver::{farm::Farm, test_env::TestEnvAttribute};

use crate::driver::farm::GroupSpec;

use slog::Logger;

use anyhow::Result;
use clap::Parser;
use reqwest::Url;

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

    fn prepare_group(group_setup: &GroupSetup, logger: Logger) -> Result<()> {
        println!("SystemTestGroup.prepare_group");

        let farm_base_url = Url::parse(constants::DEFAULT_FARM_BASE_URL).expect("can't fail");
        let farm = Farm::new(farm_base_url, logger);

        let group_spec = GroupSpec {
            vm_allocation: None,
            required_host_features: vec![],
            preferred_network: None,
        };

        Ok(farm.create_group(
            &group_setup.farm_group_name,
            group_setup.group_timeout,
            group_spec,
        )?)
    }

    fn finalize_group(group_setup: &GroupSetup, logger: Logger) -> Result<()> {
        println!("SystemTestGroup.finalize_group");

        let farm_base_url = Url::parse(constants::DEFAULT_FARM_BASE_URL).expect("can't fail");
        let farm = Farm::new(farm_base_url, logger);

        Ok(farm.delete_group(&group_setup.farm_group_name)?)
    }

    pub fn execute_from_args(&mut self) -> Result<()> {
        println!("SystemTestGroup.execute_from_args");
        let args = CliArgs::parse().validate()?;
        println!("Parsed args as: {:?}", args);

        let group_ctx = GroupContext::new(args.group_dir.path)?;
        match args.action {
            SystemTestsSubcommand::Run => {
                println!("Run parent");
                // obtain driver context
                // the setup is always executed first
                let mut schedule = TaskSchedule::new(group_ctx).append("::setup");
                schedule = self
                    .tests
                    .keys()
                    .fold(schedule, |schedule, name| schedule.append(name))
                    .append("::finalize");
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
                let process_ctx = ProcessContext::new(
                    group_ctx,
                    Command::RunTask {
                        task_name: task_name.clone(),
                    },
                )?;
                match task_name.as_str() {
                    "::setup" => {
                        println!("Child: running setup");
                        // Step 1: create an independent driver context for this process
                        let env = process_ctx.group_context.create_setup_env()?;

                        fs::create_dir_all(&env.get_path("ssh/authorized_pub_keys"))?;

                        // Step 2: invoke InternetComputer interfaces
                        let ic_setup = IcSetup::from_bazel_env();
                        ic_setup.write_attribute(&env);

                        let group_setup = GroupSetup::from_bazel_env();
                        group_setup.write_attribute(&env);

                        // Create group via Farm API
                        Self::prepare_group(&group_setup, process_ctx.logger()).unwrap();

                        // Step 3: call user-defined setup function
                        let setup_fn = self.consume_setup();
                        setup_fn(env);
                    }
                    "::finalize" => {
                        // let group_setup = GroupSetup::from_bazel_env();
                        // group_setup.write_attribute(&env);
                        let finalize_env = process_ctx.group_context.create_finalize_env()?;
                        let group_setup = GroupSetup::read_attribute(&finalize_env);
                        Self::finalize_group(&group_setup, process_ctx.logger()).unwrap();
                    }
                    test_name => {
                        println!("Child: running test");
                        // Step 1: create fresh test_env using setup_env as template
                        let env = process_ctx.group_context.create_test_env(test_name)?;
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
