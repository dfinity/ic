#![allow(dead_code)]

use crate::driver::{
    new::{artifact_manager::ArtifactManager, logger},
    test_env::TestEnv,
};
use anyhow::{bail, Result};
use slog::Logger;
use std::{fs, path::PathBuf, time::SystemTime};

#[derive(Debug)]
pub struct GroupContext {
    pub exec_path: PathBuf,
    artifact_manager: ArtifactManager,
    logger: Logger,
}

impl GroupContext {
    pub fn new(group_dir: PathBuf) -> Result<Self> {
        println!("GroupContext.new");

        let exec_path = std::env::current_exe().expect("could not acquire parent process path");
        if !exec_path.is_file() {
            bail!("{:?} is not a file.", exec_path)
        }

        // The following should have the effect of "mkdir -p $group_dir"
        fs::create_dir_all(&group_dir)?;

        let logger = logger::new_stdout_logger();

        let artifact_manager = ArtifactManager {
            group_dir,
            logger: logger.clone(),
        };

        Ok(Self {
            exec_path,
            artifact_manager,
            logger,
        })
    }

    pub fn group_dir(&self) -> PathBuf {
        self.artifact_manager.group_dir.clone()
    }
}

#[derive(Debug, Clone)]
pub enum Command {
    RunGroup,
    RunTask { task_name: String },
}

#[derive(Debug)]
pub struct ProcessContext {
    pub group_context: GroupContext,
    pub constructed_at: SystemTime,
    pub command: Command,
    logger: Logger,
}

impl ProcessContext {
    pub fn new(group_context: GroupContext, command: Command) -> Result<Self> {
        println!("ProcessContex.new");

        let constructed_at = SystemTime::now();

        let logger = logger::new_stdout_logger();

        Ok(Self {
            group_context,
            constructed_at,
            command,
            logger,
        })
    }

    pub fn create_setup_env(&self) -> Result<TestEnv> {
        let setup_dir = self.group_context.artifact_manager.setup_dir()?;
        TestEnv::new(setup_dir, self.logger.clone())
    }

    pub fn create_test_env(&self, test_name: &str) -> Result<TestEnv> {
        let target_dir = self.group_context.artifact_manager.test_dir(test_name)?;
        let setup_dir = self.group_context.artifact_manager.setup_dir()?;
        TestEnv::fork_from(
            setup_dir.as_path(),
            target_dir.as_path(),
            self.logger.clone(),
        )
    }
}
