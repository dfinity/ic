#![allow(dead_code)]

use crate::driver::{new::logger, test_env::TestEnv};
use anyhow::{bail, Result};
use slog::Logger;
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::constants;

use slog::info;

#[derive(Debug)]
pub struct GroupContext {
    pub exec_path: PathBuf,
    pub group_dir: PathBuf,
    logger: Logger,
}

impl GroupContext {
    pub fn new(group_dir: PathBuf) -> Result<Self> {
        let logger = logger::new_stdout_logger();
        println!("GroupContext.new");

        let exec_path = std::env::current_exe().expect("could not acquire parent process path");
        if !exec_path.is_file() {
            bail!("{:?} is not a file.", exec_path)
        }

        // The following should have the effect of "mkdir -p $group_dir"
        fs::create_dir_all(&group_dir)?;

        Ok(Self {
            exec_path,
            group_dir,
            logger,
        })
    }

    pub fn group_dir(&self) -> PathBuf {
        self.group_dir.clone()
    }

    fn dir_exists<P: AsRef<Path>>(path: P) -> bool {
        fs::read_dir(path.as_ref()).is_ok()
    }

    fn ensure_dir<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = self.group_dir.parent().unwrap().join(path.as_ref());
        if Self::dir_exists(path.clone()) {
            println!("GroupContext: directory already exists: {:?}", path);
        } else {
            println!("GroupContext: creating directory: {:?}", path);
            fs::create_dir_all(path)?;
        }
        Ok(())
    }

    /// Returns the path to the setup artifact directory,
    /// ensuring that the directory actually exists.
    pub fn get_or_create_setup_dir(&self) -> Result<PathBuf> {
        let root_env_path = self.group_dir.join(constants::ROOT_ENV_DIR);
        let setup_path = self.group_dir.join(constants::GROUP_SETUP_DIR);

        if root_env_path.is_dir() && !setup_path.exists() {
            // todo: this function should eventually just `fork` the root environment.
            TestEnv::shell_copy(&root_env_path, &setup_path)?;
        }

        self.ensure_dir(setup_path.clone()).map(|_| setup_path)
    }

    /// Returns the path to the artifact directory for this [test_name],
    /// ensuring that the directory actually exists.
    ///
    /// This function must be called after setup_dir
    pub fn get_or_create_test_dir(&self, test_name: &str) -> Result<PathBuf> {
        let setup_path = self.group_dir.join(constants::GROUP_SETUP_DIR);
        assert!(
            Self::dir_exists(setup_path.clone()),
            "test directory must be created after {:?}, which does not exist",
            setup_path
        );

        let test_path = self.group_dir.join(constants::TESTS_DIR).join(test_name);
        info!(self.logger, "Ensuring directory {:?} exists ...", test_path);
        self.ensure_dir(test_path.clone()).map(|_| test_path)
    }

    pub fn create_setup_env(&self) -> Result<TestEnv> {
        let setup_dir = self.get_or_create_setup_dir()?;
        TestEnv::new(setup_dir, self.logger.clone())
    }

    pub fn create_test_env(&self, test_name: &str) -> Result<TestEnv> {
        let target_dir = self.get_or_create_test_dir(test_name)?;
        let setup_dir = self.get_or_create_setup_dir()?;
        TestEnv::fork_from(
            setup_dir.as_path(),
            target_dir.as_path(),
            self.logger.clone(),
        )
    }

    pub fn create_finalize_env(&self) -> Result<TestEnv> {
        // TODO: check that setup exists
        let setup_dir = self.get_or_create_setup_dir()?;
        TestEnv::new(setup_dir, self.logger.clone())
    }

    pub fn logger(&self) -> Logger {
        self.logger.clone()
    }

    pub fn log(&self) -> &Logger {
        &self.logger
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
        println!("ProcessContext.new");

        let constructed_at = SystemTime::now();

        let logger = logger::new_stdout_logger();

        Ok(Self {
            group_context,
            constructed_at,
            command,
            logger,
        })
    }

    pub fn logger(&self) -> Logger {
        self.logger.clone()
    }
}
