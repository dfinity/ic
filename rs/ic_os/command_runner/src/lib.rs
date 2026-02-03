use async_trait::async_trait;
use std::io;
use std::process::{Command, ExitStatus, Output};

/// A trait for running commands.
///
/// This trait provides an abstraction over `std::process::Command` execution,
/// allowing for easy mocking in tests.
#[mockall::automock]
pub trait CommandRunner: Send + Sync {
    /// Executes the given command and returns its output.
    fn output(&self, command: &mut Command) -> io::Result<Output>;

    /// Executes the given command and returns its exit status.
    fn status(&self, command: &mut Command) -> io::Result<ExitStatus>;
}

/// Real implementation of `CommandRunner` that executes commands.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn output(&self, command: &mut Command) -> io::Result<Output> {
        command.output()
    }

    fn status(&self, command: &mut Command) -> io::Result<ExitStatus> {
        command.status()
    }
}

#[async_trait]
#[mockall::automock]
/// A trait for running commands asynchronously.
///
/// This trait provides an abstraction over `tokio::process::Command` execution,
/// allowing for easy mocking in tests.
pub trait AsyncCommandRunner: Send + Sync {
    /// Executes the given command and returns its output.
    async fn output(&self, command: &mut tokio::process::Command) -> io::Result<Output>;

    /// Executes the given command and returns its exit status.
    async fn status(&self, command: &mut tokio::process::Command) -> io::Result<ExitStatus>;
}

pub struct RealAsyncCommandRunner;

#[async_trait]
impl AsyncCommandRunner for RealAsyncCommandRunner {
    async fn output(&self, command: &mut tokio::process::Command) -> io::Result<Output> {
        command.output().await
    }

    async fn status(&self, command: &mut tokio::process::Command) -> io::Result<ExitStatus> {
        command.status().await
    }
}
