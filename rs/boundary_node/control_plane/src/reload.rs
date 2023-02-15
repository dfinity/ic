use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Error};
use async_trait::async_trait;
use nix::{
    sys::signal::{kill as send_signal, Signal},
    unistd::Pid,
};

#[async_trait]
pub trait Reload: Sync + Send {
    async fn reload(&self) -> Result<(), Error>;
}

pub struct PidReloader {
    pid_path: PathBuf,
    signal: Signal,
}

impl PidReloader {
    pub fn new(pid_path: PathBuf, signal: Signal) -> Self {
        Self { pid_path, signal }
    }
}

#[async_trait]
impl Reload for PidReloader {
    async fn reload(&self) -> Result<(), Error> {
        let pid = fs::read_to_string(self.pid_path.clone()).context("failed to read pid file")?;
        let pid = pid.trim().parse::<i32>().context("failed to parse pid")?;
        let pid = Pid::from_raw(pid);

        send_signal(pid, self.signal)?;

        Ok(())
    }
}

pub struct SystemdReloader {
    bin_path: PathBuf,
    service: String,
    command: String,
}

impl SystemdReloader {
    pub fn new(bin_path: PathBuf, service: &str, command: &str) -> Self {
        Self {
            bin_path,
            service: service.into(),
            command: command.into(),
        }
    }
}

// SystemdReloader performs a reload of a service
// by invoking a restart via systemd service
#[async_trait]
impl Reload for SystemdReloader {
    async fn reload(&self) -> Result<(), Error> {
        let mut child = Command::new(&self.bin_path)
            .args([&self.command, &self.service])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        child.wait()?;

        Ok(())
    }
}

pub struct WithReload<T, R>(pub T, pub R);
