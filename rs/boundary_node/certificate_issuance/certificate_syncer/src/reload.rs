use std::{fs, path::PathBuf, time::Instant};

use anyhow::{Context as AnyhowContext, Error};
use async_trait::async_trait;
use nix::{
    sys::signal::{kill as send_signal, Signal},
    unistd::Pid,
};
use opentelemetry::KeyValue;
use tracing::info;

use crate::metrics::{MetricParams, WithMetrics};

#[async_trait]
pub trait Reload: Sync + Send {
    async fn reload(&self) -> Result<(), Error>;
}

pub struct WithReload<T, R: Reload>(pub T, pub R);

pub struct Reloader {
    pid_path: PathBuf,
    signal: Signal,
}

impl Reloader {
    pub fn new(pid_path: PathBuf, signal: Signal) -> Self {
        Self { pid_path, signal }
    }
}

#[async_trait]
impl Reload for Reloader {
    async fn reload(&self) -> Result<(), Error> {
        let pid = fs::read_to_string(self.pid_path.clone()).context("failed to read pid file")?;
        let pid = pid.trim().parse::<i32>().context("failed to parse pid")?;
        let pid = Pid::from_raw(pid);

        send_signal(pid, self.signal)?;

        Ok(())
    }
}

#[async_trait]
impl<T: Reload> Reload for WithMetrics<T> {
    async fn reload(&self) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.reload().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}
