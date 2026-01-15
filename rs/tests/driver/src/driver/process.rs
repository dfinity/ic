use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use slog::{Logger, info};
use std::process::{Command, ExitStatus, Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command as AsyncCommand},
    select,
    sync::watch::{Receiver, channel},
    task::{self, JoinHandle},
};

pub trait KillFn: FnOnce() + Send + Sync {}
impl<T: FnOnce() + Send + Sync> KillFn for T {}

use crate::driver::event::TaskId;
pub struct Process {
    child: Child,
    stdout_jh: JoinHandle<()>,
    stderr_jh: JoinHandle<()>,
}

impl Process {
    pub async fn new(task_id: TaskId, cmd: Command, log: Logger) -> (Self, impl FnOnce()) {
        let mut cmd: AsyncCommand = cmd.into();
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // When the `Process` object is dropped, the child is sent a kill
        // signal.
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().expect("Spawning subprocess should succeed");

        let stdout = child.stdout.take().unwrap();
        let (kill_tx, kill_watch) = channel::<bool>(false);

        let stdout_jh = task::spawn(Self::listen_on_channel(
            kill_watch.clone(),
            task_id.clone(),
            log.clone(),
            ChannelName::StdOut,
            stdout,
        ));
        let stderr = child.stderr.take().unwrap();
        let stderr_jh = task::spawn(Self::listen_on_channel(
            kill_watch,
            task_id,
            log.clone(),
            ChannelName::StdErr,
            stderr,
        ));

        let self_ = Self {
            child,
            stdout_jh,
            stderr_jh,
        };

        let kill_signal = {
            let pid = Pid::from_raw(self_.child.id().unwrap() as i32);
            move || {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = kill_tx.send(true);
            }
        };

        (self_, kill_signal)
    }

    /// Waits for stdout/err to be closed. Then waits for the child process to
    /// exit and returns the corresponding ExitStatus.
    pub async fn block_on_exit(self) -> std::io::Result<ExitStatus> {
        let mut child = self.child;
        // The listeners should not return with an error, so it should be safe
        // to unwrap().
        self.stdout_jh.await.unwrap();
        self.stderr_jh.await.unwrap();
        child.wait().await
    }

    async fn listen_on_channel<R>(
        mut kill_watch: Receiver<bool>,
        task_id: TaskId,
        log: Logger,
        channel_tag: ChannelName,
        src: R,
    ) where
        R: AsyncRead + Unpin,
    {
        let buffered_reader = BufReader::new(src);
        let mut lines = buffered_reader.lines();
        loop {
            select! {
                line_res = lines.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            let task_id: String = format!("{task_id}");
                            let output_channel: String = format!("{channel_tag:?}");
                            info!(log, "{}", line; "task_id" => task_id, "output_channel" => output_channel)
                        }
                        Ok(None) => break,
                        Err(e) => eprintln!("listen_on_channel(): {e:?}"),
                    }
                }
                _ = kill_watch.changed() => {
                    info!(log, "({}|{:?}): Kill received.", task_id, channel_tag);
                    return;
                }
            }
        }
        info!(log, "({}|{:?}): Channel has closed.", task_id, channel_tag);
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ChannelName {
    StdOut,
    StdErr,
}
