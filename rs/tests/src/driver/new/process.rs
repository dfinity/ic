use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use std::{
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command as AsyncCommand},
    task::{self, JoinHandle},
};

pub trait KillFn: FnOnce() + Send + Sync {}
impl<T: FnOnce() + Send + Sync> KillFn for T {}

use super::event::{Event, EventSubscriber, EventSubscriberFactory, TaskId};
pub struct Process {
    child: Child,
    stdout_jh: JoinHandle<()>,
    stderr_jh: JoinHandle<()>,
}

impl Process {
    pub async fn new(
        task_id: TaskId,
        cmd: Command,
        sub_fact: Arc<dyn EventSubscriberFactory>,
    ) -> (Self, impl FnOnce()) {
        let mut cmd: AsyncCommand = cmd.into();
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // When the `Process` object is dropped, the child is sent a kill
        // signal.
        cmd.kill_on_drop(true);
        let mut child = cmd.spawn().expect("Could not spawn child.");
        let stdout = child.stdout.take().unwrap();
        let stdout_jh = task::spawn(Self::listen_on_channel(
            task_id.clone(),
            sub_fact.create_subscriber(),
            ChannelName::StdOut,
            stdout,
        ));
        let stderr = child.stderr.take().unwrap();
        let stderr_jh = task::spawn(Self::listen_on_channel(
            task_id,
            sub_fact.create_subscriber(),
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
        task_id: TaskId,
        mut event_sub: Box<dyn EventSubscriber>,
        channel_tag: ChannelName,
        src: R,
    ) where
        R: AsyncRead + Unpin,
    {
        let buffered_reader = BufReader::new(src);
        let mut lines = buffered_reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => (event_sub)(ProcessEventPayload::output_line(
                    task_id.clone(),
                    channel_tag.clone(),
                    line,
                )),
                Ok(None) => break,
                Err(e) => eprintln!("listen_on_channel(): {:?}", e),
            }
        }
        (event_sub)(ProcessEventPayload::channel_closed(
            task_id.clone(),
            channel_tag,
        ));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessEventPayload {
    OutputLine {
        channel_name: ChannelName,
        line: String,
    },
    ChannelClosed {
        channel_name: ChannelName,
    },
    Exited(ExitStatus),
}

impl ProcessEventPayload {
    pub fn output_line(task_id: TaskId, channel_name: ChannelName, line: String) -> Event {
        Event::process_event(
            task_id,
            ProcessEventPayload::OutputLine { channel_name, line },
        )
    }

    pub fn channel_closed(task_id: TaskId, tag: ChannelName) -> Event {
        Event::process_event(
            task_id,
            ProcessEventPayload::ChannelClosed { channel_name: tag },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelName {
    StdOut,
    StdErr,
}

#[cfg(test)]
mod tests {
    use crate::driver::new::event::{EventPayload, EventSubscriber};

    use super::*;
    use crossbeam_channel::{unbounded, Sender};

    // A simple wrapper so that we can implement the EventSubscriberFactory
    // here.
    struct SubscriberFactorySender(Sender<Event>);

    impl EventSubscriberFactory for SubscriberFactorySender {
        fn create_subscriber(&self) -> Box<dyn EventSubscriber> {
            let new_sender = self.0.clone();

            Box::new(move |evt: Event| new_sender.send(evt).expect("Could not send event!"))
        }
    }

    #[test]
    fn can_capture_output_from_bash() {
        let r = tokio::runtime::Runtime::new().unwrap();
        let task_id = "proc".to_string();
        let (event_sender, event_recv) = unbounded();
        let event_sender = Arc::new(SubscriberFactorySender(event_sender));

        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        cmd.arg("for i in {1..10}; do echo $i; done;");

        let (p, _kill_signal) = r.block_on(Process::new(task_id, cmd, event_sender));
        let _exit_status = r.block_on(p.block_on_exit()).unwrap();

        let mut events: Vec<_> = vec![];
        while let Ok(e) = event_recv.recv() {
            events.push(e);
        }

        let original_length = events.len();
        let mut events: Vec<_> = events.into_iter().filter(|e| !is_close_event(e)).collect();
        // we expect two closing events in total
        assert_eq!(events.len(), original_length - 2);
        for i in (1..=10).rev() {
            assert!(is_line(
                events.pop().unwrap(),
                ChannelName::StdOut,
                &i.to_string()
            ));
        }
    }

    fn is_line(event: Event, expected_channel_name: ChannelName, expected_line: &str) -> bool {
        matches!(
            event.what,
            EventPayload::ProcessEvent {
                task_id: _,
                process_event: ProcessEventPayload::OutputLine {
                    channel_name,
                    line
                }
            } if channel_name == expected_channel_name && line == expected_line
        )
    }

    fn is_close_event(event: &Event) -> bool {
        matches!(
            event.what,
            EventPayload::ProcessEvent {
                task_id: _,
                process_event: ProcessEventPayload::ChannelClosed { channel_name: _ }
            }
        )
    }
}
