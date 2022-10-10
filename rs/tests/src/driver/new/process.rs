use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use std::{
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command as AsyncCommand},
    task::{self, JoinHandle},
};
pub struct Process {
    child: Child,
    signal_state: SignalState,
    stdout_jh: JoinHandle<()>,
    stderr_jh: JoinHandle<()>,
}

impl Process {
    pub async fn new(
        cmd: Command,
        sub: impl EventSubscriber<Payload = ProcessEvent> + 'static,
    ) -> Self {
        let sub = Arc::new(sub);
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
            sub.clone(),
            ChannelName::StdOut,
            stdout,
        ));
        let stderr = child.stderr.take().unwrap();
        let stderr_jh = task::spawn(Self::listen_on_channel(sub, ChannelName::StdErr, stderr));

        Self {
            child,
            signal_state: SignalState::NotSignalled,
            stdout_jh,
            stderr_jh,
        }
    }

    pub fn kill(&mut self) {
        if self.signal_state == SignalState::NotSignalled {
            let pid = Pid::from_raw(self.child.id().unwrap() as i32);
            kill(pid, Signal::SIGKILL).expect("Could not send kill signal!");
            self.signal_state = SignalState::KillSent;
        }
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

    async fn listen_on_channel<S, R>(sub: Arc<S>, channel_tag: ChannelName, src: R)
    where
        S: EventSubscriber<Payload = ProcessEvent>,
        R: AsyncRead + Unpin,
    {
        let buffered_reader = BufReader::new(src);
        let mut lines = buffered_reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => sub.send(ProcessEvent::output_line(channel_tag.clone(), line)),
                Ok(None) => break,
                Err(e) => eprintln!("listen_on_channel(): {:?}", e),
            }
        }
        sub.send(ProcessEvent::channel_closed(channel_tag));
    }
}

pub trait EventSubscriber: Send + Sync {
    type Payload;

    fn send(&self, ev: Event<Self::Payload>);
}

#[derive(Debug)]
pub enum ProcessEvent {
    OutputLine {
        channel_name: ChannelName,
        line: String,
    },
    ChannelClosed {
        channel_name: ChannelName,
    },
    Exited(ExitStatus),
}

impl ProcessEvent {
    pub fn output_line(tag: ChannelName, line: String) -> Event<Self> {
        Event::new(ProcessEvent::OutputLine {
            channel_name: tag,
            line,
        })
    }

    pub fn channel_closed(tag: ChannelName) -> Event<Self> {
        Event::new(ProcessEvent::ChannelClosed { channel_name: tag })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelName {
    StdOut,
    StdErr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalState {
    NotSignalled,
    KillSent,
}

#[derive(Debug)]
pub struct Event<T> {
    pub when: SystemTime,
    pub what: T,
}

impl<T> Event<T> {
    pub fn new(what: T) -> Self {
        Self {
            when: SystemTime::now(),
            what,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type PEvent = Event<ProcessEvent>;
    #[derive(Clone)]
    struct EventSink(pub Arc<Mutex<Vec<PEvent>>>);

    impl EventSubscriber for EventSink {
        type Payload = ProcessEvent;

        fn send(&self, ev: super::Event<Self::Payload>) {
            let mut sink = self.0.lock().unwrap();
            sink.push(ev);
        }
    }

    #[test]
    fn can_capture_output_from_bash() {
        let r = tokio::runtime::Runtime::new().unwrap();

        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        cmd.arg("for i in {1..10}; do echo $i; done;");

        let sub = EventSink(Arc::new(Mutex::new(vec![])));
        let p = r.block_on(Process::new(cmd, sub.clone()));
        let _exit_status = r.block_on(p.block_on_exit()).unwrap();

        let mut events: Vec<_> = {
            let mut lock = sub.0.lock().unwrap();
            std::mem::take(lock.as_mut())
        };

        assert!(is_close_event(events.pop().unwrap()));
        assert!(is_close_event(events.pop().unwrap()));
        for i in (1..=10).rev() {
            assert!(is_line(
                events.pop().unwrap(),
                ChannelName::StdOut,
                &i.to_string()
            ));
        }
    }

    fn is_line(value: PEvent, expected_channel_name: ChannelName, expected_line: &str) -> bool {
        if let ProcessEvent::OutputLine { channel_name, line } = value.what {
            if channel_name == expected_channel_name && line == expected_line {
                return true;
            }
        }
        false
    }

    fn is_close_event(value: PEvent) -> bool {
        if let ProcessEvent::ChannelClosed { channel_name: _ } = value.what {
            return true;
        }
        false
    }
}
