//! `ProcessManager` allows the orchestration of processes. Each process is
//! given a unique, user-defined identifier when calling `start_process()`.
//! Running processes can be killed using `kill_process()`. Output lines that
//! are printed on stdout or stderr are turned into corresponding events. The
//! events can be read by calling `take_stream()` on a ProcessManager-instance.
//!
//! When dropped, all processes that were started by the process manager and
//! that are still running are sent a kill-signal.
use futures::stream::{BoxStream, FuturesUnordered, StreamExt, StreamFuture};
use futures::FutureExt;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::collections::BTreeMap;
use std::fmt::Formatter;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::{
    process::{Child, Command},
    sync::mpsc::{
        channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
    },
};
use tokio_stream::wrappers::{LinesStream, ReceiverStream};

pub type ProcessManagerResult<T> = Result<T, ProcessManagerError>;

type SharedProcessMap = Arc<RwLock<BTreeMap<String, ManagedProcess>>>;
type InitializationQueue = UnboundedSender<InitializationMessage>;
type EventChannel = Receiver<ProcessManagerEvent>;

pub struct ProcessManager {
    /// The current state of each managed process.
    process_map: SharedProcessMap,
    /// Asynchronous event listeners for the output and exit signals of
    /// processes are only registered within the internal event loop. Thus,
    /// whenever a process is spawned, a corresponding signal is sent from the
    /// `start_process`-method to the internal event loop through this channel.
    init_queue: InitializationQueue,
    /// The channel that receives the process events from the event loop.
    /// If the `ProcessManager` implemented `Stream` directly, calling `next()`
    /// on it would consume the manager itself and make its method inaccessible
    /// to users. Thus, the stream is provided in the form of a channel that is
    /// moved out of the `ProcessManager` via `take_stream()`.
    event_channel: Option<EventChannel>,
}

/// A command to be spawned and managed by the ProcessManager. Compared to
/// `std::process::Command`, `ManagedCommand` is cloneable and does not expose
/// configuration flags which ultimately are under control of the
/// ProcessManager.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManagedCommand {
    command: String,
    args: Vec<String>,
    terminate_on_drop: bool,
}

impl ManagedCommand {
    #[allow(dead_code)]
    pub fn new(command: String, args: Vec<String>) -> Self {
        Self {
            command,
            args,
            terminate_on_drop: false,
        }
    }

    /// Send SIGTERM-signal when the managed process is dropped. By default a
    /// child is process is sent a SIGKILL-signal when dropped.
    pub fn terminate_on_drop(mut self) -> Self {
        self.terminate_on_drop = true;
        self
    }
}

impl ProcessManager {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Default::default()
    }

    pub fn start_process(
        &self,
        handle: &str,
        managed_command: ManagedCommand,
    ) -> ProcessManagerResult<()> {
        self.start_process_with_drop_handler_(handle, managed_command, None)
    }

    pub fn start_process_with_drop_handler(
        &self,
        handle: &str,
        managed_command: ManagedCommand,
        drop_handler: Box<dyn Send + Sync>,
    ) -> ProcessManagerResult<()> {
        self.start_process_with_drop_handler_(handle, managed_command, Some(drop_handler))
    }

    pub fn start_process_with_drop_handler_(
        &self,
        handle: &str,
        managed_command: ManagedCommand,
        drop_handler: Option<Box<dyn Send + Sync>>,
    ) -> ProcessManagerResult<()> {
        let spawn_message = {
            let handle = handle.to_string();
            let ManagedCommand { command, args, .. } = managed_command;
            // grab a write lock on the state
            let mut process_map = self.process_map.write().unwrap();
            if process_map.contains_key(&handle) {
                return Err(ProcessManagerError::HandleAlreadyExists);
            }

            let mut cmd = Command::new(command);
            for arg in args.iter() {
                cmd.arg(arg);
            }
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

            let shutdown_signal = if managed_command.terminate_on_drop {
                Signal::SIGTERM
            } else {
                Signal::SIGKILL
            };
            let child = cmd.spawn().map_err(ProcessManagerError::IoError)?;
            let id = child.id().expect("Could not fetch id.");
            process_map.insert(
                handle.clone(),
                ManagedProcess {
                    pid: id,
                    shutdown_signal: Some(shutdown_signal),
                    state: ProcessState::Spawned,
                    _drop_handler: drop_handler,
                },
            );
            InitializationMessage { handle, child }
        };
        self.init_queue
            .send(spawn_message)
            .map_err(|e| ProcessManagerError::InitializationError(format!("{:?}", e)))?;

        Ok(())
    }

    /// Sends a `SIGKILL`-signal to the process identified by `handle`.
    #[allow(dead_code)]
    pub fn kill_process(&self, handle: &str) -> ProcessManagerResult<()> {
        self.send_signal(handle, Signal::SIGKILL)
    }

    /// Sends a `SIGTERM`-signal to the process identified by `handle`.
    pub fn terminate_process(&self, handle: &str) -> ProcessManagerResult<()> {
        self.send_signal(handle, Signal::SIGTERM)
    }

    /// Sends a `SIGTERM`-signal to the whole process group identified by
    /// `handle`.
    pub fn terminate_group_process(&self, handle: &str) -> ProcessManagerResult<()> {
        self.send_group_signal(handle, Signal::SIGTERM)
    }

    /// Apparently, as of Dec 09 2020 the orchestrator doesn't respond well to
    /// SIGTERM, which is albeit minor, a significant issue. Hence, we need
    /// to really SIGKILL them. This function will send a specified signal
    /// to all processes. The caller should now whether the process_manager
    /// is being used
    pub fn signal_all_processes_and_clear(&self, signal: Signal) -> ProcessManagerResult<()> {
        let mut process_map = self.process_map.write().unwrap();
        for mp in process_map.values() {
            mp.send_signal(signal)?;
        }
        process_map.clear();
        Ok(())
    }

    fn send_signal(&self, handle: &str, signal: Signal) -> ProcessManagerResult<()> {
        let process_map = self.process_map.read().unwrap();
        let managed_proc = process_map.get(handle);
        if let Some(managed_proc) = managed_proc {
            managed_proc.send_signal(signal)
        } else {
            Err(ProcessManagerError::ProcessNotFound(handle.to_string()))
        }
    }

    fn send_group_signal(&self, handle: &str, signal: Signal) -> ProcessManagerResult<()> {
        let process_map = self.process_map.read().unwrap();
        let managed_proc = process_map.get(handle);
        if let Some(managed_proc) = managed_proc {
            managed_proc.send_group_signal(signal)
        } else {
            Err(ProcessManagerError::ProcessNotFound(handle.to_string()))
        }
    }

    /// Checks whether the handle is contained in the process map.
    pub fn has_process(&self, handle: &str) -> bool {
        self.process_map.read().unwrap().contains_key(handle)
    }

    #[allow(dead_code)]
    pub fn take_stream(
        &mut self,
    ) -> Option<impl futures::stream::Stream<Item = ProcessManagerEvent>> {
        self.event_channel.take().map(ReceiverStream::new)
    }

    /// Returns a future that runs the event loop (i.e. starts/stops the
    /// processes, manages the processes state and listens to process events).
    /// The code structure is isomorphic to a co-routine in other languages.
    /// However, instead of yielding, an event is added to the
    /// `event_sender`-channel.
    async fn event_loop(
        process_map: SharedProcessMap,
        mut init_queue: UnboundedReceiver<InitializationMessage>,
        event_sender: Sender<ProcessManagerEvent>,
    ) {
        // `streams` fires whenever there is an event one of the pipes of the spawned
        // processes.
        let mut streams: FuturesUnordered<StreamFuture<BoxStream<'_, StreamEvent>>> =
            FuturesUnordered::new();
        // `exit_signals` fires whenever a spawned process exits
        let mut exit_signals = FuturesUnordered::new();

        use ProcessEvent::*;
        use ProcessState::*;
        loop {
            tokio::select! {
                stream_event = streams.next(), if !streams.is_empty() => {
                    if let Some((event, tail)) = stream_event {
                        let event = event.unwrap();
                        match event {
                            StreamEvent::Line(handle, source, line) => {
                                let r = event_sender.send(
                                    ProcessManagerEvent::new(
                                        handle,
                                        OutputLine(source, line)
                                    )
                                ).await;
                                if r.is_err() { break; }

                                streams.push(tail.into_future());
                            }
                            StreamEvent::Closed(handle, source) => {
                                // update process map, hold lock only for update
                                let new_state = {
                                    let mut process_map = process_map.write().unwrap();
                                    let managed_proc = match process_map.get_mut(&handle) {
                                        Some(v) => v,
                                        None => continue
                                    };
                                    let new_state = match managed_proc.state {
                                        Spawned => PipeClosed(source),
                                        PipeClosed(_) => PipesClosed,
                                        PipesClosed => {
                                            panic!("Both pipes are already closed!");
                                        }
                                    };
                                    managed_proc.set_state(new_state.clone());
                                    new_state
                                };

                                // emit state change event
                                let r = event_sender.send(
                                    ProcessManagerEvent::new(
                                        handle,
                                        StateChange(new_state)
                                    )
                                ).await;
                                if r.is_err() { break; }
                            }
                            StreamEvent::Err(handle, _source, error) => {
                                let r = event_sender.send(
                                    ProcessManagerEvent::new(
                                        handle,
                                        ProcessEvent::IoError(error)
                                    )
                                ).await;
                                if r.is_err() { break; }
                                streams.push(tail.into_future());
                            },
                        }
                    }
                }
                spawn_signal = init_queue.recv() => {
                    let InitializationMessage { handle, mut child } = match spawn_signal {
                        Some(v) => v,
                        None => {
                            eprintln!("Sender was dropped");
                            break
                        }
                    };

                    {
                        let process_map = process_map.read().unwrap();
                        assert!(
                            process_map.get(&handle).is_some(),
                            "Process is not registered."
                        )
                    }

                    let stdout_stream = child
                        .stdout
                        .take()
                        .map(|r| async_read_to_event_stream(handle.clone(), r, Source::Stdout))
                        .expect("Could not grab stdout of child process.");
                    let stderr_stream = child
                        .stderr
                        .take()
                        .map(|r| async_read_to_event_stream(handle.clone(), r, Source::Stderr))
                        .expect("Could not grab stderr of child process.");

                    let boxed_child = (
                        async move {
                            let exit_result = child.wait().await;
                            (handle, exit_result)
                    }).boxed();
                    streams.push(stdout_stream.into_future());
                    streams.push(stderr_stream.into_future());
                    exit_signals.push(boxed_child);
                }
                exit_signal = exit_signals.next(), if !exit_signals.is_empty() => {
                    if let Some(exit_result) = exit_signal {
                        let (handle, exit_result) = exit_result;
                        {
                            let mut process_map = process_map.write().unwrap();

                            // This is the only place where the processes get removed
                            // from the process map.
                            process_map.remove(&handle);
                        }
                        let exit_result = Arc::new(exit_result);
                        let r = event_sender.send(
                            ProcessManagerEvent::new(
                                handle.clone(),
                                Exited(exit_result)
                            )
                        ).await;
                        if r.is_err() { break; }
                    }
                }
            }
        }
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        let process_map: SharedProcessMap = Default::default();
        let (event_sender, event_channel) = channel::<ProcessManagerEvent>(1);
        let (init_queue, init_queue_rcvr) = unbounded_channel::<InitializationMessage>();

        tokio::task::spawn(Self::event_loop(
            process_map.clone(),
            init_queue_rcvr,
            event_sender,
        ));

        Self {
            process_map,
            init_queue,
            event_channel: Some(event_channel),
        }
    }
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        for proc in self.process_map.read().unwrap().values() {
            let _ = proc.shutdown();
        }
    }
}

struct ManagedProcess {
    pid: u32,
    shutdown_signal: Option<Signal>,
    state: ProcessState,
    _drop_handler: Option<Box<dyn Send + Sync>>,
}

impl ManagedProcess {
    #[allow(dead_code)]
    fn state(&self) -> &ProcessState {
        &self.state
    }

    fn set_state(&mut self, state: ProcessState) {
        self.state = state;
    }

    #[allow(dead_code)]
    fn pid(&self) -> u32 {
        self.pid
    }

    fn send_signal(&self, signal: Signal) -> ProcessManagerResult<()> {
        signal::kill(Pid::from_raw(self.pid as i32), signal)
            .map_err(|e| ProcessManagerError::SignalError(signal, format!("{:?}", e)))?;
        Ok(())
    }

    fn send_group_signal(&self, signal: Signal) -> ProcessManagerResult<()> {
        let pid = self.pid as i32;
        let gpid = -pid;
        signal::kill(Pid::from_raw(gpid), signal)
            .map_err(|e| ProcessManagerError::SignalError(signal, format!("{:?}", e)))?;
        Ok(())
    }

    /// Sends the configured shutdown signal to the process or SIGKILL if no
    /// shutdown signal was configured.
    fn shutdown(&self) -> ProcessManagerResult<()> {
        let signal = self.shutdown_signal.unwrap_or(Signal::SIGKILL);
        self.send_signal(signal)
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessState {
    /// The process is spawned and has the contained process id.
    Spawned,
    /// One of the pipes (stderr/stdout) was closed by the child process or an
    /// i/o error occurred.
    PipeClosed(Source),
    /// Both pipes were closed by the child process.
    PipesClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Stderr,
    Stdout,
}

#[derive(Debug)]
pub enum ProcessManagerError {
    /// The process was not found.
    ProcessNotFound(String),
    /// An i/o error occurred.
    IoError(std::io::Error),
    /// Error when sending a signal to the process.
    SignalError(Signal, String),
    /// Error when initializing the process.
    InitializationError(String),
    /// If the handle already exists.
    HandleAlreadyExists,
}

impl std::error::Error for ProcessManagerError {}

impl std::fmt::Display for ProcessManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct ProcessManagerEvent {
    pub handle: String,
    pub event: ProcessEvent,
}

impl ProcessManagerEvent {
    pub fn new(handle: String, event: ProcessEvent) -> Self {
        Self { handle, event }
    }

    #[allow(dead_code)]
    pub fn is_handle(&self, handle: &str) -> bool {
        self.handle == handle
    }
}

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    /// The process changed it's state.
    StateChange(ProcessState),
    /// An error occurred.
    IoError(Arc<std::io::Error>),
    /// Output from the process.
    OutputLine(Source, String),
    /// A process seized to exist. :-(
    Exited(Arc<std::io::Result<ExitStatus>>),
}

#[derive(Debug, Clone)]
enum StreamEvent {
    Line(String, Source, String),
    Err(String, Source, Arc<std::io::Error>),
    Closed(String, Source),
}

/// A message that signals the internal event loop that a process with `handle`
/// was spawned.
#[derive(Debug)]
struct InitializationMessage {
    handle: String,
    child: Child,
}

fn async_read_to_event_stream<'a, R: AsyncRead + Send + 'a>(
    handle: String,
    pipe: R,
    source: Source,
) -> BoxStream<'a, StreamEvent> {
    fn line_to_event(
        handle: String,
        source: Source,
    ) -> impl Fn(std::io::Result<String>) -> StreamEvent {
        move |line: std::io::Result<String>| match line {
            Ok(line) => StreamEvent::Line(handle.clone(), source.clone(), line),
            Err(e) => StreamEvent::Err(handle.clone(), source.clone(), Arc::new(e)),
        }
    }

    let handle_ = handle.clone();
    LinesStream::new(BufReader::new(pipe).lines())
        .map(line_to_event(handle, source.clone()))
        // insert a sentinel value at the end of the stream
        .chain(async move { StreamEvent::Closed(handle_, source) }.into_stream())
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::{
        ManagedCommand, ProcessEvent, ProcessManager, ProcessManagerError, ProcessManagerEvent,
        Source,
    };
    use assert_matches::assert_matches;
    use futures::stream::StreamExt;
    use std::time::Duration;

    #[tokio::test]
    async fn adding_same_handle_fails() {
        let process_manager = ProcessManager::new();

        assert!(process_manager
            .start_process(
                "handle",
                ManagedCommand::new("sleep".to_string(), vec!["1".to_string()]),
            )
            .is_ok());
        assert_matches!(
            process_manager.start_process(
                "handle",
                ManagedCommand::new("echo".to_string(), vec!["2".to_string()]),
            ),
            Err(ProcessManagerError::HandleAlreadyExists)
        );
    }

    #[tokio::test]
    async fn receives_output_from_multiple_processes() {
        let mut process_manager = ProcessManager::new();
        let event_stream = process_manager.take_stream().unwrap();

        let no_of_lines = 10usize;
        let handle_1 = "output_1";
        let handle_2 = "output_2";
        let script_1 = format!(
            "for i in {{1..{}}}; do echo output_1_$i; >&2 echo {}_e$i; sleep 0.1; done;",
            no_of_lines, handle_1
        );
        let script_2 = format!(
            "for i in {{1..{}}}; do echo output_2_$i; >&2 echo {}_e$i; sleep 0.1; done;",
            no_of_lines, handle_2
        );

        let command_1 = ManagedCommand::new("sh".into(), vec!["-c".to_string(), script_1]);
        let command_2 = ManagedCommand::new("sh".into(), vec!["-c".to_string(), script_2]);
        let stop_command = ManagedCommand::new(
            "sh".into(),
            vec!["-c".to_string(), "sleep 2; echo stop".to_string()],
        );

        assert!(process_manager.start_process(handle_1, command_1).is_ok());
        assert!(process_manager.start_process(handle_2, command_2).is_ok());
        assert!(process_manager.start_process("stop", stop_command).is_ok());

        let r = 1..=no_of_lines;
        let events = drain_until_output(event_stream, "stop").await;
        assert_correct_output_events(events.clone(), handle_1, Source::Stdout, "", r.clone());
        assert_correct_output_events(events.clone(), handle_1, Source::Stderr, "e", r.clone());
        assert_correct_output_events(events.clone(), handle_2, Source::Stdout, "", r.clone());
        assert_correct_output_events(events, handle_2, Source::Stderr, "e", r);
    }

    #[tokio::test]
    async fn can_sustain_flood() {
        let mut process_manager = ProcessManager::new();
        let event_stream = process_manager.take_stream().unwrap();

        let no_of_lines = 100_000usize;
        let handle = "output";
        let script = format!(
            "for i in {{1..{}}}; do echo output_$i; done; echo stop;",
            no_of_lines
        );
        let command = ManagedCommand::new("sh".into(), vec!["-c".to_string(), script]);

        let tick = std::time::Instant::now();
        assert!(process_manager.start_process(handle, command).is_ok());
        let events = drain_until_output(event_stream, "stop").await;
        let duration = tick.elapsed();
        println!("events/s: {}", no_of_lines as f64 / duration.as_secs_f64());
        let r = 1..=no_of_lines;
        assert_correct_output_events(events, handle, Source::Stdout, "", r);
    }

    #[tokio::test]
    async fn can_kill_process() {
        let mut process_manager = ProcessManager::new();
        let mut event_stream = process_manager.take_stream().unwrap();

        process_manager
            .start_process(
                "sleepy",
                ManagedCommand::new("sleep".into(), vec!["10".into()]),
            )
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        process_manager.kill_process("sleepy").unwrap();
        // The underlying stream remains open indefinitely. Thus, we introduce a hard
        // bound on the maximum runtime of the test.
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(event) = event_stream.next().await {
                let ProcessManagerEvent { event, .. } = event;
                if let ProcessEvent::Exited(status) = event {
                    let status = status.as_ref().as_ref().unwrap();
                    assert!(!status.success());
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    async fn drain_until_output(
        event_stream: impl futures::Stream<Item = ProcessManagerEvent>,
        output_line: &str,
    ) -> Vec<ProcessManagerEvent> {
        // The underlying stream remains open indefinitely. Thus, we introduce a hard
        // bound on the maximum runtime of the test.
        tokio::time::timeout(
            Duration::from_secs(40),
            event_stream
                .take_while(|event| {
                    futures::future::ready(match event.event {
                        ProcessEvent::OutputLine(Source::Stdout, ref line)
                            if line == output_line =>
                        {
                            false
                        }
                        _ => true,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap()
    }

    fn assert_correct_output_events<T>(
        events: Vec<ProcessManagerEvent>,
        handle: &str,
        source: Source,
        prefix: &str,
        range: T,
    ) where
        T: IntoIterator<Item = usize>,
    {
        use ProcessEvent::*;
        let lines = events
            .iter()
            .filter(|e| e.is_handle(handle))
            .map(|e| e.event.clone())
            .filter_map(|e| {
                if let OutputLine(source_, line) = e {
                    if source_ == source {
                        return Some(line);
                    }
                }
                None
            })
            .collect::<Vec<_>>();
        let expected = range
            .into_iter()
            .map(|i| format!("{}_{}{}", handle, prefix, i))
            .collect::<Vec<_>>();
        assert_eq!(lines, expected);
    }
}
