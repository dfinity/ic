//! Simple process pool to help implementing [crate::manager::Manager].
//!
//! This module provides a simple wrapper around `std::process`
//! to launch a number of processes and multiplex their outputs
//! into a single channel.
//!
//! A good place to start is the [process_pool_with_pipeline] function,
//! which is given a vector of configs and creates a [ProcessPool],
//! a [Registry] and a [Pipeline].
//!
//! All the given configurations will give rise to a command, which will
//! be spawned as a child process. The output of said process is passed to the
//! pipeline through an [Event], which consists of a process id and a
//! [ChildEvent].
//!
//! The [mio::Registry] is supposed to be cloned (with `mio::Poll::try_clone`)
//! and used to register subsequent children that you might want to launch
//! later.
use crossbeam_channel::{unbounded, Receiver, Sender};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry};
use nix::sys::signal::kill;
pub use nix::sys::signal::Signal;
use nix::unistd::Pid;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook_mio::v0_7::Signals;
use std::convert::{From, TryFrom};
use std::process::{self, Stdio};
use std::sync::{Arc, RwLock};
use std::thread;
use std::{collections::BTreeMap, io};
use std::{
    fs::{File, OpenOptions},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::PathBuf,
    time::Duration,
};

use super::buffered_reader::{BufferedReader, LineBuffer};
use crate::mio::{make_token, split_token, InputSource, SIGNAL_TOKEN};
use slog::{debug, error, o, trace, warn, Logger};

/// The ProcessPool feeds 'Events' into the passive pipeline.
/// These events consist in either events produced by the children
/// or signals comming into the manager's thread.
///
/// The dedicated [Event::Signal] is important to inform the pipeline and
/// we received a signal. In fact, the process pool will NOT terminate
/// upon receiving a signal, but this will trigger the pipeline to terminate
/// which then leads to [crate::pot::Pot::run_with] to call
/// [crate::manager::Manager::stop].
#[derive(Debug, Clone)]
pub enum Event {
    ChildEvent(Pid, ChildEvent),
    Signal(i32),
}

/// ChildEvents consists in unparsed output lines or an exit status.
#[derive(Debug, Clone)]
pub enum ChildEvent {
    Line { src: InputSource, line: String },
    Exited { status: process::ExitStatus },
}

/// Children contain a process id and the relevant bits from `std::process`
/// that are needed to read this child's output and automatically clean these
/// resources up when a `Child` goes out of scope.
pub struct Child {
    stdout: BufferedReader<process::ChildStdout, LineBuffer>,
    stderr: BufferedReader<process::ChildStderr, LineBuffer>,
    auxsrc: Vec<BufferedReader<File, LineBuffer>>,
    child: process::Child,
    pid: Pid,
}

impl Child {
    /// Reads lines from the given input source and feeds them into the provided
    /// sender as [ChildEvent::Line]s.
    pub fn perform_read<E: From<Event>>(
        &mut self,
        log: &Logger,
        src: InputSource,
        snd: &Sender<E>,
    ) {
        let pid = self.pid;
        let f = extend_and_send_lines_through(log, snd, move |line| str2e(pid, src, line));

        let read_res = match src {
            InputSource::Stdout => self.stdout.process_read_event(f),
            InputSource::Stderr => self.stderr.process_read_event(f),
            InputSource::Auxsrc(n) => {
                if let Some(ref mut aux) = self.auxsrc.get_mut(n) {
                    aux.process_read_event(f)
                } else {
                    error!(
                        log,
                        "No available auxsrc({}) to read from; this should not happen", n
                    );
                    None
                }
            }
        };

        // read_res should always be Some(()); this is because we only call
        // Child::perform_read when our mio::poll tells us there is something to
        // read; hence, process_read_event must return `Some` because there is a
        // Read'er to read from.
        if read_res.is_none() {
            warn!(log, "process_read_event returned None");
        }
    }

    pub fn flush_and_clear_all<E: From<Event>>(&mut self, log: &Logger, snd: &Sender<E>) {
        for src in InputSource::enumerate() {
            self.flush_and_clear(log, src, snd);
        }
    }

    pub fn flush_and_clear<E: From<Event>>(
        &mut self,
        log: &Logger,
        src: InputSource,
        snd: &Sender<E>,
    ) {
        let pid = self.pid;
        match src {
            InputSource::Stdout => send_lines_through_and_clear(
                log,
                snd,
                |line| str2e(pid, InputSource::Stdout, line),
                &mut self.stdout.buf,
            ),
            InputSource::Stderr => send_lines_through_and_clear(
                log,
                snd,
                |line| str2e(pid, InputSource::Stderr, line),
                &mut self.stderr.buf,
            ),
            InputSource::Auxsrc(n) => {
                if let Some(ref mut aux) = self.auxsrc.get_mut(n) {
                    send_lines_through_and_clear(
                        log,
                        snd,
                        |line| str2e(pid, InputSource::Auxsrc(n), line),
                        &mut aux.buf,
                    )
                }
            }
        }
    }
}

/// Converts a String to whatever event type we're using
pub fn str2e<E: From<Event>>(pid: Pid, src: InputSource, line: String) -> E {
    E::from(Event::ChildEvent(pid, ChildEvent::Line { src, line }))
}

/// Simple helper to send all available lines through whenever processing a read
/// event.
pub fn extend_and_send_lines_through<E>(
    logger: &Logger,
    snd: &Sender<E>,
    str2e: impl Fn(String) -> E,
) -> impl Fn(&[u8], &mut LineBuffer) {
    let snd = snd.clone();
    let logger = logger.clone();
    move |us, buf| {
        buf.extend_from_slice(us);
        while let Some(line) = buf.read_line() {
            if let Err(e) = snd.send(str2e(line)) {
                warn!(logger, "Couldn't send: {:?}", e);
            }
        }
    }
}

/// Simple helper to send all available lines through a sender AND
/// clears the underlying line buffer; It sends the last unfinished line if any.
pub fn send_lines_through_and_clear<E>(
    logger: &Logger,
    snd: &Sender<E>,
    str2e: impl Fn(String) -> E,
    lb: &mut LineBuffer,
) {
    while let Some(line) = lb.read_line() {
        if let Err(e) = snd.send(str2e(line)) {
            warn!(logger, "Couldn't send: {:?}", e);
        }
    }

    let last = lb.clear();
    if !last.is_empty() {
        if let Err(e) = snd.send(str2e(last)) {
            warn!(logger, "Couldn't send: {:?}", e);
        }
    }
}

/// The process pool keeps a set of children, a status variable and a
/// mio::Poll.
pub struct ProcessPool<Cfg> {
    /// The children under management are modified by the wait-loop-thread and
    /// we might launch new children after starting the pool
    /// Keeping the Pid as the key is redundant, but its really the most
    /// convenient way to search for a process.
    pub children: Arc<RwLock<BTreeMap<Pid, Child>>>,

    /// We maintain the associated config that spawned each child. We keep
    /// this separate from 'children' above to avoid having to make Cfg:
    /// Send + Sync. Currently, this is append-only and maintains configs
    /// for nodes that might have stopped running.
    pub configs: BTreeMap<Pid, Cfg>,

    /// We keep a variable around to stop the worker threads cleanly.
    /// Setting 'is_stopping = true' will cause the wait_thread and the
    /// poll_thread to stop, enabling us to join on them.
    pub shutting_down: Arc<RwLock<bool>>,

    /// JoinHandle for the poll thread
    poll_thread: Option<thread::JoinHandle<()>>,

    /// JoinHandle for the wait thread
    wait_thread: Option<thread::JoinHandle<()>>,

    logger: Logger,
}

/// The [ManagedProcessCfg] trait captures the necessary bits of information
/// we need to provide [ProcessPool] for correct management.
pub trait ManagedProcessCfg {
    /// Returns the command to launch this managed process.
    fn command(&mut self) -> process::Command;

    /// Fondue can monitor a specified fifo for events; This is useful when, for
    /// instance, the managed process writes to its own stdout and stderr
    /// and we wish to keep a separate information channel for log messages.
    /// When this function is implemented to return `Some`, the process pool
    /// will also poll this file descriptor and send the lines it reads as
    /// [InputSource::Auxsrc] into the pipeline.
    fn auxiliary_info_source(&self) -> Vec<PathBuf>;
}

impl<Cfg: ManagedProcessCfg> ProcessPool<Cfg> {
    pub fn new(logger: &Logger) -> Self {
        ProcessPool {
            children: Default::default(),
            configs: Default::default(),
            shutting_down: Arc::new(RwLock::new(false)),
            poll_thread: None,
            wait_thread: None,
            logger: logger.new(o!("where" => "process_pool")),
        }
    }

    /// Spawns a child process, registers its stdout and stderr into a mio::Poll
    /// and stores the process::Child in the 'children' map.
    pub fn spawn_and_register_child(&mut self, mut cfg: Cfg, registry: &mut Registry) -> Pid {
        let mut cmd = cfg.command();
        let cmd_str = format!("{:?}", cmd);
        let mut child = match cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(v) => v,
            Err(e) => panic!("spawn() failed for command `{:?}` with error: {:?}", cmd, e),
        };

        let pid: Pid =
            Pid::from_raw(i32::try_from(child.id()).expect("Can't convert child.id() to Pid"));

        trace!(
            self.logger,
            "spawn_and_register_child";
            "cmd" => cmd_str,
            "pid" => format!("{:?}", pid),
        );

        // We now take the children stdout and stderr raw file descriptors.
        // We use `into_raw_fd` to transfer ownership. The drop handle on Child
        // should close them.
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Now, we register the child's stderr, stdout and auxsrc for polling.
        // Note that we first get the children lock. This is to prevent a scenario
        // where the poll thread is blocked on polling, but as soon as we add a new
        // mio source it wakes up and goes fetch input from that source, however,
        // this thread did not add the the new child to the children map
        // and we end up with the warning "Event for unregistered process"
        {
            let mut children = self.children.write().expect("couldn't lock");

            registry
                .register(
                    &mut SourceFd(&stdout.as_raw_fd()),
                    make_token(pid, InputSource::Stdout),
                    Interest::READABLE,
                )
                .expect("Failed to register child's stdout");

            registry
                .register(
                    &mut SourceFd(&stderr.as_raw_fd()),
                    make_token(pid, InputSource::Stderr),
                    Interest::READABLE,
                )
                .expect("Failed to register child's stderr");

            trace!(self.logger, "Registered stdout and stderr in mio");

            // Now we map over all the auxiliary information sources and attempt to open
            // them for reading. Those that suceed will get registered with
            // their respective Auxsrc(pos) tag in the mio registry.
            let vec_auxsrc = cfg
                .auxiliary_info_source()
                .into_iter()
                .enumerate()
                .filter_map(|(pos, path)| {
                    let mut open_opts = OpenOptions::new();
                    open_opts.read(true);
                    if cfg!(unix) {
                        open_opts.custom_flags(libc::O_NONBLOCK);
                    }
                    match open_opts.open(&path) {
                        Err(e) => {
                            warn!(
                                self.logger,
                                "Could not open auxsrc at {:?} for reading: {:?}", path, e
                            );
                            None
                        }
                        Ok(file) => {
                            registry
                                .register(
                                    &mut SourceFd(&file.as_raw_fd()),
                                    make_token(pid, InputSource::Auxsrc(pos)),
                                    Interest::READABLE,
                                )
                                .expect("Failed to register child's auxsrc");

                            trace!(self.logger, "Registered auxsrc in mio");
                            Some(file)
                        }
                    }
                });

            // Adds the child to the managed pool; this must happen AFTER registering
            // the stdout and stderr, otherwise we get the "borrow after move" error.
            children.insert(
                pid,
                Child {
                    pid,
                    stdout: BufferedReader::new(stdout),
                    stderr: BufferedReader::new(stderr),
                    auxsrc: vec_auxsrc
                        .map(BufferedReader::<File, LineBuffer>::new)
                        .collect(),
                    child,
                },
            );
            drop(children);

            trace!(self.logger, "Registered the new child in children map");
        }

        // Stores the config with the associated pid it launched.
        self.configs.insert(pid, cfg);
        debug!(self.logger, "Spawned child process (pid: {})", pid);
        pid
    }

    /// Spawns a number of children at a time.
    pub fn spawn_and_register_children(&mut self, env: Vec<Cfg>, registry: &mut Registry) {
        for cfg in env.into_iter() {
            self.spawn_and_register_child(cfg, registry);
        }
    }

    /// Given a config, returns a stream that will yield the events of the
    /// managed processes running under the pool and the mio::Registry to
    /// register new poll-able sources.
    ///
    /// This function also registers a [Signals] for [SIGINT] signals in
    /// the calling thread. This means that the calling thread won't be
    /// interrupted by SIGING. Instead, SIGINT will be sent on the pipeline
    /// and can be properly caught and trigger a cleanup on the manager.
    #[allow(clippy::type_complexity)]
    pub fn start<E: From<Event> + Send + 'static>(
        &mut self,
        env: Vec<Cfg>,
    ) -> io::Result<(Sender<E>, Receiver<E>, Registry)> {
        // The thread in which Signals is created stops
        // responding to signals, and the only way to see them is polling the
        // associated object. In this case, this thread stops responding
        // to SIGINT and SIGTERM.
        let signals = Signals::new(&[SIGINT, SIGTERM]).expect("Couldn't create signals");
        debug!(self.logger, "Created signal handler");
        self.start_with_signal_filter(env, signals)
    }

    /// Same as `start`, but receives a custom [signal_hook_mio::v0_7::Signals]
    pub fn start_with_signal_filter<E: From<Event> + Send + 'static>(
        &mut self,
        env: Vec<Cfg>,
        mut signals: Signals,
    ) -> io::Result<(Sender<E>, Receiver<E>, Registry)> {
        let mut poll = Poll::new().expect("Couldn't create poll");
        poll.registry()
            .register(&mut signals, SIGNAL_TOKEN, Interest::READABLE)
            .expect("Couldn't register signals to poller");

        let mut registry = poll
            .registry()
            .try_clone()
            .expect("Couldn't clone registry");

        self.spawn_and_register_children(env, &mut registry);

        let (snd, rec): (Sender<E>, _) = unbounded();

        // We launch a thread that polls on the output of the children
        // and feed their events into 'snd' above.
        let poll_thread = thread::spawn({
            let logger = self.logger.clone();
            let children = self.children.clone();
            let shutting_down = self.shutting_down.clone();
            let snd = snd.clone();
            move || loop {
                if *shutting_down.read().unwrap() {
                    let mut children = children.write().unwrap();
                    for (_pid, c) in children.iter_mut() {
                        c.flush_and_clear_all(&logger, &snd);
                    }
                    *children = BTreeMap::default();
                    drop(children);
                    break;
                }

                let mut events = Events::with_capacity(1024);
                if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(150))) {
                    // In case we receive a signal while blocked at poll, it returns EINTR.
                    // All is fine and we just run over the loop
                    // one more time and the signal will be delivered through mio.
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    } else {
                        panic!("Can't poll: {:?}", e);
                    }
                }

                for event in &events {
                    if event.token() == SIGNAL_TOKEN {
                        for sig in signals.pending() {
                            debug!(
                                logger,
                                "Received signal {:?}. Forwarding it on the pipeline.", sig
                            );
                            snd.send(E::from(Event::Signal(sig)))
                                .expect("Coultn't send signal");
                        }
                    } else {
                        let (pid, src) = split_token(event.token());

                        if let Some(c) = children
                            .write()
                            .expect("Couldn't get write lock on children")
                            .get_mut(&pid)
                        {
                            if event.is_readable() {
                                c.perform_read(&logger, src, &snd);
                            }

                            if event.is_read_closed() {
                                c.flush_and_clear(&logger, src, &snd);
                            }
                        } else {
                            warn!(logger, "Event for unregistered process: {}", pid);
                        }
                    }
                }
            }
        });

        // We also launch another thread that waits on child processes and removes
        // the children that have returned from the managed processes map.
        let wait_thread = thread::spawn({
            let logger = self.logger.clone();
            let children = self.children.clone();
            let shutting_down = self.shutting_down.clone();
            let snd = snd.clone();
            move || loop {
                if *shutting_down.read().unwrap() {
                    break;
                }

                thread::sleep(Duration::from_millis(100));
                let mut rm_from_children: Vec<Pid> = Vec::new();
                let mut children = children.write().unwrap();
                for (pid, child) in children.iter_mut() {
                    if let Some(status) = child.child.try_wait().expect("Couldn't wait") {
                        debug!(logger, "Child {:?} exited with {:?}", pid, status);
                        snd.send(E::from(Event::ChildEvent(
                            *pid,
                            ChildEvent::Exited { status },
                        )))
                        .expect("Couldn't send");
                        rm_from_children.push(*pid);
                    }
                }

                for p in rm_from_children {
                    children.remove(&p);
                }

                drop(children);
            }
        });

        self.poll_thread = Some(poll_thread);
        self.wait_thread = Some(wait_thread);

        Ok((snd, rec, registry))
    }

    /// Stops the pool by setting its shutting_down variable to true and
    /// killing the children that are still alive. If the child process has
    /// assigned its process group to its own pid, we kill the entire group.
    pub fn stop(&mut self) {
        debug!(self.logger, "Stopping all processes");

        // Send SIGTERM to all children; then release the lock and wait a little.
        // We then send SIGKILL to all remaining children.
        let children = self.children.write().unwrap();
        for (pid, _child) in children.iter() {
            signal_pid(&self.logger, Signal::SIGTERM, pid);
        }
        drop(children);

        // This wait gives time for the wait-thread to collect the results
        // of the different children.
        std::thread::sleep(Duration::from_secs(2));
        let children = self.children.write().unwrap();
        for (pid, _child) in children.iter() {
            signal_pid(&self.logger, Signal::SIGKILL, pid);
        }
        // *children = BTreeMap::default(); // also, for good measure, ensure we drop
        // all of it.
        drop(children);

        // Finally, we record the shutdown. This tells the poll-thread and
        // wait-thread that they should NOT do another iteration and return instead.
        *self.shutting_down.write().unwrap() = true;

        debug!(self.logger, "Joining poll and wait threads");
        // Wait for both worker threads to finish.
        if let Some(j) = self.poll_thread.take() {
            let _ = j.join();
        }
        if let Some(j) = self.wait_thread.take() {
            let _ = j.join();
        }
    }

    /// Kills and removes a child process; returns the configuration
    /// used to spawn that process in the first place.
    pub fn kill_and_remove(&mut self, pid: &Pid, sig: Signal) -> Option<Cfg> {
        let cfg = self.configs.remove(pid)?;
        let _child = self
            .children
            .write()
            .expect("Couldn't get write lock")
            .remove(pid)?;

        signal_pid(&self.logger, sig, pid);
        Some(cfg)
    }

    /// Restarts a given process by killing it, then relaunching with the same
    /// configuration. Returns `None` if the given pid is not registered within
    /// this process_pool; Returns `Some(p)` on a successfull restart, where `p`
    /// is the new pid.
    ///
    /// *NOTE*: (VER-737) If the process is not SIGKILLED, it might be orphaned.
    pub fn restart_process(
        &mut self,
        pid: &Pid,
        registry: &mut Registry,
        sig: Signal,
        wait_before_restart: Duration,
    ) -> Option<Pid> {
        let cfg = self.kill_and_remove(pid, sig)?;

        // TODO(VER-737): Instead of waiting an arbitrary duration, we should
        // put a mechanism in place that waits for the process to exit.
        thread::sleep(wait_before_restart);
        Some(self.spawn_and_register_child(cfg, registry))
    }
}

type ProcessPoolInstance<Cfg> = (ProcessPool<Cfg>, Registry);

pub fn process_pool<Cfg: ManagedProcessCfg + Send, E: From<Event> + Send + 'static>(
    cfg: Vec<Cfg>,
    logger: &Logger,
    pipeline: impl FnOnce() -> Box<dyn FnMut(E)> + Send + 'static,
) -> ProcessPoolInstance<Cfg> {
    let mut man = ProcessPool::new(logger);
    let (_, pool_recv, registry) = man.start(cfg).expect("process_pool failed to start");
    thread::spawn({
        move || {
            let mut pipeline = pipeline();
            while let Ok(e) = pool_recv.recv() {
                pipeline(e);
            }
        }
    });
    (man, registry)
}

/// Kills a child process. We use `killpg` instead of `kill` when the child
/// set its process group id to its own pid.
fn signal_pid(logger: &Logger, s: Signal, pid: &Pid) {
    // Try to kill the process but does /NOT/ panic if something goes wrong,
    // we must continue to clean up.
    debug!(logger, "Sending {} to {}", s, *pid);
    if let Err(_e) = kill(*pid, s) {
        warn!(logger, "Couldn't send {} to {}", s, *pid);
    }
}
