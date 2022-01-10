//! Contains the necessary machinery to run [pot::Pot]s in forked processes.
//!
//! Once a pot is launched, it is converted into a `RunningPot`. The running
//! pots are periodically monitored for changes in the main event loop (in
//! the [execute] function). When a `RunningPot`'s underlying process finishes
//! we convert said `RunningPot` into a [CompletedPot]. In a picture:
//!
//! ```text
//!                                   ╭-----╮
//!                  launch           v     |
//!     pot::Pot -------------> RunningPot  | wait or timeout?
//!                                 | |     |
//!                                 | ╰-----╯
//!                                 |
//!                                 | complete
//!                                 v
//!                             CompletedPot
//! ```
//!
//! When there are no more pots to run we finish and report results.
//!
//! # Notes and Design Decisions
//!
//! * When running pots sequentially (cfg.jobs == 1), we inherit the parents
//!   stderr/stdout, so the user sees the output on their terminal as it is
//!   produced. When running pots in parallel, there is no --nocapture option on
//!   purpose. After a pot finishes we print all of its output in one go. This
//!   makes it easy to search and study the logs of a given pot.
//!
//! * We explicitely do not use slog in here because slog spawns threads;
//!   Forking when there are threads running is probably best avoided.
//!   (Here's why)[https://www.linuxprogrammingblog.com/threads-and-fork-think-twice-before-using-them]
//! * The results and test reports produced by running a pot are only sent
//!   _after_ the pot is done. This is deliberate but it means that when the pot
//!   process crashes or is terminated due to a timeout, we get no results. We
//!   used to communicate results as the tests ran but this introduced more
//!   complexity than benefits.
//!
//! * The code in this module was heavily inspired by `raclette`.

#![allow(clippy::new_without_default)]

use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use mio::unix::pipe;
use mio::{Events, Interest, Poll};
use nix::sys::signal::{kill, killpg, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{self, fork, ForkResult, Pid};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook_mio::v0_7::Signals;

pub use crate::result::*;

use crate::ic_manager::{buffered_reader::BufferedReader, IcManagerSettings};
use crate::mio::{make_token, split_token, InputSource, SIGNAL_TOKEN};
use crate::pot::inner as pot;
use crate::pot::stream_decoder::*;

/// Execution configuration options.
pub struct Config {
    /// Configures the time we are willing to wait for the
    /// entire execution of a pot.
    pub pot_timeout: std::time::Duration,

    /// Do we want to filter the tests out of a pot?
    pub filter: Option<pot::Filter>,

    /// How many pots in parallel should we run
    pub jobs: usize,

    /// The settings for running each individual pot
    pub pot_config: pot::Config,

    /// And finally, the domain specific settings for manager startup
    pub man_config: IcManagerSettings,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            pot_timeout: Duration::from_secs(1500),
            filter: None,
            jobs: 1,
            pot_config: pot::Config::default(),
            man_config: IcManagerSettings::default(),
        }
    }
}

impl Config {
    pub fn random_pot_rng_seed(self) -> Self {
        Config {
            pot_config: self.pot_config.random_rng_seed(),
            ..self
        }
    }
}

/// Executes a list of tasks and produces an [ExecutionResult] with the status
/// of /all/ tasks, regardless of whether they were skipped, ignored, etc.
pub fn execute(config: &Config, mut tasks: Vec<pot::Pot>) -> Option<ExecutionResult> {
    if let Some(ref filter) = config.filter {
        for t in tasks.iter_mut() {
            t.apply_filter(filter);
        }
    }

    // Execution proceeds by launching or skipping each task in `tasks`,
    // sequentially. We use mio under the hood.
    let poll_timeout = Duration::from_millis(100);
    let mut events = Events::with_capacity(128);
    let mut executor = Executor {
        running: BTreeMap::new(),
        result: ExecutionResult(vec![]),
        poll: Poll::new().expect("Couldn't create poll"),

        // This variable increases whenever we receive a SIGINT
        // or SIGTERM. We use this to decide whether to launch additional tasks
        // or to just report their tests as 'Ignored'.
        sigint_ctr: 0,
    };

    // Installs our signal handler. From this point onwards, this thread stops
    // responding to SIGINT and SIGTERM. Be very careful moving this line and
    // even more careful spawning threads before this point.
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Couldn't create signals");

    executor
        .poll
        .registry()
        .register(&mut signals, SIGNAL_TOKEN, Interest::READABLE)
        .expect("failed to register signal handler in a Poll registry");

    tasks.reverse();

    // While there are tasks to be ran or running,
    while !tasks.is_empty() || !executor.running.is_empty() {
        // If we have tasks to be ran and not enough jobs running, we can launch some.
        while !tasks.is_empty() && executor.running.len() < config.jobs {
            let p = tasks.pop().unwrap(); // we just checked tasks is not empty! :)
            executor.launch_or_skip(p, config);
        }

        if let Err(e) = executor.poll.poll(&mut events, Some(poll_timeout)) {
            // In case we receive a signal while blocked at poll, it returns EINTR.
            // All is fine and we just run over the loop
            // one more time and the signal will be delivered through mio.
            // check this for context: https://github.com/vorner/signal-hook/issues/98
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            } else {
                executor.signal_running_pots(Signal::SIGKILL, true);
                return None;
            }
        }

        for event in events.iter() {
            if event.token() == SIGNAL_TOKEN {
                for sig in signals.pending() {
                    eprintln!("[!!] Received signal {:?}", sig);
                    if sig == SIGINT || sig == SIGTERM {
                        executor.handle_sigint();
                    }
                }
            } else {
                let (pid, src) = split_token(event.token());
                if let Some(obs) = executor.running.get_mut(&pid) {
                    if event.is_readable() {
                        obs.process_read_event(src);
                    }
                    if event.is_read_closed() {
                        obs.process_read_closed(src);
                    }
                } else {
                    eprintln!("[!!] Event for unregistered pid: {}", pid);
                }
            }
        }

        // Makes sure to remove the completed pids from the set of running pids
        // I was not able to accomplish this in [Executor::wait] due to Rust complaining
        // about borrowing self in too many different ways
        let completed_pids = executor.wait(config.pot_timeout);
        for (pid, (status, dur)) in completed_pids {
            let task = executor.running.remove(&pid).unwrap();
            executor
                .result
                .0
                .push(task.complete(status, dur, config.jobs > 1));
        }
    }

    Some(executor.result)
}

/// The [Executor] is the main component and keeps track of
/// all pots that are curerntly running, the results seen so far,
/// the [mio::Poll] and how many SIGINT we received so far.
pub struct Executor {
    running: BTreeMap<Pid, RunningPot>,
    result: ExecutionResult,
    poll: Poll,
    sigint_ctr: usize,
}

/// After a [ic_fondue::pot::Pot] is [launch]ed, it "becomes" a [RunningPot].
/// The `result_pipe` doesn't need to be buffered as we only read from it
/// at the end of execution. The `test_names` carries the names of the tests
/// that we are expecting to run with this pot. This is important to be able to
/// report what was supposed to run when a pot just crashes.
struct RunningPot {
    pid: Pid,
    pot_name: String,
    test_names: Vec<String>,
    result_pipe: pipe::Receiver,
    stdout_pipe: BufferedReader<pipe::Receiver, Vec<u8>>,
    stderr_pipe: BufferedReader<pipe::Receiver, Vec<u8>>,
    started_at: Instant,
}

impl RunningPot {
    fn process_read_event(&mut self, src: InputSource) {
        match src {
            InputSource::Stdout => {
                self.stdout_pipe.process_read_event(|buf, v| {
                    v.extend_from_slice(buf);
                });
            }
            InputSource::Stderr => {
                self.stderr_pipe.process_read_event(|buf, v| {
                    v.extend_from_slice(buf);
                });
            }
            // As it currently stands, we only register Stdout and Stderr in
            // this mio poll; hence, processing a read event for an auxiliar information
            // source should never happen. Yet, instead of creating another datatype,
            // we chose to reuse the one that already exists; Moreover, if we ever
            // want to have more mio sources, this is already supported. :)
            InputSource::Auxsrc(_) => unreachable!(),
        };
    }

    fn process_read_closed(&mut self, src: InputSource) {
        match src {
            InputSource::Stdout => self.stdout_pipe.close(),
            InputSource::Stderr => self.stderr_pipe.close(),
            InputSource::Auxsrc(_) => unreachable!(),
        }
    }

    /// Calls `waitpid` for the given [RunningPot] and decides whether to
    /// terminate the pot because it has been running for too long.
    fn wait(&mut self, timeout: Duration) -> Option<(Status, Duration)> {
        let duration = self.started_at.elapsed();
        let mut maybe_status = match waitpid(Some(self.pid), Some(WaitPidFlag::WNOHANG)).unwrap() {
            WaitStatus::Exited(_, code) => Some(if code == 0 {
                (Status::Success, duration)
            } else {
                (Status::Failure(code), duration)
            }),
            WaitStatus::Signaled(_, sig, _) => {
                // When a child returned through a signal, there's high chances
                // that said child did not perform any cleanup. We'll send a SIGKILL
                // to its process group just in case.
                killpg(self.pid, Signal::SIGKILL).unwrap();
                Some((Status::Signaled(sig.as_str()), duration))
            }
            _ => None,
        };

        if maybe_status.is_none() && duration >= timeout {
            killpg(self.pid, Signal::SIGKILL).unwrap();
            maybe_status = Some((Status::Timeout, duration));
        }

        maybe_status
    }

    /// Computes a [CompletedPot] from a [RunningPot] and tries to read the
    /// [PotResult] from the [result_pipe]. When the status is not a crash
    /// (that is, [Status::Signaled] or [Status::Timeout]) we should be able
    /// to read such result.
    fn complete(self, st: Status, duration: Duration, print_bufs: bool) -> CompletedPot {
        let RunningPot {
            pid,
            pot_name,
            test_names,
            stdout_pipe,
            stderr_pipe,
            result_pipe,
            started_at,
        } = self;

        // When running in sequential mode (jobs == 1), these buffers will
        // always be empty. Each pot will inherit stderr/out.
        if print_bufs {
            print_buffer(
                &format!("STDOUT for {:?}, pot '{}'", pid, pot_name),
                &stdout_pipe.buf,
            );
            print_buffer(
                &format!("STDERR for {:?}, pot '{}'", pid, pot_name),
                &stderr_pipe.buf,
            );
            println!();
        }

        // If the pot has NOT timed-out or cancelled by user signal, we expect
        // the [PotResult] produced by [run_with] to be written to our `result_pipe`.
        let mut sd = StreamDecoder::from_pipe(result_pipe);
        let opt_result = sd.try_decode();

        CompletedPot {
            pot_name,
            pid_and_status: Some((pid, st)),
            result: opt_result,
            test_names,
            duration,
            started_at,
        }
    }
}

fn print_buffer(lbl: &str, buf: &[u8]) {
    if buf.is_empty() {
        println!("<<< EMPTY {} >>>", lbl);
    } else {
        println!("<<< BEGIN {} >>>", lbl);
        println!("{}", String::from_utf8_lossy(buf));
        println!("<<< END {} >>>", lbl);
    }
}

impl Executor {
    /// Evaluates whether `p` should be launched or skipped based on the CLI
    /// --skip option and on whether or not the user sent SIGINT already.
    fn launch_or_skip(&mut self, p: pot::Pot, config: &Config) {
        // If the pot contains only tests marked to be skipped  we're not executing
        // anything anymore; just produce a result that shows that we've
        // pondered running these tests but decided against.
        let result = if pot::should_skip(&p.test) {
            Some(TestResult::Skipped)
        } else if self.signaled() {
            Some(TestResult::Failed)
        } else {
            None
        };
        if let Some(r) = result {
            self.result.0.push(CompletedPot::new(
                p.derived_name.clone(),
                p.test.test_names(),
                r,
            ))
        } else {
            // If we are supposed to evaluate this task, we launch the pot into a separate
            // process and register it in our poll for further monitoring.
            let _pid = self.launch(p, config);
        }
    }

    /// Launches a process responsible for running the given pot and registers
    /// the necessary pipes in the internal poll and the [RunningPot] within
    /// `self.observing`. Returns the process id of the launched process.
    fn launch(&mut self, p: pot::Pot, cfg: &Config) -> Pid {
        let (stdout_sender, mut stdout_receiver) = pipe::new().unwrap();
        let (stderr_sender, mut stderr_receiver) = pipe::new().unwrap();
        let (mut result_sender, result_receiver) = pipe::new().unwrap();

        stdout_receiver.set_nonblocking(true).unwrap();
        stderr_receiver.set_nonblocking(true).unwrap();
        result_receiver.set_nonblocking(true).unwrap();

        // This two statements have a scope of their own to ensure
        // the lock is released.
        {
            io::stdout().lock().flush().unwrap();
            io::stderr().lock().flush().unwrap();
        }

        let pid = match unsafe { fork() }.expect("failed to fork") {
            ForkResult::Child => {
                // Setting the process group id is important: it enables us to kill the entire
                // process group, which will kill any grand-child process, when cleaning up.
                let self_pid = unistd::getpid();
                unistd::setpgid(self_pid, self_pid).expect("child: failed to set PGID");

                std::mem::drop(stdout_receiver);
                std::mem::drop(stderr_receiver);
                std::mem::drop(result_receiver);

                // When we're not running pots in parallel (cfg.jobs == 1),
                // we inherit stderr and stdout from the parent instead
                // of capturing it.
                if cfg.jobs > 1 {
                    let stdout_fd = std::io::stdout().as_raw_fd();
                    let stderr_fd = std::io::stderr().as_raw_fd();

                    unistd::close(stdout_fd).expect("child: failed to close stdout");
                    unistd::dup2(stdout_sender.as_raw_fd(), stdout_fd).unwrap();

                    unistd::close(stderr_fd).expect("child: failed to close stderr");
                    unistd::dup2(stderr_sender.as_raw_fd(), stderr_fd).unwrap();
                }

                // If the manager configuration provides us with a handle,
                // then we execute composable tests against that handle rather
                // than starting up a manager.
                let res = if let Some(h) = cfg.man_config.request_handle() {
                    println!("Calling p.run_against_handle...");
                    p.run_against_handle(&cfg.pot_config, h)
                } else {
                    println!("Calling p.run_with...");
                    p.run_with(&cfg.pot_config, cfg.man_config.clone())
                };

                serialize_and_write(&mut result_sender, &res).unwrap();
                std::process::exit(if res.is_success() { 0 } else { 1 })
            }
            ForkResult::Parent { child, .. } => child,
        };

        // If we're running more than one test at a time, we'll manage
        // each process stdout/stderr, otherwise it will just be inherited.
        if cfg.jobs > 1 {
            self.poll
                .registry()
                .register(
                    &mut stdout_receiver,
                    make_token(pid, InputSource::Stdout),
                    Interest::READABLE,
                )
                .expect("Registering stdout_receiver failed");

            self.poll
                .registry()
                .register(
                    &mut stderr_receiver,
                    make_token(pid, InputSource::Stderr),
                    Interest::READABLE,
                )
                .expect("Registering stderr receiver failed");
        }

        let obs = RunningPot {
            pid,
            pot_name: p.derived_name,
            test_names: p.test.test_names(),
            result_pipe: result_receiver,
            stdout_pipe: BufferedReader::new(stdout_receiver),
            stderr_pipe: BufferedReader::new(stderr_receiver),
            started_at: Instant::now(),
        };
        self.running.insert(pid, obs);
        pid
    }

    fn signaled(&self) -> bool {
        self.sigint_ctr > 0
    }

    /// Calls `wait(WNOHANG)` for each [RunningPot] in our state; It does _not_
    /// remove the returned pids from `self.running`. It's the callers
    /// responsibility to do so.
    fn wait(&mut self, timeout: Duration) -> BTreeMap<Pid, (Status, Duration)> {
        let mut completed_pids = BTreeMap::new();
        for (pid, obs) in self.running.iter_mut() {
            if let Some((status, dur)) = obs.wait(timeout) {
                completed_pids.insert(*pid, (status, dur));
            }
        }
        completed_pids
    }

    /// Handles sigints using our counter on how many sigints have been
    /// seen so far. The idea is that on the first sigint we
    /// forward it to the observed process in order to give it a chance to
    /// clean up. Only after the first attempt is when we try to be a little
    /// more drastic.
    fn handle_sigint(&mut self) {
        self.sigint_ctr += 1;

        let (sig, group) = match self.sigint_ctr {
            1 => (Signal::SIGINT, false),
            2 => (Signal::SIGTERM, true),
            _ => (Signal::SIGKILL, true),
        };

        self.signal_running_pots(sig, group);
    }

    /// Sends a signal to all curently running processes; the `group` flag
    /// is used to decide whther to `kill` or `killpg`.
    fn signal_running_pots(&self, sig: Signal, group: bool) {
        for (pid, _) in self.running.iter() {
            eprintln!(
                "Sending {} to process {}: {}",
                sig,
                if group { "group" } else { "id" },
                *pid
            );

            if group {
                let _ = killpg(*pid, sig);
            } else {
                let _ = kill(*pid, sig);
            }
        }
    }
}
