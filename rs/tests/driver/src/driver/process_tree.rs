//! Kills and describes the process tree of a task's subprocess through `/proc`.
//!
//! Only `/proc` files that the kernel serves without locking the memory map of
//! the process are read: `stat`, `wchan`, `syscall` and `stack`. Reading e.g.
//! `cmdline` of a process that is stuck in the kernel with its memory map locked
//! would block the reader as well. Reading `syscall` and `stack` can still block
//! while the process is in the middle of an `execve`, so [`describe`] and
//! [`describe_tree`] read `/proc` on a separate thread and give up after
//! [`DESCRIBE_TIMEOUT`].
//!
//! The pids in `/proc` are those of the PID namespace that `/proc` was mounted
//! for. When that isn't the namespace of the driver, the driver's pids would name
//! other processes, so then the tree of a process is taken to be empty and
//! nothing is described.

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::{OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

/// How long [`describe`] and [`describe_tree`] wait for `/proc` to be read.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`kill_tree`] waits, in total, for the processes it sent `SIGSTOP`
/// to stop. Threads that wait uninterruptibly in the kernel don't stop before
/// the wait ends.
const STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// The maximum number of times [`kill_tree`] looks for descendants. Stopped
/// processes don't fork, so the second look normally finds no new ones.
const MAX_STOP_ROUNDS: usize = 10;

/// `PF_EXITING` from `include/linux/sched.h`: the process is exiting, e.g.
/// because it was killed.
const PF_EXITING: u32 = 0x4;

/// The fields of a `/proc/<pid>/stat` or `/proc/<pid>/task/<tid>/stat` file
/// that are used here.
#[derive(Debug, PartialEq)]
struct Stat {
    comm: String,
    state: char,
    ppid: i32,
    flags: u32,
}

/// Parses the content of a `stat` file, see `proc_pid_stat(5)`. Its second
/// field, `comm`, can contain anything, including spaces, parentheses and bytes
/// that aren't UTF-8, so it's taken to span from the first ` (` to the last
/// `) `.
fn parse_stat(content: &[u8]) -> Option<Stat> {
    let content = String::from_utf8_lossy(content);
    let (_pid, rest) = content.split_once(" (")?;
    let (comm, rest) = rest.rsplit_once(") ")?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;
    // Skip pgrp, session, tty_nr and tpgid.
    let flags = fields.nth(4)?.parse().ok()?;
    Some(Stat {
        comm: comm.to_string(),
        state,
        ppid,
        flags,
    })
}

fn read_stat(path: &str) -> Option<Stat> {
    parse_stat(&fs::read(path).ok()?)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|content| String::from_utf8_lossy(&content).trim().to_string())
}

/// Whether `/proc` shows the PID namespace of this process.
fn proc_shows_own_pid_namespace() -> bool {
    static SHOWS_OWN: OnceLock<bool> = OnceLock::new();
    *SHOWS_OWN.get_or_init(|| {
        fs::read_link("/proc/self")
            .ok()
            .and_then(|pid| pid.to_str()?.parse::<u32>().ok())
            == Some(std::process::id())
    })
}

/// The stats of the threads of `pid`, which are none if it's gone.
fn thread_stats(pid: Pid) -> Vec<(i32, Stat)> {
    let mut tids: Vec<i32> = fs::read_dir(format!("/proc/{pid}/task"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    tids.sort_unstable();
    tids.into_iter()
        .filter_map(|tid| Some((tid, read_stat(&format!("/proc/{pid}/task/{tid}/stat"))?)))
        .collect()
}

/// Returns the descendants of `root` together with their `comm`, parents before
/// their children.
pub fn descendants(root: Pid) -> Vec<(Pid, String)> {
    if !proc_shows_own_pid_namespace() {
        return vec![];
    }
    let mut children: BTreeMap<i32, Vec<(i32, String)>> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            // A process that exits during the scan has no `stat` anymore and is skipped.
            if let Some(stat) = read_stat(&format!("/proc/{pid}/stat")) {
                children
                    .entry(stat.ppid)
                    .or_default()
                    .push((pid, stat.comm));
            }
        }
    }
    let mut descendants = vec![];
    let mut parents = vec![root.as_raw()];
    while let Some(parent) = parents.pop() {
        for (pid, comm) in children.remove(&parent).unwrap_or_default() {
            parents.push(pid);
            descendants.push((Pid::from_raw(pid), comm));
        }
    }
    descendants
}

/// Kills `root` and its descendants with `SIGKILL` and returns the descendants
/// together with their `comm`.
///
/// The descendants are found through `/proc`, rather than by putting `root` in
/// a process group of its own and killing the group, so that signals sent to
/// the process group of the driver, e.g. by Ctrl-C or by Bazel when it stops
/// the test, still reach them. The price is that only the processes that are
/// still in the tree are killed: not a process whose parent exited, which is
/// reparented out of the tree, like a daemon that forked twice.
///
/// The tree is stopped with `SIGSTOP` first, until no new descendants show up,
/// and only then killed. Otherwise a descendant could fork a child after the tree
/// was looked up, and killing a parent reparents its children out of the tree
/// before they could be found.
pub fn kill_tree(root: Pid) -> Vec<(Pid, String)> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let _ = kill(root, Signal::SIGSTOP);
    let mut tree: Vec<(Pid, String)> = vec![];
    let mut stopped = BTreeSet::from([root]);
    for _ in 0..MAX_STOP_ROUNDS {
        // A process that was sent `SIGSTOP` can still be in the middle of a fork,
        // whose child only shows up once the fork completes, so look for new
        // descendants only after the processes stopped.
        for pid in &stopped {
            while !is_stopped(*pid) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
        }
        let new: Vec<_> = descendants(root)
            .into_iter()
            .filter(|(pid, _)| !stopped.contains(pid))
            .collect();
        if new.is_empty() {
            break;
        }
        for (pid, _) in &new {
            let _ = kill(*pid, Signal::SIGSTOP);
            stopped.insert(*pid);
        }
        tree.extend(new);
    }
    let _ = kill(root, Signal::SIGKILL);
    for (pid, _) in &tree {
        let _ = kill(*pid, Signal::SIGKILL);
    }
    tree
}

/// Whether all threads of `pid` are stopped, traced or dead, which they all are
/// once it's gone.
fn is_stopped(pid: Pid) -> bool {
    thread_stats(pid)
        .iter()
        .all(|(_, stat)| matches!(stat.state, 'T' | 't' | 'Z' | 'X'))
}

/// Like [`describe`] for `root` and its descendants.
pub fn describe_tree(root: Pid) -> String {
    on_helper_thread(move || {
        let pids = std::iter::once(root)
            .chain(descendants(root).into_iter().map(|(pid, _)| pid))
            .collect();
        describe_now(pids)
    })
}

/// Describes what the threads of the given processes are doing in the kernel,
/// to show where they are stuck. It lists, per thread:
///
/// * its state: `R`unning, `S`leeping interruptibly, waiting uninterruptibly
///   (`D`), s`T`opped, ...;
/// * the kernel function it waits in (`wchan`);
/// * the content of its `/proc/<pid>/task/<tid>/syscall` file, if the driver may
///   trace it: the number and the arguments of the system call it is in, or `-1`
///   when it waits outside of a system call, e.g. on a page fault, or `running`,
///   each followed by its stack pointer and program counter in user space;
/// * its kernel stack, if readable, which takes `CAP_SYS_ADMIN` in the initial
///   user namespace.
///
/// Threads that sleep interruptibly, as idle threads do, are only counted per
/// `comm`, wait channel and system call number. The kernel release and the
/// system-wide pressure stall information come first.
pub fn describe(pids: Vec<Pid>) -> String {
    on_helper_thread(move || describe_now(pids))
}

fn on_helper_thread(f: impl FnOnce() -> String + Send + 'static) -> String {
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("describe-procs".to_string())
        .spawn(move || {
            let _ = sender.send(f());
        });
    if let Err(err) = spawned {
        return format!("Could not spawn a thread to read /proc: {err}");
    }
    receiver
        .recv_timeout(DESCRIBE_TIMEOUT)
        .unwrap_or_else(|_| format!("Reading /proc did not finish within {DESCRIBE_TIMEOUT:?}"))
}

fn describe_now(pids: Vec<Pid>) -> String {
    if !proc_shows_own_pid_namespace() {
        return "Can't describe the processes: /proc shows another PID namespace than the driver's"
            .to_string();
    }
    let mut lines = vec![];
    if let Some(release) = read_trimmed("/proc/sys/kernel/osrelease") {
        lines.push(format!("kernel release: {release}"));
    }
    for resource in ["cpu", "memory", "io"] {
        if let Some(pressure) = read_trimmed(&format!("/proc/pressure/{resource}")) {
            lines.push(format!(
                "{resource} pressure: {}",
                pressure.replace('\n', "; ")
            ));
        }
    }
    for pid in pids {
        describe_process(pid, &mut lines);
    }
    lines.join("\n")
}

fn describe_process(pid: Pid, lines: &mut Vec<String>) {
    let Some(process) = read_stat(&format!("/proc/{pid}/stat")) else {
        lines.push(format!("process {pid}: no longer exists"));
        return;
    };
    let exiting = if process.flags & PF_EXITING != 0 {
        ", exiting"
    } else {
        ""
    };
    lines.push(format!(
        "process {pid} ({}): state {}{exiting}",
        process.comm, process.state
    ));
    // The number of interruptibly sleeping threads per comm, wait channel and system call number.
    let mut sleeping: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (tid, thread) in thread_stats(pid) {
        let dir = format!("/proc/{pid}/task/{tid}");
        let wchan = read_trimmed(&format!("{dir}/wchan")).unwrap_or_else(|| "?".to_string());
        let syscall = read_trimmed(&format!("{dir}/syscall")).unwrap_or_else(|| "?".to_string());
        if thread.state == 'S' {
            let number = syscall.split_whitespace().next().unwrap_or("?").to_string();
            *sleeping.entry((thread.comm, wchan, number)).or_default() += 1;
            continue;
        }
        lines.push(format!(
            "  thread {tid} ({}): state {}, wchan {wchan}, syscall {syscall}",
            thread.comm, thread.state
        ));
        if let Some(stack) = read_trimmed(&format!("{dir}/stack")) {
            lines.extend(stack.lines().map(|frame| format!("    {frame}")));
        }
    }
    for ((comm, wchan, number), count) in sleeping {
        lines.push(format!(
            "  {count} thread(s) ({comm}): state S, wchan {wchan}, syscall {number}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
        path::Path,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn parses_stat_with_parentheses_and_spaces_in_comm() {
        let content = b"4242 (a) (b c) S 17 4242 4242 0 -1 4194564 \
                        139 0 0 0 0 0 0 0 20 0 1 0 1234 2195456 124 \
                        18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(
            parse_stat(content),
            Some(Stat {
                comm: "a) (b c".to_string(),
                state: 'S',
                ppid: 17,
                flags: 4194564,
            })
        );
    }

    #[test]
    fn parses_stat_with_comm_that_is_not_utf8() {
        // `comm` is cut to 15 bytes, which can split a multi-byte character.
        let content = b"4242 (abcdefghijklmn\xc3) R 17 4242 4242 0 -1 4194304 0 0";
        let stat = parse_stat(content).unwrap();
        assert_eq!((stat.state, stat.ppid, stat.flags), ('R', 17, 4194304));
    }

    #[test]
    fn rejects_truncated_stat() {
        assert_eq!(parse_stat(b"4242 (sh) S 17"), None);
        assert_eq!(parse_stat(b""), None);
    }

    #[test]
    fn proc_shows_the_pid_namespace_of_the_tests() {
        // Otherwise the tests below can't find any descendants.
        assert!(proc_shows_own_pid_namespace());
    }

    /// Spawns a shell with two `sleep` children and waits until both are forked.
    fn spawn_tree() -> Child {
        let mut shell = Command::new("sh")
            .args(["-c", "sleep 1000 & sleep 1000 & echo forked; wait"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(shell.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "forked\n");
        shell
    }

    fn pid_of(child: &Child) -> Pid {
        Pid::from_raw(child.id() as i32)
    }

    /// Whether `pid` is gone or a zombie, i.e. was killed but not yet reaped.
    fn is_dead(pid: Pid) -> bool {
        read_stat(&format!("/proc/{pid}/stat")).is_none_or(|stat| stat.state == 'Z')
    }

    /// Waits until all processes are dead, see [`is_dead`].
    fn assert_all_die(pids: impl IntoIterator<Item = Pid>) {
        let deadline = Instant::now() + Duration::from_secs(30);
        for pid in pids {
            while !is_dead(pid) {
                assert!(Instant::now() < deadline, "process {pid} survived");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn kill_tree_kills_all_descendants() {
        let mut shell = spawn_tree();
        let shell_pid = pid_of(&shell);
        let sleeps = descendants(shell_pid);
        assert_eq!(sleeps.len(), 2, "{sleeps:?}");

        let killed = kill_tree(shell_pid);

        assert_eq!(
            killed.iter().map(|(pid, _)| *pid).collect::<BTreeSet<_>>(),
            sleeps.iter().map(|(pid, _)| *pid).collect::<BTreeSet<_>>()
        );
        assert_eq!(shell.wait().unwrap().signal(), Some(libc::SIGKILL));
        // Once the shell is gone, its children are reaped by whoever adopts them.
        assert_all_die(killed.into_iter().map(|(pid, _)| pid));
    }

    /// The live processes whose `comm` is `comm`.
    fn live_processes_named(comm: &str) -> Vec<Pid> {
        fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
            .map(Pid::from_raw)
            .filter(|pid| {
                read_stat(&format!("/proc/{pid}/stat"))
                    .is_some_and(|stat| stat.comm == comm && stat.state != 'Z')
            })
            .collect()
    }

    /// A link to `sleep` with a name of its own in a new temporary directory, to
    /// tell the `sleep`s that run as the link apart from other processes: the
    /// name becomes their `comm`. Returns the directory, the link and the name.
    fn sleep_link(prefix: &str) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let dir = tempfile::tempdir().unwrap();
        let comm = format!("{prefix}{}", std::process::id() % 100_000);
        let link = dir.path().join(&comm);
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .expect("sleep should be installed");
        std::os::unix::fs::symlink(sleep, &link).unwrap();
        (dir, link, comm)
    }

    /// Asserts that no process named `comm` is alive once the processes that were
    /// killed had a moment to die, and kills the ones that are.
    fn assert_none_survives(comm: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut survivors = live_processes_named(comm);
        while !survivors.is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
            survivors = live_processes_named(comm);
        }
        for pid in &survivors {
            let _ = kill(*pid, Signal::SIGKILL);
        }
        assert!(survivors.is_empty(), "kill_tree left {survivors:?} alive");
    }

    #[test]
    fn kill_tree_kills_a_tree_that_keeps_forking() {
        // The shell starts a `sleep` in the background every millisecond.
        let (_dir, link, comm) = sleep_link("ktmany");
        for _ in 0..10 {
            let mut shell = Command::new("sh")
                .args(["-c", r#"while :; do "$0" 1000 & sleep 0.001; done"#])
                .arg(&link)
                .spawn()
                .unwrap();
            thread::sleep(Duration::from_millis(50));

            kill_tree(pid_of(&shell));

            assert_eq!(shell.wait().unwrap().signal(), Some(libc::SIGKILL));
            assert_none_survives(&comm);
        }
    }

    /// Forks a process that forks a child and kills it right away, over and over.
    /// So the process is in the middle of a fork most of the time, like a process
    /// that is starting a subprocess when it's killed. Each child names itself
    /// `comm` and sleeps.
    fn fork_forker(comm: &CStr) -> Pid {
        // The child of a fork of the multi-threaded test process may only call
        // async-signal-safe functions.
        match unsafe { libc::fork() } {
            0 => loop {
                match unsafe { libc::fork() } {
                    0 => unsafe {
                        libc::prctl(libc::PR_SET_NAME, comm.as_ptr());
                        libc::sleep(1000);
                        libc::_exit(0);
                    },
                    child if child > 0 => unsafe {
                        libc::kill(child, libc::SIGKILL);
                        libc::waitpid(child, std::ptr::null_mut(), 0);
                    },
                    _ => {}
                }
            },
            pid if pid > 0 => Pid::from_raw(pid),
            _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
        }
    }

    #[test]
    fn kill_tree_kills_a_child_that_is_being_forked() {
        // The child of a fork that is in progress when `SIGSTOP` is sent only
        // shows up once the fork completes.
        let comm = CString::new(format!("ktfork{}", std::process::id() % 100_000)).unwrap();
        for i in 0..100 {
            let forker = fork_forker(&comm);
            thread::sleep(Duration::from_micros(2000 + i * 37 % 3000));

            kill_tree(forker);

            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(forker.as_raw(), &mut status, 0) },
                forker.as_raw()
            );
            assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
        }
        // A child that escaped needs a moment to name itself.
        thread::sleep(Duration::from_millis(100));
        assert_none_survives(comm.to_str().unwrap());
    }

    #[test]
    fn describe_tree_lists_root_and_descendants() {
        let mut shell = spawn_tree();
        let shell_pid = pid_of(&shell);
        let sleeps = descendants(shell_pid);

        let description = describe_tree(shell_pid);

        kill_tree(shell_pid);
        let _ = shell.wait();
        assert!(
            description.contains(&format!("process {shell_pid} (sh): state ")),
            "{description}"
        );
        for (pid, _) in sleeps {
            assert!(
                description.contains(&format!("process {pid} (")),
                "{description}"
            );
        }
    }

    #[test]
    fn describe_reports_processes_that_no_longer_exist() {
        let mut shell = Command::new("true").spawn().unwrap();
        let pid = pid_of(&shell);
        shell.wait().unwrap();

        let description = describe(vec![pid]);

        assert!(
            description.contains(&format!("process {pid}: no longer exists")),
            "{description}"
        );
    }
}
