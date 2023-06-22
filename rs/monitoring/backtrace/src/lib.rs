//! In-process support for retrieving stack traces for all threads.

use lazy_static::lazy_static;
use regex::Regex;
use rstack_self::Trace;
use std::env;
use std::process::Command;
use std::sync::Once;

/// Command line flag passed to child processes.
const FLAG_IC_BACKTRACE: &str = "--ic_backtrace";

/// One time flag to be set by `init()` and checked by `collect()`.
static INIT_CALLED: Once = Once::new();

/// Produces a stack trace of all threads of this process. Returns an error if
/// `init()` has not been called during process startup; or if collection fails
/// for some other reason.
///
/// Because processes cannot `ptrace` themselves, we spawn a child process
/// running the same executable to do the actual collection.
///
/// In order to differentiate between the regular process and a child process,
/// we pass the latter an `--ic_backtrace` command line argument. The logic to
/// intercept that command line flag, collect the parent process' stack traces
/// and exit is in `init()`, which must be called at process start time.
pub fn collect() -> Result<Trace, String> {
    if !INIT_CALLED.is_completed() {
        return Err("init() must be called at process startup".into());
    }

    let exe = env::current_exe().unwrap();
    rstack_self::trace(Command::new(exe).arg(FLAG_IC_BACKTRACE)).map_err(|e| e.to_string())
}

/// Produces a formatted stack trace of all threads of this process.
///
/// See [`collect()`] for details.
pub fn collect_fmt() -> Result<String, String> {
    lazy_static! {
        // For some reason, most (but not all) symbol names appear to have something
        // like a hash suffix, e.g. `std::panicking::try::ha8949d2082cf3644`. Drop it.
        static ref NAME_HASH_RE: Regex = Regex::new(r"::h[0-9a-f]{16}$").unwrap();
    }

    match collect() {
        Ok(trace) => {
            use std::fmt::Write;

            let mut buf = String::new();
            for thread in trace.threads() {
                writeln!(buf, "Thread {} [{}]", thread.id(), thread.name()).unwrap();
                for frame in thread.frames() {
                    for symbol in frame.symbols() {
                        // If the name has a hash suffix (like `::h0123456789abcdef`) drop it.
                        let mut name = symbol.name().unwrap_or("????");
                        if NAME_HASH_RE.is_match(name) {
                            name = &name[..name.len() - 19];
                        }
                        writeln!(buf, "\t{:#016x} - {}", frame.ip(), name).unwrap();

                        if let Some(file) = symbol.file() {
                            writeln!(
                                buf,
                                "\t\t\t\tat {}:{}",
                                file.display(),
                                symbol.line().unwrap_or(0)
                            )
                            .unwrap();
                        }
                    }
                }
                buf.push('\n');
            }
            Ok(buf)
        }

        Err(e) => Err(format!("Thread dump failed: {:#?}", e)),
    }
}

/// Must be called during startup by any process that may want to call
/// `collect()` at a later point. Because processes cannot `ptrace` themselves,
/// we spawn a child process to do the work. This is the hook for that child
/// process (to dump the stack traces and exit) and a no-op for the process
/// itself.
///
/// If this is a child process (i.e. it has an `--ic_backtrace` command line
/// argument), the function collects a stack trace of the parent process
/// (`ppid`); outputs it `bincode`-encoded to `stdout`; and exits.
///
/// If this is not a child process (i.e. no `--ic_backtrace` command line
/// argument), then it is basically a no-op (except for setting a flac that is
/// later checked by `collect()`).
///
/// ## Panics
/// If this is a child process but parent process stack trace collection fails.
pub fn init() {
    // Remember that `init()` was called. This is not a guarantee that it will
    // necessarily be called by a child process, but it's a good indication.
    INIT_CALLED.call_once(|| {});

    // If any command line argument is `FLAG_IC_BACKTRACE`, either dump the parent
    // thread stacks and exit; or panic.
    for arg in env::args().skip(1) {
        if arg == FLAG_IC_BACKTRACE {
            match rstack_self::child() {
                Ok(()) => std::process::exit(0),
                Err(e) => panic!("Failed to collect parent process stack traces: {}", e),
            }
        }
    }
}
