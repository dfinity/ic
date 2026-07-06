//! Per-group console-log streamer for the Local system-test backend.
//!
//! Each VM booted by the [`LocalBackend`](crate::driver::local_backend::LocalBackend)
//! has its serial console captured by QEMU into a `console.log` file (see the
//! `-chardev file,...,append=on` / `-device isa-serial` args built in
//! [`LocalBackend::start_vm`](crate::driver::local_backend::LocalBackend::start_vm)).
//! This task discovers those files and tails each of them to the test log,
//! prefixing every line with `[console=<vm>]`.
//!
//! Discovery is event-based: an `inotify` watch on the per-group `vms` directory
//! spawns a tailer the instant a VM's directory is created — before the VM has
//! even written its first console line — so the streamed lines are emitted (and
//! thus timestamped in the test log) close to when the VM actually produced
//! them. A one-time directory scan right after the watch is armed covers any VM
//! directory that was created before the watch, so no periodic rescan is needed.
//!
//! It is the console-log counterpart of
//! [`logs_stream_task`](crate::driver::logs_stream_task): both never return and
//! are wired into the plan as a supervisor over the setup → tests → teardown
//! subtree, so the task scheduler silently kills them once that subtree
//! finishes (this is not treated as a failure).
//!
//! Console streaming is opt-in via the `--stream-console-logs` CLI flag, which
//! is only set by the Local backend (`system_test(... )`'s `_local` variant in
//! `rs/tests/system_tests.bzl`). On Farm the task is an
//! [`EmptyTask`](crate::driver::task::EmptyTask) and never runs; even if it did,
//! the `local_backend/vms` directory it scans simply would not exist.

use crate::driver::context::GroupContext;
use futures::StreamExt;
use inotify::{EventMask, Inotify, WatchMask};
use regex::Regex;
use slog::{Logger, debug, error, info};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    runtime::Runtime,
};

pub(crate) const LOG_CONSOLES_TASK_NAME: &str = "log_consoles";

/// How long the wait loop sleeps while waiting for the Local backend to create
/// the `local_backend/vms` directory (before any VM exists).
const RETRY_DELAY_WAIT_VMS_DIR: Duration = Duration::from_millis(200);
/// How long to wait before retrying when the console file is not yet present or
/// has to be reopened after a read error.
const RETRY_DELAY_WAIT_CONSOLE: Duration = Duration::from_millis(200);
/// Size of the buffer used to read `inotify` events. Each event is a 16-byte
/// header plus a short, NUL-padded name, so this holds many events at once.
const INOTIFY_BUF_LEN: usize = 4096;

pub(crate) fn log_consoles_task(group_ctx: GroupContext) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {LOG_CONSOLES_TASK_NAME}");

    let rt: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));

    // The Local backend materializes each VM under
    // `<group_dir>/local_backend/vms/<sanitized_vm_name>/`, writing the serial
    // console to `console.log` in that directory (see
    // `LocalBackend::vm_dir` / `start_vm` in `local_backend.rs`). We derive the
    // directory path directly; the backend owns and populates it.
    let vms_dir = group_ctx.group_dir.join("local_backend").join("vms");

    // Wait for the backend to create `vms_dir`. It is created lazily, together
    // with the first VM's directory (`create_vm` / `attach_disk_images` in
    // `local_backend.rs`), so we watch it rather than create it ourselves — the
    // directory is owned by the backend. The `inotify` watch must be armed on an
    // existing directory.
    while !vms_dir.exists() {
        std::thread::sleep(RETRY_DELAY_WAIT_VMS_DIR);
    }

    let mut streamed: BTreeSet<String> = BTreeSet::new();
    let mut skipped: BTreeSet<String> = BTreeSet::new();

    // Event-based discovery via `inotify`. This never returns: the happy path
    // blocks on `inotify` events forever (until the task scheduler kills this
    // subprocess), and any `inotify` failure panics rather than degrading to a
    // slower polling mode.
    watch_consoles(
        &vms_dir,
        &mut streamed,
        &mut skipped,
        &group_ctx.exclude_logs,
        &rt,
        &logger,
    );
}

/// Watches `vms_dir` with `inotify` and spawns a console tailer the instant a
/// new VM directory appears, so the tailer is already following `console.log`
/// before the VM writes its first line.
///
/// Never returns: the happy path blocks on `inotify` events forever (until the
/// task scheduler kills this subprocess). Any `inotify` failure panics.
fn watch_consoles(
    vms_dir: &Path,
    streamed: &mut BTreeSet<String>,
    skipped: &mut BTreeSet<String>,
    exclude_logs: &[Regex],
    rt: &Runtime,
    logger: &Logger,
) -> ! {
    let mut inotify = Inotify::init().expect("failed to initialize inotify");

    // Watch for directory creation directly under `vms_dir`. Every direct child
    // there is a per-VM directory; the backend creates them with `mkdir`
    // (`CREATE`), but we also accept `MOVED_TO` to be robust against a future
    // create-then-rename. The watch is non-recursive: files created *inside* a
    // VM directory (e.g. `console.log`) do not generate events, which is exactly
    // why the tailer is spawned on directory creation and then waits for
    // `console.log` to appear.
    inotify
        .watches()
        .add(vms_dir, WatchMask::CREATE | WatchMask::MOVED_TO)
        .unwrap_or_else(|err| panic!("failed to watch {}: {err}", vms_dir.display()));

    // One-time scan AFTER arming the watch: a VM directory created before the
    // watch — notably the first one, created together with `vms_dir` itself —
    // produced an event we never saw. Scanning now catches those; any overlap
    // with buffered events is deduplicated via `streamed`/`skipped`. Events that
    // occur from here on are queued by the kernel until we read them, so nothing
    // is missed in the gap before the loop below.
    match discover_vm_dirs(vms_dir) {
        Ok(discovered) => {
            process_discovered(discovered, streamed, skipped, exclude_logs, rt, logger)
        }
        Err(err) => debug!(logger, "Initial VM directory scan failed: {err}"),
    }

    let mut buffer = [0_u8; INOTIFY_BUF_LEN];
    loop {
        let events = inotify
            .read_events_blocking(&mut buffer)
            .expect("failed to read inotify events");
        let mut discovered: HashMap<String, PathBuf> = HashMap::new();
        for event in events {
            // Only directory-creation events name a new VM; `console.log` lives
            // one level below the watched directory and is picked up by the
            // tailer, not by `inotify`.
            if event.mask.contains(EventMask::ISDIR)
                && let Some(name) = event.name
            {
                let name = name.to_string_lossy().into_owned();
                let console = vms_dir.join(&name).join("console.log");
                discovered.insert(name, console);
            }
        }
        process_discovered(discovered, streamed, skipped, exclude_logs, rt, logger);
    }
}

/// Returns a map from VM name (the sanitized per-VM directory name) to the path
/// of its `console.log` for every VM directory currently present, regardless of
/// whether `console.log` exists yet (the tailer waits for it).
fn discover_vm_dirs(vms_dir: &Path) -> std::io::Result<HashMap<String, PathBuf>> {
    let mut consoles: HashMap<String, PathBuf> = HashMap::new();
    for entry in std::fs::read_dir(vms_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let console = entry.path().join("console.log");
            consoles.insert(name, console);
        }
    }
    Ok(consoles)
}

/// Spawns a console-tailing task for every newly discovered VM, deduplicating
/// against `streamed` and honoring the `--exclude-logs` patterns (recorded in
/// `skipped`).
fn process_discovered(
    discovered: HashMap<String, PathBuf>,
    streamed: &mut BTreeSet<String>,
    skipped: &mut BTreeSet<String>,
    exclude_logs: &[Regex],
    rt: &Runtime,
    logger: &Logger,
) {
    for (name, path) in discovered {
        if streamed.contains(&name) || skipped.contains(&name) {
            continue;
        }

        if exclude_logs.iter().any(|pattern| pattern.is_match(&name)) {
            debug!(
                logger,
                "Skipping console streaming of [console={name}] because it was excluded by the `--exclude-logs` pattern"
            );
            skipped.insert(name);
            continue;
        }

        info!(
            logger,
            "Streaming console log for newly discovered VM [console={name}] from {}",
            path.display()
        );
        streamed.insert(name.clone());
        // The task starts, but the handle is never joined.
        rt.spawn(stream_console_file(logger.clone(), name, path));
    }
}

/// Matches ANSI/VT terminal escape sequences that appear on the serial console
/// (SGR colour codes, cursor movement, OSC strings, charset designations, ...).
/// Removing them keeps the streamed test log readable as plain text.
static ANSI_ESCAPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
          \x1b \] [^\x07\x1b]* (?: \x07 | \x1b \\ )         # OSC: ESC ] ... BEL or ST
        | \x1b [\x40-\x5a\x5c-\x5f]                          # Fe:  two-character escape
        | \x1b \[ [\x30-\x3f]* [\x20-\x2f]* [\x40-\x7e]      # CSI: ESC [ params final
        | \x1b [\x20-\x2f]+ [\x30-\x7e]                      # nF:  charset designation
        ",
    )
    .expect("valid ANSI escape regex")
});

/// Strips terminal control codes from a console line so the test log stays
/// readable: ANSI/VT escape sequences are removed via [`ANSI_ESCAPE_RE`], and
/// any remaining lone control characters (carriage returns, backspaces, bells,
/// NULs, ...) are dropped. Tabs are preserved.
fn strip_control_codes(line: &str) -> String {
    ANSI_ESCAPE_RE
        .replace_all(line, "")
        .chars()
        .filter(|c| *c == '\t' || !c.is_control())
        .collect()
}

/// Tails `path` forever, printing every complete line to stdout (which is
/// captured into the test log) prefixed with `[console=<label>]`.
///
/// The console file is written with `append='on'`, so it only ever grows: a VM
/// restart (e.g. a guest-initiated reboot under the Local backend) appends to it
/// rather than truncating it. This lets us tail it like `tail -f`, keeping a
/// byte offset only to resume after a (rare) read error.
///
/// Rather than polling at end-of-file, the tailer arms an `inotify` `MODIFY`
/// watch on the file and awaits it, so a newly appended line is emitted with
/// essentially no delay. The watch is armed before each read reaches EOF, so an
/// append that lands in the gap between hitting EOF and awaiting the next event
/// is already queued by the kernel and wakes us immediately — no line is missed.
async fn stream_console_file(logger: Logger, label: String, path: PathBuf) {
    // Arm a `MODIFY` watch on the console file. It appears slightly after the VM
    // directory (when the backend launches QEMU), so retry until it exists: a
    // failed `add` (ENOENT) doubles as the wait for the file to be created.
    let inotify = Inotify::init().expect("failed to initialize inotify");
    while let Err(_err) = inotify.watches().add(&path, WatchMask::MODIFY) {
        tokio::time::sleep(RETRY_DELAY_WAIT_CONSOLE).await;
    }
    let mut events = inotify
        .into_event_stream([0_u8; INOTIFY_BUF_LEN])
        .expect("failed to create inotify event stream");

    let mut offset: u64 = 0;
    loop {
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) => {
                // The file may briefly disappear/reappear; retry quietly.
                debug!(
                    logger,
                    "Opening console log for [console={label}] failed ({err}); retrying ..."
                );
                tokio::time::sleep(RETRY_DELAY_WAIT_CONSOLE).await;
                continue;
            }
        };

        if offset > 0
            && let Err(err) = file.seek(std::io::SeekFrom::Start(offset)).await
        {
            error!(
                logger,
                "Seeking console log for [console={label}] to offset {offset} failed: {err}"
            );
            offset = 0;
        }

        let mut reader = BufReader::new(file);
        // Accumulates the current line across reads so that a line that is only
        // partially flushed at EOF is printed once, in full, rather than split.
        let mut line = String::new();
        loop {
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF: block until the file is appended to, then read again.
                    // The `MODIFY` watch was armed before this read, so an append
                    // since the last read is already queued and wakes us at once.
                    match events.next().await {
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            error!(
                                logger,
                                "Watching console log for [console={label}] failed: {err}; reopening ..."
                            );
                            break;
                        }
                        // The stream only ends if the inotify instance is
                        // dropped, which never happens here; bail out cleanly.
                        None => return,
                    }
                }
                Ok(n) => {
                    offset += n as u64;
                    if line.ends_with('\n') {
                        let trimmed = line.trim_end_matches(['\n', '\r']);
                        let cleaned = strip_control_codes(trimmed);
                        info!(logger, "[console={label}] {cleaned}");
                        line.clear();
                    }
                    // Otherwise the line is incomplete (no trailing newline yet);
                    // keep accumulating into `line` on the next read.
                }
                Err(err) => {
                    error!(
                        logger,
                        "Reading console log for [console={label}] failed: {err}; reopening ..."
                    );
                    break;
                }
            }
        }

        // The inner loop only breaks on a read/watch error; pause briefly before
        // reopening to avoid a hot loop.
        tokio::time::sleep(RETRY_DELAY_WAIT_CONSOLE).await;
    }
}
