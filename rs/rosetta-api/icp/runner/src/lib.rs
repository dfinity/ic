pub mod constants;
use crate::constants::{
    MAX_START_ATTEMPTS, NUM_TRIES, START_TIMEOUT, WAIT_BETWEEN_ATTEMPTS,
    WAIT_BETWEEN_START_ATTEMPTS,
};
use candid::Principal;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::str::FromStr;
use std::time::Instant;
use tempfile::TempDir;
use tokio::time::sleep;

struct KillOnDrop(Child);

impl KillOnDrop {
    /// Returns the exit status of the Rosetta process if it has exited.
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, StartAttemptError> {
        self.0.try_wait().map_err(|e| {
            StartAttemptError::fatal(format!("Failed to poll the Rosetta process: {e}"))
        })
    }
}

pub struct RosettaContext {
    proc: KillOnDrop,
    pub state_directory: TempDir,
    pub port: u16,
}

impl RosettaContext {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Kills the process in which the rosetta server and blocks synchronizer are running.
    /// Leaves the state directory untouched.
    /// This is useful when you want to restart the rosetta server with the same state directory. (Load existing blocks from storage)
    pub fn kill_rosetta_process(&mut self) {
        self.proc.0.kill().expect("Failed to kill rosetta process");
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // A process that has already exited (and been reaped by `try_wait`) can't be killed.
        if let Ok(Some(status)) = self.0.try_wait() {
            println!("Rosetta had already exited with {status}");
            return;
        }
        match self.0.kill() {
            Ok(_) => println!("Rosetta has been successfully stopped"),
            Err(err) => println!("Rosetta was NOT successfully stopped: {err:?}"),
        }
    }
}

pub struct RosettaOptions {
    pub ledger_id: Option<Principal>,

    pub store_type: String,

    pub ic_url: String,

    pub offline: bool,
}

impl RosettaOptions {
    pub fn builder(ic_url: String) -> RosettaOptionsBuilder {
        RosettaOptionsBuilder::new(ic_url)
    }
}

pub struct RosettaOptionsBuilder {
    ledger_id: Option<Principal>,
    persistent_storage: bool,
    ic_url: String,
    offline: bool,
}

impl RosettaOptionsBuilder {
    pub fn new(ic_url: String) -> Self {
        RosettaOptionsBuilder {
            ledger_id: None,
            persistent_storage: false,
            ic_url,
            offline: false,
        }
    }

    pub fn with_ledger_id(mut self, ledger_id: Principal) -> Self {
        self.ledger_id = Some(ledger_id);
        self
    }

    pub fn with_persistent_storage(mut self) -> Self {
        self.persistent_storage = true;
        self
    }

    pub fn offline(mut self) -> Self {
        self.offline = true;
        self
    }

    pub fn build(self) -> RosettaOptions {
        RosettaOptions {
            ledger_id: self.ledger_id,
            store_type: if self.persistent_storage {
                "sqlite".to_string()
            } else {
                "sqlite-in-memory".to_string()
            },
            ic_url: self.ic_url,
            offline: self.offline,
        }
    }
}

/// Why an attempt to start Rosetta failed.
struct StartAttemptError {
    message: String,
    /// Whether another attempt makes sense. Only an early exit of the Rosetta
    /// process (e.g. because the replica was temporarily unreachable) is worth
    /// retrying; running out of time or failing to poll the process is not.
    retryable: bool,
}

impl StartAttemptError {
    fn exited(message: String) -> Self {
        Self {
            message,
            retryable: true,
        }
    }

    fn fatal(message: String) -> Self {
        Self {
            message,
            retryable: false,
        }
    }
}

/// Starts Rosetta and waits until it serves `/network/list`.
///
/// Rosetta exits (with a panic) when it can't reach the ledger while
/// initializing, e.g. because the (PocketIC) replica is temporarily
/// unresponsive, and it only writes its port file after that initialization.
/// Such an early exit is therefore detected instead of waiting forever for a
/// port file that will never appear, and starting Rosetta is retried up to
/// [`MAX_START_ATTEMPTS`] times. All attempts together are bounded by
/// [`START_TIMEOUT`], after which this function panics with a descriptive
/// message instead of hanging until the bazel test timeout.
pub async fn start_rosetta(
    rosetta_bin: &Path,
    state_directory: TempDir,
    arguments: RosettaOptions,
) -> RosettaContext {
    assert!(
        rosetta_bin.exists(),
        "ic-rosetta-api path {} does not exist",
        rosetta_bin.display()
    );

    let port_file = state_directory.path().join("port");
    let deadline = Instant::now() + START_TIMEOUT;
    let mut attempt = 1;
    loop {
        match try_start_rosetta(
            rosetta_bin,
            &state_directory,
            &port_file,
            &arguments,
            deadline,
        )
        .await
        {
            Ok((proc, port)) => {
                return RosettaContext {
                    proc,
                    state_directory,
                    port,
                };
            }
            Err(err)
                if err.retryable
                    && attempt < MAX_START_ATTEMPTS
                    && Instant::now() + WAIT_BETWEEN_START_ATTEMPTS < deadline =>
            {
                eprintln!(
                    "Failed to start Rosetta (attempt {attempt}/{MAX_START_ATTEMPTS}): {}. \
                     Retrying in {WAIT_BETWEEN_START_ATTEMPTS:?}...",
                    err.message
                );
                attempt += 1;
                sleep(WAIT_BETWEEN_START_ATTEMPTS).await;
            }
            Err(err) if err.retryable && attempt >= MAX_START_ATTEMPTS => {
                panic!(
                    "Failed to start Rosetta after {MAX_START_ATTEMPTS} attempts: {}",
                    err.message
                )
            }
            Err(err) => {
                panic!(
                    "Failed to start Rosetta within {START_TIMEOUT:?} ({attempt} attempt(s)): {}",
                    err.message
                )
            }
        }
    }
}

/// Spawns Rosetta once and waits until it serves `/network/list`.
///
/// Returns an error when the Rosetta process exits (retryable), when the
/// `deadline` passes before it serves `/network/list`, or when it doesn't
/// become ready within [`NUM_TRIES`] readiness probes. The spawned process is
/// killed when the returned [`KillOnDrop`] is dropped, so a failed attempt
/// leaves no process behind.
async fn try_start_rosetta(
    rosetta_bin: &Path,
    state_directory: &TempDir,
    port_file: &Path,
    arguments: &RosettaOptions,
    deadline: Instant,
) -> Result<(KillOnDrop, u16), StartAttemptError> {
    if port_file.exists()
        && let Err(e) = std::fs::remove_file(port_file)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        panic!("Unable to remove port file: {e:?}");
    }

    let mut cmd = Command::new(rosetta_bin);
    cmd.arg("--ic-url")
        .arg(&arguments.ic_url)
        .arg("--port-file")
        .arg(port_file)
        .arg("--store-type")
        .arg(arguments.store_type.clone());

    if arguments.store_type == "sqlite" {
        cmd.arg("--store-location")
            .arg(std::fs::canonicalize(state_directory).unwrap());
    }

    if let Some(ledger_id) = arguments.ledger_id {
        cmd.arg("--canister-id").arg(ledger_id.to_string());
    }

    if arguments.offline {
        cmd.arg("--offline");
    }

    let mut proc = KillOnDrop(cmd.spawn().unwrap_or_else(|e| {
        panic!(
            "Failed to execute ic-rosetta-api (path = {}, exists? = {}): {}",
            rosetta_bin.display(),
            rosetta_bin.exists(),
            e
        )
    }));

    // Rosetta only writes its port file after it has successfully initialized
    // its ledger client, so if it dies before that the file never appears.
    let port = loop {
        if let Some(port) = read_port(port_file) {
            break port;
        }
        if let Some(status) = proc.try_wait()? {
            return Err(StartAttemptError::exited(format!(
                "Rosetta exited with {status} before writing its port file {}",
                port_file.display()
            )));
        }
        if Instant::now() >= deadline {
            return Err(StartAttemptError::fatal(format!(
                "Rosetta didn't write its port file {} in time",
                port_file.display()
            )));
        }
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
    };

    let http_client = reqwest::Client::new();
    // wait because rosetta may be recovering from existing state
    let mut tries_left = NUM_TRIES;
    loop {
        let res = http_client
            .post(format!("http://localhost:{port}/network/list").as_str())
            .header("Content-Type", "application/json")
            .send()
            .await;
        if res.is_ok_and(|res| res.status().is_success()) {
            break;
        }
        if let Some(status) = proc.try_wait()? {
            return Err(StartAttemptError::exited(format!(
                "Rosetta exited with {status} before serving /network/list on port {port}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(StartAttemptError::fatal(format!(
                "Rosetta didn't serve /network/list on port {port} in time"
            )));
        }
        tries_left -= 1;
        if tries_left == 0 {
            return Err(StartAttemptError::fatal(format!(
                "Rosetta didn't serve /network/list on port {port} within {NUM_TRIES} attempts"
            )));
        }
        sleep(WAIT_BETWEEN_ATTEMPTS).await;
    }

    Ok((proc, port))
}

/// Reads the port Rosetta listens on from its port file, or returns `None`
/// while the file doesn't exist yet or hasn't been completely written.
fn read_port(port_file: &Path) -> Option<u16> {
    std::fs::read_to_string(port_file)
        .ok()
        .and_then(|port| u16::from_str(port.trim()).ok())
}
