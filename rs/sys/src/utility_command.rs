use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command as StdCommand, ExitStatus, Stdio};

const VSOCK_AGENT_PATH: &str = "/opt/dfinity/vsock_agent";

#[derive(Clone, Debug)]
pub enum UtilityCommandError {
    IoError(String),
    Failed(String, ExitStatus),
}

impl std::fmt::Display for UtilityCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtilityCommandError::IoError(err) => write!(f, "{}", err),
            UtilityCommandError::Failed(err, status) => {
                write!(f, "Utility command failed with status {}: {}", status, err)
            }
        }
    }
}

impl std::error::Error for UtilityCommandError {}

pub type UtilityCommandResult<T> = Result<T, UtilityCommandError>;

/// An invocation of a program, possibly including some input that is passed to
/// stdin.
///
/// This is used to interact with the USB HSM via system tools.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtilityCommand {
    program: String,
    args: Vec<String>,
    input: Vec<u8>,
}

impl UtilityCommand {
    /// A utility command executing `program` with arguments `args`.
    pub fn new(program: String, args: Vec<String>) -> Self {
        Self {
            program,
            args,
            input: vec![],
        }
    }

    pub fn with_input(mut self, input: Vec<u8>) -> Self {
        self.input = input;
        self
    }

    /// Execute the command and capture the output.
    pub fn execute(&self) -> UtilityCommandResult<Vec<u8>> {
        let mut cmd = StdCommand::new(self.program.clone());
        cmd.args(self.args.clone());
        cmd.stdin(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdout(Stdio::piped());

        let map_to_err = |e: std::io::Error| {
            UtilityCommandError::IoError(format!("Error while running '{}': {}", self, e))
        };
        let mut child = cmd.spawn().map_err(map_to_err)?;

        let mut stdin = match child.stdin.take() {
            Some(v) => v,
            None => {
                return Err(UtilityCommandError::IoError(
                    "Could not fetch stdin of child process.".to_string(),
                ))
            }
        };

        stdin.write_all(self.input.as_slice()).map_err(map_to_err)?;
        stdin.flush().map_err(map_to_err)?;
        drop(stdin);
        let output = child.wait_with_output().map_err(map_to_err)?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(UtilityCommandError::Failed(
                format!(
                    "Error while running '{}': {}",
                    self,
                    std::str::from_utf8(output.stderr.as_slice())
                        .unwrap()
                        .to_string()
                ),
                output.status,
            ))
        }
    }

    /// Create the utility command that, when called, reads the public key from
    /// the USB HSM.
    pub fn read_public_key(hsm_slot: Option<&str>, key_id: Option<&str>) -> Self {
        Self::new(
            "pkcs11-tool".to_string(),
            vec![
                "--read-object",         // operation
                "--slot",                //
                hsm_slot.unwrap_or("0"), // default: 0
                "--type",                //
                "pubkey",                // type
                "--id",                  //
                key_id.unwrap_or("01"),  // default: 01
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        )
    }

    pub fn sign_message(
        msg: Vec<u8>,
        hsm_slot: Option<&str>,
        pin: Option<&str>,
        key_id: Option<&str>,
    ) -> Self {
        Self::new(
            "pkcs11-tool".to_string(),
            vec![
                "--slot",                // choose HSM slot
                hsm_slot.unwrap_or("0"), // default: 0
                "--pin",                 //
                pin.unwrap_or("358138"), // default:
                "--sign",                // operation
                "--id",                  //
                key_id.unwrap_or("01"),  // default: 01
                "--mechanism",
                "ECDSA",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        )
        .with_input(ic_crypto_sha256::Sha256::hash(msg.as_slice()).to_vec())
    }

    /// Try to attach the USB HSM, if the VSOCK_AGENT_PATH binary
    /// exists. Ignore any errors in the execution.
    pub fn try_to_attach_hsm() {
        if let Ok(metadata) = std::fs::metadata(VSOCK_AGENT_PATH) {
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 != 0 {
                // Executable exists. We will run it, without checking the result.
                // The attach may fail or happen later, and that needs to be handled at a
                // higher level.
                // Once we finish migration to the Ubuntu-based IC-OS and the Vsock-based HSM
                // sharing, we'll want to know whether and why the command failed.
                if StdCommand::new(VSOCK_AGENT_PATH)
                    .arg("--attach-hsm".to_string())
                    .status()
                    .is_ok()
                {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            }
        }
    }

    /// Try to detach the USB HSM, if the VSOCK_AGENT_PATH binary
    /// exists. Ignore any errors in the execution.
    pub fn try_to_detach_hsm() {
        if let Ok(metadata) = std::fs::metadata(VSOCK_AGENT_PATH) {
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 != 0 {
                // Executable exists. We will run it, without checking the result.
                // Once we finish migration to the Ubuntu-based IC-OS and the Vsock-based HSM
                // sharing, we'll want to know if this command failed.
                let _ = StdCommand::new(VSOCK_AGENT_PATH)
                    .arg("--detach-hsm".to_string())
                    .status();
            }
        }
    }
}

impl std::fmt::Display for UtilityCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}", self.program)?;
        self.args.iter().try_for_each(|a| write!(f, " {}", a))?;
        write!(f, "` input: {}", hex::encode(self.input.clone()))
    }
}
