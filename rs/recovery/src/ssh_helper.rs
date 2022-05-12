use crate::cli::wait_for_confirmation;
use crate::command_helper::exec_cmd;
use crate::RecoveryResult;
use slog::{info, Logger};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

const SSH_ARGS: &[&str] = &[
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "NumberOfPasswordPrompts=0",
    "-A",
];

/// Simplify SSH connections to a certion account@ip address using the given SSH
/// arguments.
pub struct SshHelper {
    logger: Logger,
    pub account: String,
    pub ip: IpAddr,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
}

impl SshHelper {
    pub fn new(
        logger: Logger,
        account: String,
        ip: IpAddr,
        require_confirmation: bool,
        key_file: Option<PathBuf>,
    ) -> Self {
        Self {
            logger,
            account,
            ip,
            require_confirmation,
            key_file,
        }
    }

    /// Execute the given command string on a remote machine using SSH.
    pub fn ssh(&self, commands: String) -> RecoveryResult<Option<String>> {
        let mut ssh = self.get_command(commands);
        info!(self.logger, "");
        info!(self.logger, "About to execute:");
        info!(self.logger, "{:?}", ssh);
        if self.require_confirmation {
            wait_for_confirmation(&self.logger);
        }
        match exec_cmd(&mut ssh) {
            Ok(Some(res)) => {
                info!(self.logger, "{}", res);
                Ok(Some(res))
            }
            res => res,
        }
    }

    /// Return the [Command] object of an SSH command executing the given command
    /// string on a remote machine.
    pub fn get_command(&self, commands: String) -> Command {
        let mut ssh = Command::new("ssh");
        ssh.args(SSH_ARGS);
        if let Some(file) = &self.key_file {
            ssh.arg("-i").arg(file);
        }
        ssh.arg(format!("{}@{}", self.account, self.ip));
        ssh.arg(commands);
        ssh
    }

    /// Return `true` if this SSH helper can establish a connection to the configured host
    pub fn can_connect(&self) -> bool {
        self.ssh("echo 1;".to_string()).is_ok()
    }
}

/// Return the configured SSH command options as an environment argument usable by `rsync`.
pub fn get_rsync_ssh_arg(key_file: Option<&PathBuf>) -> String {
    let mut arg = format!("ssh {}", SSH_ARGS.join(" "));
    if let Some(file) = key_file {
        arg.push_str(&format!(" -i {}", file.display()));
    }
    arg
}
