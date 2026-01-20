use crate::{
    RecoveryResult,
    cli::wait_for_confirmation,
    command_helper::exec_cmd,
    error::RecoveryError,
    file_sync_helper::{rsync, rsync_includes, rsync_with_retries},
    util::SshUser,
};
use slog::{Logger, info, warn};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    thread, time,
};

const SSH_ARGS: &[&str] = &[
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "NumberOfPasswordPrompts=0",
    "-o",
    "ConnectionAttempts=4",
    "-o",
    "ConnectTimeout=15",
    "-A",
];

/// Simplify SSH connections to a certion account@ip address using the given SSH
/// arguments.
pub struct SshHelper {
    logger: Logger,
    pub ssh_user: SshUser,
    pub ip: IpAddr,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
}

impl SshHelper {
    pub fn new(
        logger: Logger,
        ssh_user: SshUser,
        ip: IpAddr,
        require_confirmation: bool,
        key_file: Option<PathBuf>,
    ) -> Self {
        Self {
            logger,
            ssh_user,
            ip,
            require_confirmation,
            key_file,
        }
    }

    /// Return a remote path string usable by commands like `rsync`.
    pub fn remote_path<P: AsRef<Path>>(&self, path: P) -> String {
        match self.ip {
            IpAddr::V4(_) => format!("{}@{}:{}", self.ssh_user, self.ip, path.as_ref().display()),
            IpAddr::V6(_) => format!(
                "{}@[{}]:{}",
                self.ssh_user,
                self.ip,
                path.as_ref().display()
            ),
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
        ssh.arg(format!("{}@{}", self.ssh_user, self.ip));
        ssh.arg(commands);
        ssh
    }

    /// Wrapper around `crate::file_sync_helper::rsync_with_retries`
    pub fn rsync_with_retries<S, T>(
        &self,
        src: S,
        target: T,
        auto_retry: bool,
        max_retries: usize,
    ) -> RecoveryResult<Option<String>>
    where
        S: AsRef<Path>,
        T: AsRef<Path>,
    {
        rsync_with_retries(
            &self.logger,
            src,
            target,
            self.require_confirmation,
            self.key_file.as_ref(),
            auto_retry,
            max_retries,
        )
    }

    /// Wrapper around `crate::file_sync_helper::rsync`
    pub fn rsync<S, T>(&self, src: S, target: T) -> RecoveryResult<Option<String>>
    where
        S: AsRef<Path>,
        T: AsRef<Path>,
    {
        rsync(
            &self.logger,
            src,
            target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )
    }

    /// Wrapper around `crate::file_sync_helper::rsync_includes`
    pub fn rsync_includes<I, S, T>(
        &self,
        includes: I,
        src: S,
        target: T,
    ) -> RecoveryResult<Option<String>>
    where
        I: IntoIterator<Item: AsRef<Path>>,
        S: AsRef<Path>,
        T: AsRef<Path>,
    {
        rsync_includes(
            &self.logger,
            includes,
            src,
            target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )
    }

    /// Return `true` if this SSH helper can establish a connection to the configured host
    pub fn can_connect(&self) -> bool {
        self.ssh("echo 1;".to_string()).is_ok()
    }

    pub fn wait_for_access(&self) -> RecoveryResult<()> {
        for _ in 0..20 {
            if self.can_connect() {
                return Ok(());
            }
            warn!(self.logger, "No SSH access, retrying...");
            thread::sleep(time::Duration::from_secs(5));
        }
        Err(RecoveryError::UnexpectedError("No SSH access".into()))
    }
}

/// Return the configured SSH command options as an environment argument usable by `rsync`.
pub fn get_rsync_ssh_arg(key_file: Option<&PathBuf>) -> String {
    let mut arg = format!("ssh {}", SSH_ARGS.join(" "));
    if let Some(file) = key_file {
        // We use debug formatting because it escapes the path in case it contains spaces.
        arg.push_str(&format!(" -i {file:?}"));
    }
    arg
}
