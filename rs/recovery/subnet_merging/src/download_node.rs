use ic_recovery::{
    command_helper::confirm_exec_cmd,
    error::RecoveryResult,
    ssh_helper::SshHelper,
    util::{DataLocation, ExecutionMode, SshUser},
};
use slog::Logger;

use std::{fmt, path::PathBuf, process::Command};

/// Access to the node of a subnet whose state is downloaded: locally if the
/// tool runs on that node, and over SSH with the admin key otherwise.
///
/// Unlike [ExecutionMode], which only borrows the [SshHelper], it owns it, so
/// that a step can hold it. A command run with [DownloadNode::execute] asks for
/// confirmation on a local node too, unlike the checks made through the
/// [ExecutionMode] that [DownloadNode::mode] hands out.
pub(crate) struct DownloadNode {
    /// `None` if the tool runs on the node.
    ssh_helper: Option<SshHelper>,
    require_confirmation: bool,
    logger: Logger,
}

impl DownloadNode {
    /// SSH access to a remote node uses the admin key, which the upload of the
    /// merged state to the destination subnet needs anyway.
    pub(crate) fn new(
        location: DataLocation,
        admin_key_file: Option<PathBuf>,
        require_confirmation: bool,
        logger: Logger,
    ) -> Self {
        let ssh_helper = match location {
            DataLocation::Local => None,
            DataLocation::Remote(node_ip) => Some(SshHelper::new(
                logger.clone(),
                SshUser::Admin,
                node_ip,
                require_confirmation,
                admin_key_file,
            )),
        };
        Self {
            ssh_helper,
            require_confirmation,
            logger,
        }
    }

    pub(crate) fn ssh_helper(&self) -> Option<&SshHelper> {
        self.ssh_helper.as_ref()
    }

    pub(crate) fn require_confirmation(&self) -> bool {
        self.require_confirmation
    }

    pub(crate) fn mode(&self) -> ExecutionMode<'_> {
        match &self.ssh_helper {
            None => ExecutionMode::Local,
            Some(ssh_helper) => ExecutionMode::Remote(ssh_helper),
        }
    }

    /// Runs a shell command on the node and returns its output.
    pub(crate) fn execute(&self, command: String) -> RecoveryResult<Option<String>> {
        match &self.ssh_helper {
            None => {
                let mut sh = Command::new("sh");
                sh.arg("-c").arg(command);
                confirm_exec_cmd(&mut sh, self.require_confirmation.then_some(&self.logger))
            }
            Some(ssh_helper) => ssh_helper.ssh(command),
        }
    }
}

impl fmt::Display for DownloadNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ssh_helper {
            None => write!(f, "this node"),
            Some(ssh_helper) => write!(f, "node {}", ssh_helper.ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(location: DataLocation) -> DownloadNode {
        DownloadNode::new(location, None, false, ic_recovery::util::make_logger())
    }

    #[test]
    fn local_node_runs_commands_without_ssh() {
        let node = node(DataLocation::Local);
        assert!(node.ssh_helper().is_none());
        assert!(matches!(node.mode(), ExecutionMode::Local));
        assert_eq!(
            node.execute("echo finished".to_string())
                .unwrap()
                .as_deref()
                .map(str::trim),
            Some("finished")
        );
        assert_eq!(node.to_string(), "this node");
    }

    #[test]
    fn remote_node_runs_commands_over_ssh() {
        let node = node(DataLocation::Remote("::1".parse().unwrap()));
        assert!(node.ssh_helper().is_some());
        assert!(matches!(node.mode(), ExecutionMode::Remote(_)));
        assert_eq!(node.to_string(), "node ::1");
    }
}
