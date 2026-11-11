use ic_recovery::{
    command_helper::confirm_exec_cmd,
    error::RecoveryResult,
    ssh_helper::SshHelper,
    util::{DataLocation, SshUser},
};
use slog::Logger;

use std::{fmt, path::PathBuf, process::Command};

/// The node of a subnet whose state is downloaded, and how to run commands on
/// it: locally if the tool runs on that node, and over SSH with the admin key
/// otherwise.
pub(crate) struct DownloadNode {
    pub(crate) location: DataLocation,
    pub(crate) admin_key_file: Option<PathBuf>,
    pub(crate) require_confirmation: bool,
    pub(crate) logger: Logger,
}

impl DownloadNode {
    /// SSH access to the node with the admin key, which the upload of the
    /// merged state to the destination subnet needs anyway. `None` if the tool
    /// runs on that node.
    pub(crate) fn ssh_helper(&self) -> Option<SshHelper> {
        match self.location {
            DataLocation::Local => None,
            DataLocation::Remote(node_ip) => Some(SshHelper::new(
                self.logger.clone(),
                SshUser::Admin,
                node_ip,
                self.require_confirmation,
                self.admin_key_file.clone(),
            )),
        }
    }

    /// Runs a shell command on the node and returns its output.
    pub(crate) fn execute(&self, command: String) -> RecoveryResult<Option<String>> {
        match self.ssh_helper() {
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
        match self.location {
            DataLocation::Local => write!(f, "this node"),
            DataLocation::Remote(node_ip) => write!(f, "node {node_ip}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_node() -> DownloadNode {
        DownloadNode {
            location: DataLocation::Local,
            admin_key_file: None,
            require_confirmation: false,
            logger: ic_recovery::util::make_logger(),
        }
    }

    #[test]
    fn local_node_runs_commands_without_ssh() {
        let node = local_node();
        assert!(node.ssh_helper().is_none());
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
        let node = DownloadNode {
            location: DataLocation::Remote("::1".parse().unwrap()),
            ..local_node()
        };
        assert!(node.ssh_helper().is_some());
        assert_eq!(node.to_string(), "node ::1");
    }
}
