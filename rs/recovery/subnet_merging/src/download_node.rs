use ic_recovery::{
    command_helper::confirm_exec_cmd,
    error::RecoveryResult,
    ssh_helper::SshHelper,
    util::{DataLocation, ExecutionMode, SshUser},
};
use ic_state_layout::{
    CheckpointStatus, STATE_SYNC_CHECKPOINT_MARKER, UNVERIFIED_CHECKPOINT_MARKER,
};
use slog::Logger;

use std::{
    fmt,
    path::{Path, PathBuf},
    process::Command,
};

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

    /// The status of the checkpoint in the directory `checkpoint` on the node,
    /// or `None` if the node does not hold it.
    ///
    /// The markers the state manager uses are checked with the same shell
    /// commands whether the node is local or remote, in the same order as
    /// `CheckpointLayout::checkpoint_status` checks them.
    pub(crate) fn checkpoint_status(
        &self,
        checkpoint: &Path,
    ) -> RecoveryResult<Option<CheckpointStatus>> {
        let ssh_helper = self.ssh_helper();
        let node = match &ssh_helper {
            None => ExecutionMode::Local,
            Some(ssh_helper) => ExecutionMode::Remote(ssh_helper),
        };
        if !node.path_exists(checkpoint)? {
            return Ok(None);
        }
        if node.path_exists(&checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER))? {
            return Ok(Some(CheckpointStatus::UnverifiedStateSync));
        }
        if node.path_exists(&checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER))? {
            return Ok(Some(CheckpointStatus::UnverifiedRegular));
        }
        Ok(Some(CheckpointStatus::Verified))
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
    use ic_state_layout::{CheckpointLayout, ReadOnly};
    use ic_types::Height;

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

    fn status_name(status: Option<CheckpointStatus>) -> &'static str {
        match status {
            None => "missing",
            Some(CheckpointStatus::Verified) => "verified",
            Some(CheckpointStatus::UnverifiedRegular) => "unverified",
            Some(CheckpointStatus::UnverifiedStateSync) => "state sync",
        }
    }

    /// The status determined from the markers agrees with the one the state
    /// layout code determines.
    #[test]
    fn checkpoint_status_matches_state_layout() {
        let root = std::env::temp_dir().join(format!(
            "subnet_merging_checkpoint_status_test_{}",
            std::process::id()
        ));
        let height = Height::new(100);
        let checkpoint = root.join("0000000000000064");
        let node = local_node();

        let check = |expected: &str| {
            let status = node.checkpoint_status(&checkpoint).unwrap();
            assert_eq!(status_name(status), expected);
            if checkpoint.exists() {
                let layout =
                    CheckpointLayout::<ReadOnly>::new_untracked(checkpoint.clone(), height)
                        .unwrap();
                assert_eq!(status_name(Some(layout.checkpoint_status())), expected);
            }
        };

        check("missing");

        std::fs::create_dir_all(&checkpoint).unwrap();
        check("verified");

        let unverified = checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER);
        let state_sync = checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER);
        std::fs::write(&unverified, b"").unwrap();
        check("unverified");

        std::fs::write(&state_sync, b"").unwrap();
        check("state sync");

        // The state sync marker is removed last, so it may be the only one.
        std::fs::remove_file(&unverified).unwrap();
        check("state sync");

        std::fs::remove_file(&state_sync).unwrap();
        check("verified");

        std::fs::remove_dir_all(&root).unwrap();
    }
}
