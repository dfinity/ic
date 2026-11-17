use crate::{
    command_helper::confirm_exec_cmd,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::write_bytes,
    ssh_helper::SshHelper,
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_crypto_utils_threshold_sig_der::public_key_der_to_pem;
use ic_state_layout::{
    CheckpointStatus, STATE_SYNC_CHECKPOINT_MARKER, UNVERIFIED_CHECKPOINT_MARKER,
};
use ic_types::Height;
use serde::{Deserialize, Serialize};
use slog::{Drain, Logger, o};
use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
    process::Command,
};
use std::{future::Future, path::Path, str::FromStr};
use tokio::runtime::Runtime;

#[derive(Clone)]
pub enum SshUser {
    Admin,
    Readonly,
    Backup,
    Recovery,
    Other(String),
}

impl fmt::Display for SshUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshUser::Admin => write!(f, "admin"),
            SshUser::Readonly => write!(f, "readonly"),
            SshUser::Backup => write!(f, "backup"),
            SshUser::Recovery => write!(f, "recovery"),
            SshUser::Other(user) => write!(f, "{}", user),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DataLocation {
    Local,
    Remote(IpAddr),
}

pub fn data_location_from_str(s: &str) -> RecoveryResult<DataLocation> {
    if s == "local" {
        return Ok(DataLocation::Local);
    }
    Ok(DataLocation::Remote(IpAddr::V6(
        Ipv6Addr::from_str(s).map_err(|e| {
            RecoveryError::UnexpectedError(format!("Unable to parse ipv6 address {e:?}"))
        })?,
    )))
}

/// Helper enum to abstract over local and remote implementations of functions that need to access
/// the filesystem of the node. Local implementations execute commands directly on the machine,
/// while remote implementations use ssh to execute them on the remote node.
pub enum ExecutionMode {
    Local,
    Remote(SshHelper),
}

impl ExecutionMode {
    /// Runs a shell command on the node and returns its output.
    ///
    /// A local command asks for confirmation if `confirmation_logger` is given.
    /// Whether a remote command asks for confirmation is configured on its
    /// [SshHelper] instead.
    pub fn execute(
        &self,
        command: String,
        confirmation_logger: Option<&Logger>,
    ) -> RecoveryResult<Option<String>> {
        match self {
            Self::Local => confirm_exec_cmd(
                Command::new("sh").arg("-c").arg(command),
                confirmation_logger,
            ),
            Self::Remote(ssh_helper) => ssh_helper.ssh(command),
        }
    }

    pub fn path_exists(&self, path: &Path) -> RecoveryResult<bool> {
        self.execute(
            format!("test -e {} && echo y || echo n", path.display()),
            None,
        )
        .map(|output| output.is_some_and(|s| s.trim() == "y"))
    }

    /// The status of the checkpoint in the directory `checkpoint`, or `None`
    /// if it does not exist.
    ///
    /// The markers the state manager uses are checked in the same order as
    /// `CheckpointLayout::checkpoint_status` checks them.
    pub fn checkpoint_status(&self, checkpoint: &Path) -> RecoveryResult<Option<CheckpointStatus>> {
        if !self.path_exists(checkpoint)? {
            return Ok(None);
        }
        if self.path_exists(&checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER))? {
            return Ok(Some(CheckpointStatus::UnverifiedStateSync));
        }
        if self.path_exists(&checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER))? {
            return Ok(Some(CheckpointStatus::UnverifiedRegular));
        }
        Ok(Some(CheckpointStatus::Verified))
    }

    pub fn get_maybe_latest_checkpoint_name_and_height(
        &self,
        checkpoints_path: &Path,
    ) -> RecoveryResult<Option<(String, Height)>> {
        let maybe_output = self.execute(
            format!("ls -1 {} | sort | tail -n 1", checkpoints_path.display()),
            None,
        )?;

        let Some(output) = maybe_output else {
            return Ok(None);
        };

        let name = output.trim();
        let height = parse_hex_str(name)?;

        Ok(Some((name.to_string(), Height::from(height))))
    }
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "this node"),
            Self::Remote(ssh_helper) => write!(f, "node {}", ssh_helper.ip),
        }
    }
}

pub enum CheckpointHeight {
    Latest,
    Specified(u64),
}

impl From<Option<u64>> for CheckpointHeight {
    fn from(value: Option<u64>) -> Self {
        match value {
            Some(height) => CheckpointHeight::Specified(height),
            None => CheckpointHeight::Latest,
        }
    }
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
    rt.block_on(f)
}

pub fn parse_hex_str(string: &str) -> RecoveryResult<u64> {
    u64::from_str_radix(string, 16).map_err(|e| {
        RecoveryError::invalid_output_error(format!(
            "Could not read checkpoint height from dir name '{string}': {e}"
        ))
    })
}

pub fn subnet_id_from_str(s: &str) -> RecoveryResult<SubnetId> {
    PrincipalId::from_str(s)
        .map_err(|e| RecoveryError::UnexpectedError(format!("Unable to parse subnet_id {e:?}")))
        .map(SubnetId::from)
}

pub fn node_id_from_str(s: &str) -> RecoveryResult<NodeId> {
    PrincipalId::from_str(s)
        .map_err(|e| RecoveryError::UnexpectedError(format!("Unable to parse node_id {e:?}")))
        .map(NodeId::from)
}

pub fn node_id_and_pub_key_from_str(s: &str) -> RecoveryResult<(NodeId, String)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let [node_id_str, pub_key_str] = parts.as_slice() else {
        return Err(RecoveryError::UnexpectedError(format!(
            "Unable to parse node_id and public key from string: {s}"
        )));
    };

    let node_id = node_id_from_str(node_id_str)?;
    let pub_key = pub_key_str.to_string();
    Ok((node_id, pub_key))
}

pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

pub fn write_public_key_to_file(der_bytes: &[u8], path: &Path) -> RecoveryResult<()> {
    write_bytes(path, public_key_der_to_pem(der_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_and_pub_key_from_str() {
        let valid_node_id_str = "igjkj-job4m-om7ug-cmzok-admxb-ag2xv-xqlgk-2bxsr-ro2mx-r5i7q-hqe";
        let invalid_node_id_str = "igjkj-job4m";

        let valid_pub_key_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwS/0S6xH0g/xLDV0Tz7VeMZE9AKPeSbLmCsq9bY3F1 foo@dfinity.org";

        let valid_input = format!("{}:{}", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                valid_pub_key_str.to_string()
            )
        );

        // Works also with additional colons (same logic as in `ic-admin`)
        let valid_input = format!("{}::{}", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                format!(":{}", valid_pub_key_str)
            )
        );

        // Works also with additional colons (same logic as in `ic-admin`)
        let valid_input = format!("{}:{}:", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                format!("{}:", valid_pub_key_str)
            )
        );

        let invalid_input = format!("{}:{}", invalid_node_id_str, valid_pub_key_str);
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = String::new();
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = valid_node_id_str.to_string();
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = valid_pub_key_str.to_string();
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());
    }

    #[test]
    fn execution_mode_runs_local_commands_and_names_the_node() {
        assert_eq!(
            ExecutionMode::Local
                .execute("echo finished".to_string(), None)
                .unwrap()
                .as_deref()
                .map(str::trim),
            Some("finished")
        );
        assert_eq!(ExecutionMode::Local.to_string(), "this node");

        let ssh_helper = SshHelper::new(
            make_logger(),
            SshUser::Admin,
            "::1".parse().unwrap(),
            false,
            None,
        );
        assert_eq!(ExecutionMode::Remote(ssh_helper).to_string(), "node ::1");
    }

    /// The status determined from the markers agrees with the one the state
    /// layout code determines.
    #[test]
    fn checkpoint_status_matches_state_layout() {
        use ic_state_layout::{CheckpointLayout, ReadOnly};

        let root = tempfile::tempdir().expect("Could not create a temp dir");
        let height = Height::new(100);
        let checkpoint = root.path().join("0000000000000064");

        let check = |expected: Option<CheckpointStatus>| {
            let status = ExecutionMode::Local.checkpoint_status(&checkpoint).unwrap();
            assert_eq!(status, expected);
            if checkpoint.exists() {
                let layout =
                    CheckpointLayout::<ReadOnly>::new_untracked(checkpoint.clone(), height)
                        .unwrap();
                assert_eq!(Some(layout.checkpoint_status()), expected);
            }
        };

        check(None);

        std::fs::create_dir_all(&checkpoint).unwrap();
        check(Some(CheckpointStatus::Verified));

        let unverified = checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER);
        let state_sync = checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER);
        std::fs::write(&unverified, b"").unwrap();
        check(Some(CheckpointStatus::UnverifiedRegular));

        std::fs::write(&state_sync, b"").unwrap();
        check(Some(CheckpointStatus::UnverifiedStateSync));

        // The state sync marker is removed last, so it may be the only one.
        std::fs::remove_file(&unverified).unwrap();
        check(Some(CheckpointStatus::UnverifiedStateSync));

        std::fs::remove_file(&state_sync).unwrap();
        check(Some(CheckpointStatus::Verified));
    }
}
