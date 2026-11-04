use crate::{
    layout::{CUP_FILE_NAME, Layout},
    readiness,
    utils::{CheckError, get_subnet_record_at_version, wait_for, wait_for_unless_fatal},
};

use ic_base_types::SubnetId;
use ic_protobuf::state::v1 as pb_state;
use ic_recovery::{
    CUPS_DIR, IC_DATA_PATH, IC_STATE, STATES_METADATA,
    cli::wait_for_confirmation,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::read_bytes,
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
};
use ic_state_layout::{
    CHECKPOINTS_DIR, STATE_SYNC_CHECKPOINT_MARKER, StateLayout, UNVERIFIED_CHECKPOINT_MARKER,
};
use ic_state_manager::{manifest::manifest_hash, state_sync::types::Manifest};
use ic_subnet_tools::utils::get_cup;
use ic_types::{
    CryptoHashOfState, Height,
    consensus::{CatchUpPackage, HasHeight},
    crypto::CryptoHash,
};
use prost::Message;
use slog::{Logger, info};

use std::{
    fmt::Display,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// Waits until the record of the subnet that is being merged away is labeled
/// "cooling down" and persists the registry version `V` it was read at (not
/// necessarily the version that set the label), which is what the merge
/// readiness condition is evaluated against.
pub(crate) struct CheckCoolingDownStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckCoolingDownStep {
    fn descr(&self) -> String {
        format!(
            "Wait until the registry labels subnet {} as \"cooling down\", and record the \
             registry version at which the label was read.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let source_subnet_id = self.source_subnet_id;
        let cooling_down_version = wait_for(
            &format!("subnet {source_subnet_id} is labeled \"cooling down\""),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                let (registry_version, subnet_record) =
                    self.registry_helper.get_subnet_record(source_subnet_id)?;
                let Some(subnet_record) = subnet_record else {
                    return Err(RecoveryError::RegistryError(format!(
                        "No record of subnet {source_subnet_id} at registry version \
                         {registry_version}"
                    )));
                };
                if !subnet_record.cooling_down {
                    return Err(RecoveryError::RegistryError(format!(
                        "Subnet {source_subnet_id} is not labeled \"cooling down\" at registry \
                         version {registry_version} yet"
                    )));
                }
                Ok(registry_version)
            },
        )?;

        info!(
            self.logger,
            "Subnet {source_subnet_id} is labeled \"cooling down\" at registry version \
             {cooling_down_version}",
        );

        self.layout
            .write_cooling_down_registry_version(source_subnet_id, cooling_down_version.get())
    }
}

/// Waits until the merge readiness condition holds for the subnet that is
/// cooling down.
pub(crate) struct CheckMergeReadinessStep {
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for CheckMergeReadinessStep {
    fn descr(&self) -> String {
        format!(
            "Wait until subnet {} is ready to be merged.",
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let registry_version = self
            .layout
            .read_cooling_down_registry_version(self.source_subnet_id)?;

        readiness::await_merge_readiness(
            &self.registry_helper,
            self.source_subnet_id,
            registry_version,
            self.timeout,
            self.poll_interval,
            &self.logger,
        )
    }
}

/// Waits until the node the state is downloaded from holds the CUP its subnet
/// halts at, i.e. the first one whose summary is created at a registry version
/// carrying the `halt_at_cup_height` flag, together with a complete checkpoint
/// of the state that CUP names.
///
/// Waiting for the CUP rather than for the subnet to report that it is halted:
/// the CUP is what names the state the subnet came to rest in, and it exists
/// only once that state has been certified and its hash agreed upon. A subnet
/// that has just stopped delivering batches, on the other hand, may not have
/// finished writing and hashing the checkpoint it stopped at, and downloading
/// its latest checkpoint then yields the previous one, a whole DKG interval
/// before the state the merge is supposed to be assembled from.
///
/// The CUP is the copy the orchestrator has written to disk: that is the one
/// that is downloaded with the state (by a later step) and validated against
/// it.
///
/// Holding the CUP does not mean that the node holds the checkpoint, though:
/// the CUP may have been assembled by the rest of the subnet and gossiped to
/// the node while the node is still writing, validating, or hashing its own
/// checkpoint at that height, all of which the state manager does
/// asynchronously to execution and certification. So this also waits until the
/// node has published the manifest of that checkpoint, until the manifest's
/// root hash is the state hash the CUP names, and until the checkpoint exists
/// without either unverified marker. State sync can publish a manifest without
/// verifying the checkpoint, so the manifest alone is not sufficient.
///
/// Waiting is given up right away, rather than at the timeout, if the node's
/// checkpoint can never match the CUP: if its root hash differs from the CUP's
/// state hash, or if it was state synced without being verified.
pub(crate) struct WaitForHaltingCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node_ip: IpAddr,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    /// Accesses the node on every poll, so it must not ask for confirmation
    /// itself: the operator is asked once, before polling starts, if
    /// `ssh_confirmation` is set.
    pub(crate) ssh_helper: SshHelper,
    pub(crate) ssh_confirmation: bool,
    pub(crate) timeout: Duration,
    pub(crate) poll_interval: Duration,
    pub(crate) logger: Logger,
}

impl Step for WaitForHaltingCupStep {
    fn descr(&self) -> String {
        format!(
            "Wait until node {} holds the CUP subnet {} halts at on disk, together with a \
             verified checkpoint of the state that CUP names.",
            self.node_ip, self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        if self.ssh_confirmation {
            info!(
                self.logger,
                "About to poll node {} every {:?}, for up to {:?}, via ssh and rsync as {}: pulling \
                 its CUP and states metadata, and checking the markers of its checkpoint at the \
                 CUP's height. You will not be asked to confirm each access.",
                self.node_ip,
                self.poll_interval,
                self.timeout,
                self.ssh_helper.ssh_user,
            );
            wait_for_confirmation(&self.logger);
        }

        // A node that is not answering yet, or a file that cannot be pulled off
        // it yet, is the normal state of affairs while the subnet is still
        // running towards its halting CUP, so errors are retried unless they
        // show that the node's checkpoint can never match the halting CUP.
        let height = wait_for_unless_fatal(
            &format!("subnet {} reaches the CUP it halts at", self.subnet_id),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                self.check()?.ok_or_else(|| {
                    CheckError::Retry(RecoveryError::UnexpectedError(format!(
                        "node {} does not hold the CUP subnet {} halts at and its checkpoint yet",
                        self.node_ip, self.subnet_id,
                    )))
                })
            },
        )?;
        info!(
            self.logger,
            "Subnet {} halted at height {height}", self.subnet_id
        );
        Ok(())
    }
}

impl WaitForHaltingCupStep {
    /// Returns the height of the halting CUP if the node holds it and a
    /// verified checkpoint of the state it names, `None` if it does not yet,
    /// a retryable error if the node could not be asked, and a fatal error if
    /// its checkpoint can never match the halting CUP.
    fn check(&self) -> Result<Option<Height>, CheckError> {
        let cup = self.on_disk_cup()?;
        let cup_height = cup.height();
        let cup_registry_version = cup.content.registry_version();

        // The `halt_at_cup_height` flag is read at the registry version of the
        // summary block active at a height, and that version only changes at a
        // summary, so batch delivery stops exactly when the summary carrying the
        // flag becomes active. No CUP follows the one carrying the flag, so the
        // first such CUP on disk is the one the subnet halts at.
        let halting = get_subnet_record_at_version(
            &self.registry_helper,
            self.subnet_id,
            cup_registry_version,
        )?
        .is_some_and(|record| record.halt_at_cup_height);
        if !halting {
            info!(
                self.logger,
                "Node {} holds the CUP at height {cup_height} on disk, whose registry version \
                 {cup_registry_version} does not carry the `halt_at_cup_height` flag of subnet {} \
                 yet",
                self.node_ip,
                self.subnet_id,
            );
            return Ok(None);
        }

        let Some(root_hash) = self.published_root_hash(cup_height)? else {
            info!(
                self.logger,
                "Node {} holds the CUP at height {cup_height} subnet {} halts at, but has not \
                 published a manifest at that height yet",
                self.node_ip,
                self.subnet_id,
            );
            return Ok(None);
        };
        if root_hash != cup.content.state_hash {
            return Err(CheckError::Fatal(RecoveryError::ValidationFailed(format!(
                "The checkpoint of node {} at height {cup_height} has root hash {root_hash:?}, \
                 not the state hash {:?} of the CUP subnet {} halts at",
                self.node_ip, cup.content.state_hash, self.subnet_id,
            ))));
        }

        let checkpoint_dir = PathBuf::from(IC_DATA_PATH)
            .join(IC_STATE)
            .join(CHECKPOINTS_DIR)
            .join(StateLayout::checkpoint_name(cup_height));
        let output = self
            .ssh_helper
            .ssh(checkpoint_status_command(&checkpoint_dir))?;
        match parse_checkpoint_status(output.as_deref().unwrap_or_default())? {
            CheckpointStatus::Verified => Ok(Some(cup_height)),
            CheckpointStatus::UnverifiedRegular => {
                info!(
                    self.logger,
                    "Node {} has not finished verifying its checkpoint at height {cup_height} yet",
                    self.node_ip,
                );
                Ok(None)
            }
            // State sync publishes the manifest only after it has either
            // verified the checkpoint, removing both markers, or decided not to,
            // in which case the checkpoint stays unverified: a halted subnet
            // creates no later checkpoint that would supersede it.
            CheckpointStatus::UnverifiedStateSync => {
                Err(CheckError::Fatal(RecoveryError::ValidationFailed(format!(
                    "The checkpoint of node {} at height {cup_height} was state synced and is \
                     not verified; select another download node of subnet {} with a verified \
                     checkpoint at the halting height",
                    self.node_ip, self.subnet_id,
                ))))
            }
        }
    }

    /// The CUP the orchestrator of the node has written to disk, pulled off the
    /// node and kept next to the other artifacts of the merge.
    fn on_disk_cup(&self) -> RecoveryResult<CatchUpPackage> {
        let remote_cup = self.ssh_helper.remote_path(
            PathBuf::from(IC_DATA_PATH)
                .join(CUPS_DIR)
                .join(CUP_FILE_NAME),
        );
        let local_cup = self.layout.halting_cup_file(self.subnet_id);

        self.ssh_helper.rsync(remote_cup, &local_cup)?;

        get_cup(&local_cup)
    }

    /// The root hash of the manifest the state manager of the node has
    /// published for its checkpoint at `height`, or `None` if it has not
    /// published one yet.
    ///
    /// Locally created checkpoints publish their manifest after verification.
    /// State-synced checkpoints may publish it without verification, so the
    /// caller must also check the checkpoint's markers on the node.
    fn published_root_hash(&self, height: Height) -> RecoveryResult<Option<CryptoHashOfState>> {
        let remote_states_metadata = self.ssh_helper.remote_path(
            PathBuf::from(IC_DATA_PATH)
                .join(IC_STATE)
                .join(STATES_METADATA),
        );
        let local_states_metadata = self.layout.states_metadata_file(self.subnet_id);

        self.ssh_helper
            .rsync(remote_states_metadata, &local_states_metadata)?;

        let states_metadata_error = |err: &dyn Display| {
            RecoveryError::UnexpectedError(format!(
                "Failed to decode the states metadata of node {} ({}): {err}",
                self.node_ip,
                local_states_metadata.display(),
            ))
        };
        let mut states_metadata =
            pb_state::StatesMetadata::decode(read_bytes(&local_states_metadata)?.as_slice())
                .map_err(|err| states_metadata_error(&err))?;

        let Some(manifest) = states_metadata
            .by_height
            .remove(&height.get())
            .and_then(|metadata| metadata.manifest)
        else {
            return Ok(None);
        };
        let manifest = Manifest::try_from(manifest).map_err(|err| states_metadata_error(&err))?;

        Ok(Some(CryptoHashOfState::from(CryptoHash(
            manifest_hash(&manifest).to_vec(),
        ))))
    }
}

/// The status of a checkpoint on a node, as determined by its markers.
#[derive(Copy, Clone, PartialEq, Debug)]
enum CheckpointStatus {
    Verified,
    /// Locally created, and not verified yet.
    UnverifiedRegular,
    /// Created by state sync, and not verified.
    UnverifiedStateSync,
}

impl CheckpointStatus {
    fn as_str(&self) -> &'static str {
        match self {
            CheckpointStatus::Verified => "verified",
            CheckpointStatus::UnverifiedRegular => "unverified_regular",
            CheckpointStatus::UnverifiedStateSync => "unverified_state_sync",
        }
    }
}

/// A shell command printing the status of the remote checkpoint, using the
/// same marker rules as `CheckpointLayout::checkpoint_status`: the state sync
/// marker takes precedence, as it is removed last when a checkpoint is
/// verified. Directory access is checked before the markers so that an
/// inaccessible or missing checkpoint fails rather than looks verified merely
/// because its markers cannot be found.
fn checkpoint_status_command(checkpoint_dir: &Path) -> String {
    let checkpoint_dir = checkpoint_dir.display().to_string().replace('\'', "'\\''");
    format!(
        "cd '{checkpoint_dir}' && test -r . && test -x . && \
         if test -e {STATE_SYNC_CHECKPOINT_MARKER}; then echo {state_sync}; \
         elif test -e {UNVERIFIED_CHECKPOINT_MARKER}; then echo {regular}; \
         else echo {verified}; fi",
        state_sync = CheckpointStatus::UnverifiedStateSync.as_str(),
        regular = CheckpointStatus::UnverifiedRegular.as_str(),
        verified = CheckpointStatus::Verified.as_str(),
    )
}

/// Parses the output of `checkpoint_status_command`.
fn parse_checkpoint_status(output: &str) -> RecoveryResult<CheckpointStatus> {
    [
        CheckpointStatus::Verified,
        CheckpointStatus::UnverifiedRegular,
        CheckpointStatus::UnverifiedStateSync,
    ]
    .into_iter()
    .find(|status| status.as_str() == output.trim())
    .ok_or_else(|| {
        RecoveryError::UnexpectedError(format!(
            "Unexpected output of the checkpoint status check: {output:?}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities_tmpdir::tmpdir;
    use std::{fs, process::Command};

    #[test]
    fn remote_checkpoint_status_follows_the_markers() {
        let root = tmpdir("halting-checkpoint");
        // Exercise shell quoting too: checkpoint paths must be treated as data.
        let checkpoint = root.path().join("checkpoint with 'quotes'");
        fs::create_dir(&checkpoint).unwrap();
        let status = || {
            let output = Command::new("sh")
                .arg("-c")
                .arg(checkpoint_status_command(&checkpoint))
                .output()
                .unwrap();
            output
                .status
                .success()
                .then(|| parse_checkpoint_status(&String::from_utf8(output.stdout).unwrap()))
                .map(Result::unwrap)
        };

        assert_eq!(status(), Some(CheckpointStatus::Verified));
        fs::write(checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER), []).unwrap();
        assert_eq!(status(), Some(CheckpointStatus::UnverifiedRegular));

        // A state-synced checkpoint has both markers. Verifying it removes the
        // state sync marker last, so it stays unverified until both are gone.
        fs::write(checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER), []).unwrap();
        assert_eq!(status(), Some(CheckpointStatus::UnverifiedStateSync));
        fs::remove_file(checkpoint.join(UNVERIFIED_CHECKPOINT_MARKER)).unwrap();
        assert_eq!(status(), Some(CheckpointStatus::UnverifiedStateSync));
        fs::remove_file(checkpoint.join(STATE_SYNC_CHECKPOINT_MARKER)).unwrap();
        assert_eq!(status(), Some(CheckpointStatus::Verified));

        // Stale metadata is not proof that the checkpoint still exists.
        fs::remove_dir(&checkpoint).unwrap();
        assert_eq!(status(), None);
    }

    #[test]
    fn unexpected_checkpoint_status_output_is_rejected() {
        assert!(parse_checkpoint_status("").is_err());
        assert!(parse_checkpoint_status("verified but not really").is_err());
        assert_eq!(
            parse_checkpoint_status("verified\n").unwrap(),
            CheckpointStatus::Verified
        );
    }
}
