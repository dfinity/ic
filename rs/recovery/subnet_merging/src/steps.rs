use crate::{
    layout::{CUP_FILE_NAME, Layout},
    readiness,
    utils::{get_subnet_record_at_version, wait_for},
};

use ic_base_types::SubnetId;
use ic_protobuf::state::v1 as pb_state;
use ic_recovery::{
    CUPS_DIR, IC_DATA_PATH, IC_STATE, STATES_METADATA,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::read_bytes,
    registry_helper::RegistryHelper,
    ssh_helper::SshHelper,
    steps::Step,
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

use std::{fmt::Display, net::IpAddr, path::PathBuf, time::Duration};

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
/// node has published the manifest of that checkpoint, which the state manager
/// does only once the checkpoint is verified, and until the manifest's root
/// hash is the state hash the CUP names.
pub(crate) struct WaitForHaltingCupStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) node_ip: IpAddr,
    pub(crate) registry_helper: RegistryHelper,
    pub(crate) layout: Layout,
    pub(crate) ssh_helper: SshHelper,
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
        // A node that is not answering yet, or a file that cannot be pulled off
        // it yet, is the normal state of affairs while the subnet is still
        // running towards its halting CUP, so every error is retried.
        let height = wait_for(
            &format!("subnet {} reaches the CUP it halts at", self.subnet_id),
            self.timeout,
            self.poll_interval,
            &self.logger,
            || {
                self.check()?.ok_or_else(|| {
                    RecoveryError::UnexpectedError(format!(
                        "node {} does not hold the CUP subnet {} halts at and its checkpoint yet",
                        self.node_ip, self.subnet_id,
                    ))
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
    /// and an error if the node could not be asked.
    fn check(&self) -> RecoveryResult<Option<Height>> {
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
                 published a verified checkpoint at that height yet",
                self.node_ip,
                self.subnet_id,
            );
            return Ok(None);
        };
        if root_hash != cup.content.state_hash {
            return Err(RecoveryError::ValidationFailed(format!(
                "The checkpoint of node {} at height {cup_height} has root hash {root_hash:?}, \
                 not the state hash {:?} of the CUP subnet {} halts at",
                self.node_ip, cup.content.state_hash, self.subnet_id,
            )));
        }

        Ok(Some(cup_height))
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
    /// The state manager persists the manifest of a checkpoint to
    /// `states_metadata.pbuf` only once that checkpoint has been verified,
    /// whether it created the checkpoint itself or fetched it via state sync. A
    /// manifest there thus means that the checkpoint is complete and ready to be
    /// downloaded.
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
