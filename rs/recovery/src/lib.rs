//! The recovery library contains several functions and wrappers of tools useful
//! to subnet recovery, such as `ic-admin` proposals, state up- and download,
//! state replay, restart of nodes, etc. The library is designed to be usable by
//! command line interfaces. Therefore, input arguments are first captured and
//! returned in form of a recovery [Step], holding the human-readable (and
//! reproducible) description of the step, as well as its potential automatic
//! execution.
use crate::{
    cli::wait_for_confirmation, file_sync_helper::remove_dir, registry_helper::RegistryHelper,
};
use admin_helper::{AdminHelper, IcAdmin, RegistryParams};
use command_helper::exec_cmd;
use error::{RecoveryError, RecoveryResult};
use file_sync_helper::{create_dir, download_binary, read_dir};
use futures::future::join_all;
use ic_base_types::{CanisterId, NodeId};
use ic_cup_explorer::get_catchup_content;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_replay::{
    cmd::{AddAndBlessReplicaVersionCmd, AddRegistryContentCmd, SubCommand},
    player::StateParams,
};
use ic_types::{messages::HttpStatusResponse, Height, ReplicaVersion, SubnetId};
use registry_helper::RegistryPollingStrategy;
use serde::{Deserialize, Serialize};
use slog::{info, warn, Logger};
use ssh_helper::SshHelper;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    thread,
    time::{self, Duration, SystemTime},
};
use steps::*;
use url::Url;
use util::{block_on, parse_hex_str};

pub mod admin_helper;
pub mod app_subnet_recovery;
pub mod args_merger;
pub mod cli;
pub mod cmd;
pub mod command_helper;
pub mod error;
pub mod file_sync_helper;
pub mod nns_recovery_failover_nodes;
pub mod nns_recovery_same_nodes;
pub mod recovery_iterator;
pub mod recovery_state;
pub mod registry_helper;
pub mod replay_helper;
pub(crate) mod ssh_helper;
pub mod steps;
pub mod util;

pub const RECOVERY_DIRECTORY_NAME: &str = "recovery";
pub const IC_DATA_PATH: &str = "/var/lib/ic/data";
pub const IC_STATE_DIR: &str = "data/ic_state";
pub const CUPS_DIR: &str = "cups";
pub const IC_CHECKPOINTS_PATH: &str = "ic_state/checkpoints";
pub const IC_CERTIFICATIONS_PATH: &str = "ic_consensus_pool/certification";
pub const IC_JSON5_PATH: &str = "/run/ic-node/config/ic.json5";
pub const IC_STATE_EXCLUDES: &[&str] = &[
    "images",
    "tip",
    "backups",
    "fs_tmp",
    "recovery",
    // The page_deltas/ directory should not be copied over on rsync as well,
    // it is a new directory used for storing the files backing up the
    // page deltas. We do not need to copy page deltas when nodes are re-assigned.
    "page_deltas",
    IC_REGISTRY_LOCAL_STORE,
];
pub const IC_STATE: &str = "ic_state";
pub const NEW_IC_STATE: &str = "new_ic_state";
pub const IC_REGISTRY_LOCAL_STORE: &str = "ic_registry_local_store";
pub const CHECKPOINTS: &str = "checkpoints";
pub const ADMIN: &str = "admin";
pub const READONLY: &str = "readonly";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct NeuronArgs {
    dfx_hsm_pin: String,
    slot: String,
    neuron_id: String,
    key_id: String,
}

#[derive(Debug)]
pub struct NodeMetrics {
    _ip: IpAddr,
    pub finalization_height: Height,
    pub certification_height: Height,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryArgs {
    pub dir: PathBuf,
    pub nns_url: Url,
    pub replica_version: Option<ReplicaVersion>,
    pub key_file: Option<PathBuf>,
    pub test_mode: bool,
    pub skip_prompts: bool,
}

/// The recovery struct comprises working directories for the recovery of a
/// given replica version and NNS. It offers several functions useful for subnet
/// recovery, by providing an interface to tools such as `ic-replay` and
/// `ic-recovery`, as well as ssh and rsync procedures.
/// Although operations on subnets and the downloaded state are idempotent, certain
/// orders of execution will naturally lead to errors (i.e. replaying the state
/// before downloading it).
#[derive(Clone)]
pub struct Recovery {
    pub recovery_dir: PathBuf,
    pub binary_dir: PathBuf,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    pub local_store_path: PathBuf,

    pub admin_helper: AdminHelper,
    pub registry_helper: RegistryHelper,

    pub key_file: Option<PathBuf>,
    ssh_confirmation: bool,

    pub logger: Logger,
}

impl Recovery {
    /// Start new recovery instance by creating directories and downloading
    /// binaries.
    pub fn new(
        logger: Logger,
        args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        registry_nns_url: Url,
        registry_polling_strategy: RegistryPollingStrategy,
    ) -> RecoveryResult<Self> {
        let ssh_confirmation = !args.test_mode;
        let recovery_dir = args.dir.join(RECOVERY_DIRECTORY_NAME);
        let binary_dir = recovery_dir.join("binaries");
        let data_dir = recovery_dir.join("original_data");
        let work_dir = recovery_dir.join("working_dir");
        let local_store_path = work_dir.join("data").join(IC_REGISTRY_LOCAL_STORE);
        let nns_pem = recovery_dir.join("nns.pem");

        Recovery::create_dirs(&[&binary_dir, &data_dir, &work_dir, &local_store_path])?;

        let registry_helper = RegistryHelper::new(
            logger.clone(),
            registry_nns_url,
            local_store_path.clone(),
            nns_pem.as_path(),
            registry_polling_strategy,
        );

        if ssh_confirmation {
            wait_for_confirmation(&logger);
        }

        if !binary_dir.join("ic-admin").exists() {
            if let Some(version) = args.replica_version {
                block_on(download_binary(
                    &logger,
                    version,
                    String::from("ic-admin"),
                    &binary_dir,
                ))?;
            } else {
                info!(logger, "No ic-admin version provided, skipping download.");
            }
        } else {
            info!(logger, "ic-admin exists, skipping download.");
        }

        let admin_helper = AdminHelper::new(binary_dir.clone(), args.nns_url, neuron_args);

        Ok(Self {
            recovery_dir,
            binary_dir,
            data_dir,
            work_dir,
            local_store_path,
            admin_helper,
            registry_helper,
            key_file: args.key_file,
            ssh_confirmation,
            logger,
        })
    }

    /// Construct a [Url] for the NNS endpoint of the given node IP
    pub fn get_nns_endpoint(node_ip: IpAddr) -> RecoveryResult<Url> {
        Url::parse(&format!("http://[{}]:8080", node_ip)).map_err(|e| {
            RecoveryError::invalid_output_error(format!("Failed to parse NNS URL: {}", e))
        })
    }

    /// Set recovery to a different NNS by creating a new [AdminHelper].
    pub fn set_nns(&mut self, nns_url: Url, neuron_args: Option<NeuronArgs>) {
        self.admin_helper = AdminHelper::new(self.binary_dir.clone(), nns_url, neuron_args);
    }

    // Create directories used to store downloaded states, binaries and results
    fn create_dirs(dirs: &[&Path]) -> RecoveryResult<()> {
        for dir in dirs {
            create_dir(dir)?;
        }

        Ok(())
    }

    /// Removes all the checkpoints except the "highest" one.
    ///
    /// Returns an error when there are no checkpoints.
    pub fn remove_all_but_highest_checkpoints(
        checkpoint_path: &Path,
        logger: &Logger,
    ) -> RecoveryResult<Height> {
        let checkpoints = Self::get_checkpoint_names(checkpoint_path)?;
        let (max_name, max_height) = Self::get_latest_checkpoint_name_and_height(checkpoint_path)?;

        for checkpoint in checkpoints {
            if checkpoint == max_name {
                continue;
            }

            info!(logger, "Deleting checkpoint {}", checkpoint);
            remove_dir(&checkpoint_path.join(checkpoint))?;
        }

        Ok(max_height)
    }

    /// Return a recovery [AdminStep] to halt or unhalt the given subnet
    pub fn halt_subnet(&self, subnet_id: SubnetId, is_halted: bool, keys: &[String]) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_halt_subnet_command(subnet_id, is_halted, keys),
        }
    }

    /// Executes the given SSH command.
    pub fn execute_ssh_command(
        &self,
        account: &str,
        node_ip: IpAddr,
        commands: &str,
    ) -> RecoveryResult<Option<String>> {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            account.to_string(),
            node_ip,
            self.ssh_confirmation,
            self.key_file.clone(),
        );
        ssh_helper.ssh(commands.to_string())
    }

    /// Returns true if ssh access to the given account and ip exists.
    pub fn check_ssh_access(&self, account: &str, node_ip: IpAddr) -> bool {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            account.to_string(),
            node_ip,
            self.ssh_confirmation,
            self.key_file.clone(),
        );
        ssh_helper.can_connect()
    }

    // Execute an `ic-admin` command, log the output.
    fn exec_admin_cmd(logger: &Logger, ic_admin_cmd: &IcAdmin) -> RecoveryResult<()> {
        let mut cmd = AdminHelper::to_system_command(ic_admin_cmd);
        if let Some(res) = exec_cmd(&mut cmd)? {
            info!(logger, "{}", res);
        }
        Ok(())
    }

    /// Return a [DownloadCertificationsStep] downloading the certification pools of all reachable
    /// nodes in the given subnet to the recovery data directory using the readonly account.
    pub fn get_download_certs_step(&self, subnet_id: SubnetId, admin: bool) -> impl Step {
        DownloadCertificationsStep {
            logger: self.logger.clone(),
            subnet_id,
            registry_helper: self.registry_helper.clone(),
            work_dir: self.work_dir.clone(),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
            admin,
        }
    }

    /// Return a [MergeCertificationPoolsStep] moving certifications and share from all
    /// downloaded pools into a new pool to be used during replay.
    pub fn get_merge_certification_pools_step(&self) -> impl Step {
        MergeCertificationPoolsStep {
            logger: self.logger.clone(),
            work_dir: self.work_dir.clone(),
        }
    }

    /// Return a [DownloadIcStateStep] downloading the ic_state of the given
    /// node to the recovery data directory using the given account.
    pub fn get_download_state_step(
        &self,
        node_ip: IpAddr,
        try_readonly: bool,
        keep_downloaded_state: bool,
        additional_excludes: Vec<&str>,
    ) -> impl Step {
        DownloadIcStateStep {
            logger: self.logger.clone(),
            try_readonly,
            node_ip,
            target: self.data_dir.display().to_string(),
            keep_downloaded_state,
            working_dir: self.work_dir.display().to_string(),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
            additional_excludes: additional_excludes
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    }

    /// Return a [ReplayStep] to replay the downloaded state of the given
    /// subnet.
    pub fn get_replay_step(
        &self,
        subnet_id: SubnetId,
        subcmd: Option<ReplaySubCmd>,
        canister_caller_id: Option<CanisterId>,
    ) -> impl Step {
        ReplayStep {
            logger: self.logger.clone(),
            subnet_id,
            work_dir: self.work_dir.clone(),
            config: self.work_dir.join("ic.json5"),
            subcmd,
            canister_caller_id,
            result: self.work_dir.join(replay_helper::OUTPUT_FILE_NAME),
        }
    }

    /// Return a [ReplayStep] to replay the downloaded state of the given
    /// subnet and execute [SubCommand::AddAndBlessReplicaVersion].
    pub fn get_replay_with_upgrade_step(
        &self,
        subnet_id: SubnetId,
        upgrade_version: ReplicaVersion,
        upgrade_url: Url,
        sha256: String,
    ) -> RecoveryResult<impl Step> {
        let version_record = format!(
            r#"{{ "release_package_sha256_hex": "{}", "release_package_urls": ["{}"] }}"#,
            sha256, upgrade_url
        );
        Ok(self.get_replay_step(
            subnet_id,
            Some(ReplaySubCmd {
                cmd: SubCommand::AddAndBlessReplicaVersion(AddAndBlessReplicaVersionCmd {
                    replica_version_id: upgrade_version.to_string(),
                    replica_version_value: version_record.clone(),
                    update_subnet_record: true,
                }),
                descr: format!(
                    r#" add-and-bless-replica-version --update-subnet-record "{}" {}"#,
                    upgrade_version, version_record
                ),
            }),
            None,
        ))
    }

    /// Return a [ReplayStep] to replay the downloaded state of the given
    /// subnet and execute [SubCommand::AddRegistryContent].
    pub fn get_replay_with_registry_content_step(
        &self,
        subnet_id: SubnetId,
        new_registry_local_store: PathBuf,
        canister_caller_id: &str,
    ) -> RecoveryResult<impl Step> {
        let canister_id = CanisterId::from_str(canister_caller_id).map_err(|e| {
            RecoveryError::invalid_output_error(format!("Failed to parse canister id: {}", e))
        })?;
        Ok(self.get_replay_step(
            subnet_id,
            Some(ReplaySubCmd {
                cmd: SubCommand::AddRegistryContent(AddRegistryContentCmd {
                    registry_local_store_dir: new_registry_local_store.clone(),
                    verbose: true,
                    allowed_mutation_key_prefixes:
                        "crypto_,node_,catch_up_package_,subnet_record_,replica_version_"
                            .to_string(),
                }),
                descr: format!(
                    r#" --canister-caller-id {} add-registry-content "{}" --verbose"#,
                    canister_id,
                    new_registry_local_store.display()
                ),
            }),
            Some(canister_id),
        ))
    }

    /// Get names of all checkpoints currently on disk
    pub fn get_checkpoint_names(path: &Path) -> RecoveryResult<Vec<String>> {
        let res = read_dir(path)?
            .flatten()
            .filter_map(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str().map(String::from))
            })
            .collect::<Vec<String>>();
        Ok(res)
    }

    /// Get the name and the height of the latest checkpoint currently on disk
    ///
    /// Returns an error when there are no checkpoints.
    pub fn get_latest_checkpoint_name_and_height(
        checkpoints_path: &Path,
    ) -> RecoveryResult<(String, Height)> {
        Self::get_checkpoint_names(checkpoints_path)?
            .into_iter()
            .map(|name| parse_hex_str(&name).map(|height| (name, Height::from(height))))
            .collect::<RecoveryResult<Vec<_>>>()?
            .into_iter()
            .max_by_key(|(_name, height)| *height)
            .ok_or_else(|| RecoveryError::invalid_output_error("No checkpoints"))
    }

    /// Parse and return the output of the replay step.
    pub fn get_replay_output(&self) -> RecoveryResult<StateParams> {
        replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))
    }

    /// Calculate the next recovery height from the given height
    pub fn get_recovery_height(replay_height: Height) -> Height {
        (replay_height / 1000 + Height::from(1)) * 1000
    }

    pub fn get_validate_replay_step(&self, subnet_id: SubnetId, extra_batches: u64) -> impl Step {
        ValidateReplayStep {
            logger: self.logger.clone(),
            subnet_id,
            registry_helper: self.registry_helper.clone(),
            work_dir: self.work_dir.clone(),
            extra_batches,
        }
    }

    /// Return an [UploadAndRestartStep] to upload the current recovery state to
    /// a node and restart it.
    pub fn get_upload_and_restart_step(&self, node_ip: IpAddr) -> impl Step {
        self.get_upload_and_restart_step_with_data_src(node_ip, self.work_dir.join(IC_STATE_DIR))
    }

    /// Return an [UploadAndRestartStep] to upload the current recovery state to
    /// a node and restart it.
    pub fn get_upload_and_restart_step_with_data_src(
        &self,
        node_ip: IpAddr,
        data_src: PathBuf,
    ) -> impl Step {
        UploadAndRestartStep {
            logger: self.logger.clone(),
            node_ip,
            work_dir: self.work_dir.clone(),
            data_src,
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
            check_ic_replay_height: true,
        }
    }

    /// Lookup the image [Url] and sha hash of the given [ReplicaVersion]
    pub fn get_img_url_and_sha(version: &ReplicaVersion) -> RecoveryResult<(Url, String)> {
        let version_string = version.to_string();
        let url_base = format!(
            "https://download.dfinity.systems/ic/{}/guest-os/update-img/",
            version_string
        );

        let image_name = "update-img.tar.zst";
        let upgrade_url_string = format!("{}{}", url_base, image_name);
        let invalid_url = |url, e| {
            RecoveryError::invalid_output_error(format!("Invalid Url string: {}, {}", url, e))
        };
        let upgrade_url =
            Url::parse(&upgrade_url_string).map_err(|e| invalid_url(upgrade_url_string, e))?;

        let sha_url_string = format!("{}SHA256SUMS", url_base);
        let sha_url = Url::parse(&sha_url_string).map_err(|e| invalid_url(sha_url_string, e))?;

        // fetch the `SHA256SUMS` file
        let mut curl = Command::new("curl");
        curl.arg(sha_url.to_string());
        let output = exec_cmd(&mut curl)?.unwrap_or_default();

        // split the content into lines, then split each line into a pair (<hash>, <image_name>)
        let hashes = output
            .split('\n')
            .map(|line| line.split(" *").collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // return the hash for the selected image name
        for pair in hashes.iter() {
            match pair.as_slice() {
                &[sha256, name] if name == image_name => {
                    return Ok((upgrade_url, sha256.to_string()));
                }
                _ => {}
            }
        }

        Err(RecoveryError::invalid_output_error(format!(
            "No hash found in the SHA256SUMS file: {output}"
        )))
    }

    /// Return an [AdminStep] step electing the given [ReplicaVersion].
    /// Existence of artifacts for the given version is checked beforehand, thus
    /// generation of this step may fail if the version is invalid.
    pub fn elect_replica_version(
        &self,
        upgrade_version: &ReplicaVersion,
        upgrade_url: Url,
        sha256: String,
    ) -> RecoveryResult<impl Step> {
        Ok(AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_update_elected_replica_versions_command(
                    upgrade_version,
                    &upgrade_url,
                    sha256,
                ),
        })
    }

    /// Return an [AdminStep] step upgrading the given subnet to the given
    /// replica version.
    pub fn deploy_guestos_to_all_subnet_nodes(
        &self,
        subnet_id: SubnetId,
        upgrade_version: &ReplicaVersion,
    ) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_deploy_guestos_to_all_subnet_nodes_command(
                    subnet_id,
                    upgrade_version,
                ),
        }
    }

    /// Return an [AdminStep] step updating the recovery CUP of the given
    /// subnet.
    pub fn update_recovery_cup(
        &self,
        subnet_id: SubnetId,
        checkpoint_height: Height,
        state_hash: String,
        replacement_nodes: &[NodeId],
        registry_params: Option<RegistryParams>,
        ecdsa_subnet_id: Option<SubnetId>,
    ) -> RecoveryResult<impl Step> {
        let key_ids = ecdsa_subnet_id
            .map(|id| match self.registry_helper.get_ecdsa_config(id) {
                Ok((_registry_version, Some(config))) => config.key_ids,
                Ok((registry_version, None)) => {
                    info!(
                        self.logger,
                        "No ECDSA config at registry version {}", registry_version
                    );
                    vec![]
                }
                Err(err) => {
                    warn!(self.logger, "Failed to get ECDSA config: {}", err);
                    vec![]
                }
            })
            .unwrap_or_default();

        Ok(AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_update_recovery_cup_command(
                    subnet_id,
                    checkpoint_height,
                    state_hash,
                    key_ids,
                    replacement_nodes,
                    registry_params,
                    ecdsa_subnet_id,
                    SystemTime::now(),
                ),
        })
    }

    /// Return an [UploadAndRestartStep] to upload the current recovery state to
    /// a node and restart it.
    pub fn get_wait_for_cup_step(&self, node_ip: IpAddr) -> impl Step {
        WaitForCUPStep {
            logger: self.logger.clone(),
            node_ip,
            work_dir: self.work_dir.clone(),
        }
    }

    /// Returns the status of a replica. It is requested from a public API.
    pub async fn get_replica_status(url: Url) -> RecoveryResult<HttpStatusResponse> {
        let joined_url = url.clone().join("api/v2/status").map_err(|e| {
            RecoveryError::invalid_output_error(format!("failed to join URLs: {}", e))
        })?;

        let response = reqwest::Client::builder()
            .timeout(time::Duration::from_secs(6))
            .build()
            .map_err(|e| {
                RecoveryError::invalid_output_error(format!("cannot build a reqwest client: {}", e))
            })?
            .get(joined_url)
            .send()
            .await
            .map_err(|err| {
                RecoveryError::invalid_output_error(format!("Failed to create request: {}", err))
            })?;

        let cbor_response = serde_cbor::from_slice(&response.bytes().await.map_err(|e| {
            RecoveryError::invalid_output_error(format!(
                "failed to convert a response to bytes: {}",
                e
            ))
        })?)
        .map_err(|e| {
            RecoveryError::invalid_output_error(format!("response is not encoded as cbor: {}", e))
        })?;

        serde_cbor::value::from_value::<HttpStatusResponse>(cbor_response).map_err(|e| {
            RecoveryError::invalid_output_error(format!(
                "failed to deserialize a response to HttpStatusResponse: {}",
                e
            ))
        })
    }

    /// Gets the replica version from the endpoint even if it is unhealthy.
    pub fn get_assigned_replica_version_any_health(url: Url) -> RecoveryResult<String> {
        let version = block_on(Recovery::get_replica_status(url))?.impl_version;

        version.ok_or_else(|| RecoveryError::invalid_output_error("No version found in status"))
    }

    // Wait until the recovery CUP as specified in the replay output is present on the given node
    // and the node reports *some* replica version
    pub fn wait_for_recovery_cup(
        logger: &Logger,
        node_ip: IpAddr,
        recovery_height: Height,
        state_hash: String,
    ) -> RecoveryResult<()> {
        let node_url = Url::parse(&format!("http://[{}]:8080/", node_ip)).map_err(|err| {
            RecoveryError::invalid_output_error(format!(
                "Could not parse node URL for IP {}: {}",
                node_ip, err
            ))
        })?;

        let mut cup_present = false;
        for i in 0..30 {
            let maybe_cup = match block_on(get_catchup_content(&node_url)) {
                Ok(res) => res,
                Err(e) => {
                    info!(logger, "Try: {}. Could not fetch CUP: {}", i, e);
                    None
                }
            };

            if let Some(cup_content) = maybe_cup {
                let (cup_height, cup_hash) = (
                    Height::from(cup_content.random_beacon.unwrap().height),
                    hex::encode(&cup_content.state_hash),
                );

                info!(
                    logger,
                    "Try: {}. Found CUP at height {} and state hash {} on upload node",
                    i,
                    cup_height,
                    cup_hash
                );

                if cup_height == recovery_height && state_hash == cup_hash {
                    info!(logger, "Recovery CUP present!");

                    let repl_version =
                        Recovery::get_assigned_replica_version_any_health(node_url.clone());
                    info!(logger, "Status response: {:?}", repl_version);
                    if repl_version.is_ok() {
                        cup_present = true;
                        break;
                    } else {
                        info!(logger, "Replica not yet restarted");
                    }
                }
            }

            info!(logger, "Recovery CUP not yet present, retrying...");
            thread::sleep(time::Duration::from_secs(15));
        }

        if !cup_present {
            return Err(RecoveryError::invalid_output_error(
                "Did not find recovery CUP on upload node".to_string(),
            ));
        }

        Ok(())
    }

    /// Return a [CleanupStep] to remove the recovery directory and all of its contents
    pub fn get_cleanup_step(&self) -> impl Step {
        CleanupStep {
            recovery_dir: self.recovery_dir.clone(),
        }
    }

    /// Return a [StopReplicaStep] to stop the replica with the given IP
    pub fn get_stop_replica_step(&self, node_ip: IpAddr) -> impl Step {
        StopReplicaStep {
            logger: self.logger.clone(),
            node_ip,
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }

    /// Return an [UpdateLocalStoreStep] to update the current local store using ic-replay
    pub fn get_update_local_store_step(&self, subnet_id: SubnetId) -> impl Step {
        UpdateLocalStoreStep {
            subnet_id,
            work_dir: self.work_dir.clone(),
        }
    }

    /// Return an [GetRecoveryCUPStep] to get the recovery CUP using ic-replay
    pub fn get_recovery_cup_step(&self, subnet_id: SubnetId) -> RecoveryResult<impl Step> {
        let state_params = self.get_replay_output()?;
        let recovery_height = Recovery::get_recovery_height(state_params.height);
        Ok(GetRecoveryCUPStep {
            subnet_id,
            config: self.work_dir.join("ic.json5"),
            result: self.work_dir.join("set_recovery_cup.txt"),
            state_hash: state_params.hash,
            work_dir: self.work_dir.clone(),
            recovery_height,
        })
    }

    /// Return a [CreateTarsStep] to create tar files of the current registry local store and ic state
    pub fn get_create_tars_step(&self) -> impl Step {
        let mut tar = Command::new("tar");
        tar.arg("-C")
            .arg(self.work_dir.join("data").join(IC_REGISTRY_LOCAL_STORE))
            .arg("-zcvf")
            .arg(
                self.work_dir
                    .join(format!("{}.tar.gz", IC_REGISTRY_LOCAL_STORE)),
            )
            .arg(".");

        CreateTarsStep {
            logger: self.logger.clone(),
            store_tar_cmd: tar,
        }
    }

    pub fn get_copy_ic_state(&self, new_state_dir: PathBuf) -> impl Step {
        CopyIcStateStep {
            logger: self.logger.clone(),
            work_dir: self.work_dir.join(IC_STATE_DIR),
            new_state_dir,
        }
    }

    /// Return an [UploadCUPAndTar] uploading tars and extracted CUP to subnet nodes
    pub fn get_upload_cup_and_tar_step(&self, subnet_id: SubnetId) -> impl Step {
        UploadCUPAndTar {
            logger: self.logger.clone(),
            registry_helper: self.registry_helper.clone(),
            subnet_id,
            work_dir: self.work_dir.clone(),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }

    /// Return an [AdminStep] proposing the creation of a new system subnet with testnet parameters
    pub fn get_propose_to_create_test_system_subnet_step(
        &self,
        subnet_id_override: SubnetId,
        replica_version: ReplicaVersion,
        node_ids: &[NodeId],
    ) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self.admin_helper.get_propose_to_create_test_system_subnet(
                subnet_id_override,
                replica_version,
                node_ids,
            ),
        }
    }

    /// Return a [DownloadRegistryStoreStep] to download the registry store containing entries for
    /// the given [SubnetId] from the given download node
    pub fn get_download_registry_store_step(
        &self,
        download_node: IpAddr,
        original_nns_id: SubnetId,
    ) -> impl Step {
        DownloadRegistryStoreStep {
            logger: self.logger.clone(),
            node_ip: download_node,
            original_nns_id,
            work_dir: self.work_dir.clone(),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }

    /// Return an [UploadAndHostTarStep] to upload and host a tar file on the given auxiliary host
    pub fn get_upload_and_host_tar(
        &self,
        aux_host: String,
        aux_ip: IpAddr,
        tar: PathBuf,
    ) -> impl Step {
        UploadAndHostTarStep {
            logger: self.logger.clone(),
            aux_host,
            aux_ip,
            tar,
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }
}

pub async fn get_node_metrics(logger: &Logger, ip: &IpAddr) -> Option<NodeMetrics> {
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        reqwest::get(format!("http://[{}]:9090", ip)),
    )
    .await;
    let res = match response {
        Ok(Ok(res)) => res,
        e => {
            warn!(logger, "Http request failed: {:?}", e);
            return None;
        }
    };
    let body = match res.text().await {
        Ok(val) => val,
        Err(e) => {
            warn!(logger, "Http decode failed: {:?}", e);
            return None;
        }
    };
    let mut node_heights = NodeMetrics {
        finalization_height: Height::from(0),
        certification_height: Height::from(0),
        _ip: *ip,
    };
    for line in body.split('\n') {
        let mut parts = line.split(' ');
        if let (Some(prefix), Some(height)) = (parts.next(), parts.next()) {
            match prefix {
                "certification_last_certified_height" => match height.trim().parse::<u64>() {
                    Ok(val) => node_heights.certification_height = Height::from(val),
                    error => warn!(logger, "Couldn't parse height {}: {:?}", height, error),
                },
                r#"artifact_pool_consensus_height_stat{pool_type="validated",stat="max",type="finalization"}"# => {
                    match height.trim().parse::<u64>() {
                        Ok(val) => node_heights.finalization_height = Height::from(val),
                        error => {
                            warn!(logger, "Couldn't parse height {}: {:?}", height, error)
                        }
                    }
                }
                _ => continue,
            }
        }
    }
    Some(node_heights)
}

/// Grabs metrics from all nodes and greps for the certification and finalization heights.
pub fn get_node_heights_from_metrics(
    logger: &Logger,
    registry_helper: &RegistryHelper,
    subnet_id: SubnetId,
) -> RecoveryResult<Vec<NodeMetrics>> {
    let ips = get_member_ips(registry_helper, subnet_id)?;
    let metrics: Vec<NodeMetrics> =
        block_on(join_all(ips.iter().map(|ip| get_node_metrics(logger, ip))))
            .into_iter()
            .flatten()
            .collect();
    if ips.len() > metrics.len() {
        warn!(
            logger,
            "Failed to get metrics from {} nodes!",
            ips.len() - metrics.len()
        );
    }
    Ok(metrics)
}

/// Lookup IP addresses of all members of the given subnet
pub fn get_member_ips(
    registry_helper: &RegistryHelper,
    subnet_id: SubnetId,
) -> RecoveryResult<Vec<IpAddr>> {
    let (registry_version, node_ids) = registry_helper.get_node_ids_on_subnet(subnet_id)?;

    let Some(node_ids) = node_ids else {
        return Err(RecoveryError::RegistryError(format!(
            "no node ids found in the registry version {} for subnet_id {}",
            registry_version, subnet_id
        )));
    };

    node_ids
        .into_iter()
        .filter_map(|node_id| {
            registry_helper
                .registry_client()
                .get_node_record(node_id, registry_version)
                .unwrap_or_default()
        })
        .filter_map(|node_record| {
            node_record.http.map(|http| {
                http.ip_addr.parse().map_err(|err| {
                    RecoveryError::UnexpectedError(format!(
                        "couldn't parse ip address from the registry: {:?}",
                        err
                    ))
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities_tmpdir::tmpdir;

    #[test]
    fn get_latest_checkpoint_name_and_height_test() {
        let checkpoints_dir = tmpdir("checkpoints");
        create_fake_checkpoint_dirs(
            checkpoints_dir.path(),
            &[
                /*height=64800*/ "000000000000fd20",
                /*height=64900*/ "000000000000fd84",
            ],
        );

        let (name, height) =
            Recovery::get_latest_checkpoint_name_and_height(checkpoints_dir.path())
                .expect("Failed getting the latest checkpoint name and height");

        assert_eq!(name, "000000000000fd84");
        assert_eq!(height, Height::from(64900));
    }

    #[test]
    fn get_latest_checkpoint_name_and_height_returns_error_on_invalid_checkpoint_name() {
        let checkpoints_dir = tmpdir("checkpoints");
        create_fake_checkpoint_dirs(
            checkpoints_dir.path(),
            &[
                /*height=64800*/ "000000000000fd20",
                /*height=64900*/ "000000000000fd84",
                /*height=???*/ "invalid_checkpoint_name",
            ],
        );

        assert!(Recovery::get_latest_checkpoint_name_and_height(checkpoints_dir.path()).is_err());
    }

    #[test]
    fn get_latest_checkpoint_name_and_height_returns_error_when_no_checkpoints() {
        let checkpoints_dir = tmpdir("checkpoints");

        assert!(Recovery::get_latest_checkpoint_name_and_height(checkpoints_dir.path()).is_err());
    }

    #[test]
    fn remove_all_but_highest_checkpoints_test() {
        let logger = util::make_logger();
        let checkpoints_dir = tmpdir("checkpoints");
        create_fake_checkpoint_dirs(
            checkpoints_dir.path(),
            &[
                /*height=64800*/ "000000000000fd20",
                /*height=64900*/ "000000000000fd84",
            ],
        );

        let height = Recovery::remove_all_but_highest_checkpoints(checkpoints_dir.path(), &logger)
            .expect("Failed to remove checkpoints");

        assert_eq!(height, Height::from(64900));
        assert_eq!(
            Recovery::get_checkpoint_names(checkpoints_dir.path()).unwrap(),
            vec![String::from("000000000000fd84")]
        );
    }

    #[test]
    fn remove_all_but_highest_checkpoints_returns_error_when_no_checkpoints() {
        let logger = util::make_logger();
        let checkpoints_dir = tmpdir("checkpoints");

        assert!(
            Recovery::remove_all_but_highest_checkpoints(checkpoints_dir.path(), &logger).is_err()
        );
    }

    fn create_fake_checkpoint_dirs(root: &Path, checkpoint_names: &[&str]) {
        for checkpoint_name in checkpoint_names {
            create_dir(&root.join(checkpoint_name)).unwrap();
        }
    }
}
