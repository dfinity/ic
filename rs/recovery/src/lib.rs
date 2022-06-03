//! The recovery library contains several functions and wrappers of tools useful
//! to subnet recovery, such as `ic-admin` proposals, state up- and download,
//! state replay, restart of nodes, etc. The library is designed to be usable by
//! command line interfaces. Therefore, input arguments are first captured and
//! returned in form of a recovery [Step], holding the human-readable (and
//! reproducable) description of the step, as well as its potential automatic
//! execution.
use admin_helper::{AdminHelper, IcAdmin, RegistryParams};
use command_helper::{exec_cmd, pipe_all};
use error::{RecoveryError, RecoveryResult};
use file_sync_helper::{create_dir, download_binary, read_dir};
use ic_base_types::{CanisterId, NodeId, PrincipalId};
use ic_cup_explorer::get_catchup_content;
use ic_replay::cmd::{AddAndBlessReplicaVersionCmd, AddRegistryContentCmd, SubCommand};
use ic_replay::player::StateParams;
use ic_types::messages::HttpStatusResponse;
use ic_types::{Height, ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use ssh_helper::SshHelper;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::{thread, time};
use steps::*;
use url::Url;
use util::block_on;

pub mod admin_helper;
pub mod app_subnet_recovery;
pub mod cli;
pub mod cmd;
pub(crate) mod command_helper;
pub mod error;
pub mod file_sync_helper;
pub mod nns_recovery_failover_nodes;
pub mod nns_recovery_same_nodes;
pub mod recovery_iterator;
pub mod replay_helper;
pub(crate) mod ssh_helper;
pub mod steps;
pub(crate) mod util;

pub const IC_DATA_PATH: &str = "/var/lib/ic/data";
pub const IC_STATE_DIR: &str = "data/ic_state";
pub const IC_CHECKPOINTS_PATH: &str = "ic_state/checkpoints";
pub const IC_JSON5_PATH: &str = "/run/ic-node/config/ic.json5";
pub const IC_STATE_EXCLUDES: &[&str] = &["images", "tip", "backups", "fs_tmp", "cups"];
pub const IC_STATE: &str = "ic_state";
pub const NEW_IC_STATE: &str = "new_ic_state";
pub const IC_REGISTRY_LOCAL_STORE: &str = "ic_registry_local_store";
pub const CHECKPOINTS: &str = "checkpoints";
pub const ADMIN: &str = "admin";
pub const READONLY: &str = "readonly";

#[derive(Clone, Debug)]
pub struct NeuronArgs {
    dfx_hsm_pin: String,
    slot: String,
    neuron_id: String,
    key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeHeight {
    pub instance: SocketAddr,
    pub height: Height,
}

pub struct RecoveryArgs {
    pub dir: PathBuf,
    pub nns_url: Url,
    pub replica_version: Option<ReplicaVersion>,
    pub key_file: Option<PathBuf>,
}

/// The recovery struct comprises working directories for the recovery of a
/// given replica version and NNS. It offers several functions useful for subnet
/// recovery, by providing an interface to tools such as `ic-replay` and
/// `ic-recovery`, as well as ssh and rsync procedures.
/// Although operations on subnets and the downloaded state are idempotent, certain
/// orders of execution will naturally lead to errors (i.e. replaying the state
/// before downloading it).
pub struct Recovery {
    pub recovery_dir: PathBuf,
    pub binary_dir: PathBuf,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,

    pub admin_helper: AdminHelper,

    pub key_file: Option<PathBuf>,
    ssh_confirmation: bool,

    logger: Logger,
}

impl Recovery {
    /// Start new recovery instance by creating directories and downloading
    /// binaries.
    pub fn new(
        logger: Logger,
        args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        ssh_confirmation: bool,
    ) -> RecoveryResult<Self> {
        let recovery_dir = args.dir.join("recovery");
        let binary_dir = recovery_dir.join("binaries");
        let data_dir = recovery_dir.join("original_data");
        let work_dir = recovery_dir.join("working_dir");

        let r = Self {
            recovery_dir,
            binary_dir: binary_dir.clone(),
            data_dir,
            work_dir,
            admin_helper: AdminHelper::new(binary_dir.clone(), args.nns_url, neuron_args),
            key_file: args.key_file,
            ssh_confirmation,
            logger,
        };

        r.create_dirs()?;

        if !binary_dir.join("ic-admin").exists() {
            if let Some(version) = args.replica_version {
                block_on(download_binary(
                    &r.logger,
                    version,
                    String::from("ic-admin"),
                    r.binary_dir.clone(),
                ))?;
            } else {
                info!(r.logger, "No ic-admin version provided, skipping download.");
            }
        } else {
            info!(r.logger, "ic-admin exists, skipping download.");
        }

        Ok(r)
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
    fn create_dirs(&self) -> RecoveryResult<()> {
        create_dir(&self.binary_dir)?;
        create_dir(&self.data_dir)?;
        create_dir(&self.work_dir)
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

    // Return a curl [Command] base for querying prometheus.
    fn get_prometheus_curl_base() -> Command {
        let mut curl = Command::new("curl");
        curl.args(&["-G", "http://prometheus.dfinity.systems:9090/api/v1/query"]);
        curl.args(&["-fsSL", "-m", "30", "--retry", "10", "--retry-connrefused"]);
        curl.args(&["-H", "Accept: application/json", "--data-urlencode"]);
        curl
    }

    /// Return the currently highest reported certification height of the given
    /// subnet by querying prometheus.
    pub fn get_certification_height(subnet_id: SubnetId) -> RecoveryResult<Height> {
        let mut curl = Recovery::get_prometheus_curl_base();
        curl.arg(format!("query=(max_over_time(certification_last_certified_height{{job=\"replica\",ic_subnet=~\"{:?}\"}}[1d]))", subnet_id));

        let mut jq = Command::new("jq");
        jq.arg(".data.result | map({instance: .metric.instance, height: (.value[1] | tonumber) }) | max_by(.height) | .height");

        if let Some(res) = pipe_all(&mut [curl, jq])? {
            let height = Height::from(res.trim().parse::<u64>().map_err(|e| {
                RecoveryError::invalid_output_error(format!(
                    "Could not parse height: {}, {}",
                    res, e
                ))
            })?);
            Ok(height)
        } else {
            Err(RecoveryError::invalid_output_error(
                "Empty prometheus output.".to_string(),
            ))
        }
    }

    /// Return current finalization heights of all replica instances on the
    /// given subnet, as reported by prometheus.
    pub fn get_finalization_heights(subnet_id: SubnetId) -> RecoveryResult<Vec<NodeHeight>> {
        let mut curl = Recovery::get_prometheus_curl_base();
        curl.arg(format!("query=(max_over_time(artifact_pool_consensus_height_stat{{job=\"replica\",ic_subnet=~\"{}\",type=\"finalization\",pool_type=\"validated\",stat=\"max\"}}[1d]))", subnet_id));

        let mut jq = Command::new("jq");
        jq.arg(".data.result | map({instance: .metric.instance, height: (.value[1] | tonumber) })");

        if let Some(res) = pipe_all(&mut [curl, jq])? {
            let r: Vec<NodeHeight> = serde_json::from_str(&res).map_err(|e| {
                RecoveryError::invalid_output_error(format!("Failed to parse json {}: {}", res, e))
            })?;
            Ok(r)
        } else {
            Err(RecoveryError::invalid_output_error(
                "Empty prometheus output.".to_string(),
            ))
        }
    }

    // Query prometheus to get current finalization heights of nodes in the given
    // subnet, then randomly select one with max height and return.
    pub fn get_rnd_node_ip_with_max_finalization(
        subnet_id: SubnetId,
    ) -> RecoveryResult<NodeHeight> {
        let node_heights = Recovery::get_finalization_heights(subnet_id)?;
        node_heights
            .into_iter()
            .max_by_key(|s| s.height)
            .ok_or_else(|| {
                RecoveryError::invalid_output_error("No finalization heights found".to_string())
            })
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

    /// Query the current NNS for the subnet record of
    /// the given subnet, log the output.
    pub fn get_subnet(&self, subnet_id: SubnetId) -> RecoveryResult<()> {
        Recovery::exec_admin_cmd(
            &self.logger,
            &self.admin_helper.get_subnet_command(subnet_id),
        )
    }

    /// Query the IC topology as determined by the
    /// current NNS, log the output.
    pub fn get_topology(&self) -> RecoveryResult<()> {
        Recovery::exec_admin_cmd(&self.logger, &self.admin_helper.get_topology_command())
    }

    // Execute an `ic-admin` command, log the output.
    fn exec_admin_cmd(logger: &Logger, ic_admin_cmd: &IcAdmin) -> RecoveryResult<()> {
        let mut cmd = AdminHelper::to_system_command(ic_admin_cmd);
        if let Some(res) = exec_cmd(&mut cmd)? {
            info!(logger, "{}", res);
        }
        Ok(())
    }

    /// Lookup IP addresses of all members of the given subnet
    pub fn get_member_ips(
        logger: &Logger,
        admin_helper: &AdminHelper,
        subnet_id: SubnetId,
    ) -> RecoveryResult<Vec<IpAddr>> {
        let get_subnet =
            AdminHelper::to_system_command(&admin_helper.get_subnet_command(subnet_id));
        let mut jq = Command::new("jq");
        jq.arg(".records[0].value.membership");
        pipe_all(&mut [get_subnet, jq])
            .and_then(|res| {
                let membership = res.ok_or_else(|| {
                    RecoveryError::invalid_output_error("Empty membership record".to_string())
                })?;
                serde_json::from_str::<Vec<String>>(&membership).map_err(|e| {
                    RecoveryError::invalid_output_error(format!(
                        "Failed to parse json {}: {}",
                        membership, e
                    ))
                })
            })
            .and_then(|id_strings| {
                info!(logger, "{:?}", id_strings);
                id_strings
                    .iter()
                    .map(|s| {
                        let principal = PrincipalId::from_str(s).map_err(|err| {
                            RecoveryError::invalid_output_error(format!(
                                "Could not parse node id: {}, {}",
                                s, err
                            ))
                        })?;
                        Ok(NodeId::from(principal))
                    })
                    .collect::<RecoveryResult<Vec<NodeId>>>()
            })
            .and_then(|ids| {
                ids.iter()
                    .map(|id| Recovery::get_ip_of_node(logger, admin_helper, id))
                    .collect::<RecoveryResult<Vec<IpAddr>>>()
            })
    }

    /// Lookup IP of the given node
    pub fn get_ip_of_node(
        logger: &Logger,
        admin_helper: &AdminHelper,
        node_id: &NodeId,
    ) -> RecoveryResult<IpAddr> {
        let get_node = AdminHelper::to_system_command(&admin_helper.get_node_command(node_id));
        let mut tail = Command::new("tail");
        tail.arg("-n1");
        let mut sed = Command::new("sed");
        sed.arg("-e").arg(r#"s/^.* ip_addr: "\([^"]*\)".*$/\1/"#);
        pipe_all(&mut [get_node, tail, sed]).and_then(|res| {
            info!(logger, "{:?}", res);
            let ip_string = res.ok_or_else(|| {
                RecoveryError::invalid_output_error("Empty node IP record".to_string())
            })?;
            ip_string.trim().parse::<IpAddr>().map_err(|err| {
                RecoveryError::invalid_output_error(format!(
                    "Could not parse node IP: {}, {}",
                    node_id, err
                ))
            })
        })
    }

    /// Return a [DownloadIcStateStep] downloading the ic_state of the given
    /// node to the recovery data directory using the given account.
    pub fn get_download_state_step(&self, node_ip: IpAddr, try_readonly: bool) -> impl Step {
        DownloadIcStateStep {
            logger: self.logger.clone(),
            try_readonly,
            node_ip,
            target: self.data_dir.display().to_string(),
            working_dir: self.work_dir.display().to_string(),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }

    /// Return an [UpdateConfigStep] updateing the ic.json5 config to point to
    /// the downloaded state.
    pub fn get_update_config_step(&self) -> impl Step {
        UpdateConfigStep {
            work_dir: self.work_dir.display().to_string(),
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
    ) -> RecoveryResult<impl Step> {
        let (upgrade_url, sha256) = Recovery::get_img_url_and_sha(&upgrade_version)?;
        let version_record = format!(
            r#"{{ "release_package_url": "{}", "release_package_sha256_hex": "{}" }}"#,
            upgrade_url, sha256
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
            work_dir: self.work_dir.clone(),
            extra_batches,
        }
    }

    /// Return an [UploadAndRestartStep] to upload the current recovery state to
    /// a node and restart it.
    pub fn get_upload_and_restart_step(&self, node_ip: IpAddr) -> impl Step {
        UploadAndRestartStep {
            logger: self.logger.clone(),
            node_ip,
            work_dir: self.work_dir.clone(),
            data_src: self.work_dir.join(IC_STATE_DIR),
            require_confirmation: self.ssh_confirmation,
            key_file: self.key_file.clone(),
        }
    }

    /// Lookup the image [Url] and sha hash of the given [ReplicaVersion]
    pub fn get_img_url_and_sha(version: &ReplicaVersion) -> RecoveryResult<(Url, String)> {
        let mut version_string = version.to_string();
        let mut test_version = false;
        let parts: Vec<_> = version_string.split('-').collect();
        if parts.len() > 1 && parts[parts.len() - 1] == "test" {
            test_version = true;
            version_string = parts[..parts.len() - 1].join("-");
        }
        let url_base = format!(
            "https://download.dfinity.systems/ic/{}/guest-os/update-img/",
            version_string
        );

        let upgrade_url_string = format!(
            "{}update-img{}.tar.gz",
            url_base,
            if test_version { "-test" } else { "" }
        );
        let invalid_url = |url, e| {
            RecoveryError::invalid_output_error(format!("Invalid Url string: {}, {}", url, e))
        };
        let upgrade_url =
            Url::parse(&upgrade_url_string).map_err(|e| invalid_url(upgrade_url_string, e))?;

        let sha_url_string = format!("{}SHA256SUMS", url_base);
        let sha_url = Url::parse(&sha_url_string).map_err(|e| invalid_url(sha_url_string, e))?;

        let mut curl = Command::new("curl");
        curl.arg(sha_url.to_string());
        let mut sed = Command::new("sed");
        sed.arg("-n");
        if test_version {
            sed.arg("1p");
        } else {
            sed.arg("2p");
        }
        let mut awk = Command::new("awk");
        awk.arg("{print $1;}");

        if let Some(res) = pipe_all(&mut [curl, sed, awk])? {
            let sha256 = res.trim().to_string();
            if !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(RecoveryError::invalid_output_error(format!(
                    "SHA256 malformed: {}",
                    sha256
                )));
            }
            Ok((upgrade_url, sha256))
        } else {
            Err(RecoveryError::invalid_output_error(
                "Empty output".to_string(),
            ))
        }
    }

    /// Return an [AdminStep] step blessing the given [ReplicaVersion].
    /// Existence of artifacts for the given version is checked beforehand, thus
    /// generation of this step may fail if the version is invalid.
    pub fn bless_replica_version(
        &self,
        upgrade_version: &ReplicaVersion,
    ) -> RecoveryResult<impl Step> {
        let (upgrade_url, sha256) = Recovery::get_img_url_and_sha(upgrade_version)?;
        Ok(AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_bless_replica_version_flexible_command(
                    upgrade_version,
                    &upgrade_url,
                    sha256,
                ),
        })
    }

    /// Return an [AdminStep] step upgrading the given subnet to the given
    /// replica version.
    pub fn update_subnet_replica_version(
        &self,
        subnet_id: SubnetId,
        upgrade_version: &ReplicaVersion,
    ) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_update_subnet_replica_version_command(subnet_id, upgrade_version),
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
    ) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self
                .admin_helper
                .get_propose_to_update_recovery_cup_command(
                    subnet_id,
                    checkpoint_height,
                    state_hash,
                    replacement_nodes,
                    registry_params,
                ),
        }
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

        let cbor_response = serde_cbor::from_slice(
            &response
                .bytes()
                .await
                .map_err(|e| {
                    RecoveryError::invalid_output_error(format!(
                        "failed to convert a response to bytes: {}",
                        e
                    ))
                })?
                .to_vec(),
        )
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
        let version = match block_on(Recovery::get_replica_status(url)) {
            Ok(status) => status,
            Err(err) => return Err(err),
        }
        .impl_version;
        match version {
            Some(ver) => Ok(ver),
            None => Err(RecoveryError::invalid_output_error(
                "No version found in status".to_string(),
            )),
        }
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
        for i in 0..50 {
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
            thread::sleep(time::Duration::from_secs(10));
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
            config: self.work_dir.join("ic.json5"),
            result: self.work_dir.join("update_local_store.txt"),
        }
    }

    /// Return an [SetRecoveryCUPStep] to set the recovery CUP using ic-replay
    pub fn get_set_recovery_cup_step(&self, subnet_id: SubnetId) -> RecoveryResult<impl Step> {
        let state_params = self.get_replay_output()?;
        let recovery_height = Recovery::get_recovery_height(state_params.height);
        Ok(SetRecoveryCUPStep {
            subnet_id,
            config: self.work_dir.join("ic.json5"),
            result: self.work_dir.join("set_recovery_cup.txt"),
            state_hash: state_params.hash,
            recovery_height,
        })
    }

    /// Return an [AdminStep] extracting the current cup into cup.proto using ic-admin
    pub fn get_extract_cup_file_step(&self, subnet_id: SubnetId) -> impl Step {
        AdminStep {
            logger: self.logger.clone(),
            ic_admin_cmd: self.admin_helper.get_extract_cup_command(
                subnet_id,
                self.work_dir.join("data").join(IC_REGISTRY_LOCAL_STORE),
                self.work_dir.join("cup.proto"),
            ),
        }
    }

    /// Return a [CreateTarsStep] to create tar files of the current registry local store and ic state
    pub fn get_create_tars_step(&self, with_state: bool) -> impl Step {
        let mut tar1 = Command::new("tar");
        tar1.arg("-C")
            .arg(self.work_dir.join("data").join(IC_REGISTRY_LOCAL_STORE))
            .arg("-zcvf")
            .arg(
                self.work_dir
                    .join(format!("{}.tar.gz", IC_REGISTRY_LOCAL_STORE)),
            )
            .arg(".");

        let state_tar_cmd = if with_state {
            let mut tar2 = Command::new("tar");
            tar2.arg("-C")
                .arg(self.work_dir.join("data"))
                .arg("-zcvf")
                .arg(self.work_dir.join(format!("{}.tar.gz", IC_STATE)))
                .arg(IC_STATE);
            Some(tar2)
        } else {
            None
        };

        CreateTarsStep {
            logger: self.logger.clone(),
            store_tar_cmd: tar1,
            state_tar_cmd,
        }
    }

    /// Return an [UploadCUPAndTar] uploading tars and extracted CUP to subnet nodes
    pub fn get_upload_cup_and_tar_step(
        &self,
        subnet_id: SubnetId,
        upload_node: Option<IpAddr>,
    ) -> impl Step {
        UploadCUPAndTar {
            logger: self.logger.clone(),
            admin_helper: self.admin_helper.clone(),
            subnet_id,
            upload_node,
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

    /// Return a [DownloadRegistryStoreStep] to download the registry store containing entries for the given [SubnetId] from the given download node
    pub fn get_download_regsitry_store_step(
        &self,
        download_node: IpAddr,
        original_nns_id: SubnetId,
    ) -> impl Step {
        DownloadRegistryStoreStep {
            logger: self.logger.clone(),
            admin_binary: self.admin_helper.binary.clone(),
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
