use crate::{
    CHECKPOINTS, DataLocation, IC_CERTIFICATIONS_PATH, IC_CHECKPOINTS_PATH, IC_DATA_PATH,
    IC_JSON5_PATH, IC_REGISTRY_LOCAL_STORE, IC_STATE, IC_STATE_EXCLUDES, NEW_IC_STATE,
    OLD_IC_STATE, Recovery,
    admin_helper::IcAdmin,
    command_helper::{confirm_exec_cmd, exec_cmd},
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{clear_dir, create_dir, read_dir, rsync, rsync_with_retries},
    get_member_ips, get_node_heights_from_metrics,
    registry_helper::RegistryHelper,
    replay_helper,
    ssh_helper::SshHelper,
    util::{SshUser, block_on, parse_hex_str},
};
use core::convert::From;
use ic_artifact_pool::certification_pool::CertificationPoolImpl;
use ic_base_types::{CanisterId, NodeId, PrincipalId};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::certification::CertificationPool;
use ic_metrics::MetricsRegistry;
use ic_replay::cmd::{GetRecoveryCupCmd, SubCommand};
use ic_types::{Height, SubnetId, consensus::certification::CertificationMessage};
use slog::{Logger, debug, info, warn};
use std::{collections::HashMap, net::IpAddr, path::PathBuf, process::Command, thread, time};

/// Subnet recovery is composed of several steps. Each recovery step comprises a
/// certain input state of which both its execution, and its description is
/// derived. Thus, changing the execution or state of a step ideally implies
/// also changing its description (and vice-versa). This ensures that
/// description and automatic execution of steps stay in sync, to guarantee that
/// manual execution of steps, using only their description, also remains
/// functional.
pub trait Step {
    fn descr(&self) -> String;
    fn exec(&self) -> RecoveryResult<()>;
}

impl<T: Step + 'static> From<T> for Box<dyn Step> {
    fn from(step: T) -> Self {
        Box::new(step)
    }
}

/// A step containing an ic-admin proposal or query to be executed.
#[derive(Debug)]
pub struct AdminStep {
    pub logger: Logger,
    pub ic_admin_cmd: IcAdmin,
}

impl Step for AdminStep {
    // Description of an [AdminStep] is the associated CLI string to be passed to
    // the ic-admin binary
    fn descr(&self) -> String {
        self.ic_admin_cmd.join(" ")
    }

    // Execute the ic-admin CLI string as a system command
    fn exec(&self) -> RecoveryResult<()> {
        Recovery::exec_admin_cmd(&self.logger, &self.ic_admin_cmd)
    }
}

pub struct DownloadCertificationsStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub registry_helper: RegistryHelper,
    pub work_dir: PathBuf,
    pub require_confirmation: bool,
    pub auto_retry: bool,
    pub key_file: Option<PathBuf>,
    pub ssh_user: SshUser,
}

impl Step for DownloadCertificationsStep {
    fn descr(&self) -> String {
        format!(
            "Download certification pools from all reachable nodes to {:?}.",
            self.work_dir.join("certifications")
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ssh_user = self.ssh_user.to_string();
        let cert_path = format!("{IC_DATA_PATH}/{IC_CERTIFICATIONS_PATH}");
        let ips = get_member_ips(&self.registry_helper, self.subnet_id)?;

        let n = ips.len();
        let f = (n.max(1) - 1) / 3;
        let minimum_required = n - f;

        let mut number_successful_downloads = 0;
        for (i, ip) in ips.iter().enumerate() {
            let data_src = format!("{ssh_user}@[{ip}]:{cert_path}");
            let target = self.work_dir.join("certifications").join(ip.to_string());
            if let Err(e) = create_dir(&target) {
                warn!(self.logger, "Failed to create target dir: {:?}", e);
                continue;
            }

            info!(
                self.logger,
                "[{}/{n}] Downloading certifications from {ip} ...",
                i + 1,
            );
            let res = rsync_with_retries(
                &self.logger,
                vec![],
                &data_src,
                &target.display().to_string(),
                self.require_confirmation,
                self.key_file.as_ref(),
                self.auto_retry,
                5,
            );

            match res {
                Ok(_) => {
                    info!(self.logger, "Successful download from {ip}");

                    number_successful_downloads += 1;
                }
                Err(e) => {
                    warn!(self.logger, "Skipping download: {:?}", e);
                }
            }
        }

        if number_successful_downloads < minimum_required {
            Err(RecoveryError::invalid_output_error(format!(
                "Failed to download enough certification pools. Successfully downloaded from {number_successful_downloads} out of {n} nodes, while at least {minimum_required} are required."
            )))
        } else {
            Ok(())
        }
    }
}

pub struct MergeCertificationPoolsStep {
    pub logger: Logger,
    pub work_dir: PathBuf,
}

impl Step for MergeCertificationPoolsStep {
    fn descr(&self) -> String {
        format!(
            "Analyze certifications found in {:?} and move them to a new pool in {:?} for replay. \
            Note that we do not verify signatures yet but will do so later during replay. If at that \
            point we encounter any invalid signatures, delete the offending and merged certification \
            pools and restart recovery from here.",
            self.work_dir.join("certifications"),
            self.work_dir.join("data/ic_consensus_pool")
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let pools = read_dir(&self.work_dir.join("certifications"))?
            .flat_map(|r| r.map_err(|e| warn!(self.logger, "Failed to read dir: {:?}", e)))
            .map(|dir| {
                let pool = CertificationPoolImpl::new(
                    NodeId::from(PrincipalId::new_anonymous()),
                    ArtifactPoolConfig::new(dir.path()),
                    self.logger.clone().into(),
                    MetricsRegistry::new(),
                );
                let ip = dir.file_name().to_string_lossy().to_string();

                (ip, pool)
            })
            .collect::<HashMap<String, CertificationPoolImpl>>();

        // Analyze and move full certifications
        let new_pool = CertificationPoolImpl::new(
            NodeId::from(PrincipalId::new_anonymous()),
            ArtifactPoolConfig::new(self.work_dir.join("data/ic_consensus_pool")),
            self.logger.clone().into(),
            MetricsRegistry::new(),
        );

        info!(
            self.logger,
            "Moving certifications of all nodes to new pool."
        );
        pools.iter().for_each(|(ip, p)| {
            p.validated.certifications().get_all().for_each(|c| {
                if let Some(cert) = new_pool.certification_at_height(c.height) {
                    if cert != c {
                        warn!(
                            self.logger,
                            "{ip}: Found two certifications for height {}: ", c.height
                        );
                        warn!(self.logger, "Existing: {:#?}", cert);
                        warn!(self.logger, "New (ignored): {:#?}", c);
                    }
                } else {
                    debug!(
                        self.logger,
                        "Height {}: inserting certification from node {ip}", c.height
                    );
                    new_pool
                        .validated
                        .insert(CertificationMessage::Certification(c))
                }
            })
        });

        let max_full_cert = new_pool.validated.certifications().get_highest().ok();

        if let Some(cert) = max_full_cert.as_ref() {
            info!(
                self.logger,
                "Maximum full certification height across all nodes: {}, hash: {:?}",
                cert.height,
                cert.signed.content.hash
            );
        }

        // Analyze and move shares
        let max_cert_share = pools
            .values()
            .flat_map(|p| p.validated.certification_shares().get_highest_iter().next())
            .max_by_key(|c| c.height);

        let min_share_height = pools
            .values()
            .flat_map(|p| p.validated.certification_shares().height_range())
            .map(|range| range.min.get())
            .min();

        // Find the min and max height of certification shares higher than than the highest full certification
        let (min, max) = match (max_full_cert, max_cert_share) {
            (None, None) => {
                return Err(RecoveryError::UnexpectedError(
                    "Did not find any certifications or certification shares in pools.".into(),
                ));
            }
            (Some(f), Some(s)) => (f.height.get() + 1, s.height.get()),
            (Some(_), None) => return Ok(()),
            (None, Some(s)) => (
                min_share_height.unwrap_or_else(|| s.height.get()),
                s.height.get(),
            ),
        };

        if min > max {
            info!(self.logger, "No higher certification shares found.");
            return Ok(());
        }

        for h in min..=max {
            let height = Height::from(h);
            info!(
                self.logger,
                "Moving certification shares of height {height} to new pool."
            );
            let shares = pools
                .iter()
                .flat_map(|(ip, p)| p.shares_at_height(height).map(|s| (s, ip.clone())))
                .collect::<HashMap<_, _>>();

            shares.into_iter().for_each(|(s, ip)| {
                debug!(
                    self.logger,
                    "Inserting share from node {ip}: {:?}", s.signed
                );
                new_pool
                    .validated
                    .insert(CertificationMessage::CertificationShare(s))
            });
        }

        Ok(())
    }
}

pub struct DownloadIcStateStep {
    pub logger: Logger,
    pub ssh_user: SshUser,
    pub node_ip: IpAddr,
    pub target: String,
    pub working_dir: String,
    pub keep_downloaded_state: bool,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
    pub additional_excludes: Vec<String>,
}

impl Step for DownloadIcStateStep {
    fn descr(&self) -> String {
        let data_src = format!("[{}]:{}", self.node_ip, IC_DATA_PATH);
        let config_src = format!("[{}]:{}", self.node_ip, IC_JSON5_PATH);
        if self.keep_downloaded_state {
            format!(
                "Copy node state from {} and config from {} to {}. Then copy to {}",
                data_src, config_src, self.target, self.working_dir
            )
        } else {
            format!(
                "Copy node state from {} and config from {} to {}.",
                data_src, config_src, self.working_dir
            )
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        let mut ssh_helper = SshHelper::new(
            self.logger.clone(),
            self.ssh_user.to_string(),
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

        if ssh_helper.wait_for_access().is_err() {
            ssh_helper.account = SshUser::Admin.to_string();
            if !ssh_helper.can_connect() {
                return Err(RecoveryError::invalid_output_error("SSH access denied"));
            }
        }

        info!(
            self.logger,
            "Continuing with account: {}", ssh_helper.account
        );

        let data_src = format!("{}@[{}]:{}", ssh_helper.account, self.node_ip, IC_DATA_PATH);
        let config_src = format!(
            "{}@[{}]:{}",
            ssh_helper.account, self.node_ip, IC_JSON5_PATH
        );

        let mut excludes: Vec<&str> = IC_STATE_EXCLUDES
            .iter()
            .copied()
            .chain(self.additional_excludes.iter().map(|x| x.as_str()))
            .collect();

        let res = ssh_helper
            .ssh(format!(
                r"echo $(ls {IC_DATA_PATH}/{IC_CHECKPOINTS_PATH} | sort | awk 'n>=1 {{ print a[n%1] }} {{ a[n++%1]=$0 }}');"
            ))?
            .unwrap_or_default();
        res.trim().split(' ').for_each(|cp| {
            excludes.push(cp);
        });

        // If we already have some certifications, we do not download them again.
        if PathBuf::from(self.working_dir.clone())
            .join("data/ic_consensus_pool/certification")
            .exists()
        {
            info!(self.logger, "Excluding certifications from download");
            excludes.push("certification");
            excludes.push("certifications");
        }

        // If we already have the consensus pool, we do not download it again.
        if PathBuf::from(self.working_dir.clone())
            .join("data/ic_consensus_pool/consensus")
            .exists()
        {
            info!(self.logger, "Excluding consensus pool from download");
            excludes.push("ic_consensus_pool/consensus");
        }

        let target = if self.keep_downloaded_state {
            &self.target
        } else {
            &self.working_dir
        };

        rsync(
            &self.logger,
            excludes.clone(),
            &data_src,
            target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        rsync(
            &self.logger,
            Vec::<String>::default(),
            &config_src,
            target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        if self.keep_downloaded_state {
            rsync(
                &self.logger,
                excludes,
                &format!("{}/", self.target),
                &self.working_dir,
                false,
                None,
            )?;
        }

        Ok(())
    }
}

pub struct CopyLocalIcStateStep {
    pub logger: Logger,
    pub working_dir: String,
    pub require_confirmation: bool,
}

impl Step for CopyLocalIcStateStep {
    fn descr(&self) -> String {
        format!(
            "Copy node state from {} and config from {} to {}.",
            IC_DATA_PATH, IC_JSON5_PATH, self.working_dir
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let mut excludes: Vec<&str> = IC_STATE_EXCLUDES.to_vec();

        // Do not copy state using rsync, we will use the `cp` instead
        excludes.push(CHECKPOINTS);

        let work_dir = PathBuf::from(self.working_dir.clone());
        // If we already have some certifications, we do not copy them again.
        if work_dir
            .join("data/ic_consensus_pool/certification")
            .exists()
        {
            info!(self.logger, "Excluding certifications from copy");
            excludes.push("certification");
            excludes.push("certifications");
        }
        // If we already have the consensus pool, we do not copy it again.
        if PathBuf::from(self.working_dir.clone())
            .join("data/ic_consensus_pool/consensus")
            .exists()
        {
            info!(self.logger, "Excluding consensus pool from copy");
            excludes.push("ic_consensus_pool/consensus");
        }

        rsync(
            &self.logger,
            excludes,
            IC_DATA_PATH,
            &self.working_dir,
            self.require_confirmation,
            None,
        )?;

        rsync(
            &self.logger,
            Vec::<String>::default(),
            IC_JSON5_PATH,
            &self.working_dir,
            self.require_confirmation,
            None,
        )?;

        let ic_checkpoints_path = PathBuf::from(IC_DATA_PATH).join(IC_CHECKPOINTS_PATH);
        let latest_checkpoint =
            Recovery::get_latest_checkpoint_name_and_height(&ic_checkpoints_path)?;
        info!(
            self.logger,
            "Found latest checkpoint: {latest_checkpoint:?}"
        );

        let recovery_checkpoints_path = work_dir.join("data").join(IC_CHECKPOINTS_PATH);
        let log = self.require_confirmation.then_some(&self.logger);

        info!(self.logger, "Creating recovery checkpoint directory");
        let mut mkdir = Command::new("mkdir");
        mkdir.arg("-p").arg(&recovery_checkpoints_path);
        confirm_exec_cmd(&mut mkdir, log)?;

        info!(
            self.logger,
            "Moving latest checkpoint into recovery directory"
        );
        let mut cp = Command::new("cp");
        cp.arg("-R")
            .arg(ic_checkpoints_path.join(latest_checkpoint.0.clone()))
            .arg(recovery_checkpoints_path);
        confirm_exec_cmd(&mut cp, log)?;

        Ok(())
    }
}

pub struct ReplaySubCmd {
    pub cmd: SubCommand,
    pub descr: String,
}

pub struct ReplayStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub work_dir: PathBuf,
    pub config: PathBuf,
    pub subcmd: Option<ReplaySubCmd>,
    pub canister_caller_id: Option<CanisterId>,
    pub replay_until_height: Option<u64>,
    pub result: PathBuf,
    pub skip_prompts: bool,
}

impl Step for ReplayStep {
    fn descr(&self) -> String {
        let checkpoint_path = self.work_dir.join("data").join(IC_CHECKPOINTS_PATH);
        let mut base = format!(
            "Delete old checkpoints found in {}, and execute:\nic-replay {} --subnet-id {:?}{}",
            checkpoint_path.display(),
            self.config.display(),
            self.subnet_id,
            self.replay_until_height
                .map(|h| format!(" --replay-until-height {h}"))
                .unwrap_or_default()
        );
        if let Some(subcmd) = &self.subcmd {
            base.push_str(&subcmd.descr);
        }
        base
    }

    fn exec(&self) -> RecoveryResult<()> {
        let checkpoint_path = self.work_dir.join("data").join(IC_CHECKPOINTS_PATH);

        let checkpoint_height =
            Recovery::remove_all_but_highest_checkpoints(&checkpoint_path, &self.logger)?;

        let state_params = block_on(replay_helper::replay(
            self.subnet_id,
            self.config.clone(),
            self.canister_caller_id,
            self.work_dir.join("data"),
            self.subcmd.as_ref().map(|c| c.cmd.clone()),
            self.replay_until_height,
            self.result.clone(),
            self.skip_prompts,
        ))?;

        let latest_height = state_params.height;
        let state_hash = state_params.hash;

        info!(self.logger, "Checkpoint height: {}", checkpoint_height);
        info!(self.logger, "Height after replay: {}", latest_height);

        if latest_height < checkpoint_height {
            return Err(RecoveryError::invalid_output_error(
                "Replay height and checkpoint height diverged.",
            ));
        }

        info!(self.logger, "State hash: {}", state_hash);

        info!(self.logger, "Deleting old checkpoints");
        Recovery::remove_all_but_highest_checkpoints(&checkpoint_path, &self.logger)?;

        Ok(())
    }
}

pub struct ValidateReplayStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub registry_helper: RegistryHelper,
    pub work_dir: PathBuf,
    pub extra_batches: u64,
}

impl Step for ValidateReplayStep {
    fn descr(&self) -> String {
        "Compare height after replay to certification and finalization heights of subnet as reported by individual nodes.".to_string()
    }

    fn exec(&self) -> RecoveryResult<()> {
        let latest_height =
            replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?.height;

        let heights =
            get_node_heights_from_metrics(&self.logger, &self.registry_helper, self.subnet_id)?;
        let cert_height = &heights
            .iter()
            .max_by_key(|v| v.certification_height)
            .map(|v| v.certification_height)
            .ok_or_else(|| RecoveryError::invalid_output_error("No certification heights found"))?;

        let finalization_height = &heights
            .iter()
            .max_by_key(|v| v.finalization_height)
            .map(|v| v.finalization_height)
            .ok_or_else(|| RecoveryError::invalid_output_error("No finalization heights found"))?;

        info!(self.logger, "Certification height: {}", cert_height);
        info!(
            self.logger,
            "Max finalization height: {}", finalization_height
        );
        info!(self.logger, "Height after replay: {}", latest_height);

        if self.extra_batches > 0 {
            info!(self.logger, "Extra batches: {}", self.extra_batches);
        }
        if latest_height.get() - self.extra_batches < cert_height.get() {
            return Err(RecoveryError::invalid_output_error(
                "Replay height smaller than certification height.",
            ));
        }

        info!(self.logger, "Success!");

        Ok(())
    }
}

pub struct UploadAndRestartStep {
    pub logger: Logger,
    pub upload_method: DataLocation,
    pub work_dir: PathBuf,
    pub data_src: PathBuf,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
    pub check_ic_replay_height: bool,
}

impl UploadAndRestartStep {
    const CMD_STOP_REPLICA: &str = "sudo systemctl stop ic-replica;";
    // Note that on older versions of IC-OS this service does not exist.
    // So try this operation, but ignore possible failure if service
    // does not exist on the affected version.
    const CMD_RESTART_REPLICA: &str = "\
        (sudo systemctl restart setup-permissions || true);\
        sudo systemctl start ic-replica;\
        sudo systemctl status ic-replica;";

    /// Sets the right state permissions on `target`, by copying the
    /// permissions of the src path, removing executable permission and
    /// giving read permissions for the target path to group and others.
    fn cmd_set_permissions(src: &str, target: &str) -> String {
        let mut set_permissions = String::new();
        set_permissions.push_str(&format!("sudo chmod -R --reference={src} {target};"));
        set_permissions.push_str(&format!("sudo chown -R --reference={src} {target};"));
        set_permissions.push_str(&format!(
            r"sudo find {target} -type f -exec chmod a-x {{}} \;;"
        ));
        set_permissions.push_str(&format!(
            r"sudo find {target} -type f -exec chmod go+r {{}} \;;"
        ));
        set_permissions
    }
}
impl Step for UploadAndRestartStep {
    fn descr(&self) -> String {
        let replica = match self.upload_method {
            DataLocation::Remote(ip) => &format!("replica {ip}"),
            DataLocation::Local => "local replica",
        };
        format!(
            "Stopping {replica}, uploading and replacing state from {}, set access \
            rights, restart replica.",
            self.data_src.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let account = SshUser::Admin;
        let checkpoint_path = self.data_src.join(CHECKPOINTS);
        let checkpoints = Recovery::get_checkpoint_names(&checkpoint_path)?;

        let [max_checkpoint] = checkpoints.as_slice() else {
            return Err(RecoveryError::invalid_output_error(
                "Found multiple checkpoints in upload directory",
            ));
        };

        if self.check_ic_replay_height {
            let replay_height =
                replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?
                    .height;

            if parse_hex_str(max_checkpoint)? != replay_height.get() {
                return Err(RecoveryError::invalid_output_error(format!(
                    "Latest checkpoint height ({max_checkpoint}) doesn't match replay output ({replay_height})"
                )));
            }
        }

        let ic_state_path = format!("{IC_DATA_PATH}/{IC_STATE}");
        let src = format!("{}/", self.data_src.display());

        // Decide: remote or local recovery
        if let DataLocation::Remote(node_ip) = self.upload_method {
            // For remote recoveries, we copy the source directory via rsync.
            // To improve rsync times, we copy the latest checkpoint to the
            // upload directory.
            let upload_dir = format!("{IC_DATA_PATH}/{NEW_IC_STATE}");
            let ic_checkpoints_path = format!("{IC_DATA_PATH}/{IC_CHECKPOINTS_PATH}");
            // path of highest checkpoint on upload node
            let copy_from =
                format!("{ic_checkpoints_path}/$(ls {ic_checkpoints_path} | sort | tail -1)");
            // path and name of checkpoint after replay
            let copy_to = format!("{upload_dir}/{CHECKPOINTS}/{max_checkpoint}");
            let cp = format!("sudo cp -r {copy_from} {copy_to}");
            let cmd_create_and_copy_checkpoint_dir = format!(
                "sudo mkdir -p {upload_dir}/{CHECKPOINTS}; {cp}; sudo chown -R {account} {upload_dir};"
            );

            let ssh_helper = SshHelper::new(
                self.logger.clone(),
                account.to_string(),
                node_ip,
                self.require_confirmation,
                self.key_file.clone(),
            );
            info!(
                self.logger,
                "Creating remote directory and copying previous checkpoint..."
            );
            if let Some(res) = ssh_helper.ssh(cmd_create_and_copy_checkpoint_dir)? {
                info!(self.logger, "{}", res);
            }
            let target = format!("{account}@[{node_ip}]:{upload_dir}/");
            info!(self.logger, "Uploading state...");
            rsync(
                &self.logger,
                IC_STATE_EXCLUDES.to_vec(),
                &src,
                &target,
                self.require_confirmation,
                self.key_file.as_ref(),
            )?;

            let cmd_set_permissions = Self::cmd_set_permissions(&ic_state_path, &upload_dir);
            let cmd_replace_state =
                format!("sudo rm -r {ic_state_path}; sudo mv {upload_dir} {ic_state_path};");

            info!(self.logger, "Restarting replica...");
            ssh_helper.ssh(Self::CMD_STOP_REPLICA.to_string())?;
            ssh_helper.ssh(cmd_set_permissions)?;
            ssh_helper.ssh(cmd_replace_state)?;
            ssh_helper.ssh(Self::CMD_RESTART_REPLICA.to_string())?;
        } else {
            let log = self.require_confirmation.then_some(&self.logger);
            info!(self.logger, "Stopping replica...");
            confirm_exec_cmd(
                Command::new("bash").arg("-c").arg(Self::CMD_STOP_REPLICA),
                log,
            )?;

            info!(self.logger, "Setting file permissions...");
            let cmd_set_permissions = Self::cmd_set_permissions(&ic_state_path, &src);
            confirm_exec_cmd(Command::new("bash").arg("-c").arg(cmd_set_permissions), log)?;

            // For local recoveries we first backup the original state, and
            // then simply `mv` the new state to the upload directory. No
            // rsync is needed, and thus no checkpoint copying.
            let backup_path = format!("{}/{}", self.work_dir.display(), OLD_IC_STATE);
            info!(self.logger, "Moving original state into {}...", backup_path);
            let mut cmd_backup_state = Command::new("sudo");
            cmd_backup_state.arg("mv");
            cmd_backup_state.arg(&ic_state_path);
            cmd_backup_state.arg(backup_path);
            confirm_exec_cmd(&mut cmd_backup_state, log)?;

            info!(self.logger, "Moving state locally...");
            let mut mv_to_target = Command::new("sudo");
            mv_to_target.arg("mv");
            mv_to_target.arg(src);
            mv_to_target.arg(ic_state_path);
            confirm_exec_cmd(&mut mv_to_target, log)?;

            info!(self.logger, "Restarting replica...");
            confirm_exec_cmd(
                Command::new("bash")
                    .arg("-c")
                    .arg(Self::CMD_RESTART_REPLICA),
                log,
            )?;
        }
        Ok(())
    }
}

pub struct WaitForCUPStep {
    pub logger: Logger,
    pub node_ip: IpAddr,
    pub work_dir: PathBuf,
}

impl Step for WaitForCUPStep {
    fn descr(&self) -> String {
        format!(
            "Waiting until recovery CUP is found on node {}.",
            self.node_ip
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let state_params =
            replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?;
        let recovery_height = Recovery::get_recovery_height(state_params.height);

        Recovery::wait_for_recovery_cup(
            &self.logger,
            self.node_ip,
            recovery_height,
            state_params.hash,
        )
    }
}

pub struct CleanupStep {
    pub recovery_dir: PathBuf,
}

impl Step for CleanupStep {
    fn descr(&self) -> String {
        format!("Clearing directory {}.", self.recovery_dir.display())
    }

    fn exec(&self) -> RecoveryResult<()> {
        clear_dir(&self.recovery_dir)
    }
}

pub struct StopReplicaStep {
    pub logger: Logger,
    pub node_ip: IpAddr,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
}

impl Step for StopReplicaStep {
    fn descr(&self) -> String {
        format!("Stopping replica on {}.", self.node_ip)
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            SshUser::Admin.to_string(),
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );
        ssh_helper.ssh("sudo systemctl stop ic-replica".to_string())?;
        Ok(())
    }
}

pub struct UpdateLocalStoreStep {
    pub subnet_id: SubnetId,
    pub work_dir: PathBuf,
    pub skip_prompts: bool,
}

impl Step for UpdateLocalStoreStep {
    fn descr(&self) -> String {
        format!(
            "Update registry local store by executing:\nic-replay {:?} --subnet-id {:?} update-registry-local-store",
            self.work_dir.join("ic.json5"),
            self.subnet_id
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        block_on(replay_helper::replay(
            self.subnet_id,
            self.work_dir.join("ic.json5"),
            None,
            self.work_dir.join("data"),
            Some(SubCommand::UpdateRegistryLocalStore),
            None,
            self.work_dir.join("update_local_store.txt"),
            self.skip_prompts,
        ))?;
        Ok(())
    }
}

pub struct GetRecoveryCUPStep {
    pub subnet_id: SubnetId,
    pub config: PathBuf,
    pub state_hash: String,
    pub recovery_height: Height,
    pub result: PathBuf,
    pub work_dir: PathBuf,
    pub skip_prompts: bool,
}

impl Step for GetRecoveryCUPStep {
    fn descr(&self) -> String {
        format!(
            "Set recovery CUP by executing:\n\
            ic-replay {} --subnet-id {} get-recovery-cup {} {} cup.proto",
            self.config.display(),
            self.subnet_id,
            self.state_hash,
            self.recovery_height
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        block_on(replay_helper::replay(
            self.subnet_id,
            self.config.clone(),
            None,
            self.work_dir.join("data"),
            Some(SubCommand::GetRecoveryCup(GetRecoveryCupCmd {
                state_hash: self.state_hash.clone(),
                height: self.recovery_height.get(),
                output_file: self.work_dir.join("cup.proto"),
            })),
            None,
            self.result.clone(),
            self.skip_prompts,
        ))?;
        Ok(())
    }
}

pub struct CreateRegistryTarStep {
    pub logger: Logger,
    pub store_tar_cmd: Command,
}

impl Step for CreateRegistryTarStep {
    fn descr(&self) -> String {
        format!("Creating tar files by executing:\n{:?}", self.store_tar_cmd,)
    }

    fn exec(&self) -> RecoveryResult<()> {
        let mut tar1 = Command::new("tar");
        tar1.args(self.store_tar_cmd.get_args());
        if let Some(res) = exec_cmd(&mut tar1)? {
            info!(self.logger, "{}", res);
        }
        Ok(())
    }
}

pub struct CopyIcStateStep {
    pub logger: Logger,
    pub work_dir: PathBuf,
    pub new_state_dir: PathBuf,
}

impl Step for CopyIcStateStep {
    fn descr(&self) -> String {
        format!(
            "Copying ic_state for upload to: {}",
            self.new_state_dir.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        rsync(
            &self.logger,
            Vec::<String>::default(),
            &format!("{}/", self.work_dir.display()),
            &format!("{}/", self.new_state_dir.display()),
            false,
            None,
        )?;
        Ok(())
    }
}

pub struct UploadCUPAndTarStep {
    pub logger: Logger,
    pub registry_helper: RegistryHelper,
    pub node_ip: IpAddr,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
    pub work_dir: PathBuf,
}

impl UploadCUPAndTarStep {
    pub fn get_restart_commands(&self) -> String {
        format!(
            r#"
cd {};
OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/ic_registry_local_store);
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/ic_registry_local_store);
mkdir ic_registry_local_store;
tar -xf ic_registry_local_store.tar.zst -C ic_registry_local_store;
sudo chown -R "$OWNER_UID:$GROUP_UID" ic_registry_local_store;
OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/cups);
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/cups);
sudo chown -R "$OWNER_UID:$GROUP_UID" cup.proto;
sudo systemctl stop ic-replica;
sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/;
sudo cp cup.proto /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb;
sudo systemctl restart setup-permissions || true ;
sudo systemctl start ic-replica;
sudo systemctl status ic-replica;
"#,
            UploadCUPAndTarStep::get_upload_dir_name(),
        )
    }

    pub fn get_upload_dir_name() -> String {
        "/tmp/subnet_recovery".to_string()
    }
}

impl Step for UploadCUPAndTarStep {
    fn descr(&self) -> String {
        format!(
            "Uploading CUP and registry to [{}]:{} and execute:\n{}",
            self.node_ip,
            UploadCUPAndTarStep::get_upload_dir_name(),
            self.get_restart_commands()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            SshUser::Admin.to_string(),
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

        if !ssh_helper.can_connect() {
            info!(
                self.logger,
                "No admin access to: {}, skipping upload...", self.node_ip
            );
            return Err(RecoveryError::invalid_output_error("SSH access denied"));
        }

        info!(self.logger, "Uploading to {}", self.node_ip);
        let upload_dir = UploadCUPAndTarStep::get_upload_dir_name();
        ssh_helper.ssh(format!("sudo rm -rf {upload_dir} && mkdir {upload_dir}"))?;

        let target = format!("{}@[{}]:{}/", SshUser::Admin, self.node_ip, upload_dir);

        rsync(
            &self.logger,
            Vec::<String>::default(),
            &format!("{}/cup.proto", self.work_dir.display()),
            &target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        rsync(
            &self.logger,
            Vec::<String>::default(),
            &format!(
                "{}/ic_registry_local_store.tar.zst",
                self.work_dir.display()
            ),
            &target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        ssh_helper.ssh(self.get_restart_commands())?;

        Ok(())
    }
}

pub struct CreateNNSRecoveryTarStep {
    pub logger: Logger,
    pub work_dir: PathBuf,
    pub output_dir: PathBuf,
}

impl CreateNNSRecoveryTarStep {
    pub fn get_tar_name() -> String {
        "recovery.tar.zst".to_string()
    }

    pub fn get_sha_name() -> String {
        Self::get_tar_name() + ".sha256"
    }

    fn get_create_commands(&self) -> String {
        // We use debug formatting because it escapes the paths in case they contain spaces.
        format!(
            r#"
mkdir -p {output_dir:?}
tar --zstd -cvf {tar_file:?} -C {work_dir:?} cup.proto {IC_REGISTRY_LOCAL_STORE}.tar.zst

artifacts_hash="$(sha256sum {tar_file:?} | cut -d ' ' -f1)"
echo "$artifacts_hash" > {sha_file:?}
            "#,
            output_dir = self.output_dir,
            tar_file = self.output_dir.join(Self::get_tar_name()),
            sha_file = self.output_dir.join(Self::get_sha_name()),
            work_dir = self.work_dir,
        )
    }

    fn get_next_steps(&self, artifacts_hash: &str) -> String {
        // We use debug formatting because it escapes the paths in case they contain spaces.
        format!(
            r#"
Recovery artifacts with hash {artifacts_hash} were successfully created in {output_dir:?}.
Now please:
  - Upload {tar_file:?} to:
    - https://download.dfinity.systems/recovery/{artifacts_hash}/{tar_name}
    - https://download.dfinity.network/recovery/{artifacts_hash}/{tar_name}
    - TODO: Update directions after recovery runbook complete
  - Provide other Node Providers with the commit hash as version, the image hash, and the artifacts hash. Ask them to reboot and follow the recovery instructions.
            "#,
            output_dir = self.output_dir,
            tar_file = self.output_dir.join(Self::get_tar_name()),
            tar_name = Self::get_tar_name(),
        )
    }
}

impl Step for CreateNNSRecoveryTarStep {
    fn descr(&self) -> String {
        format!(
            "Creating recovery artifacts by executing:\n{}",
            self.get_create_commands()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        if let Some(res) = exec_cmd(
            Command::new("bash")
                .arg("-c")
                .arg(self.get_create_commands()),
        )? {
            info!(self.logger, "{}", res);
        }

        let Some(sha256) =
            exec_cmd(Command::new("cat").arg(self.output_dir.join(Self::get_sha_name())))?
        else {
            return Err(RecoveryError::invalid_output_error(format!(
                "Could not read {}/{}",
                self.output_dir.display(),
                Self::get_sha_name()
            )));
        };
        info!(self.logger, "{}", self.get_next_steps(sha256.trim()));

        Ok(())
    }
}

pub struct DownloadRegistryStoreStep {
    pub logger: Logger,
    pub node_ip: IpAddr,
    pub original_nns_id: SubnetId,
    pub work_dir: PathBuf,
    pub require_confirmation: bool,
    pub ssh_user: SshUser,
    pub key_file: Option<PathBuf>,
}

impl Step for DownloadRegistryStoreStep {
    fn descr(&self) -> String {
        let data_src = format!("[{}]:{}", self.node_ip, IC_DATA_PATH);
        format!(
            "Copy registry local store from {} to {}.",
            data_src,
            self.work_dir.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            self.ssh_user.to_string(),
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

        info!(
            self.logger,
            "Waiting until subnet with original NNS id is up."
        );
        let tries = 50;
        let backoff = 10;
        let mut child_subnet_found = false;
        for i in 0..tries {
            if let Err(e) = ssh_helper.ssh(format!(r#"/opt/ic/bin/ic-regedit snapshot /var/lib/ic/data/ic_registry_local_store/ |grep -q "subnet_record_{}""#, self.original_nns_id))
            {
                info!(self.logger, "Try {}: {}", i, e);
            } else {
                info!(self.logger, "Found subnet with original NNS id!");
                child_subnet_found = true;
                break;
            }
            thread::sleep(time::Duration::from_secs(backoff));
        }

        if !child_subnet_found {
            return Err(RecoveryError::UnexpectedError(format!(
                "Child subnet didn't come up within {} seconds.",
                tries * backoff
            )));
        }

        let data_src = format!(
            "{}@[{}]:{}/{}",
            self.ssh_user, self.node_ip, IC_DATA_PATH, IC_REGISTRY_LOCAL_STORE
        );

        rsync(
            &self.logger,
            Vec::<String>::default(),
            &data_src,
            &format!("{}/", self.work_dir.display()),
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        Ok(())
    }
}

pub struct UploadAndHostTarStep {
    pub logger: Logger,
    pub aux_host: String,
    pub aux_ip: IpAddr,
    pub tar: PathBuf,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
}

impl Step for UploadAndHostTarStep {
    fn descr(&self) -> String {
        format!(
            "Installing daemonize & python3 on {}@[{}], uploading and hosting {}",
            self.aux_host,
            self.aux_ip,
            self.tar.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            self.aux_host.clone(),
            self.aux_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

        let upload_dir = "/tmp/recovery_registry";

        ssh_helper.ssh("nix-env -i daemonize python3".to_string())?;
        ssh_helper.ssh(format!("mkdir -p {upload_dir}"))?;

        let target = format!("{}@[{}]:{}/", self.aux_host, self.aux_ip, upload_dir);
        let src = format!("{}", self.tar.display());
        rsync(
            &self.logger,
            Vec::<String>::default(),
            &src,
            &target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        ssh_helper.ssh("daemonize $(which python3) -m http.server --bind :: 8081".to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ic_test_utilities_consensus::fake::{Fake, FakeSigner};
    use ic_test_utilities_types::ids::node_test_id;
    use ic_types::{
        consensus::certification::{Certification, CertificationContent, CertificationShare},
        crypto::{CryptoHash, Signed},
        signature::{ThresholdSignature, ThresholdSignatureShare},
    };
    use tempfile::TempDir;

    use super::*;

    fn make_certification(height: u64, hash: Vec<u8>) -> CertificationMessage {
        CertificationMessage::Certification(Certification {
            height: Height::from(height),
            signed: Signed {
                content: CertificationContent::new(CryptoHash(hash).into()),
                signature: ThresholdSignature::fake(),
            },
        })
    }

    fn make_share(height: u64, hash: Vec<u8>, node_id: u64) -> CertificationMessage {
        CertificationMessage::CertificationShare(CertificationShare {
            height: Height::from(height),
            signed: Signed {
                content: CertificationContent::new(CryptoHash(hash).into()),
                signature: ThresholdSignatureShare::fake(node_test_id(node_id)),
            },
        })
    }

    fn setup_merge_certs(
        logger: &Logger,
    ) -> (TempDir, CertificationPoolImpl, CertificationPoolImpl) {
        let tmp = tempfile::tempdir().expect("Could not create a temp dir");
        let work_dir = tmp.path().to_path_buf();
        let pool1 = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("certifications/ip1")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );
        let pool2 = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("certifications/ip2")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );
        (tmp, pool1, pool2)
    }

    #[test]
    fn error_if_no_certifications_found() {
        let logger = crate::util::make_logger();
        let (tmp, _, _) = setup_merge_certs(&logger);
        let work_dir = tmp.path().to_path_buf();
        let step = MergeCertificationPoolsStep {
            logger: logger.clone(),
            work_dir,
        };
        assert!(
            matches!(step.exec(), Err(RecoveryError::UnexpectedError(e)) if e.starts_with("Did not find any certifications"))
        );
    }

    #[test]
    fn full_certifications_are_merged_correctly() {
        let logger = crate::util::make_logger();
        let (tmp, pool1, pool2) = setup_merge_certs(&logger);
        let work_dir = tmp.path().to_path_buf();

        let step = MergeCertificationPoolsStep {
            logger: logger.clone(),
            work_dir: work_dir.clone(),
        };

        // Add two different certifications for height 1 to both pools,
        // only one of them should be kept after the merge.
        let cert1 = make_certification(1, vec![1, 2, 3]);
        let cert1_2 = make_certification(1, vec![4, 5, 6]);
        pool1.validated.insert(cert1);
        pool2.validated.insert(cert1_2);

        // Add the same certification for height 2 to both pools,
        // it should only exists in the merged pool once.
        let cert2 = make_certification(2, vec![1, 2, 3]);
        pool1.validated.insert(cert2.clone());
        pool2.validated.insert(cert2);

        // Add two more certifications for heights 3 and 4, one to each pool.
        let cert3 = make_certification(3, vec![1, 2, 3]);
        let cert4 = make_certification(4, vec![1, 2, 3]);
        pool1.validated.insert(cert4);
        pool2.validated.insert(cert3);

        // Add a share at height 3 to one pool. It should not be added to the
        // merged pool as it is lower than the highest full certification (4).
        let share3 = make_share(3, vec![1], 1);
        pool1.validated.insert(share3);

        step.exec().expect("Failed to execute step.");

        let new_pool = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("data/ic_consensus_pool")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );

        assert_eq!(
            new_pool.validated.certifications().get_all().count(),
            4 // One for each height 1-4
        );
        assert_eq!(
            new_pool.validated.certification_shares().get_all().count(),
            0
        );
        let range = new_pool
            .validated
            .certifications()
            .height_range()
            .expect("no height range");
        assert_eq!((range.min.get(), range.max.get()), (1, 4));
    }

    #[test]
    fn shares_are_merged_correctly() {
        let logger = crate::util::make_logger();
        let (tmp, pool1, pool2) = setup_merge_certs(&logger);
        let work_dir = tmp.path().to_path_buf();

        let step = MergeCertificationPoolsStep {
            logger: logger.clone(),
            work_dir: work_dir.clone(),
        };

        // Add a full certification at height 4.
        let cert4 = make_certification(4, vec![1, 2, 3]);

        // Shares below or equal to the highest full share should be ignored.
        let share3 = make_share(3, vec![3], 1);
        let share4 = make_share(4, vec![4], 2);

        // These shares should be included in the new pool.
        let share5 = make_share(5, vec![5], 1);
        let share6 = make_share(6, vec![6], 1);
        let share6_2 = make_share(6, vec![6, 2], 2);

        pool1.validated.insert(cert4);
        pool1.validated.insert(share3);
        pool1.validated.insert(share4);
        pool1.validated.insert(share5.clone());
        pool1.validated.insert(share6_2);

        pool2.validated.insert(share5);
        pool2.validated.insert(share6);

        step.exec().expect("Failed to execute step.");

        let new_pool = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("data/ic_consensus_pool")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );

        assert_eq!(
            new_pool.validated.certification_shares().get_all().count(),
            3 // share5, share6, share6_2
        );
        let range = new_pool
            .validated
            .certification_shares()
            .height_range()
            .expect("no height range");
        assert_eq!((range.min.get(), range.max.get()), (5, 6));
    }
}
