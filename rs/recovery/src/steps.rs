use crate::{
    admin_helper::IcAdmin,
    command_helper::exec_cmd,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{create_dir, read_dir, remove_dir, rsync, rsync_with_retries},
    get_member_ips, get_node_heights_from_metrics,
    registry_helper::RegistryHelper,
    replay_helper,
    ssh_helper::SshHelper,
    util::{block_on, parse_hex_str},
    Recovery, ADMIN, CHECKPOINTS, IC_CERTIFICATIONS_PATH, IC_CHECKPOINTS_PATH, IC_DATA_PATH,
    IC_JSON5_PATH, IC_REGISTRY_LOCAL_STORE, IC_STATE, IC_STATE_EXCLUDES, NEW_IC_STATE, READONLY,
};
use ic_artifact_pool::certification_pool::CertificationPoolImpl;
use ic_base_types::{CanisterId, NodeId, PrincipalId};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::certification::CertificationPool;
use ic_metrics::MetricsRegistry;
use ic_replay::cmd::{GetRecoveryCupCmd, SubCommand};
use ic_types::{consensus::certification::CertificationMessage, Height, SubnetId};
use slog::{debug, info, warn, Logger};
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
    pub key_file: Option<PathBuf>,
    pub admin: bool,
}

impl Step for DownloadCertificationsStep {
    fn descr(&self) -> String {
        format!(
            "Download certification pools from all reachable nodes to {:?}.",
            self.work_dir.join("certifications")
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let user = if self.admin { ADMIN } else { READONLY };
        let cert_path = format!("{IC_DATA_PATH}/{IC_CERTIFICATIONS_PATH}");
        let ips = get_member_ips(&self.registry_helper, self.subnet_id)?;
        let downloaded_at_least_once = ips.iter().fold(false, |success, ip| {
            let data_src = format!("{user}@[{ip}]:{cert_path}");
            let target = self.work_dir.join("certifications").join(ip.to_string());
            if let Err(e) = create_dir(&target) {
                warn!(self.logger, "Failed to create target dir: {:?}", e);
                return success;
            }

            info!(self.logger, "Downloading certifications from {ip} ...");
            let res = rsync_with_retries(
                &self.logger,
                vec![],
                &data_src,
                &target.display().to_string(),
                self.require_confirmation,
                self.key_file.as_ref(),
                5,
            )
            .map_err(|e| warn!(self.logger, "Failed to download certifications: {:?}", e));

            success || res.is_ok()
        });

        if !downloaded_at_least_once {
            Err(RecoveryError::invalid_output_error(
                "Failed to download certifications from any node.",
            ))
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
            p.persistent_pool.certifications().get_all().for_each(|c| {
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
                        .persistent_pool
                        .insert(CertificationMessage::Certification(c))
                }
            })
        });

        let max_full_cert = new_pool.persistent_pool.certifications().get_highest().ok();

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
            .flat_map(|p| {
                p.persistent_pool
                    .certification_shares()
                    .get_highest_iter()
                    .next()
            })
            .max_by_key(|c| c.height);

        let min_share_height = pools
            .values()
            .flat_map(|p| p.persistent_pool.certification_shares().height_range())
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
                    .persistent_pool
                    .insert(CertificationMessage::CertificationShare(s))
            });
        }

        Ok(())
    }
}

pub struct DownloadIcStateStep {
    pub logger: Logger,
    pub try_readonly: bool,
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
        let account = if self.try_readonly {
            READONLY.to_string()
        } else {
            ADMIN.to_string()
        };
        let mut ssh_helper = SshHelper::new(
            self.logger.clone(),
            account,
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

        if ssh_helper.wait_for_access().is_err() {
            ssh_helper.account = ADMIN.to_string();
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
                r"echo $(ls {}/{} | sort | awk 'n>=1 {{ print a[n%1] }} {{ a[n++%1]=$0 }}');",
                IC_DATA_PATH, IC_CHECKPOINTS_PATH
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

        if latest_height.get() - self.extra_batches < finalization_height.get() {
            return Err(RecoveryError::invalid_output_error(
                "There exists a node with finalization height greater than the replay height.",
            ));
        }

        info!(self.logger, "Success!");

        Ok(())
    }
}

pub struct UploadAndRestartStep {
    pub logger: Logger,
    pub node_ip: IpAddr,
    pub work_dir: PathBuf,
    pub data_src: PathBuf,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
    pub check_ic_replay_height: bool,
}

impl Step for UploadAndRestartStep {
    fn descr(&self) -> String {
        format!(
            "Stopping replica {}, uploading and replacing state from {}, set access rights, \
            restart replica.",
            self.node_ip,
            self.data_src.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let account = ADMIN;
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            account.to_string(),
            self.node_ip,
            self.require_confirmation,
            self.key_file.clone(),
        );

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
                    "Latest checkpoint height ({}) doesn't match replay output ({})",
                    max_checkpoint, replay_height
                )));
            }
        }

        let ic_checkpoints_path = format!("{}/{}", IC_DATA_PATH, IC_CHECKPOINTS_PATH);
        // upload directory to create
        let upload_dir = format!("{}/{}", IC_DATA_PATH, NEW_IC_STATE);
        // path of highest checkpoint on upload node
        let copy_from = format!(
            "{}/$(ls {} | sort | tail -1)",
            ic_checkpoints_path, ic_checkpoints_path
        );
        // path and name of checkpoint after replay
        let copy_to = format!("{}/{}/{}", upload_dir, CHECKPOINTS, max_checkpoint);
        let cp = format!("sudo cp -r {} {}", copy_from, copy_to);

        info!(
            self.logger,
            "Creating remote directory and copying previous checkpoint..."
        );
        if let Some(res) = ssh_helper.ssh(format!(
            "sudo mkdir -p {}/{}; {}; sudo chown -R {} {};",
            upload_dir, CHECKPOINTS, cp, account, upload_dir
        ))? {
            info!(self.logger, "{}", res);
        }

        let target = format!("{}@[{}]:{}/", account, self.node_ip, upload_dir);
        let src = format!("{}/", self.data_src.display());
        info!(self.logger, "Uploading state...");
        rsync(
            &self.logger,
            IC_STATE_EXCLUDES.to_vec(),
            &src,
            &target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        let ic_state_path = format!("{}/{}", IC_DATA_PATH, IC_STATE);
        info!(self.logger, "Restarting replica...");
        let mut replace_state = String::new();
        replace_state.push_str("sudo systemctl stop ic-replica;");
        replace_state.push_str(&format!(
            "sudo chmod -R --reference={} {};",
            ic_state_path, upload_dir
        ));
        replace_state.push_str(&format!(
            "sudo chown -R --reference={} {};",
            ic_state_path, upload_dir
        ));
        replace_state.push_str(&format!("sudo rm -r {};", ic_state_path));
        replace_state.push_str(&format!("sudo mv {} {};", upload_dir, ic_state_path));
        replace_state.push_str(&format!(
            r"sudo find {} -type f -exec chmod a-x {{}} \;;",
            ic_state_path
        ));
        replace_state.push_str(&format!(
            r"sudo find {} -type f -exec chmod go+r {{}} \;;",
            ic_state_path
        ));
        // Note that on older versions of IC-OS this service does not exist.
        // So try this operation, but ignore possible failure if service
        // does not exist on the affected version.
        replace_state.push_str("(sudo systemctl restart setup-permissions || true);");
        replace_state.push_str("sudo systemctl start ic-replica;");
        replace_state.push_str("sudo systemctl status ic-replica;");

        ssh_helper.ssh(replace_state)?;
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
        format!("Deleting directory {}.", self.recovery_dir.display())
    }

    fn exec(&self) -> RecoveryResult<()> {
        remove_dir(&self.recovery_dir)
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
            ADMIN.to_string(),
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
}

impl Step for UpdateLocalStoreStep {
    fn descr(&self) -> String {
        format!("Update registry local store by executing:\nic-replay {:?} --subnet-id {:?} update-registry-local-store",
            self.work_dir.join("ic.json5"),
            self.subnet_id)
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
                registry_store_uri: None,
                registry_store_sha256: None,
                output_file: self.work_dir.join("cup.proto"),
            })),
            None,
            self.result.clone(),
        ))?;
        Ok(())
    }
}

pub struct CreateTarsStep {
    pub logger: Logger,
    pub store_tar_cmd: Command,
}

impl Step for CreateTarsStep {
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

pub struct UploadCUPAndTar {
    pub logger: Logger,
    pub registry_helper: RegistryHelper,
    pub subnet_id: SubnetId,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
    pub work_dir: PathBuf,
}

impl UploadCUPAndTar {
    pub fn get_restart_commands(&self) -> String {
        format!(
            r#"
cd {};
OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/ic_registry_local_store);
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/ic_registry_local_store);
mkdir ic_registry_local_store;
tar zxf ic_registry_local_store.tar.zst -C ic_registry_local_store;
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
            UploadCUPAndTar::get_upload_dir_name(),
        )
    }

    pub fn get_upload_dir_name() -> String {
        "/tmp/subnet_recovery".to_string()
    }
}

impl Step for UploadCUPAndTar {
    fn descr(&self) -> String {
        format!("Uploading CUP and registry to {} on ALL nodes with admin access. Then execute on those nodes:\n{}", UploadCUPAndTar::get_upload_dir_name(), self.get_restart_commands())
    }

    fn exec(&self) -> RecoveryResult<()> {
        let ips = get_member_ips(&self.registry_helper, self.subnet_id)?;

        ips.into_iter()
            .map(|ip| {
                let ssh_helper = SshHelper::new(
                    self.logger.clone(),
                    ADMIN.to_string(),
                    ip,
                    self.require_confirmation,
                    self.key_file.clone(),
                );

                if !ssh_helper.can_connect() {
                    info!(
                        self.logger,
                        "No admin access to: {}, skipping upload...", ip
                    );
                    return Ok(None);
                }

                info!(self.logger, "Uploading to {}", ip);
                let upload_dir = UploadCUPAndTar::get_upload_dir_name();
                ssh_helper.ssh(format!(
                    "sudo rm -rf {} && mkdir {}",
                    upload_dir, upload_dir
                ))?;

                let target = format!("{}@[{}]:{}/", ADMIN, ip, upload_dir);

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

                ssh_helper.ssh(self.get_restart_commands())
            })
            .collect::<RecoveryResult<Vec<_>>>()?;

        Ok(())
    }
}

pub struct DownloadRegistryStoreStep {
    pub logger: Logger,
    pub node_ip: IpAddr,
    pub original_nns_id: SubnetId,
    pub work_dir: PathBuf,
    pub require_confirmation: bool,
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
        let account = ADMIN.to_string();
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            account,
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
            ssh_helper.account, self.node_ip, IC_DATA_PATH, IC_REGISTRY_LOCAL_STORE
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
        ssh_helper.ssh(format!("mkdir -p {}", upload_dir))?;

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
        pool1.persistent_pool.insert(cert1);
        pool2.persistent_pool.insert(cert1_2);

        // Add the same certification for height 2 to both pools,
        // it should only exists in the merged pool once.
        let cert2 = make_certification(2, vec![1, 2, 3]);
        pool1.persistent_pool.insert(cert2.clone());
        pool2.persistent_pool.insert(cert2);

        // Add two more certifications for heights 3 and 4, one to each pool.
        let cert3 = make_certification(3, vec![1, 2, 3]);
        let cert4 = make_certification(4, vec![1, 2, 3]);
        pool1.persistent_pool.insert(cert4);
        pool2.persistent_pool.insert(cert3);

        // Add a share at height 3 to one pool. It should not be added to the
        // merged pool as it is lower than the highest full certification (4).
        let share3 = make_share(3, vec![1], 1);
        pool1.persistent_pool.insert(share3);

        step.exec().expect("Failed to execute step.");

        let new_pool = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("data/ic_consensus_pool")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );

        assert_eq!(
            new_pool.persistent_pool.certifications().get_all().count(),
            4 // One for each height 1-4
        );
        assert_eq!(
            new_pool
                .persistent_pool
                .certification_shares()
                .get_all()
                .count(),
            0
        );
        let range = new_pool
            .persistent_pool
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

        pool1.persistent_pool.insert(cert4);
        pool1.persistent_pool.insert(share3);
        pool1.persistent_pool.insert(share4);
        pool1.persistent_pool.insert(share5.clone());
        pool1.persistent_pool.insert(share6_2);

        pool2.persistent_pool.insert(share5);
        pool2.persistent_pool.insert(share6);

        step.exec().expect("Failed to execute step.");

        let new_pool = CertificationPoolImpl::new(
            node_test_id(0),
            ArtifactPoolConfig::new(work_dir.join("data/ic_consensus_pool")),
            logger.clone().into(),
            MetricsRegistry::new(),
        );

        assert_eq!(
            new_pool
                .persistent_pool
                .certification_shares()
                .get_all()
                .count(),
            3 // share5, share6, share6_2
        );
        let range = new_pool
            .persistent_pool
            .certification_shares()
            .height_range()
            .expect("no height range");
        assert_eq!((range.min.get(), range.max.get()), (5, 6));
    }
}
