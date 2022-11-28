use crate::admin_helper::IcAdmin;
use crate::command_helper::exec_cmd;
use crate::error::{RecoveryError, RecoveryResult};
use crate::file_sync_helper::{remove_dir, rsync};
use crate::ssh_helper::SshHelper;
use crate::util::{block_on, parse_hex_str};
use crate::{
    get_member_ips, get_node_heights_from_metrics, replay_helper, ADMIN, CHECKPOINTS, IC_STATE,
    NEW_IC_STATE, READONLY,
};
use crate::{
    Recovery, IC_CHECKPOINTS_PATH, IC_DATA_PATH, IC_JSON5_PATH, IC_REGISTRY_LOCAL_STORE,
    IC_STATE_EXCLUDES,
};
use ic_base_types::CanisterId;
use ic_registry_client::client::RegistryClientImpl;
use ic_replay::cmd::{GetRecoveryCupCmd, SubCommand};
use ic_types::{Height, SubnetId};
use slog::{info, Logger};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::{thread, time};

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
pub struct DownloadIcStateStep {
    pub logger: Logger,
    pub try_readonly: bool,
    pub node_ip: IpAddr,
    pub target: String,
    pub working_dir: String,
    pub require_confirmation: bool,
    pub key_file: Option<PathBuf>,
}

impl Step for DownloadIcStateStep {
    fn descr(&self) -> String {
        let data_src = format!("[{}]:{}", self.node_ip, IC_DATA_PATH);
        let config_src = format!("[{}]:{}", self.node_ip, IC_JSON5_PATH);
        format!(
            "Copy ic data from {} and config from {} to {}. Then copy to {}",
            data_src, config_src, self.target, self.working_dir
        )
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
        let mut access_granted = false;
        for _ in 0..20 {
            if ssh_helper.can_connect() {
                access_granted = true;
                break;
            }
            info!(self.logger, "No SSH access, retrying...");
            thread::sleep(time::Duration::from_secs(5));
        }
        if !access_granted {
            ssh_helper.account = ADMIN.to_string();
            if !ssh_helper.can_connect() {
                return Err(RecoveryError::invalid_output_error(
                    "SSH access denied".to_string(),
                ));
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

        let mut excludes = IC_STATE_EXCLUDES.to_vec();
        let res = ssh_helper
            .ssh(format!(
                r"echo $(ls {}/{} | sort | awk 'n>=1 {{ print a[n%1] }} {{ a[n++%1]=$0 }}');",
                IC_DATA_PATH, IC_CHECKPOINTS_PATH
            ))?
            .unwrap_or_default();
        res.trim().split(' ').for_each(|cp| {
            excludes.push(cp);
        });

        rsync(
            &self.logger,
            excludes,
            &data_src,
            &self.target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        rsync(
            &self.logger,
            vec![],
            &config_src,
            &self.target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        rsync(
            &self.logger,
            vec![],
            &format!("{}/", self.target),
            &self.working_dir,
            false,
            None,
        )?;

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
    pub result: PathBuf,
}

impl Step for ReplayStep {
    fn descr(&self) -> String {
        let checkpoint_path = self.work_dir.join("data").join(IC_CHECKPOINTS_PATH);
        let mut base = format!(
            "Delete old checkpoints found in {}, and execute:\nic-replay {} --subnet-id {:?}",
            checkpoint_path.display(),
            self.config.display(),
            self.subnet_id,
        );
        if let Some(subcmd) = &self.subcmd {
            base.push_str(&subcmd.descr);
        }
        base
    }

    fn exec(&self) -> RecoveryResult<()> {
        let checkpoint_path = self.work_dir.join("data").join(IC_CHECKPOINTS_PATH);

        let checkpoints = Recovery::get_checkpoint_names(&checkpoint_path)?;

        let checkpoint_heights = checkpoints
            .iter()
            .map(|c| parse_hex_str(c))
            .collect::<RecoveryResult<Vec<u64>>>()?;

        let delete_checkpoints = |except: &u64| {
            Recovery::get_checkpoint_names(&checkpoint_path)?
                .iter()
                .filter(|c| parse_hex_str(c).unwrap() != *except)
                .map(|c| {
                    info!(self.logger, "Deleting checkpoint {}", c);
                    remove_dir(&checkpoint_path.join(c))
                })
                .collect::<RecoveryResult<Vec<_>>>()
        };

        if let Some(max) = checkpoint_heights.iter().max() {
            delete_checkpoints(max)?;
            let height = Height::from(*max);

            let state_params = block_on(replay_helper::replay(
                self.subnet_id,
                self.config.clone(),
                self.canister_caller_id,
                self.work_dir.join("data"),
                self.subcmd.as_ref().map(|c| c.cmd.clone()),
                self.result.clone(),
            ))?;

            let latest_height = state_params.height;
            let state_hash = state_params.hash;

            info!(self.logger, "Checkpoint height: {}", height);
            info!(self.logger, "Height after replay: {}", latest_height);

            if latest_height < height {
                return Err(RecoveryError::invalid_output_error(
                    "Replay height and checkpoint height diverged.".to_string(),
                ));
            }

            info!(self.logger, "State hash: {}", state_hash);

            info!(self.logger, "Deleting old checkpoints");
            delete_checkpoints(&latest_height.get())?;

            return Ok(());
        }

        Err(RecoveryError::invalid_output_error(
            "Did not find any checkpoints".to_string(),
        ))
    }
}

pub struct ValidateReplayStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub registry_client: Arc<RegistryClientImpl>,
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

        let heights = get_node_heights_from_metrics(
            &self.logger,
            self.registry_client.clone(),
            self.subnet_id,
        )?;
        let cert_height = &heights
            .iter()
            .max_by_key(|v| v.certification_height)
            .map(|v| v.certification_height)
            .ok_or_else(|| {
                RecoveryError::OutputError("No certification heights found".to_string())
            })?;

        let finalization_height = &heights
            .iter()
            .max_by_key(|v| v.finalization_height)
            .map(|v| v.finalization_height)
            .ok_or_else(|| {
                RecoveryError::invalid_output_error("No finalization heights found".to_string())
            })?;

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
                "Replay height smaller than certification height.".to_string(),
            ));
        }

        if latest_height.get() - self.extra_batches < finalization_height.get() {
            return Err(RecoveryError::invalid_output_error(
                "There exists a node with finalization height greater than the replay height."
                    .to_string(),
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
}

impl Step for UploadAndRestartStep {
    fn descr(&self) -> String {
        format!("Stopping replica {}, uploading and replacing state from {}, set access rights, restart replica.", self.node_ip, self.data_src.display())
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

        if checkpoints.len() != 1 {
            return Err(RecoveryError::invalid_output_error(
                "Found multiple checkpoints in upload directory".to_string(),
            ));
        }

        let max_checkpoint = checkpoints.into_iter().max().ok_or_else(|| {
            RecoveryError::invalid_output_error("No checkpoints found".to_string())
        })?;
        let replay_height =
            replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?.height;

        if parse_hex_str(&max_checkpoint)? != replay_height.get() {
            return Err(RecoveryError::invalid_output_error(format!(
                "Latest checkpoint height ({}) doesn't match replay output ({})",
                max_checkpoint, replay_height
            )));
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
        format!("Update registry local store by executing:\nic-replay {:?} --subnet-id {:?} update-registry-local-store", self.work_dir.join("ic.json5"), self.subnet_id)
    }

    fn exec(&self) -> RecoveryResult<()> {
        block_on(replay_helper::replay(
            self.subnet_id,
            self.work_dir.join("ic.json5"),
            None,
            self.work_dir.join("data"),
            Some(SubCommand::UpdateRegistryLocalStore),
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
        format!("Set recovery CUP by executing:\nic-replay {:?} --subnet-id {:?} get-recovery-cup {:?} {:?} cup.proto", self.config, self.subnet_id, self.state_hash, self.recovery_height)
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
        format!("Copying ic_state for upload to: {:?}", self.new_state_dir,)
    }

    fn exec(&self) -> RecoveryResult<()> {
        rsync(
            &self.logger,
            vec![],
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
    pub registry_client: Arc<RegistryClientImpl>,
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
tar zxf ic_registry_local_store.tar.gz -C ic_registry_local_store;
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
        let ips = get_member_ips(self.registry_client.clone(), self.subnet_id)?;

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
                    vec![],
                    &format!("{}/cup.proto", self.work_dir.display()),
                    &target,
                    self.require_confirmation,
                    self.key_file.as_ref(),
                )?;

                rsync(
                    &self.logger,
                    vec![],
                    &format!("{}/ic_registry_local_store.tar.gz", self.work_dir.display()),
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
            vec![],
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
            vec![],
            &src,
            &target,
            self.require_confirmation,
            self.key_file.as_ref(),
        )?;

        ssh_helper.ssh("daemonize $(which python3) -m http.server --bind :: 8081".to_string())?;

        Ok(())
    }
}
