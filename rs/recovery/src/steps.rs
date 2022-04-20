use crate::admin_helper::IcAdmin;
use crate::command_helper::pipe_all;
use crate::error::{RecoveryError, RecoveryResult};
use crate::file_sync_helper::{create_dir, read_dir, remove_dir, rsync, write_file};
use crate::replay_helper;
use crate::ssh_helper::SshHelper;
use crate::util::{block_on, parse_hex_str};
use crate::{Recovery, IC_CHECKPOINTS_PATH, IC_DATA_PATH, IC_JSON5_PATH, IC_STATE_EXCLUDES};
use ic_types::{Height, SubnetId};
use slog::{info, Logger};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
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
        Recovery::exec_admin_cmd(self.logger.clone(), &self.ic_admin_cmd)
    }
}

pub struct DownloadIcStateStep {
    pub logger: Logger,
    pub try_readonly: bool,
    pub node_ip: IpAddr,
    pub target: String,
    pub key_file: Option<PathBuf>,
}

impl Step for DownloadIcStateStep {
    fn descr(&self) -> String {
        let data_src = format!("[{}]:{}", self.node_ip, IC_DATA_PATH);
        let config_src = format!("[{}]:{}", self.node_ip, IC_JSON5_PATH);
        format!(
            "Copy ic data from {} and config from {} to {}.",
            data_src, config_src, self.target
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let account = if self.try_readonly {
            "readonly".to_string()
        } else {
            "admin".to_string()
        };
        let mut ssh_helper = SshHelper::new(
            self.logger.clone(),
            account,
            self.node_ip,
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
            ssh_helper.account = "admin".to_string();
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

        if let Some(res) = rsync(
            &self.logger,
            IC_STATE_EXCLUDES.to_vec(),
            &data_src,
            &self.target,
            self.key_file.as_ref(),
        )? {
            info!(self.logger, "{}", res);
        }
        if let Some(res) = rsync(
            &self.logger,
            vec![],
            &config_src,
            &self.target,
            self.key_file.as_ref(),
        )? {
            info!(self.logger, "{}", res);
        }

        Ok(())
    }
}

pub struct CreateBackupStep {
    pub logger: Logger,
    pub data_src: PathBuf,
    pub backup_dir: PathBuf,
}

impl Step for CreateBackupStep {
    fn descr(&self) -> String {
        format!(
            "Copy data from {} to {}.",
            self.data_src.display(),
            self.backup_dir.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        create_dir(&self.backup_dir)?;
        rsync(
            &self.logger,
            vec![],
            &self.data_src.display().to_string(),
            &self.backup_dir.display().to_string(),
            None,
        )?;
        Ok(())
    }
}

pub struct UpdateConfigStep {
    pub target: String,
    pub work_dir: String,
}

impl Step for UpdateConfigStep {
    fn descr(&self) -> String {
        format!(
            "In {}/ic.json5, update node_ip and listen_addr to localhost, and replace ic path with working directory. Save file to {}/ic.json5",
            self.target, self.work_dir
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let mut cat = Command::new("cat");
        cat.arg(format!("{}/ic.json5", self.target));
        let mut sed1 = Command::new("sed");
        sed1.arg("-e")
            .arg(r#"s/node_ip: \".*\"/node_ip: \"127.0.0.1\"/"#);
        let mut sed2 = Command::new("sed");
        sed2.arg("-e")
            .arg(r#"s/listen_addr: \".*:\([0-9]*\)\"/listen_addr: \"127.0.0.1:\1\"/"#);
        let mut sed3 = Command::new("sed");
        sed3.arg("-e")
            .arg(format!("s|/var/lib/ic/|{}/|g", self.target));

        if let Some(res) = pipe_all(&mut [cat, sed1, sed2, sed3])? {
            let mut path = PathBuf::from(&self.work_dir);
            path.push("ic.json5");
            write_file(&path, res)?;
            Ok(())
        } else {
            Err(RecoveryError::invalid_output_error(
                "Could not save to file (empty).".to_string(),
            ))
        }
    }
}

pub struct ReplayStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub data_dir: PathBuf,
    pub config: PathBuf,
    pub result: PathBuf,
}

impl Step for ReplayStep {
    fn descr(&self) -> String {
        let checkpoint_path = self.data_dir.join("data").join(IC_CHECKPOINTS_PATH);
        format!(
            "Delete old checkpoints found in {}, then execute:\nic-replay {} --subnet-id {:?}",
            checkpoint_path.display(),
            self.config.display(),
            self.subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let checkpoint_path = self.data_dir.join("data").join(IC_CHECKPOINTS_PATH);
        let paths = read_dir(&checkpoint_path)?;

        let checkpoints = paths
            .flatten()
            .filter_map(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str().map(|s| String::from(s)))
            })
            .collect::<Vec<String>>();

        let checkpoint_heights = checkpoints
            .iter()
            .map(|c| parse_hex_str(c))
            .collect::<RecoveryResult<Vec<u64>>>()?;

        if let Some(max) = checkpoint_heights.iter().max() {
            checkpoints
                .iter()
                .filter(|c| parse_hex_str(c).unwrap() != *max)
                .map(|c| remove_dir(&checkpoint_path.join(c)))
                .collect::<RecoveryResult<Vec<_>>>()?;
            let height = Height::from(*max);

            let (latest_height, state_hash) = block_on(replay_helper::replay(
                self.subnet_id,
                self.config.clone(),
                self.result.clone(),
            ))?;

            info!(self.logger, "Checkpoint height: {}", height);
            info!(self.logger, "Height after replay: {}", latest_height);

            if latest_height < height {
                return Err(RecoveryError::invalid_output_error(
                    "Replay height and checkpoint height diverged.".to_string(),
                ));
            }

            info!(self.logger, "State hash: {}", state_hash);

            return Ok(());
        }

        Err(RecoveryError::invalid_output_error(
            "Did not find any checkpoints".to_string(),
        ))
    }
}

#[derive(Debug)]
pub struct ValidateReplayStep {
    pub logger: Logger,
    pub subnet_id: SubnetId,
    pub work_dir: PathBuf,
}

impl Step for ValidateReplayStep {
    fn descr(&self) -> String {
        "Compare height after replay to certification and finalization heights of subnet as reported by prometheus.".to_string()
    }

    fn exec(&self) -> RecoveryResult<()> {
        let (latest_height, _) =
            replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?;

        let cert_height = Recovery::get_certification_height(self.subnet_id)?;
        let finalization_height =
            Recovery::get_rnd_node_ip_with_max_finalization(self.subnet_id)?.height;

        info!(self.logger, "Certification height: {}", cert_height);
        info!(
            self.logger,
            "Max finalization height: {}", finalization_height
        );
        info!(self.logger, "Height after replay: {}", latest_height);

        if latest_height < cert_height {
            return Err(RecoveryError::invalid_output_error(
                "Replay height smaller than certification height.".to_string(),
            ));
        }

        if latest_height < finalization_height {
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
    pub key_file: Option<PathBuf>,
}

impl Step for UploadAndRestartStep {
    fn descr(&self) -> String {
        format!("Stopping replica {}, uploading and replacing state from {}, set access rights, restart replica.", self.node_ip, self.data_src.display())
    }

    fn exec(&self) -> RecoveryResult<()> {
        let (latest_height, state_hash) =
            replay_helper::read_output(self.work_dir.join(replay_helper::OUTPUT_FILE_NAME))?;
        let recovery_height = Recovery::get_recovery_height(latest_height);

        Recovery::wait_for_recovery_cup(&self.logger, self.node_ip, recovery_height, state_hash)?;

        let account = "admin";
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            account.to_string(),
            self.node_ip,
            self.key_file.clone(),
        );

        let upload_dir = format!("{}/new_ic_state", IC_DATA_PATH);

        info!(self.logger, "Creating remote directory...");
        if let Some(res) = ssh_helper.ssh(format!(
            "sudo mkdir {}; sudo chown {} {};",
            upload_dir, account, upload_dir
        ))? {
            info!(self.logger, "{}", res);
        }

        let target = format!("{}@[{}]:{}/", account, self.node_ip, upload_dir);
        let src = format!("{}/", self.data_src.display());
        info!(self.logger, "Uploading state...");
        if let Some(res) = rsync(
            &self.logger,
            IC_STATE_EXCLUDES.to_vec(),
            &src,
            &target,
            self.key_file.as_ref(),
        )? {
            info!(self.logger, "{}", res);
        }

        let ic_state_path = format!("{}/ic_state", IC_DATA_PATH);
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
        replace_state.push_str("sudo systemctl start ic-replica;");

        if let Some(res) = ssh_helper.ssh(replace_state)? {
            info!(self.logger, "{}", res);
        }
        Ok(())
    }
}

pub struct CleanupStep {
    pub recovery_dir: PathBuf,
}

impl Step for CleanupStep {
    fn descr(&self) -> String {
        format!(
            "Deleting directory {}. Backup directory is preserved if outside of recovery directory." , self.recovery_dir.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        remove_dir(&self.recovery_dir)
    }
}
