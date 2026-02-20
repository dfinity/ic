use crate::{
    NeuronArgs, RecoveryArgs,
    app_subnet_recovery::{self, AppSubnetRecovery},
    cmd::SubCommand,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{path_exists, read_file, write_file},
    nns_recovery_failover_nodes::{self, NNSRecoveryFailoverNodes},
    nns_recovery_same_nodes::{self, NNSRecoverySameNodes},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

const RECOVERY_STATE_FILE_NAME: &str = "recovery_state.json";

/// State of the recovery, i.e. which step are we on right now + arguments.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct RecoveryState<T> {
    pub recovery_args: RecoveryArgs,
    pub subcommand_args: T,
    pub neuron_args: Option<NeuronArgs>,
}

impl<T: Serialize + DeserializeOwned> RecoveryState<T> {
    /// Writes the state to the disk.
    ///
    /// The file is saved under $dir/recovery_state.json where $dir is the working directory.
    ///
    /// Note that if the working directory doesn't exist we don't save anything yet we still return
    /// [Ok(())]. This could only happen when the recovery hasn't started yet or when the recovery
    /// has already finished and the working directory has been cleaned up. In both these cases
    /// it's reasonable not to save anything.
    pub fn save(&self) -> RecoveryResult<()> {
        if !path_exists(&Self::get_directory_name(&self.recovery_args.dir))? {
            return Ok(());
        }

        let path = Self::get_file_name(&self.recovery_args.dir);
        serde_json::to_string(self)
            .map_err(RecoveryError::serialization_error)
            .and_then(|json| write_file(&path, json))
    }

    /// Reads the state from the disk.
    ///
    /// Returns [None] if the path doesn't exist, otherwise it tries to read the file and
    /// deserialize the content and returns [Some<RecoveryState>].
    pub fn read(dir: &Path) -> RecoveryResult<Option<Self>> {
        let path = Self::get_file_name(dir);

        if path_exists(&path)? {
            read_file(&path).and_then(|content| {
                serde_json::from_str(&content).map_err(RecoveryError::parsing_error)
            })
        } else {
            Ok(None)
        }
    }

    fn get_directory_name(dir: &Path) -> PathBuf {
        dir.join(crate::RECOVERY_DIRECTORY_NAME)
    }

    fn get_file_name(dir: &Path) -> PathBuf {
        Self::get_directory_name(dir).join(RECOVERY_STATE_FILE_NAME)
    }
}

pub trait HasRecoveryState {
    type StepType;
    type SubcommandArgsType;

    fn get_next_step(&self) -> Option<Self::StepType>;

    fn get_state(&self) -> RecoveryResult<RecoveryState<Self::SubcommandArgsType>>;
}

impl HasRecoveryState for AppSubnetRecovery {
    type StepType = app_subnet_recovery::StepType;
    type SubcommandArgsType = SubCommand;

    fn get_next_step(&self) -> Option<Self::StepType> {
        self.params.next_step
    }

    fn get_state(&self) -> RecoveryResult<RecoveryState<Self::SubcommandArgsType>> {
        Ok(RecoveryState {
            recovery_args: self.recovery_args.clone(),
            neuron_args: self.neuron_args.clone(),
            subcommand_args: SubCommand::AppSubnetRecovery(self.params.clone()),
        })
    }
}

impl HasRecoveryState for NNSRecoveryFailoverNodes {
    type StepType = nns_recovery_failover_nodes::StepType;
    type SubcommandArgsType = SubCommand;

    fn get_next_step(&self) -> Option<Self::StepType> {
        self.params.next_step
    }

    fn get_state(&self) -> RecoveryResult<RecoveryState<Self::SubcommandArgsType>> {
        Ok(RecoveryState {
            recovery_args: self.recovery_args.clone(),
            neuron_args: self.neuron_args.clone(),
            subcommand_args: SubCommand::NNSRecoveryFailoverNodes(self.params.clone()),
        })
    }
}

impl HasRecoveryState for NNSRecoverySameNodes {
    type StepType = nns_recovery_same_nodes::StepType;
    type SubcommandArgsType = SubCommand;

    fn get_next_step(&self) -> Option<Self::StepType> {
        self.params.next_step
    }

    fn get_state(&self) -> RecoveryResult<RecoveryState<Self::SubcommandArgsType>> {
        Ok(RecoveryState {
            recovery_args: self.recovery_args.clone(),
            neuron_args: None,
            subcommand_args: SubCommand::NNSRecoverySameNodes(self.params.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, str::FromStr};

    use crate::app_subnet_recovery::AppSubnetRecoveryArgs;
    use crate::error::GracefulExpect;

    use super::*;
    use ic_base_types::{PrincipalId, SubnetId};
    use tempfile::tempdir;
    use url::Url;

    #[test]
    pub fn serialization_works() {
        let tmp = tempdir().expect("Couldn't create a temp test directory");
        fs::create_dir_all(tmp.path().join("recovery")).unwrap();
        let state = fake_recovery_state(tmp.path());

        assert!(state.save().is_ok());
        assert!(tmp.path().join("recovery/recovery_state.json").exists());

        let deserialized_state =
            RecoveryState::read(tmp.path()).expect_graceful("Failed to deserialize the state");

        assert_eq!(deserialized_state, Some(state));
    }

    #[test]
    fn does_not_write_the_state_when_dir_does_not_exist() {
        let tmp = tempdir().expect("Couldn't create a temp test directory");
        let non_existing_path = tmp.path().join("non_existing_subdir");

        assert!(fake_recovery_state(&non_existing_path).save().is_ok());
        assert!(!path_exists(&non_existing_path).unwrap());
    }

    #[test]
    pub fn returns_none_when_path_doesnt_exist() {
        let tmp = tempdir().expect("Couldn't create a temp test directory");

        assert_eq!(RecoveryState::<SubCommand>::read(tmp.path()).unwrap(), None);
    }

    fn fake_recovery_state(dir: &Path) -> RecoveryState<SubCommand> {
        RecoveryState::<SubCommand> {
            recovery_args: RecoveryArgs {
                dir: PathBuf::from(dir),
                nns_url: Url::parse("https://fake_nns_url.com/").unwrap(),
                replica_version: None,
                admin_key_file: Some(PathBuf::from(dir)),
                test_mode: true,
                skip_prompts: true,
                use_local_binaries: false,
            },
            subcommand_args: SubCommand::AppSubnetRecovery(AppSubnetRecoveryArgs {
                subnet_id: fake_subnet_id(),
                upgrade_version: None,
                replacement_nodes: None,
                replay_until_height: None,
                readonly_pub_key: Some(String::from("Fake public key")),
                readonly_key_file: Some(PathBuf::from(dir)),
                download_pool_node: None,
                download_state_method: None,
                keep_downloaded_state: Some(false),
                upload_method: None,
                wait_for_cup_node: None,
                chain_key_subnet_id: Some(fake_subnet_id()),
                next_step: None,
                upgrade_image_url: None,
                upgrade_image_hash: None,
                upgrade_image_launch_measurements_path: None,
                skip: None,
            }),
            neuron_args: None,
        }
    }

    fn fake_subnet_id() -> SubnetId {
        PrincipalId::from_str("gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe")
            .map(SubnetId::from)
            .unwrap()
    }
}
