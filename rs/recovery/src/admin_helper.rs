use ic_base_types::{NodeId, RegistryVersion};
use ic_types::Height;
use ic_types::{ReplicaVersion, SubnetId};

use crate::NeuronArgs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

pub type IcAdmin = Vec<String>;

pub struct RegistryParams {
    pub registry_store_uri: Url,
    pub registry_store_hash: String,
    pub registry_version: RegistryVersion,
}

/// Struct simplyfiying the creation of `ic-admin` commands for a given NNS Url.
#[derive(Debug, Clone)]
pub struct AdminHelper {
    pub binary: PathBuf,
    pub nns_url: Url,
    pub neuron_args: Option<NeuronArgs>,
}

impl AdminHelper {
    /// Create a new command builder for a given binary path, NNS url and
    /// [NeuronArgs].
    pub fn new(binary: PathBuf, nns_url: Url, neuron_args: Option<NeuronArgs>) -> Self {
        Self {
            binary,
            nns_url,
            neuron_args,
        }
    }

    fn get_ic_admin_cmd_base(&self, neuron_args: &Option<NeuronArgs>) -> IcAdmin {
        let mut ica = self.binary.clone();
        ica.push("ic-admin");
        let mut ic_admin = vec![ica.display().to_string()];
        ic_admin.push("--nns-url".to_string());
        ic_admin.push(format!("\"{}\"", self.nns_url));

        // Existance of [NeuronArgs] implies no testing mode. Add hsm parameters to
        // base.
        if let Some(args) = neuron_args {
            ic_admin.push("--use-hsm".to_string());
            ic_admin.push(format!("--slot={}", args.slot));
            ic_admin.push(format!("--key-id={}", args.key_id));
            ic_admin.push(format!("--pin=\"{}\"", args.dfx_hsm_pin));
        }

        ic_admin
    }

    fn add_propose_to_update_subnet_base(
        ic_admin: &mut IcAdmin,
        neuron_args: &Option<NeuronArgs>,
        subnet_id: SubnetId,
    ) {
        ic_admin.push("propose-to-update-subnet".to_string());
        ic_admin.push("--subnet".to_string());
        ic_admin.push(subnet_id.to_string());
        AdminHelper::add_proposer_args(ic_admin, neuron_args);
    }

    // Existance of [NeuronArgs] implies no testing mode. Add proposer neuron id,
    // else add test neuron proposer.
    fn add_proposer_args(ic_admin: &mut IcAdmin, neuron_args: &Option<NeuronArgs>) {
        if let Some(args) = neuron_args {
            ic_admin.push("--proposer".to_string());
            ic_admin.push(args.neuron_id.clone());
        } else {
            ic_admin.push("--test-neuron-proposer".to_string());
        }
    }

    pub fn get_halt_subnet_command(
        &self,
        subnet_id: SubnetId,
        is_halted: bool,
        keys: &[String],
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        AdminHelper::add_propose_to_update_subnet_base(&mut ic_admin, &self.neuron_args, subnet_id);
        ic_admin.push(format!("--is-halted={}", is_halted));
        keys.iter()
            .map(|k| format!("--ssh-readonly-access=\"{}\"", k))
            .for_each(|k| ic_admin.push(k));
        ic_admin.push("--summary".to_string());
        ic_admin.push(format!(
            "\"{} subnet {}, for recovery and update ssh readonly access\"",
            if is_halted { "Halt" } else { "Unhalt" },
            subnet_id,
        ));

        ic_admin
    }

    pub fn get_propose_to_bless_replica_version_flexible_command(
        &self,
        upgrade_version: &ReplicaVersion,
        upgrade_url: &Url,
        sha256: String,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.push("propose-to-bless-replica-version-flexible".to_string());
        ic_admin.push(format!("\"{}\"", upgrade_version));
        ic_admin.push(format!("\"{}\"", upgrade_url));
        ic_admin.push(format!("\"{}\"", sha256));
        AdminHelper::add_proposer_args(&mut ic_admin, &self.neuron_args);
        ic_admin
    }

    pub fn get_propose_to_update_subnet_replica_version_command(
        &self,
        subnet_id: SubnetId,
        upgrade_version: &ReplicaVersion,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.push("propose-to-update-subnet-replica-version".to_string());
        ic_admin.push(subnet_id.to_string());
        ic_admin.push(upgrade_version.to_string());
        ic_admin.push("--summary".to_string());
        ic_admin.push(format!(
            "\"Upgrade replica version of subnet {}.\"",
            subnet_id
        ));
        AdminHelper::add_proposer_args(&mut ic_admin, &self.neuron_args);
        ic_admin
    }

    pub fn get_propose_to_update_recovery_cup_command(
        &self,
        subnet_id: SubnetId,
        checkpoint_height: Height,
        state_hash: String,
        replacement_nodes: &[NodeId],
        registry_params: Option<RegistryParams>,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.push("propose-to-update-recovery-cup".to_string());
        ic_admin.push("--subnet-index".to_string());
        ic_admin.push(subnet_id.to_string());
        ic_admin.push("--height".to_string());
        ic_admin.push(checkpoint_height.to_string());
        ic_admin.push("--state-hash".to_string());
        ic_admin.push(state_hash);
        if !replacement_nodes.is_empty() {
            ic_admin.push("--replacement-nodes".to_string());
            replacement_nodes
                .iter()
                .for_each(|n| ic_admin.push(format!("\"{}\"", n)));
        }

        if let Some(params) = registry_params {
            ic_admin.push("--registry-store-uri".to_string());
            ic_admin.push(params.registry_store_uri.to_string());
            ic_admin.push("--registry-store-hash".to_string());
            ic_admin.push(params.registry_store_hash);
            ic_admin.push("--registry-version".to_string());
            ic_admin.push(params.registry_version.to_string());
        }

        ic_admin.push("--summary".to_string());
        ic_admin.push(format!("\"Recover subnet {}.\"", subnet_id));

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        ic_admin.push("--time-ns".to_string());
        ic_admin.push(since_the_epoch.as_nanos().to_string());

        AdminHelper::add_proposer_args(&mut ic_admin, &self.neuron_args);
        ic_admin
    }

    /// Return an ic_admin command string to create a system subnet with dkg interval of 12
    pub fn get_propose_to_create_test_system_subnet(
        &self,
        subnet_id_override: SubnetId,
        replica_version: ReplicaVersion,
        node_ids: &[NodeId],
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.append(&mut vec![
            "propose-to-create-subnet".to_string(),
            "--unit-delay-millis".to_string(),
            "2000".to_string(),
            "--subnet-handler-id".to_string(),
            "unused".to_string(),
            "--replica-version-id".to_string(),
            replica_version.to_string(),
            "--subnet-id-override".to_string(),
            subnet_id_override.to_string(),
            "--dkg-interval-length".to_string(),
            "12".to_string(),
            "--is-halted".to_string(),
            "--subnet-type".to_string(),
            "system".to_string(),
        ]);
        node_ids.iter().for_each(|id| ic_admin.push(id.to_string()));
        AdminHelper::add_proposer_args(&mut ic_admin, &self.neuron_args);
        ic_admin
    }

    pub fn get_extract_cup_command(
        &self,
        subnet_id: SubnetId,
        registry_store: PathBuf,
        output_file: PathBuf,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&None);
        ic_admin.push("get-recovery-cup".to_string());
        ic_admin.push(subnet_id.to_string());
        ic_admin.push("--registry-local-store".to_string());
        ic_admin.push(format!("{:?}", registry_store));
        ic_admin.push("--output-file".to_string());
        ic_admin.push(format!("{:?}", output_file));
        ic_admin
    }

    pub fn get_node_command(&self, node_id: &NodeId) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&None);
        ic_admin.push("get-node".to_string());
        ic_admin.push(node_id.to_string());
        ic_admin
    }

    pub fn get_subnet_command(&self, subnet_id: SubnetId) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&None);
        ic_admin.push("get-subnet".to_string());
        ic_admin.push(subnet_id.to_string());
        ic_admin
    }

    pub fn get_topology_command(&self) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&None);
        ic_admin.push("get-topology".to_string());
        ic_admin
    }

    pub fn to_system_command(ic_admin: &IcAdmin) -> Command {
        let mut cmd = Command::new(&ic_admin[0]);
        cmd.args(ic_admin[1..].iter().map(|s| s.replace('\"', "")));
        cmd
    }
}
