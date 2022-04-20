use ic_types::Height;
use ic_types::{ReplicaVersion, SubnetId};

use crate::NeuronArgs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

pub type IcAdmin = Vec<String>;

/// Struct simplyfiying the creation of `ic-admin` commands for a given NNS Url.
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

    pub fn get_halt_subnet_command(&self, subnet_id: SubnetId, is_halted: bool) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        AdminHelper::add_propose_to_update_subnet_base(&mut ic_admin, &self.neuron_args, subnet_id);
        ic_admin.push(format!("--is-halted={}", is_halted));
        ic_admin.push("--summary".to_string());
        ic_admin.push(format!(
            "\"{} subnet {}, for recovery\"",
            if is_halted { "Halt" } else { "Unhalt" },
            subnet_id,
        ));

        ic_admin
    }

    pub fn set_ssh_readonly_keys_command(&self, subnet_id: SubnetId, keys: &[String]) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        AdminHelper::add_propose_to_update_subnet_base(&mut ic_admin, &self.neuron_args, subnet_id);

        keys.iter()
            .map(|k| format!("--ssh-readonly-access=\"{}\"", k))
            .for_each(|k| ic_admin.push(k));

        ic_admin.push("--summary".to_string());
        ic_admin.push("\"Set readonly keys for subnet recovery\"".to_string());

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
        replacement_nodes: &[String],
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
}
