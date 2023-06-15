use crate::NeuronArgs;
use ic_base_types::{NodeId, RegistryVersion};
use ic_ic00_types::EcdsaKeyId;
use ic_types::{Height, ReplicaVersion, SubnetId};
use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

pub type IcAdmin = Vec<String>;

pub struct RegistryParams {
    pub registry_store_uri: Url,
    pub registry_store_hash: String,
    pub registry_version: RegistryVersion,
}

/// Struct simplyfiying the creation of `ic-admin` commands for a given NNS [Url].
#[derive(Debug, Clone)]
pub struct AdminHelper {
    pub binary: PathBuf,
    pub nns_url: Url,
    pub neuron_args: Option<NeuronArgs>,
}

impl AdminHelper {
    /// Create a new command builder for a given binary path, NNS [Url] and
    /// [NeuronArgs].
    pub fn new(binary: PathBuf, nns_url: Url, neuron_args: Option<NeuronArgs>) -> Self {
        Self {
            binary,
            nns_url,
            neuron_args,
        }
    }

    pub fn get_ic_admin_cmd_base(&self, neuron_args: &Option<NeuronArgs>) -> IcAdmin {
        let mut ica = self.binary.clone();
        ica.push("ic-admin");
        let mut ic_admin = vec![ica.display().to_string()];
        ic_admin.push("--nns-url".to_string());
        ic_admin.push(format!("\"{}\"", self.nns_url));

        // Existence of [NeuronArgs] implies no testing mode. Add hsm parameters to
        // base.
        if let Some(args) = neuron_args {
            ic_admin.push("--use-hsm".to_string());
            ic_admin.push(format!("--slot={}", args.slot));
            ic_admin.push(format!("--key-id={}", args.key_id));
            ic_admin.push(format!("--pin=\"{}\"", args.dfx_hsm_pin));
        }

        ic_admin
    }

    pub fn add_propose_to_update_subnet_base(
        ic_admin: &mut IcAdmin,
        neuron_args: &Option<NeuronArgs>,
        subnet_id: SubnetId,
    ) {
        ic_admin.push("propose-to-update-subnet".to_string());
        ic_admin.push("--subnet".to_string());
        ic_admin.push(subnet_id.to_string());
        AdminHelper::add_proposer_args(ic_admin, neuron_args);
    }

    // Existence of [NeuronArgs] implies no testing mode. Add proposer neuron id,
    // else add test neuron proposer.
    pub fn add_proposer_args(ic_admin: &mut IcAdmin, neuron_args: &Option<NeuronArgs>) {
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

    pub fn get_propose_to_update_elected_replica_versions_command(
        &self,
        upgrade_version: &ReplicaVersion,
        upgrade_url: &Url,
        sha256: String,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.push("propose-to-update-elected-replica-versions".to_string());
        ic_admin.push("--replica-version-to-elect".to_string());
        ic_admin.push(format!("\"{upgrade_version}\""));
        ic_admin.push("--release-package-urls".to_string());
        ic_admin.push(format!("\"{upgrade_url}\""));
        ic_admin.push("--release-package-sha256-hex".to_string());
        ic_admin.push(format!("\"{sha256}\""));
        ic_admin.push("--summary".to_string());
        ic_admin.push(format!(
            "\"Elect new replica binary revision (commit {upgrade_version})\""
        ));
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
        ecdsa_key_ids: Vec<EcdsaKeyId>,
        replacement_nodes: &[NodeId],
        registry_params: Option<RegistryParams>,
        ecdsa_subnet_id: Option<SubnetId>,
        time: SystemTime,
    ) -> IcAdmin {
        let mut ic_admin = self.get_ic_admin_cmd_base(&self.neuron_args);
        ic_admin.push("propose-to-update-recovery-cup".to_string());
        ic_admin.push("--subnet-index".to_string());
        ic_admin.push(subnet_id.to_string());
        ic_admin.push("--height".to_string());
        ic_admin.push(checkpoint_height.to_string());
        ic_admin.push("--state-hash".to_string());
        ic_admin.push(state_hash);

        let ecdsa_subnet = ecdsa_subnet_id
            .map(|id| format!(r#", "subnet_id": "{}""#, id))
            .unwrap_or_default();

        if !ecdsa_key_ids.is_empty() {
            ic_admin.push("--ecdsa-keys-to-request".to_string());
            let keys = ecdsa_key_ids
                .iter()
                .map(|k| format!(r#"{{ "key_id": "{}"{} }}"#, k, ecdsa_subnet))
                .collect::<Vec<String>>()
                .join(" , ");
            ic_admin.push(format!("'[ {} ]'", keys));
        }

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

        let since_the_epoch = time
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
            "--summary".to_string(),
            format!("Create subnet with id {}", subnet_id_override),
        ]);
        node_ids.iter().for_each(|id| ic_admin.push(id.to_string()));
        AdminHelper::add_proposer_args(&mut ic_admin, &self.neuron_args);
        ic_admin
    }

    pub fn to_system_command(ic_admin: &IcAdmin) -> Command {
        let mut cmd = Command::new(&ic_admin[0]);
        cmd.args(ic_admin[1..].iter().map(|s| {
            if !s.contains("key_id") {
                s.replace('\"', "")
            } else {
                s.replace('\'', "")
            }
        }));
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_base_types::PrincipalId;
    use std::{str::FromStr, time::Duration};

    const FAKE_IC_ADMIN_DIR: &str = "/fake/ic/admin/dir/";
    const FAKE_NNS_URL: &str = "https://fake_nns_url.com:8080";
    const FAKE_SUBNET_ID_1: &str =
        "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe";
    const FAKE_SUBNET_ID_2: &str =
        "mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe";
    const FAKE_NODE_ID: &str = "nqpqw-cp42a-rmdsx-fpui3-ncne5-kzq6o-m67an-w25cx-zu636-lcf2v-fqe";
    const FAKE_REPLICA_VERSION: &str = "fake_replica_version";

    #[test]
    fn get_halt_subnet_command_test() {
        let result = fake_admin_helper()
            .get_halt_subnet_command(
                subnet_id_from_str(FAKE_SUBNET_ID_1),
                /*is_halted=*/ true,
                &["fake public key".to_string()],
            )
            .join(" ");

        assert_eq!(result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-subnet \
            --subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --test-neuron-proposer \
            --is-halted=true \
            --ssh-readonly-access=\"fake public key\" \
            --summary \"Halt subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe, for recovery and update ssh readonly access\""
            );
    }

    #[test]
    fn get_propose_to_create_test_system_subnet_test() {
        let result = fake_admin_helper()
            .get_propose_to_create_test_system_subnet(
                subnet_id_from_str(FAKE_SUBNET_ID_1),
                ReplicaVersion::try_from(FAKE_REPLICA_VERSION).unwrap(),
                &[node_id_from_str(FAKE_NODE_ID)],
            )
            .join(" ");

        assert_eq!(result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-create-subnet \
            --unit-delay-millis 2000 \
            --subnet-handler-id unused \
            --replica-version-id fake_replica_version \
            --subnet-id-override gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --dkg-interval-length 12 \
            --is-halted \
            --subnet-type system \
            --summary Create subnet with id gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe nqpqw-cp42a-rmdsx-fpui3-ncne5-kzq6o-m67an-w25cx-zu636-lcf2v-fqe \
            --test-neuron-proposer");
    }

    #[test]
    fn get_propose_to_update_elected_replica_versions_command_test() {
        let result = fake_admin_helper()
            .get_propose_to_update_elected_replica_versions_command(
                &ReplicaVersion::try_from(FAKE_REPLICA_VERSION).unwrap(),
                &Url::try_from("https://fake_upgrade_url.com").unwrap(),
                "fake_sha_256".to_string(),
            )
            .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-elected-replica-versions \
            --replica-version-to-elect \"fake_replica_version\" \
            --release-package-urls \"https://fake_upgrade_url.com/\" \
            --release-package-sha256-hex \"fake_sha_256\" \
            --summary \"Elect new replica binary revision (commit fake_replica_version)\" \
            --test-neuron-proposer"
        );
    }

    #[test]
    fn get_propose_to_update_recovery_cup_command_minimum_options_test() {
        let result = fake_admin_helper()
            .get_propose_to_update_recovery_cup_command(
                subnet_id_from_str(FAKE_SUBNET_ID_1),
                Height::from(666),
                "fake_state_hash".to_string(),
                vec![],
                &[],
                None,
                None,
                UNIX_EPOCH + Duration::from_nanos(123456),
            )
            .join(" ");

        assert_eq!(result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-recovery-cup \
            --subnet-index gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --height 666 \
            --state-hash fake_state_hash \
            --summary \"Recover subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe.\" \
            --time-ns 123456 \
            --test-neuron-proposer");
    }

    #[test]
    fn get_propose_to_update_recovery_cup_command_maximum_options_test() {
        let result = fake_admin_helper_with_neuron_args()
            .get_propose_to_update_recovery_cup_command(
                subnet_id_from_str(FAKE_SUBNET_ID_1),
                Height::from(666),
                "fake_state_hash".to_string(),
                vec![
                    EcdsaKeyId::from_str("Secp256k1:some_key_1").unwrap(),
                    EcdsaKeyId::from_str("Secp256k1:some_key_2").unwrap(),
                ],
                &[node_id_from_str(FAKE_NODE_ID)],
                Some(RegistryParams {
                    registry_store_uri: Url::try_from("https://fake_registry_store_uri.com")
                        .unwrap(),
                    registry_store_hash: "fake_registry_store_hash".to_string(),
                    registry_version: RegistryVersion::from(666),
                }),
                Some(subnet_id_from_str(FAKE_SUBNET_ID_2)),
                UNIX_EPOCH + Duration::from_nanos(123456),
            )
            .join(" ");

        assert_eq!(result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            --use-hsm \
            --slot=fake_slot \
            --key-id=fake_key_id \
            --pin=\"fake_dfx_hsm_pin\" \
            propose-to-update-recovery-cup \
            --subnet-index gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --height 666 \
            --state-hash fake_state_hash \
            --ecdsa-keys-to-request '[ { \"key_id\": \"Secp256k1:some_key_1\", \"subnet_id\": \"mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe\" } , { \"key_id\": \"Secp256k1:some_key_2\", \"subnet_id\": \"mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe\" } ]' \
            --replacement-nodes \"nqpqw-cp42a-rmdsx-fpui3-ncne5-kzq6o-m67an-w25cx-zu636-lcf2v-fqe\" \
            --registry-store-uri https://fake_registry_store_uri.com/ \
            --registry-store-hash fake_registry_store_hash \
            --registry-version 666 \
            --summary \"Recover subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe.\" \
            --time-ns 123456 \
            --proposer fake_neuron_id");
    }

    #[test]
    fn get_propose_to_update_subnet_replica_version_command_test() {
        let result = fake_admin_helper()
            .get_propose_to_update_subnet_replica_version_command(
                subnet_id_from_str(FAKE_SUBNET_ID_1),
                &ReplicaVersion::try_from(FAKE_REPLICA_VERSION).unwrap(),
            )
            .join(" ");

        assert_eq!(result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-subnet-replica-version \
            gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            fake_replica_version \
            --summary \"Upgrade replica version of subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe.\" \
            --test-neuron-proposer");
    }

    fn subnet_id_from_str(subnet_id: &str) -> SubnetId {
        PrincipalId::from_str(subnet_id)
            .map(SubnetId::from)
            .unwrap()
    }

    fn node_id_from_str(subnet_id: &str) -> NodeId {
        PrincipalId::from_str(subnet_id).map(NodeId::from).unwrap()
    }

    fn fake_admin_helper() -> AdminHelper {
        AdminHelper::new(
            PathBuf::from(FAKE_IC_ADMIN_DIR),
            Url::try_from(FAKE_NNS_URL).unwrap(),
            /*neuron_args=*/ None,
        )
    }

    fn fake_admin_helper_with_neuron_args() -> AdminHelper {
        AdminHelper::new(
            PathBuf::from(FAKE_IC_ADMIN_DIR),
            Url::try_from(FAKE_NNS_URL).unwrap(),
            Some(NeuronArgs {
                dfx_hsm_pin: "fake_dfx_hsm_pin".to_string(),
                slot: "fake_slot".to_string(),
                neuron_id: "fake_neuron_id".to_string(),
                key_id: "fake_key_id".to_string(),
            }),
        )
    }
}
