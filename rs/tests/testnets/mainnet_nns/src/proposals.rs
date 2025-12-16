use ic_canister_client::Sender;
use ic_canister_client_sender::SigKeys;
use ic_consensus_system_test_utils::upgrade::get_blessed_replica_versions;
use ic_nns_common::types::NeuronId;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_nns_test_utils::governance::{
    submit_external_update_proposal, submit_external_update_proposal_allowing_error,
    wait_for_final_state,
};
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_system_test_driver::{
    driver::test_env_api::{HasPublicApiUrl, IcNodeSnapshot},
    nns::{get_governance_canister, submit_update_elected_replica_versions_proposal},
    util::runtime_from_url,
};
use ic_types::{NodeId, ReplicaVersion, SubnetId};
use once_cell::sync::OnceCell;
use registry_canister::mutations::{
    do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
    do_change_subnet_membership::ChangeSubnetMembershipPayload,
    do_update_subnet::UpdateSubnetPayload,
};
use slog::{Logger, info};
use url::Url;

// Test neuron secret key and corresponding controller principal
pub(crate) const NEURON_CONTROLLER: &str =
    "bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae";
pub(crate) const NEURON_SECRET_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIKohpVANxO4xElQYXElAOXZHwJSVHERLE8feXSfoKwxX
oSMDIQBqgs2z86b+S5X9HvsxtE46UZwfDHtebwmSQWSIcKr2ew==
-----END PRIVATE KEY-----";

static RECOVERED_NNS_DICTATOR_NEURON_ID: OnceCell<NeuronId> = OnceCell::new();

pub struct ProposalWithMainnetState {
    neuron_id: NeuronId,
    proposal_sender: Sender,
}

impl ProposalWithMainnetState {
    fn new() -> Self {
        let neuron_id = *RECOVERED_NNS_DICTATOR_NEURON_ID.get().expect(
            "'set_dictator_neuron_id' must be called before using ProposalWithMainnetState",
        );
        let sig_keys =
            SigKeys::from_pem(NEURON_SECRET_KEY_PEM).expect("Failed to parse secret key");
        let proposal_sender = Sender::SigKeys(sig_keys);

        Self {
            neuron_id,
            proposal_sender,
        }
    }

    pub fn set_dictator_neuron_id(neuron_id: NeuronId) {
        RECOVERED_NNS_DICTATOR_NEURON_ID
            .set(neuron_id)
            .expect("Dictator neuron ID can only be set once");
    }

    // Code duplicate of //rs/tests/consensus/utils/src/upgrade.rs:bless_replica_version adapted to
    // use the dictator neuron
    pub async fn bless_replica_version(
        nns_node: &IcNodeSnapshot,
        target_version: &ReplicaVersion,
        logger: &Logger,
        sha256: String,
        guest_launch_measurements: Option<GuestLaunchMeasurements>,
        upgrade_url: Vec<String>,
    ) {
        let self_ = Self::new();

        let nns = runtime_from_url(nns_node.get_public_url(), REGISTRY_CANISTER_ID.into());
        let governance_canister = get_governance_canister(&nns);
        let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
        let neuron_id = self_.neuron_id;
        let proposal_sender = self_.proposal_sender.clone();
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(logger, "Initial: {:?}", blessed_versions);

        info!(
            logger,
            "Blessing replica version {:?} with sha256 {:?} using neuron {:?}",
            target_version,
            sha256,
            neuron_id
        );

        let proposal_id = submit_update_elected_replica_versions_proposal(
            &governance_canister,
            proposal_sender,
            neuron_id,
            Some(target_version),
            Some(sha256),
            upgrade_url,
            guest_launch_measurements,
            vec![],
        )
        .await;
        wait_for_final_state(&governance_canister, proposal_id).await;
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(logger, "Updated: {:?}", blessed_versions);
    }

    // Code duplicate of //rs/tests/consensus/utils/src/ssh_access.rs:update_subnet_record adapted
    // to use the dictator neuron
    pub async fn update_subnet_record(nns_url: Url, payload: UpdateSubnetPayload) {
        let self_ = Self::new();

        let nns = runtime_from_url(nns_url, REGISTRY_CANISTER_ID.into());
        let governance_canister = get_governance_canister(&nns);
        let neuron_id = self_.neuron_id;
        let proposal_sender = self_.proposal_sender.clone();

        let subnet_id = payload.subnet_id;
        let proposal_id = submit_external_update_proposal_allowing_error(
            &governance_canister,
            proposal_sender,
            neuron_id,
            NnsFunction::UpdateConfigOfSubnet,
            payload,
            format!("Updating subnet record for subnet {}", subnet_id),
            "".to_string(),
        )
        .await
        .expect("Failed to submit proposal to update subnet record");
        wait_for_final_state(&governance_canister, proposal_id).await;
    }

    pub async fn add_api_boundary_nodes(
        nns_node: &IcNodeSnapshot,
        logger: &Logger,
        node_ids: Vec<NodeId>,
        version: String,
    ) {
        let self_ = Self::new();

        let nns = runtime_from_url(nns_node.get_public_url(), REGISTRY_CANISTER_ID.into());
        let governance_canister = get_governance_canister(&nns);
        let neuron_id = self_.neuron_id;
        let proposal_sender = self_.proposal_sender.clone();

        let proposal_id = submit_external_update_proposal_allowing_error(
            &governance_canister,
            proposal_sender,
            neuron_id,
            NnsFunction::AddApiBoundaryNodes,
            AddApiBoundaryNodesPayload { node_ids, version },
            "Adding nodes as API Boundary Nodes".to_string(),
            "".to_string(),
        )
        .await
        .expect("Failed to submit proposal to add API Boundary Nodes");
        wait_for_final_state(&governance_canister, proposal_id).await;
        info!(
            logger,
            "API Boundary Nodes addition proposal {:?} has been executed", proposal_id,
        );
    }

    // Code duplicate of //rs/tests/driver/src/nns.rs:change_subnet_membership adapted to use the
    // dictator neuron
    pub async fn change_subnet_membership(
        url: Url,
        subnet_id: SubnetId,
        node_ids_add: &[NodeId],
        node_ids_remove: &[NodeId],
    ) -> Result<(), String> {
        let self_ = Self::new();

        let nns = runtime_from_url(url, REGISTRY_CANISTER_ID.into());
        let governance_canister = get_governance_canister(&nns);
        let proposal_payload = ChangeSubnetMembershipPayload {
            subnet_id: subnet_id.get(),
            node_ids_add: node_ids_add.to_vec(),
            node_ids_remove: node_ids_remove.to_vec(),
        };
        let neuron_id = self_.neuron_id;
        let proposal_sender = self_.proposal_sender.clone();

        let proposal_id = submit_external_update_proposal(
            &governance_canister,
            proposal_sender,
            neuron_id,
            NnsFunction::ChangeSubnetMembership,
            proposal_payload,
            String::from("Change subnet membership for testing"),
            "Motivation: testing".to_string(),
        )
        .await;

        wait_for_final_state(&governance_canister, proposal_id).await;
        Ok(())
    }
}
