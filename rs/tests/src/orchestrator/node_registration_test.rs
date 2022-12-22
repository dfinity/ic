/* tag::catalog[]

Goal:: Test the node registration process by mocking the HSM signing.

Runbook::
. Setup an IC with 1-node NNS and 1 unassigned node.
. Register a node provider and a node operator principals (we use the same one).
. Copy a PEM corresponding to the NO principal onto the unassigned node.
. Delete crypto key on the unassigned node and restart the replica and the csp process again.
. Restart the replica process.
. Wait for the registry update and make sure we have 2 unassigned nodes.

Success:: We end the test with 2 registered unassigned nodes.

end::catalog[] */

use super::utils::rw_message::install_nns_and_check_progress;
use super::utils::ssh_access::execute_bash_command;
use crate::driver::test_env::SshKeyGen;
use crate::driver::{ic::InternetComputer, test_env::TestEnv, test_env_api::*};
use crate::nns::get_governance_canister;
use crate::util::{block_on, runtime_from_url};
use dfn_candid::candid_one;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::ManageNeuronResponse;
use ic_nns_governance::pb::v1::{
    add_or_remove_node_provider::Change, manage_neuron::Command, proposal::Action,
    AddOrRemoveNodeProvider, ManageNeuron, NnsFunction, NodeProvider, Proposal,
};
use ic_nns_test_utils::governance::submit_external_update_proposal_allowing_error;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use slog::info;
use std::str::FromStr;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    env.ssh_keygen(ADMIN).expect("ssh-keygen failed");
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topo = env.topology_snapshot();

    let nns_node = topo.root_subnet().nodes().next().expect("no NNS nodes");
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);

    // We use this principal for node provider and node operator.
    let principal =
        PrincipalId::from_str("bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae")
            .unwrap();

    info!(logger, "Add the node provider principal to the registry.");
    let payload = AddOrRemoveNodeProvider {
        change: Some(Change::ToAdd(NodeProvider {
            id: Some(principal),
            reward_account: None,
        })),
    };
    let neuron_id = NeuronId {
        id: ic_nns_test_utils::ids::TEST_NEURON_1_ID,
    };
    let payload = ManageNeuron {
        neuron_id_or_subaccount: None,
        command: Some(Command::MakeProposal(Box::new(Proposal {
            title: Some("title".to_string()),
            summary: "summary".to_string(),
            url: "https://forum.dfinity.org/t/x/".to_string(),
            action: Some(Action::AddOrRemoveNodeProvider(payload)),
        }))),
        id: Some(neuron_id),
    };
    let proposer = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let resp: ManageNeuronResponse = block_on(governance_canister.update_from_sender(
        "manage_neuron",
        candid_one,
        payload,
        &proposer,
    ))
    .unwrap();
    info!(logger, "Adding node provider, response: {resp:?}");

    info!(logger, "Add the node operator principal to the registry.");
    let proposal_id = block_on(submit_external_update_proposal_allowing_error(
        &governance_canister,
        proposer,
        ic_nns_common::types::NeuronId(ic_nns_test_utils::ids::TEST_NEURON_1_ID),
        NnsFunction::AssignNoid,
        AddNodeOperatorPayload {
            node_operator_principal_id: Some(principal),
            node_allowance: 10,
            node_provider_principal_id: Some(principal),
            dc_id: Default::default(),
            rewardable_nodes: Default::default(),
            ipv6: None,
        },
        "Test title".to_string(),
        "".to_string(),
    ))
    .unwrap();

    info!(logger, "Adding node operator, proposal id: {proposal_id:?}",);

    // Make sure we have exactly 1 unassigned node.
    let num_unassigned_nodes = topo.unassigned_nodes().count();
    assert_eq!(
        num_unassigned_nodes, 1,
        "unexpected number of unassigned nodes"
    );

    // Stop the replica on the unassigned node, delete crypto keys, deploy the test key PEM, restart everything.
    let script = r#"set -e
        sudo systemctl stop ic-crypto-csp
        sudo systemctl stop ic-replica
        sudo rm /var/lib/ic/crypto/public_keys.pb
        sudo rm /var/lib/ic/crypto/sks_data.pb
        cat <<EOT >/var/lib/admin/test_key.pem
-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIKohpVANxO4xElQYXElAOXZHwJSVHERLE8feXSfoKwxX
oSMDIQBqgs2z86b+S5X9HvsxtE46UZwfDHtebwmSQWSIcKr2ew==
-----END PRIVATE KEY-----
EOT
        sudo chmod a+r /var/lib/admin/test_key.pem
        sudo systemctl start ic-crypto-csp
        sudo systemctl start ic-replica
        "#
    .to_string();

    let node = topo.unassigned_nodes().next().expect("no unassigned nodes");
    info!(logger, "unassigned node: {:?}", node.get_ip_addr());
    let s = node
        .block_on_ssh_session(ADMIN)
        .expect("Failed to establish SSH session");
    info!(logger, "Rotate keys on the unassigned node and restart it",);

    if let Err(e) = execute_bash_command(&s, script) {
        panic!("Script execution failed: {:?}", e);
    }

    // Wait until the node registers itself and updates the registry, then check that we have
    // exactly 2 unassigned nodes.
    let num_unassigned_nodes = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(3)),
    )
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(
        num_unassigned_nodes, 2,
        "unexpected number of unassigned nodes"
    );
}
