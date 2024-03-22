/* tag::catalog[]
Title:: Threshold ECDSA signature test

Goal:: Verify if the threshold ECDSA feature is working properly by exercising
the ECDSA public APIs.

Runbook::
. start a subnet with ecdsa feature enabled.
. get public key of a canister
. have the canister sign a message and get the signature
. verify if the signature is correct with respect to the public key

Success:: An agent can complete the signing process and result signature verifies.

end::catalog[] */

use std::collections::HashSet;
use std::time::Duration;

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer};
use crate::nns::get_subnet_list_from_registry;
use crate::tecdsa::{
    create_new_subnet_with_keys, empty_subnet_update, enable_ecdsa_signing,
    execute_update_subnet_proposal, get_public_key_with_retries, verify_signature, DKG_INTERVAL,
};
use crate::util::*;
use canister_test::{Canister, Cycles};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    AgentError,
};
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use itertools::Itertools;
use registry_canister::mutations::do_create_subnet::EcdsaKeyRequest;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::info;

use super::{
    enable_ecdsa_signing_with_timeout, enable_ecdsa_signing_with_timeout_and_rotation_period,
    get_public_key_with_logger, get_signature_with_logger, make_key, KEY_ID1, KEY_ID2,
};

/// [EXC-1168] Flag to turn on cost scaling according to a subnet replication factor.
const USE_COST_SCALING_FLAG: bool = true;
const NUMBER_OF_NODES: usize = 4;

const ECDSA_KEY_TRANSCRIPT_CREATED: &str = "consensus_ecdsa_key_transcript_created";

/// Life cycle test requires more time
pub const LIFE_CYCLE_OVERALL_TIMEOUT: Duration = Duration::from_secs(14 * 60);
pub const LIFE_CYCLE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Creates one system subnet without ECDSA enabled and one application subnet
/// with ECDSA enabled.
pub fn config_without_ecdsa_on_nns(test_env: TestEnv) {
    use crate::driver::test_env_api::*;
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .with_unassigned_nodes(NUMBER_OF_NODES)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");
    test_env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    test_env
        .topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    let nns_node = test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &test_env)
        .expect("Failed to install NNS canisters");
}

/// Creates one system subnet and two application subnets.
pub fn config(test_env: TestEnv) {
    use crate::driver::test_env_api::*;
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .with_unassigned_nodes(NUMBER_OF_NODES)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");
    test_env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    test_env
        .topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    let nns_node = test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &test_env)
        .expect("Failed to install NNS canisters");
}

// TODO(EXC-1168): cleanup after cost scaling is fully implemented.
fn scale_cycles(cycles: Cycles) -> Cycles {
    match USE_COST_SCALING_FLAG {
        false => cycles,
        true => {
            // Subnet is constructed with `NUMBER_OF_NODES`, see `config()` and `config_without_ecdsa_on_nns()`.
            (cycles * NUMBER_OF_NODES) / SMALL_APP_SUBNET_MAX_SIZE
        }
    }
}

pub fn test_threshold_ecdsa_signature_same_subnet(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID1)],
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature that
/// is verifiable with the result from `get_ecdsa_public_key` when the subnet
/// sending the request is different than the subnet responsible for signing
/// with the key.
pub fn test_threshold_ecdsa_signature_from_other_subnet(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let (app_subnet_1, app_subnet_2) = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .tuples()
        .next()
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let node_from_app_subnet_1 = app_subnet_1.nodes().next().unwrap();
    let agent_for_app_subnet_1 = node_from_app_subnet_1.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_subnet_2.subnet_id,
            vec![make_key(KEY_ID2)],
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(
            &agent_for_app_subnet_1,
            node_from_app_subnet_1.effective_canister_id(),
        )
        .await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` fails when not enough cycles are
/// sent.
pub fn test_threshold_ecdsa_signature_fails_without_cycles(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID1)],
            &log,
        )
        .await;

        // Cycles are only required for application subnets.
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];

        info!(log, "Getting the public key to make sure the subnet has the latest registry changes and routing of ECDSA messages is working");
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();

        info!(log, "Checking that signature request fails");
        let error = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: format!(
                    "sign_with_ecdsa request sent with {} cycles, but {} cycles are required.",
                    scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
                    scale_cycles(ECDSA_SIGNATURE_FEE),
                ),
                error_code: None
            })
        )
    });
}

/// Tests that an ECDSA signature request coming from the NNS succeeds even when
/// there are no cycles sent with the request.
pub fn test_threshold_ecdsa_signature_from_nns_without_cycles(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID2)],
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID2),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

pub fn test_threshold_ecdsa_life_cycle(env: TestEnv) {
    let topology_snapshot = &env.topology_snapshot();
    let log = &env.logger();
    let app_subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("Could not find application subnet.");
    let nns_node = topology_snapshot.root_subnet().nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();
    block_on(async move {
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

        info!(
            log,
            "1. Verifying that signature and public key requests fail before signing is enabled."
        );

        let message_hash = [0xabu8; 32];
        assert_eq!(
            get_public_key_with_retries(make_key(KEY_ID2), &msg_can, log, 20)
                .await
                .unwrap_err(),
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Unable to route management canister request ecdsa_public_key: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys: []\")".to_string(),
                error_code: None,
            })
        );
        assert_eq!(
            get_signature_with_logger(
                &message_hash,
                scale_cycles(ECDSA_SIGNATURE_FEE),
                make_key(KEY_ID2),
                &msg_can,
                log,
            )
            .await
            .unwrap_err(),
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Unable to route management canister request sign_with_ecdsa: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys with signing enabled: []\")".to_string(),
                error_code: None,
            })
        );

        info!(log, "2. Enabling signing and verifying that it works.");

        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID2)],
            log,
        )
        .await;

        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);

        info!(
            log,
            "3. Sharing key with new app subnet, disabling signing on old app subnet, and then verifying signing no longer works."
        );

        let registry_client = RegistryCanister::new_with_query_timeout(
            vec![nns_node.get_public_url()],
            Duration::from_secs(10),
        );
        let original_subnets: HashSet<_> = get_subnet_list_from_registry(&registry_client)
            .await
            .into_iter()
            .collect();
        let unassigned_node_ids: Vec<_> = topology_snapshot
            .unassigned_nodes()
            .map(|n| n.node_id)
            .collect();

        let replica_version = crate::nns::get_software_version_from_snapshot(&nns_node)
            .await
            .expect("could not obtain replica software version");
        create_new_subnet_with_keys(
            &governance,
            unassigned_node_ids,
            vec![EcdsaKeyRequest {
                key_id: make_key(KEY_ID2),
                subnet_id: Some(app_subnet.subnet_id.get()),
            }],
            replica_version,
            log,
        )
        .await;
        let new_subnets: HashSet<_> = get_subnet_list_from_registry(&registry_client)
            .await
            .into_iter()
            .collect();
        let new_subnet_id = *new_subnets
            .symmetric_difference(&original_subnets)
            .next()
            .unwrap();

        let disable_signing_payload = UpdateSubnetPayload {
            subnet_id: app_subnet.subnet_id,
            ecdsa_key_signing_disable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(
            &governance,
            disable_signing_payload,
            "Disable ECDSA signing",
            log,
        )
        .await;

        // Try several times because signing won't fail until new registry data
        // is picked up.
        let mut sig_result;
        for _ in 0..20 {
            sig_result = get_signature_with_logger(
                &message_hash,
                scale_cycles(ECDSA_SIGNATURE_FEE),
                make_key(KEY_ID2),
                &msg_can,
                log,
            )
            .await;
            if let Err(sig_err) = sig_result {
                assert_eq!(
                    sig_err,
                    AgentError::CertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterReject,
                        reject_message: "Unable to route management canister request sign_with_ecdsa: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys with signing enabled: []\")".to_string(),
                        error_code: None
                    })
                );
                break;
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        info!(log, "4. Enabling signing on new subnet then verifying that signing works and public key is unchanged.");

        let proposal_payload = UpdateSubnetPayload {
            subnet_id: new_subnet_id,
            ecdsa_key_signing_enable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(&governance, proposal_payload, "Enable ECDSA signing", log)
            .await;

        let topology_snapshot = env
            .topology_snapshot()
            .block_for_newer_registry_version()
            .await
            .expect("Could not obtain updated registry.");
        let new_subnet = topology_snapshot
            .subnets()
            .find(|s| s.subnet_id == new_subnet_id)
            .expect("Could not find newly created subnet.");
        new_subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap());

        let new_public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, log)
            .await
            .unwrap();
        assert_eq!(public_key, new_public_key);
        let new_signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &new_signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` can be timed out when setting signature_request_timeout_ns.
pub fn test_threshold_ecdsa_signature_timeout(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing_with_timeout(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID1)],
            Some(Duration::from_secs(1)),
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        // Get the public key first to make sure ECDSA is working
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();
        let error = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Signature request expired".to_string(),
                error_code: None
            })
        )
    });
}

/// Tests whether ECDSA key transcript is correctly reshared when crypto keys are rotated
/// using the test settings below:
/// - DKG interval is set to 19, which roughly takes 20 or so seconds.
/// - Keys are rotated every 50 seconds, which should take more than 2 DKG intervals.
pub fn test_threshold_ecdsa_key_rotation(test_env: TestEnv) {
    let log = test_env.logger();
    let topology = test_env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();

    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing_with_timeout_and_rotation_period(
            &governance,
            app_subnet.subnet_id,
            vec![make_key(KEY_ID1)],
            None,
            Some(Duration::from_secs(50)),
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        // Get the public key first to make sure ECDSA is working
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();

        let mut count = 0;
        let mut created = 0;
        let metric_with_label = format!(
            "{}{{key_id=\"{}\"}}",
            ECDSA_KEY_TRANSCRIPT_CREATED,
            make_key(KEY_ID1)
        );
        let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
        loop {
            match metrics.fetch::<u64>().await {
                Ok(val) => {
                    created = val[&metric_with_label][0];
                    if created > 1 {
                        break;
                    }
                }
                Err(err) => {
                    info!(log, "Could not connect to metrics yet {:?}", err);
                }
            }
            count += 1;
            // Break after 200 tries
            if count > 200 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        if created <= 1 {
            panic!("Failed to observe key transcript being reshared more than once");
        }
    });
}
