/* tag::catalog[]
Title:: Threshold signature test

Goal:: Verify if the threshold signature feature is working properly by exercising
the chain key public APIs.

Runbook::
. start a subnet with chain key feature enabled.
. get public key of a canister
. have the canister sign a message and get the signature
. verify if the signature is correct with respect to the public key

Success:: An agent can complete the signing process and result signature verifies.

end::catalog[] */

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    retry_async, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, READY_WAIT_TIMEOUT,
    RETRY_BACKOFF,
};
use crate::nns::{self, get_subnet_list_from_registry};
use crate::retry_with_msg_async;
use crate::tecdsa::{
    create_new_subnet_with_keys, empty_subnet_update, enable_chain_key_signing,
    execute_update_subnet_proposal, get_public_key_with_retries, make_bip340_key_id,
    make_ecdsa_key_id, make_eddsa_key_id, scale_cycles, DKG_INTERVAL, NUMBER_OF_NODES,
};
use crate::util::*;
use anyhow::bail;
use canister_test::{Canister, Cycles};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    AgentError,
};
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_management_canister_types::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use itertools::Itertools;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::info;

use super::{
    enable_chain_key_signing_with_timeout,
    enable_chain_key_signing_with_timeout_and_rotation_period, get_public_key_and_test_signature,
    get_public_key_with_logger, get_signature_with_logger, make_key_ids_for_all_schemes,
};

const ECDSA_KEY_TRANSCRIPT_CREATED: &str = "consensus_ecdsa_key_transcript_created";
const ECDSA_PAYLOAD_METRICS: &str = "ecdsa_payload_metrics";
const XNET_RESHARE_AGREEMENTS: &str = "xnet_reshare_agreements";

/// Life cycle test requires more time
pub const LIFE_CYCLE_OVERALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const LIFE_CYCLE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(11 * 60);

/// Creates one system subnet without signing enabled and one application subnet
/// with signing enabled.
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
    let key_ids = make_key_ids_for_all_schemes();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_chain_key_signing(&governance, app_subnet.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        for key_id in &key_ids {
            get_public_key_and_test_signature(key_id, &msg_can, false, &log)
                .await
                .expect("Should successfully create and verify the signature");
        }
    });
}

/// Tests whether a call to `sign_with_ecdsa`/`sign_with_schnorr` is responded with a signature that
/// is verifiable with the result from `get_ecdsa_public_key`/`get_schnorr_public_key` when the subnet
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
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing(&governance, app_subnet_2.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(
            &agent_for_app_subnet_1,
            node_from_app_subnet_1.effective_canister_id(),
        )
        .await;

        for key_id in &key_ids {
            get_public_key_and_test_signature(key_id, &msg_can, false, &log)
                .await
                .expect("Should successfully create and verify the signature");
        }
    });
}

/// Tests whether a call to `sign_with_ecdsa`/`sign_with_schnorr` fails when not enough cycles are
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
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing(&governance, app_subnet.subnet_id, key_ids.clone(), &log).await;

        // Cycles are only required for application subnets.
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = vec![0xabu8; 32];
        for key_id in key_ids {
            info!(
                log,
                "Getting the public key to make sure the subnet has the latest registry changes \
            and routing of Chain key messages is working"
            );
            let _public_key = get_public_key_with_logger(&key_id, &msg_can, &log)
                .await
                .unwrap();

            info!(log, "Checking that signature request fails");
            let error = get_signature_with_logger(
                message_hash.clone(),
                scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
                &key_id,
                &msg_can,
                &log,
            )
            .await
            .unwrap_err();
            let method_name = match key_id {
                MasterPublicKeyId::Ecdsa(_) => "sign_with_ecdsa",
                MasterPublicKeyId::Schnorr(_) => "sign_with_schnorr",
            };
            assert_eq!(
                error,
                AgentError::CertifiedReject(RejectResponse {
                    reject_code: RejectCode::CanisterReject,
                    reject_message: format!(
                        "{} request sent with {} cycles, but {} cycles are required.",
                        method_name,
                        scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
                        scale_cycles(ECDSA_SIGNATURE_FEE),
                    ),
                    error_code: None
                })
            )
        }
    });
}

/// Tests that a threshold signature request coming from the NNS succeeds even when
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
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing(&governance, app_subnet.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        for key_id in &key_ids {
            let _public_key = get_public_key_and_test_signature(key_id, &msg_can, true, &log)
                .await
                .unwrap();
        }
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
        let key_id1 = make_ecdsa_key_id();
        let key_id2 = make_eddsa_key_id();
        let key_id3 = make_bip340_key_id();
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        let initial_key_ids = vec![key_id1.clone(), key_id2.clone()];
        let initial_key_ids_as_string = format!("[{}, {}]", key_id1, key_id2);

        enable_chain_key_signing(
            &governance,
            app_subnet.subnet_id,
            initial_key_ids.clone(),
            log,
        )
        .await;

        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

        info!(
            log,
            "0. Verifying that signature and public key requests succeed for enabled key_ids."
        );
        let mut public_keys = BTreeMap::new();
        for key_id in &initial_key_ids {
            let public_key = get_public_key_and_test_signature(key_id, &msg_can, false, log)
                .await
                .expect(
                    "Should successfully create and verify the signature for the pre-existing key",
                );
            public_keys.insert(key_id.clone(), public_key);
        }

        info!(
            log,
            "1. Verifying that signature and public key requests fail before signing is enabled."
        );

        let message_hash = vec![0xabu8; 32];
        assert_eq!(
            get_public_key_with_retries(&key_id3, &msg_can, log, 20)
                .await
                .unwrap_err(),
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: format!(
                    "Unable to route management canister request schnorr_public_key: \
                    IDkgKeyError(\"Requested unknown iDKG key: {}, existing keys: {}\")",
                    key_id3, initial_key_ids_as_string,
                ),
                error_code: None,
            })
        );
        assert_eq!(
            get_signature_with_logger(
                message_hash.clone(),
                scale_cycles(ECDSA_SIGNATURE_FEE),
                &key_id3,
                &msg_can,
                log,
            )
            .await
            .unwrap_err(),
            AgentError::CertifiedReject(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: format!(
                    "Unable to route management canister request sign_with_schnorr: \
                    IDkgKeyError(\"Requested unknown iDKG key: {}, \
                    existing keys with signing enabled: {}\")",
                    key_id3, initial_key_ids_as_string,
                ),
                error_code: None,
            })
        );

        info!(log, "2. Enabling signing and verifying that it works.");

        let key_ids = vec![key_id3.clone(), key_id2.clone(), key_id1.clone()];
        enable_chain_key_signing(&governance, app_subnet.subnet_id, key_ids.clone(), log).await;

        for key_id in &key_ids {
            let public_key = get_public_key_and_test_signature(key_id, &msg_can, false, log)
                .await
                .expect(
                    "Should successfully create and verify the signature after enabling signing",
                );
            if let Some(previous_key) = public_keys.get(key_id) {
                assert_eq!(previous_key, &public_key);
            } else {
                public_keys.insert(key_id.clone(), public_key);
            }
        }

        info!(
            log,
            "3. Sharing keys with new app subnet, \
            disabling signing on old app subnet, \
            and then verifying signing no longer works."
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

        let replica_version = nns::get_software_version_from_snapshot(&nns_node)
            .await
            .expect("could not obtain replica software version");
        create_new_subnet_with_keys(
            &governance,
            unassigned_node_ids,
            key_ids
                .iter()
                .map(|key_id| (key_id.clone(), app_subnet.subnet_id.get()))
                .collect(),
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
            chain_key_signing_disable: Some(key_ids.clone()),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(
            &governance,
            disable_signing_payload,
            "Disable chain key signing",
            log,
        )
        .await;

        // Try several times because signing won't fail until new registry data
        // is picked up.
        let mut sig_result;
        for key_id in &key_ids {
            for _ in 0..20 {
                sig_result = get_signature_with_logger(
                    message_hash.clone(),
                    scale_cycles(ECDSA_SIGNATURE_FEE),
                    key_id,
                    &msg_can,
                    log,
                )
                .await;
                let method_name = match key_id {
                    MasterPublicKeyId::Ecdsa(_) => "sign_with_ecdsa",
                    MasterPublicKeyId::Schnorr(_) => "sign_with_schnorr",
                };
                if let Err(sig_err) = sig_result {
                    assert_eq!(
                        sig_err,
                        AgentError::CertifiedReject(RejectResponse {
                            reject_code: RejectCode::CanisterReject,
                            reject_message: format!(
                                "Unable to route management canister request {}: \
                                IDkgKeyError(\"Requested unknown iDKG key: {}, \
                                existing keys with signing enabled: []\")",
                                method_name, key_id
                            ),
                            error_code: None
                        })
                    );
                    break;
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        info!(
            log,
            "4. Enabling signing on new subnet \
            then verifying that signing works and public key is unchanged."
        );

        let proposal_payload = UpdateSubnetPayload {
            subnet_id: new_subnet_id,
            chain_key_signing_enable: Some(key_ids.clone()),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(
            &governance,
            proposal_payload,
            "Enable chain key signing",
            log,
        )
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

        // Note: `await_status_is_healthy` is underneath using `reqwest::blocking" which should
        // _not_ be used in an async runtime, which is the case here. As recommended by the reqwest
        // documentation (https://docs.rs/reqwest/latest/reqwest/blocking/index.html) we are
        // wrapping `tokio::task::spawn_blocking` around the call that need to be blocked.
        // TODO: Consider making `HasPublicApiUrl::status` non-blocking.
        let _ = tokio::task::spawn_blocking(move || {
            new_subnet
                .nodes()
                .for_each(|node| node.await_status_is_healthy().unwrap())
        })
        .await;

        for key_id in &key_ids {
            let new_public_key = get_public_key_and_test_signature(key_id, &msg_can, false, log)
                .await
                .expect(
                    "Should still be able to create and verify the signature \
                    for the pre-existing key",
                );
            assert_eq!(public_keys.get(key_id).unwrap(), &new_public_key);

            // Reshare agreement on original App subnet should be purged
            let metric_with_label = format!(
                "{}{{key_id=\"{}\",type=\"{}\"}}",
                ECDSA_PAYLOAD_METRICS, key_id, XNET_RESHARE_AGREEMENTS,
            );
            let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
            retry_with_msg_async!(
                format!(
                    "check if number of reshare agreements on subnet {} is zero",
                    app_subnet.subnet_id,
                ),
                log,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match metrics.fetch::<u64>().await {
                        Ok(val) => {
                            info!(log, "metrics: {:?}", val);
                            for agreements in &val[&metric_with_label] {
                                if *agreements != 0 {
                                    panic!("Number of reshare agreements is {}", agreements)
                                }
                            }
                            Ok(())
                        }
                        Err(err) => {
                            bail!("Could not connect to metrics yet {:?}", err);
                        }
                    }
                }
            )
            .await
            .expect("Unable to fetch the metrics in time")
        }
    });
}

/// Tests whether a call to `sign_with_ecdsa`/`sign_with_schnorr` can be timed out when setting signature_request_timeout_ns.
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
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing_with_timeout(
            &governance,
            app_subnet.subnet_id,
            key_ids.clone(),
            Some(Duration::from_secs(1)),
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = vec![0xabu8; 32];
        for key_id in key_ids {
            // Get the public key first to make sure feature is working
            let _public_key = get_public_key_with_logger(&key_id, &msg_can, &log)
                .await
                .unwrap();
            let error = get_signature_with_logger(
                message_hash.clone(),
                scale_cycles(ECDSA_SIGNATURE_FEE),
                &key_id,
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
        }
    });
}

/// Tests whether chain key transcripts are correctly reshared when crypto keys are rotated
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
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing_with_timeout_and_rotation_period(
            &governance,
            app_subnet.subnet_id,
            key_ids.clone(),
            None,
            Some(Duration::from_secs(50)),
            &log,
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        // Get the public key first to make sure feature is working
        for key_id in &key_ids {
            let _public_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .unwrap();

            let mut count = 0;
            let mut created = 0;
            let metric_with_label =
                format!("{}{{key_id=\"{}\"}}", ECDSA_KEY_TRANSCRIPT_CREATED, key_id);
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
        }
    });
}
