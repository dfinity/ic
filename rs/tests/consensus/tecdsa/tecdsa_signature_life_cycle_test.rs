use std::time::Duration;

use anyhow::{bail, Result};

use canister_test::Canister;
use ic_agent::agent::{RejectCode, RejectResponse};
use ic_agent::AgentError;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_consensus_threshold_sig_system_test_utils::{
    create_new_subnet_with_keys, empty_subnet_update, enable_chain_key_signing,
    execute_update_subnet_proposal, get_public_key_and_test_signature, get_public_key_with_retries,
    get_signature_with_logger, make_bip340_key_id, make_ecdsa_key_id, make_eddsa_key_id,
    scale_cycles, setup_without_ecdsa_on_nns,
};
use ic_management_canister_types::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
        },
    },
    nns::{self, get_subnet_list_from_registry},
    systest,
    util::{block_on, runtime_from_url, MessageCanister, MetricsFetcher},
};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::info;
use std::collections::BTreeMap;
use std::collections::HashSet;

const IDKG_PAYLOAD_METRICS: &str = "idkg_payload_metrics";
const XNET_RESHARE_AGREEMENTS: &str = "xnet_reshare_agreements";

/// Life cycle test requires more time
const LIFE_CYCLE_OVERALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const LIFE_CYCLE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(11 * 60);

fn test(env: TestEnv) {
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
                    IDkgKeyError(\"Requested unknown threshold key: {}, existing keys: {}\")",
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
                    IDkgKeyError(\"Requested unknown or signing disabled threshold key: {}, \
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
                                IDkgKeyError(\"Requested unknown or signing disabled threshold key: {}, \
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
                IDKG_PAYLOAD_METRICS, key_id, XNET_RESHARE_AGREEMENTS,
            );
            let metrics = MetricsFetcher::new(app_subnet.nodes(), vec![metric_with_label.clone()]);
            ic_system_test_driver::retry_with_msg_async!(
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

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_without_ecdsa_on_nns)
        .with_overall_timeout(LIFE_CYCLE_OVERALL_TIMEOUT)
        .with_timeout_per_test(LIFE_CYCLE_PER_TEST_TIMEOUT)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
