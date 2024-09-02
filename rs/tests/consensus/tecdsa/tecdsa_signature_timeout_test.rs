use std::time::Duration;

use anyhow::Result;

use canister_test::Canister;
use ic_agent::agent::{RejectCode, RejectResponse};
use ic_agent::AgentError;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing_with_timeout, get_public_key_with_logger, get_signature_with_logger,
    make_key_ids_for_all_schemes, scale_cycles, setup_without_ecdsa_on_nns,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
    util::{block_on, runtime_from_url, MessageCanister},
};

/// Tests whether a call to `sign_with_ecdsa`/`sign_with_schnorr` can be timed out when setting signature_request_timeout_ns.
fn test(env: TestEnv) {
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

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_without_ecdsa_on_nns)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
