use slog::info;

use crate::ckbtc::lib::install_bitcoin_canister_with_network;
use candid::{Decode, Encode};
use canister_test::Canister;
use ic_agent::Agent;
use ic_btc_interface::{Config as BitcoinConfig, Flag, Network, SetConfigRequest};
use ic_config::execution_environment::{BITCOIN_MAINNET_CANISTER_ID, BITCOIN_TESTNET_CANISTER_ID};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::bitcoin::BitcoinNetwork;
use ic_nns_test_utils::governance::{
    bitcoin_set_config_by_proposal, invalid_bitcoin_set_config_by_proposal,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        test_env::{SshKeyGen, TestEnv},
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    nns::{get_governance_canister, vote_execute_proposal_assert_failed},
    util::{block_on, runtime_from_url},
};
use std::str::FromStr;

pub fn config(env: TestEnv) {
    env.ssh_keygen().expect("ssh-keygen failed");
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .use_specified_ids_allocation_range()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let agent = nns_node.build_default_agent();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    info!(logger, "Installing NNS canisters on the root subnet...");
    NnsInstallationBuilder::new()
        .at_ids()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(&logger, "NNS canisters installed successfully.");

    info!(&logger, "Installing the Bitcoin canisters...");
    block_on(async {
        install_bitcoin_canister_with_network(&nns, &logger, Network::Testnet).await;
        install_bitcoin_canister_with_network(&nns, &logger, Network::Mainnet).await;
    });
    info!(&logger, "Bitcoin canisters installed successfully.");

    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::Mainnet].into_iter() {
        // Assert that, initially, the Bitcoin API is enabled and the stability threshold is 6.
        block_on(async {
            let config = get_bitcoin_config(&agent, network).await;
            assert_eq!(config.stability_threshold, 6);
            assert_eq!(config.api_access, Flag::Enabled);
        });

        const NEW_STABILITY_THRESHOLD: u128 = 17;
        const NEW_API_ACCESS_FLAG: Flag = Flag::Disabled;

        // Submit (and execute) an invalid proposal to update the settings of the Bitcoin canisters.
        let invalid_proposal_id = block_on(async {
            invalid_bitcoin_set_config_by_proposal(
                &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
                SetConfigRequest {
                    stability_threshold: Some(NEW_STABILITY_THRESHOLD),
                    api_access: Some(NEW_API_ACCESS_FLAG),
                    ..Default::default()
                },
            )
            .await
        });
        let governance_canister = get_governance_canister(&nns);
        let error = "Couldn't execute NNS function through proposal".to_string();
        block_on(async {
            vote_execute_proposal_assert_failed(&governance_canister, invalid_proposal_id, error)
                .await;
        });

        // Submit (and execute) a proposal to update the settings of the Bitcoin canisters.
        let _proposal_id = block_on(async {
            bitcoin_set_config_by_proposal(
                network,
                &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
                SetConfigRequest {
                    stability_threshold: Some(NEW_STABILITY_THRESHOLD),
                    api_access: Some(NEW_API_ACCESS_FLAG),
                    ..Default::default()
                },
            )
            .await
        });

        // Check that the config has been updated per the proposal.
        block_on(async {
            // We retry several times in case the proposal took some time to be executed.
            ic_system_test_driver::retry_with_msg_async!(
                "check if the bitcoin config has been updated per proposal",
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    let config = get_bitcoin_config(&agent, network).await;
                    info!(&logger, "Bitcoin config: {:?}", config);

                    if config.stability_threshold == NEW_STABILITY_THRESHOLD
                        && config.api_access == NEW_API_ACCESS_FLAG
                    {
                        Ok(())
                    } else {
                        anyhow::bail!("Bitcoin config not updated as expected.")
                    }
                }
            )
            .await
            .unwrap();
        });
    }
}

async fn get_bitcoin_config(agent: &Agent, network: BitcoinNetwork) -> BitcoinConfig {
    let canister_id = match network {
        BitcoinNetwork::Mainnet => BITCOIN_MAINNET_CANISTER_ID,
        BitcoinNetwork::Testnet => BITCOIN_TESTNET_CANISTER_ID,
    };

    Decode!(
        agent
            .query(
                &candid::Principal::from_str(canister_id).unwrap(),
                "get_config"
            )
            .with_arg(Encode!().unwrap())
            .call()
            .await
            .unwrap()
            .as_slice(),
        BitcoinConfig
    )
    .unwrap()
}
