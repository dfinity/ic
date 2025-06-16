// Set up a testnet containing:
//   one 1-node System and one 1-node Application subnets, one unassigned node, single API boundary node, single ic-gateway and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24 GiB of RAM, and 50 GiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create small --lifetime-mins=180 --output-dir=./small -- --test_tmpdir=./small
//
// The --output-dir=./small will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./small will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i small/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     nodes: [
//       {
//         id: y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae,
//         ipv6: 2a0b:21c0:4003:2:5034:46ff:fe3c:e76f
//       }
//     ],
//     subnet_id: 5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe,
//     subnet_type: application
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.small--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.small--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.small--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use std::{collections::BTreeMap, time::Duration};

use anyhow::Result;

use canister_test::Canister;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::{
    create_new_subnet_with_keys, get_master_public_key, run_chain_key_signature_test,
};
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm, IC_GATEWAY_VM_NAME},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            HasIcDependencies, HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot,
            IcNodeContainer, NnsCustomizations,
        },
    },
    util::{block_on, runtime_from_url, MessageCanister},
};
use ic_types::Height;
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_overall_timeout(Duration::from_secs(99999999))
        .with_timeout_per_test(Duration::from_secs(99999999))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let key_ids = [
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "key_1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "key_1".into(),
        }),
    ];
    let key_ids_vetkd = vec![
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Bip340Secp256k1,
            name: "key_1".into(),
        }),
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "key_1".into(),
        }),
        MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "key_1".into(),
        }),
    ];

    let dkg_interval = Height::from(499);
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .with_mainnet_config()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(40)
                .with_dkg_interval_length(dkg_interval),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(34)
                .with_dkg_interval_length(dkg_interval)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: key_ids_vetkd
                        .iter()
                        .cloned()
                        .map(|key_id| KeyConfig {
                            key_id,
                            pre_signatures_to_create_in_advance: 5,
                            max_queue_size: 20,
                        })
                        .collect(),
                    signature_request_timeout_ns: Some(1800000000000),
                    idkg_key_rotation_period_ms: Some(1209600000),
                }),
        )
        .with_unassigned_nodes(34)
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let ic_gateway = env.get_deployed_ic_gateway(IC_GATEWAY_VM_NAME).unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();

    let snapshot = env.topology_snapshot();
    let registry_version = snapshot.get_registry_version();
    let unassigned_node_ids = snapshot.unassigned_nodes().map(|n| n.node_id).collect();

    let nns_node = snapshot.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let app_subnet_id = snapshot.subnets().nth(1).unwrap().subnet_id;

    let logger = env.logger();
    info!(logger, "Creating new subnet with keys.");
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        key_ids
            .iter()
            .cloned()
            .map(|key_id| (key_id, app_subnet_id.get()))
            .collect(),
        env.get_initial_replica_version().unwrap(),
        &logger,
    ));

    let _snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();

    env.sync_with_prometheus_by_name("", Some(ic_gateway_domain.to_string()));

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    let pub_keys: BTreeMap<_, _> = key_ids_vetkd
        .iter()
        .cloned()
        .map(|key_id| {
            (
                key_id.clone(),
                get_master_public_key(&nns_canister, &key_id, &logger),
            )
        })
        .collect();

    loop {
        for (key_id, chain_key_pub_key) in &pub_keys {
            run_chain_key_signature_test(&nns_canister, &logger, key_id, chain_key_pub_key.clone());
        }
        std::thread::sleep(Duration::from_secs(60));
    }
}
