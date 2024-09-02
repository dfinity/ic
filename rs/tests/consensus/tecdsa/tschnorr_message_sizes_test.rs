/* tag::catalog[]
Title:: tSchnorr signature requests with different (and exceeding) message sizes

Goal:: Test whether signature requests of varying message sizes can be handled

Runbook::
. Setup:
    . Two app subnets, one with keys for all supported tSchnorr schemes enabled.
. Create one canister on each subnet.
. For each canister and subnet:
    . Send a signature request for a message of length 0
    . Send a signature request for a message of a length just below the limit (XNet vs Local subnet)
    . Send a signature request for a message of a length the exceeds the limit (it should fail)

Success::
. Signature requests succeed and fail as expected

end::catalog[] */

use anyhow::Result;

use ic_config::subnet_config::SCHNORR_SIGNATURE_FEE;
use ic_consensus_threshold_sig_system_test_utils::{
    get_public_key_with_logger, get_signature_with_logger, make_bip340_key_id, make_eddsa_key_id,
    verify_signature, DKG_INTERVAL, NUMBER_OF_NODES,
};
use ic_management_canister_types::MasterPublicKeyId;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use ic_types::Height;
use slog::{info, Logger};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

// Note that local subnets should actually support signature requests for messages of
// up to 10 MiB in size. However, the current ic.json5 enforces a 5 MiB limit on HTTP requests.
// In order to raise the local limit below, we need to either:
//      a) Support modifying the ic.json5 in system test setups
//      b) Write our own test canister that generates the signature request itself and sends
//         it to the management canister.
const LOCAL_LIMIT: usize = 5 * MIB;
const XNET_LIMIT: usize = 2 * MIB;

fn make_schnorr_key_ids_for_all_algorithms() -> Vec<MasterPublicKeyId> {
    vec![make_eddsa_key_id(), make_bip340_key_id()]
}

/// Creates one system subnet and two application subnets, the first one with schnorr keys enabled.
fn setup(env: TestEnv) {
    use ic_system_test_driver::driver::test_env_api::*;
    let size_limit: u64 = (2 * LOCAL_LIMIT).try_into().unwrap();
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES)
                .with_max_block_payload_size(size_limit)
                .with_max_ingress_message_size(size_limit)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: make_schnorr_key_ids_for_all_algorithms()
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            key_id,
                            pre_signatures_to_create_in_advance: 5,
                            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                }),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES)
                .with_max_block_payload_size(size_limit)
                .with_max_ingress_message_size(size_limit),
        )
        .setup_and_start(&env)
        .expect("Could not start IC!");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Failed to install NNS canisters");
}

fn test_message_sizes(subnet: SubnetSnapshot, limit: usize, log: &Logger) {
    let node = subnet.nodes().next().unwrap();
    let agent = node.with_default_agent(|agent| async move { agent });
    let msg_can = block_on(MessageCanister::new(&agent, node.effective_canister_id()));
    let cycles = SCHNORR_SIGNATURE_FEE;

    for key_id in &make_schnorr_key_ids_for_all_algorithms() {
        info!(log, "Getting the public key for {}", key_id);
        let public_key = block_on(async {
            get_public_key_with_logger(key_id, &msg_can, log)
                .await
                .unwrap()
        });

        let empty_message = vec![];
        info!(log, "Getting signature of empty message for {}", key_id);
        let signature = block_on(async {
            get_signature_with_logger(empty_message.clone(), cycles, key_id, &msg_can, log)
                .await
                .unwrap()
        });
        info!(log, "Verifying signature of empty message for {}", key_id);
        verify_signature(key_id, &empty_message, &public_key, &signature);

        // Subtract 1 KIB to account for message overhead in addition to payload
        let max_message = vec![0xabu8; limit - KIB];
        info!(
            log,
            "Getting signature of message with size {} for {}",
            max_message.len(),
            key_id
        );
        let signature = block_on(async {
            get_signature_with_logger(max_message.clone(), cycles, key_id, &msg_can, log)
                .await
                .unwrap()
        });
        info!(
            log,
            "Verifying signature of message with size {} for {}",
            max_message.len(),
            key_id
        );
        verify_signature(key_id, &max_message, &public_key, &signature);

        let exceeding_message = vec![0xabu8; limit];
        info!(
            log,
            "Getting signature of message with size {} for {}",
            exceeding_message.len(),
            key_id
        );
        let result = block_on(get_signature_with_logger(
            exceeding_message,
            cycles,
            key_id,
            &msg_can,
            log,
        ));
        assert!(result.is_err());
        info!(
            log,
            "Signature request failed successfully with: {:?}", result
        )
    }
}

fn test_xnet_limit(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let mut subnets = topology_snapshot.subnets().skip(2);
    let app_subnet = subnets.next().unwrap();

    info!(log, "Testing tSchnorr message sizes using XNet");
    test_message_sizes(app_subnet, XNET_LIMIT, &log);
}

fn test_local_limit(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let mut subnets = topology_snapshot.subnets().skip(1);
    let schnorr_subnet = subnets.next().unwrap();

    info!(log, "Testing tSchnorr message sizes using local subnet");
    test_message_sizes(schnorr_subnet, LOCAL_LIMIT, &log);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_xnet_limit))
        .add_test(systest!(test_local_limit))
        .execute_from_args()?;
    Ok(())
}
