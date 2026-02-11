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
    DKG_INTERVAL, NUMBER_OF_NODES, generate_dummy_schnorr_signature_with_logger,
    get_public_key_for_canister_id_with_logger, get_schnorr_signature_with_logger,
    make_bip340_key_id, make_eddsa_key_id, verify_signature,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use ic_types::{CanisterId, Cycles, Height};
use slog::{Logger, info};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

enum LimitType {
    Local,
    XNet,
}
struct Limit {
    limit_type: LimitType,
    size: usize,
}

const LOCAL_LIMIT: Limit = Limit {
    limit_type: LimitType::Local,
    size: 10 * MIB,
};
const XNET_LIMIT: Limit = Limit {
    limit_type: LimitType::XNet,
    size: 2 * MIB,
};

fn make_schnorr_key_ids_for_all_algorithms() -> Vec<MasterPublicKeyId> {
    vec![make_eddsa_key_id(), make_bip340_key_id()]
}

/// Creates one system subnet and two application subnets, the first one with schnorr keys enabled.
fn setup(env: TestEnv) {
    use ic_system_test_driver::driver::test_env_api::*;
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: make_schnorr_key_ids_for_all_algorithms()
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            key_id,
                            pre_signatures_to_create_in_advance: Some(5),
                            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                }),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
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

/// Requests a signature, either from the message canister or the signer canister,
/// depending on the limit type. If the limit type is `Local`, then we use the
/// signer canister as it can generate larger signatures than sending an ingress message
/// to the message canister.
async fn gen_message_and_get_signature_depending_on_limit(
    limit_type: &LimitType,
    message_size: usize,
    cycles: Cycles,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    sig_can: &SignerCanister<'_>,
    log: &Logger,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let MasterPublicKeyId::Schnorr(key_id) = key_id else {
        // TODO(CON-1522): Create tests for ECDSA and VetKD key ids.
        panic!("Unexpected key id type: {key_id}");
    };

    let message = dummy_message(message_size);

    let signature = match limit_type {
        LimitType::Local => generate_dummy_schnorr_signature_with_logger(
            message.len(),
            0,
            0,
            key_id,
            None,
            sig_can,
            log,
        )
        .await
        .map(|sig| sig.signature),

        LimitType::XNet => {
            get_schnorr_signature_with_logger(message.clone(), cycles, key_id, msg_can, log).await
        }
    }
    .map_err(|err| err.to_string())?;

    Ok((message, signature))
}

/// Returns the dummy message that the signer canister uses to sign messages.
fn dummy_message(message_size: usize) -> Vec<u8> {
    vec![1; message_size]
}

fn test_message_sizes(subnet: SubnetSnapshot, limit: Limit, log: &Logger) {
    let node = subnet.nodes().next().unwrap();
    let agent = node.with_default_agent(|agent| async move { agent });
    let msg_can = block_on(MessageCanister::new(&agent, node.effective_canister_id()));
    let sig_can = block_on(SignerCanister::new(&agent, node.effective_canister_id()));
    let cycles = SCHNORR_SIGNATURE_FEE;

    for key_id in &make_schnorr_key_ids_for_all_algorithms() {
        info!(log, "Getting the public key for {}", key_id);
        // With a Local limit, it is the signer canister that generates the signature, so we need
        // to get the public key from the latter. Otherwise, we get it from the message canister.
        let public_key = block_on(get_public_key_for_canister_id_with_logger(
            CanisterId::try_from_principal_id(match limit.limit_type {
                LimitType::Local => sig_can.canister_id().into(),
                LimitType::XNet => msg_can.canister_id().into(),
            })
            .unwrap(),
            key_id,
            &msg_can,
            log,
        ))
        .unwrap();

        let empty_message_size = 0;
        info!(log, "Getting signature of empty message for {}", key_id);
        let (empty_message, signature) =
            block_on(gen_message_and_get_signature_depending_on_limit(
                &limit.limit_type,
                empty_message_size,
                cycles,
                key_id,
                &msg_can,
                &sig_can,
                log,
            ))
            .unwrap();
        info!(log, "Verifying signature of empty message for {}", key_id);
        verify_signature(key_id, &empty_message, &public_key, &signature);

        // Subtract 1 KIB to account for message overhead in addition to payload
        let max_message_size = limit.size - KIB;
        info!(
            log,
            "Getting signature of message with size {} for {}", max_message_size, key_id
        );
        let (max_message, signature) = block_on(gen_message_and_get_signature_depending_on_limit(
            &limit.limit_type,
            max_message_size,
            cycles,
            key_id,
            &msg_can,
            &sig_can,
            log,
        ))
        .unwrap();
        info!(
            log,
            "Verifying signature of message with size {} for {}", max_message_size, key_id
        );
        verify_signature(key_id, &max_message, &public_key, &signature);

        let exceeding_message_size = limit.size;
        info!(
            log,
            "Getting signature of exceeding message with size {} for {}",
            exceeding_message_size,
            key_id
        );
        let result = block_on(gen_message_and_get_signature_depending_on_limit(
            &limit.limit_type,
            exceeding_message_size,
            cycles,
            key_id,
            &msg_can,
            &sig_can,
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
