/* tag::catalog[]

Title:: Rotate ECDSA iDKG keys

Goal:: Ensure that we can rotate iDKG keys in the registry and timing assumptions hold.

Description::
We deploy an IC NNS without ECDSA keys. Then we enable ECDSA signing and key rotations. We wait until
key timestamps are updated for the first time. Wait until keys are rotated once for each node.

Runbook::
. We deploy an IC NNS without ECDSA keys.
. Enable ECDSA signing with key rotations and get the ECDSA verifying key.
. Wait until key timestamps are updated for the first time.
. Wait until keys are rotated once for each node, and verify timestamps.
. Run through ECDSA signature test

Success::
. Key timestamps are correctly initialized for all nodes
. Keys are correctly rotated once for each node
. Timing assumptions (delta, gamma) are kept at all times
. ECDSA signing still works

end::catalog[] */

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::utils::subnet_recovery::{enable_ecdsa_on_nns, run_ecdsa_signature_test};
use crate::util::{block_on, get_nns_node, MessageCanister};
use anyhow::bail;
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::KeyPurpose;
use ic_types::Height;
use slog::{info, warn, Logger};

use super::utils::rw_message::install_nns_and_message_canisters;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 3;

pub fn setup(env: TestEnv) {
    env.ensure_group_setup_created();

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_message_canisters(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let root_subnet_id = topology_snapshot.root_subnet_id();
    let nns_node = get_nns_node(&topology_snapshot);
    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );
    let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    let delta = Some(Duration::from_secs(180));
    let gamma = delta.map(|d| d.div_f64(SUBNET_SIZE as f64).mul_f64(0.85));

    // Timestamps should be none before ECDSA is turned on
    topology_snapshot.root_subnet().nodes().for_each(|n| {
        let r = block_on(get_public_key(&registry_canister, n.node_id));
        match r {
            Ok((k, ver)) => {
                print_key(&logger, n.node_id, &k, ver);
                assert!(k.timestamp.is_none());
            }
            Err(e) => info!(logger, "{}: {}", n.node_id, e),
        }
    });

    let mut init_keys: HashMap<NodeId, PublicKey> = HashMap::new();
    let mut rotated_keys: HashMap<NodeId, PublicKey> = HashMap::new();

    let pub_key = enable_ecdsa_on_nns(&nns_node, &nns_canister, root_subnet_id, delta, &logger);

    let topology_snapshot =
        block_on(topology_snapshot.block_for_min_registry_version(RegistryVersion::from(3)))
            .unwrap();

    // wait until all keys are registered with time stamps for the first time
    retry(logger.clone(), secs(60), secs(10), || {
        topology_snapshot.root_subnet().nodes().for_each(|n| {
            match block_on(get_public_key(&registry_canister, n.node_id)) {
                Ok((k, ver)) if k.timestamp.is_some() => {
                    print_key(&logger, n.node_id, &k, ver);
                    if let Some(prev_key) = init_keys.insert(n.node_id, k.clone()) {
                        assert_eq!(
                            k, prev_key,
                            "Node {} updated its key prematurely during init",
                            n.node_id
                        );
                    }
                }
                Err(e) => warn!(logger, "Failed to get key of node {}: {}", n.node_id, e),
                _ => warn!(logger, "Key of node {} doesn't have a timestamp", n.node_id),
            }
        });

        if init_keys.len() == SUBNET_SIZE {
            Ok(())
        } else {
            bail!("Not all keys have been initialized yet...")
        }
    })
    .expect("Failed to collect initial keys");

    let topology_snapshot =
        block_on(topology_snapshot.block_for_min_registry_version(RegistryVersion::from(6)))
            .unwrap();

    // Wait until all keys are rotated, verify for each that at least gamma and delta has passed
    // (both wall time and timestamp)
    retry(logger.clone(), secs(360), secs(10), || {
        topology_snapshot.root_subnet().nodes().for_each(|n| {
            if let Ok((k, ver)) = block_on(get_public_key(&registry_canister, n.node_id)) {
                let prev_key = init_keys.get(&n.node_id).unwrap();
                if &k == prev_key {
                    // Key of this node is still equal to the initial key and thus
                    // has not been rotated yet, continue with the next node.
                    return;
                }
                if let Some(prev_rotated_key) = rotated_keys.insert(n.node_id, k.clone()) {
                    // If the key of this node has already been rotated it is
                    // not allowed to change again.
                    assert_eq!(
                        k, prev_rotated_key,
                        "Node {} updated its key prematurely during rotation",
                        n.node_id
                    );
                } else {
                    // Key is not equal to the initial key and no previous rotated key has been found
                    info!(logger, "Key rotation of node {} detected!", n.node_id);
                    print_key(&logger, n.node_id, &k, ver);
                    assert_ne!(
                        prev_key.key_value, k.key_value,
                        "Key values haven't changed"
                    );

                    let init_ts =
                        SystemTime::UNIX_EPOCH + Duration::from_millis(prev_key.timestamp.unwrap());
                    let rotation_ts =
                        SystemTime::UNIX_EPOCH + Duration::from_millis(k.timestamp.unwrap());
                    let now = SystemTime::now();
                    assert!(now.duration_since(init_ts).ok() >= delta);
                    assert!(rotation_ts.duration_since(init_ts).ok() >= delta);

                    let last_init_ts = init_keys
                        .values()
                        .filter_map(|k| k.timestamp)
                        .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_millis(ts))
                        .max();

                    let last_rotation_ts = rotated_keys
                        .values()
                        .filter(|&key| key != &k)
                        .filter_map(|k| k.timestamp)
                        .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_millis(ts))
                        .max();

                    let last_ts = last_init_ts.max(last_rotation_ts).unwrap();

                    assert!(now.duration_since(last_ts).ok() >= gamma);
                    assert!(rotation_ts.duration_since(last_ts).ok() >= gamma);
                }
            } else {
                warn!(logger, "Failed to get key of node {}", n.node_id);
            }
        });

        if rotated_keys.len() == SUBNET_SIZE {
            Ok(())
        } else {
            bail!("Not all keys have been rotated yet...")
        }
    })
    .expect("Failed to collect rotated keys");

    block_on(topology_snapshot.block_for_min_registry_version(RegistryVersion::from(9))).unwrap();

    // Assert that all keys were rotated within delta-gamma time
    let first_rotation = rotated_keys
        .values()
        .filter_map(|k| k.timestamp)
        .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_millis(ts))
        .min()
        .unwrap();

    let last_rotation = rotated_keys
        .values()
        .filter_map(|k| k.timestamp)
        .map(|ts| SystemTime::UNIX_EPOCH + Duration::from_millis(ts))
        .max()
        .unwrap();

    assert!(last_rotation
        .duration_since(first_rotation)
        .map_or(false, |d| d + gamma.unwrap() <= delta.unwrap()));

    // Ensure ECDSA signing still works
    run_ecdsa_signature_test(&nns_canister, &logger, pub_key);
}

fn print_key(logger: &Logger, node_id: NodeId, pk: &PublicKey, version: u64) {
    info!(
        logger,
        "Key of Node {} @ version {}: {:?}, timestamp: {:?}",
        &node_id.to_string()[..5],
        version,
        &pk.key_value[..6],
        pk.timestamp,
    )
}

async fn get_public_key(
    registry_canister: &RegistryCanister,
    node_id: NodeId,
) -> Result<(PublicKey, u64), String> {
    match registry_canister
        .get_value(
            make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption)
                .as_bytes()
                .to_vec(),
            None,
        )
        .await
    {
        Ok((key, version)) => {
            let key = PublicKey::decode(key.as_slice()).map_err(|err| err.to_string())?;
            Ok((key, version))
        }
        Err(err) => Err(err.to_string()),
    }
}
