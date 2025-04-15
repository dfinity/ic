/* tag::catalog[]
Title:: Creating, fetching and deleting a vetkey on a subnet

Goal:: Test whether the local DKG mechanism for vetkeys works


Runbook::
. Setup::
. System subnet comprising N nodes, necessary NNS canisters
. Wait one DKG interval
. Enable vetkey on subnet
. Wait until public key becomes available
. Encrypt some data to an IBE key
. Fetch the public key from a canister
. Use it to decrypt the data from the IBE key
. Check that data matches


end::catalog[] */

use anyhow::{anyhow, Result};
use canister_test::Canister;
use futures::FutureExt;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing, get_public_key_with_logger, vetkd_derive_key,
};
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdCurve, VetKdKeyId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            retry_async, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationBuilder,
        },
    },
    systest,
    util::{block_on, runtime_from_url, MessageCanister},
};
use ic_types::{Cycles, Height};
use ic_vetkd_utils::{DerivedPublicKey, EncryptedVetKey, IBECiphertext, TransportSecretKey};
use slog::info;
use std::time::Duration;

const NODES_COUNT: usize = 4;
const DKG_INTERVAL: u64 = 20;

const MSG: &str = "Secret message that is totally important";
const INPUT: &str = "secret_message";
const SEED: [u8; 32] = [13; 32];

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    // Check all subnet nodes are healthy.
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
        .expect("Could not install NNS canisters.");
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();

    let nns_subnet = topology_snapshot.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let vetkd_key_id = VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: String::from("some_vetkd_key"),
    };
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let key_ids = vec![MasterPublicKeyId::VetKd(vetkd_key_id.clone())];

    block_on(async {
        enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

        // Fetch public key from subnet
        for key_id in &key_ids {
            let pub_key = get_public_key_with_logger(key_id, &msg_can, &log)
                .await
                .expect("Should successfully retrieve the public key");

            // Check that the key is well formed
            let dpk =
                DerivedPublicKey::deserialize(&pub_key).expect("Failed to parse vetkd public key");

            let enc_msg = IBECiphertext::encrypt(&dpk, INPUT.as_bytes(), MSG.as_bytes(), &SEED)
                .expect("Failed to encrypt message");

            let transport_key = TransportSecretKey::from_seed(SEED.to_vec())
                .expect("Failed to generate transport secret key");

            info!(log, "Trying to fetch the key");

            let encrypted_priv_key: Vec<u8> = retry_async(
                "Trying to derive encrypted key",
                &log,
                Duration::from_secs(120),
                Duration::from_secs(2),
                || {
                    vetkd_derive_key(
                        transport_key.public_key().try_into().unwrap(),
                        vetkd_key_id.clone(),
                        INPUT.as_bytes().to_vec(),
                        &msg_can,
                        Cycles::zero(),
                    )
                    .map(|maybe_key| {
                        maybe_key.map_err(|e| anyhow!("Failed to retrieve key: {e:?}"))
                    })
                },
            )
            .await
            .expect("Failed to derive encrypted key");

            let enc_key = EncryptedVetKey::deserialize(&encrypted_priv_key)
                .expect("Failed to deserialize encrypted key");

            let priv_key = enc_key
                .decrypt_and_verify(&transport_key, &dpk, INPUT.as_bytes())
                .expect("Failed to decrypt derived key");

            let msg = enc_msg
                .decrypt(&priv_key)
                .expect("Failed to decrypt the message");

            assert_eq!(&msg, MSG.as_bytes());
        }
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
