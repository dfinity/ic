/* tag::catalog[]
Title:: vetKD end to end tests

Goal:: Test vetkd_public_key and vetkd_derive_key APIs within and across subnets. In particular, ensure that
  the following high-level properties are satisfied:
  . Two executions of the vetKD protocol must yield the same (decrypted) vetKey for the same
    input/context/keyID/canister combination, even if the key derivation happens on another subnet.
  . Two executions of the vetKD protocol must yield different (decrypted) vetKeys if any of input,
    context, keyID, canister are different.

Runbook::
. Setup::
    . System subnet comprising 4 nodes, necessary NNS canisters
    . Application subnet comprising 4 nodes
. Create and enable vetKD chain key on the application subnet by means of update subnet proposals.
. Create two canisters: one on the system subnet and one on the application subnet.
. Retrieve each canister's vetKD master public key (so as to derive subkeys locally, i.e., without
  having to call the vetkd_public_key API).
. Derive and verify a vetKey with some canister for some input/context/keyID combination.
. Derive and verify a vetKey with the same canister for a different input (same context as before).
. Derive and verify a vetKey with the same canister for a different context (same input as before).
. Derive and verify a vetKey with the same canister for a different keyID (same input/context as before).
  To do so, first create/enable a second vetKD chain key on the application subnet and retrieve the
  canister master public key for some canister.
. Derive and verify a vetKey with a different canister for the same input/context combination. The canister
  lives on a different subnet so as to test the vetKD API across subnets (i.e., the routing).
. IBE-encrypt a message with one of the previously retrieved canister public keys.
. IBE-decrypt the message with the previously retrieved vetKey that corresponds to the public key
  used for encryption.

Success::
. The retrieved canister master public keys have a valid encoding.
. The vetKey derived with the same parameters (input, context, keyID) by the same canister is the same.
. The vetKey derived for a different input (with otherwise the same parameters) is NOT the same.
. The vetKey derived for a different context (with otherwise the same parameters) is NOT the same.
. The vetKey derived for a different key ID (with otherwise the same parameters) is NOT the same.
. The vetKey derived with a different canister (with otherwise the same parameters) is NOT the same.
. IBE-decryption succeeds with the correct vetKey and the decrypted message is correct.
. IBE-decryption fails with the wrong vetKeys.

end::catalog[] */

use anyhow::{Result, anyhow};
use canister_test::Canister;
use futures::FutureExt;
use ic_config::subnet_config::VETKD_FEE;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing, get_public_key_with_logger, scale_cycles_to, vetkd_derive_key,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdCurve, VetKdKeyId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            retry_async,
        },
    },
    systest,
    util::{MessageCanister, block_on, get_app_subnet_and_node, runtime_from_url},
};
use ic_types::{Cycles, Height};
use ic_vetkeys::{
    DerivedPublicKey, EncryptedVetKey, IbeCiphertext, IbeIdentity, IbeSeed, TransportSecretKey,
    VetKey,
};
use rand::Rng;
use slog::info;
use std::time::Duration;

const NODES_COUNT: usize = 4;
const DKG_INTERVAL: u64 = 20;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
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
    let rng = &mut reproducible_rng();
    let topology = env.topology_snapshot();

    let nns_subnet = topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let (app_subnet, app_node) = get_app_subnet_and_node(&topology);
    let app_agent = app_node.build_default_agent();

    let key_id = VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: String::from("key_1"),
    };

    block_on(async {
        // Create and enable vetKD chain key on Application subnet
        enable_chain_key_signing(
            &governance,
            app_subnet.subnet_id,
            vec![MasterPublicKeyId::VetKd(key_id.clone())],
            &log,
        )
        .await;

        // Create canisters on different subnets (one system subnet, one application subnet)
        let canister_nns = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        let canister_app = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;

        // Retrieve the canisters' vetKD master public (verification) keys
        let canister_master_pubkey_nns =
            retrieve_public_key_with_canister(&canister_nns, &key_id, &log).await;
        let canister_master_pubkey_app =
            retrieve_public_key_with_canister(&canister_app, &key_id, &log).await;
        assert_ne!(
            canister_master_pubkey_nns.serialize(),
            canister_master_pubkey_app.serialize()
        );

        let input = b"test-input";
        let context = b"test-context";

        let vetkey = derive_vetkey_with_canister(
            &canister_app,
            input,
            context,
            key_id.clone(),
            &canister_master_pubkey_app.derive_sub_key(context),
            scale_cycles_to(NODES_COUNT, VETKD_FEE),
            &log,
            rng,
        )
        .await;

        let vetkey_same = derive_vetkey_with_canister(
            &canister_app,
            input,
            context,
            key_id.clone(),
            &canister_master_pubkey_app.derive_sub_key(context),
            scale_cycles_to(NODES_COUNT, VETKD_FEE),
            &log,
            rng,
        )
        .await;

        // The vetKeys derived for the same input/context by the same canister MUST be the same
        assert_eq!(vetkey.signature_bytes(), vetkey_same.signature_bytes());

        let different_input = b"test-input-different";
        assert_ne!(input.to_vec(), different_input.to_vec());
        let vetkey_different_input = derive_vetkey_with_canister(
            &canister_app,
            different_input,
            context,
            key_id.clone(),
            &canister_master_pubkey_app.derive_sub_key(context),
            scale_cycles_to(NODES_COUNT, VETKD_FEE),
            &log,
            rng,
        )
        .await;

        // The vetKeys derived for different inputs for the same context by the same canister MUST NOT be the same.
        assert_ne!(
            vetkey.signature_bytes(),
            vetkey_different_input.signature_bytes()
        );

        let different_context = b"test-context-different";
        assert_ne!(context.to_vec(), different_context.to_vec());
        let vetkey_different_context = derive_vetkey_with_canister(
            &canister_app,
            input,
            different_context,
            key_id.clone(),
            &canister_master_pubkey_app.derive_sub_key(different_context),
            scale_cycles_to(NODES_COUNT, VETKD_FEE),
            &log,
            rng,
        )
        .await;

        // The vetKeys derived for different contexts for the same input by the same canister MUST NOT be the same.
        assert_ne!(
            vetkey.signature_bytes(),
            vetkey_different_context.signature_bytes()
        );

        // Create and enable vetKD chain key for a different key ID on Application subnet
        let key_id_2 = VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: String::from("key_2"),
        };
        assert_ne!(key_id, key_id_2);
        enable_chain_key_signing(
            &governance,
            app_subnet.subnet_id,
            vec![
                // Specify both key IDs, so that the existing one keeps working
                MasterPublicKeyId::VetKd(key_id.clone()),
                MasterPublicKeyId::VetKd(key_id_2.clone()),
            ],
            &log,
        )
        .await;
        // Retrieve the canisters' vetKD master public (verification) keys
        let canister_master_pubkey_app_key_id_2 =
            retrieve_public_key_with_canister(&canister_app, &key_id_2, &log).await;
        let vetkey_different_key_id = derive_vetkey_with_canister(
            &canister_app,
            input,
            context,
            key_id_2.clone(),
            &canister_master_pubkey_app_key_id_2.derive_sub_key(context),
            scale_cycles_to(NODES_COUNT, VETKD_FEE),
            &log,
            rng,
        )
        .await;

        // The vetKeys derived for the same input/context for different key IDs MUST NOT be the same.
        assert_ne!(
            vetkey_different_key_id.signature_bytes(),
            vetkey.signature_bytes()
        );

        assert_ne!(canister_nns.canister_id(), canister_app.canister_id());
        let vetkey_different_canister = derive_vetkey_with_canister(
            &canister_nns,
            input,
            context,
            key_id.clone(),
            &canister_master_pubkey_nns.derive_sub_key(context),
            Cycles::zero(),
            &log,
            rng,
        )
        .await;

        // The vetKeys derived for the same input/context in different canisters MUST NOT be the same.
        assert_ne!(
            vetkey_different_canister.signature_bytes(),
            vetkey.signature_bytes()
        );

        // IBE-encrypt a message with one of the previously retrieved canister public keys.
        let secret_message = b"secret message";
        let ibe_ciphertext = IbeCiphertext::encrypt(
            &canister_master_pubkey_app.derive_sub_key(context),
            &IbeIdentity::from_bytes(input),
            secret_message,
            &IbeSeed::random(rng),
        );

        // When using the correct vetKey (i.e., the one for the correct input/context combination), the message MUST IBE-decrypt to the correct value
        assert_eq!(
            &ibe_ciphertext
                .decrypt(&vetkey)
                .expect("failed to IBE-decrypt"),
            secret_message
        );
        // When using the wrong vetKey, IBE-decryption must fail
        assert!(ibe_ciphertext.decrypt(&vetkey_different_input).is_err());
        assert!(ibe_ciphertext.decrypt(&vetkey_different_context).is_err());
        assert!(ibe_ciphertext.decrypt(&vetkey_different_key_id).is_err());
        assert!(ibe_ciphertext.decrypt(&vetkey_different_canister).is_err());
    });
}

async fn derive_vetkey_with_canister<R: Rng>(
    msg_canister: &MessageCanister<'_>,
    input: &[u8],
    context: &[u8],
    vetkd_key_id: VetKdKeyId,
    verification_key: &DerivedPublicKey,
    cycles: Cycles,
    log: &slog::Logger,
    rng: &mut R,
) -> VetKey {
    let tsk = TransportSecretKey::from_seed(rng.r#gen::<[u8; 32]>().to_vec())
        .expect("Failed to generate transport secret key");

    info!(log, "Deriving vetKey...");
    let encrypted_vetkey: Vec<u8> = retry_async(
        "derive vetKey",
        log,
        Duration::from_secs(120),
        Duration::from_secs(2),
        || {
            vetkd_derive_key(
                tsk.public_key().try_into().unwrap(),
                vetkd_key_id.clone(),
                input.to_vec(),
                context.to_vec(),
                msg_canister,
                cycles,
            )
            .map(|maybe_key| maybe_key.map_err(|e| anyhow!("Failed to retrieve key: {e:?}")))
        },
    )
    .await
    .expect("failed to derive vetKey");

    EncryptedVetKey::deserialize(&encrypted_vetkey)
        .expect("Failed to deserialize encrypted key")
        .decrypt_and_verify(&tsk, verification_key, input)
        .expect("Failed to decrypt derived key")
}

async fn retrieve_public_key_with_canister(
    msg_canister: &MessageCanister<'_>,
    vetkd_key_id: &VetKdKeyId,
    log: &slog::Logger,
) -> DerivedPublicKey {
    info!(log, "Fetching vetKD public key...");
    let pubkey_bytes = get_public_key_with_logger(
        &MasterPublicKeyId::VetKd(vetkd_key_id.clone()),
        msg_canister,
        log,
    )
    .await
    .expect("should retrieve vetKD public key");

    DerivedPublicKey::deserialize(&pubkey_bytes).expect("failed to parse vetKD public key")
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
