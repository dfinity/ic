/* tag::catalog[]
Title:: CUP explorer test

Goal:: Test that the CUP explorer tool can download and verify CUPs of a subnet, and extract their
threshold master public keys

Runbook::
. Setup:
    . System subnet comprising 1 node, holding keys of all schemes.
    . App subnet comprising 4 nodes.
. Download the latest CUP of the subnet using the CUP explorer
. Check that the CUP verification correctly returns that the subnet is still running
. Halt the subnet at the next CUP height
. Download und verify the latest CUP of the subnet until the CUP explorer correctly determines
  that the subnet was halted
. Recover the subnet using the same state hash as in the downloaded CUP
. Ensure that the CUP explorer finds the new recovery CUP and confirms that the subnet was
  recovered correctly
. In parallel to the steps above, download the latest CUP of the system subnet and extract its
  threshold master public keys using the CUP explorer, until the CUP contains all keys
. Ensure that the public keys of a canister derived from the extracted master public keys are the
  ones returned by the management canister

end::catalog[] */
use anyhow::bail;
use canister_test::Canister;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::{
    empty_subnet_update, execute_recover_subnet_proposal, execute_update_subnet_proposal,
    get_public_key_with_retries, make_key_ids_for_all_schemes,
};
use ic_crypto_utils_canister_threshold_sig::derive_threshold_public_key;
use ic_cup_explorer::{SubnetStatus, explore, extract_master_public_keys, verify};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::types::v1 as pb;
use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::test_env::HasIcPrepDir;
use ic_system_test_driver::driver::test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF};
use ic_system_test_driver::util::{
    MessageCanister, get_app_subnet_and_node, get_nns_node, runtime_from_url,
};
use ic_system_test_driver::{
    driver::ic::{InternetComputer, Subnet},
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot},
    },
    util::block_on,
};
use ic_system_test_driver::{retry_with_msg, systest};
use ic_types::consensus::{CatchUpPackage, HasHeight};
use ic_types::crypto::{
    AlgorithmId, ExtendedDerivationPath, canister_threshold_sig::MasterPublicKey,
};
use ic_types::{Height, PrincipalId};

use anyhow::Result;
use prost::Message;
use registry_canister::mutations::do_recover_subnet::RecoverSubnetPayload;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::info;
use std::collections::BTreeSet;
use tempfile::NamedTempFile;

// A short DKG interval makes the app subnet halt faster, as it halts at the next CUP height, and
// makes the system subnet generate its vetKD key faster.
const DKG_INTERVAL: u64 = 14;
const NODES_COUNT: usize = 4;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: make_key_ids_for_all_schemes()
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                            pre_signatures_to_create_in_advance: key_id
                                .requires_pre_signatures()
                                .then_some(5),
                            key_id,
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
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    let nns_public_key = env.prep_dir("").unwrap().root_public_key_path();

    let nns_node = get_nns_node(&topology);
    let (app_subnet, _node) = get_app_subnet_and_node(&topology);

    let tmp_file = NamedTempFile::new().unwrap();
    let cup_path = tmp_file.path();

    // The initial CUP of an app subnet is a genesis CUP with a Remote DKG target,
    // which cannot be verified by the CUP explorer. We need to wait until the
    // subnet produces a CUP with a Local DKG target (after a couple of DKG intervals).
    info!(
        log,
        "Downloading and verifying initial CUP (retrying until a Local DKG target CUP is available)..."
    );
    retry_with_msg!(
        "download and verify initial CUP with Local DKG target",
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            block_on(explore(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                app_subnet.subnet_id,
                Some(cup_path.into()),
            ));
            let status = verify(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                cup_path,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            if status == SubnetStatus::Running {
                Ok(())
            } else {
                panic!(
                    "Subnet not yet running with Local DKG target CUP, status: {:?}",
                    status
                )
            }
        }
    )
    .expect("The subnet never produced a verifiable CUP with Local DKG target");

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(log, "Halt subnet {} at CUP height", app_subnet.subnet_id);
    let halt_at_cup_height_payload = UpdateSubnetPayload {
        subnet_id: app_subnet.subnet_id,
        halt_at_cup_height: Some(true),
        cooling_down: None,
        subnet_admins: None,
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        halt_at_cup_height_payload,
        "Halt at CUP height",
        &log,
    ));

    info!(log, "Downloading CUP of halted subnet");
    retry_with_msg!(
        "check if subnet has halted",
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            block_on(explore(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                app_subnet.subnet_id,
                Some(cup_path.into()),
            ));
            let status = verify(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                cup_path,
            )
            .expect("Failed to verify CUP of halted subnet");
            if status == SubnetStatus::Halted {
                Ok(())
            } else {
                bail!("Subnet not yet halted")
            }
        }
    )
    .expect("The subnet never halted");

    let bytes = std::fs::read(cup_path).expect("Failed to read file");
    let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).expect("Failed to decode bytes");
    let cup = CatchUpPackage::try_from(&proto_cup).expect("Failed to deserialize CUP content");

    info!(
        log,
        "Execute a random proposal to create a registry version in between halting and recovery",
    );
    let update_subnet_payload = UpdateSubnetPayload {
        subnet_id: app_subnet.subnet_id,
        dkg_interval_length: Some(DKG_INTERVAL),
        subnet_admins: None,
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        update_subnet_payload,
        "Update DKG length",
        &log,
    ));

    info!(log, "Recover subnet with unchanged state hash");
    let recover_subnet_payload = RecoverSubnetPayload {
        subnet_id: app_subnet.subnet_id.get(),
        initial_dkg_subnet_id: None,
        height: cup.height().get() + 1000,
        time_ns: cup
            .content
            .block
            .get_value()
            .context
            .time
            .as_nanos_since_unix_epoch()
            + 1000,
        state_hash: cup.content.state_hash.get().0,
        replacement_nodes: None,
        registry_store_uri: None,
        chain_key_config: None,
    };
    block_on(execute_recover_subnet_proposal(
        &governance,
        recover_subnet_payload,
        &log,
    ));
    let status = verify(
        nns_node.get_public_url(),
        Some(nns_public_key.clone()),
        cup_path,
    )
    .expect("Failed to verify CUP after recovery");
    assert_eq!(status, SubnetStatus::Recovered);
}

/// Extracts the master public keys of the keys held by the system subnet from the latest CUP of the
/// subnet using the CUP explorer. Checks the extracted master public keys by deriving the public
/// keys of a canister from them, and comparing these to the public keys that the management
/// canister returns for the same canister.
fn test_extract_master_public_keys(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    let nns_public_key = env.prep_dir("").unwrap().root_public_key_path();

    let nns_node = get_nns_node(&topology);
    let subnet_id = topology.root_subnet_id();

    let tmp_file = NamedTempFile::new().unwrap();
    let cup_path = tmp_file.path();

    let key_ids = make_key_ids_for_all_schemes();
    info!(
        log,
        "Extracting the master public keys of {:?} from the latest CUP of subnet {}",
        key_ids,
        subnet_id
    );
    let master_public_keys = retry_with_msg!(
        "extract the master public keys of all keys",
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            block_on(explore(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                subnet_id,
                Some(cup_path.into()),
            ));
            let master_public_keys = extract_master_public_keys(
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                cup_path,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
            let extracted_key_ids: BTreeSet<_> = master_public_keys.keys().collect();
            if extracted_key_ids == key_ids.iter().collect::<BTreeSet<_>>() {
                Ok(master_public_keys)
            } else {
                bail!("The CUP only contains the keys {:?}", extracted_key_ids)
            }
        }
    )
    .expect("The CUP never contained the master public keys of all keys");

    let agent = nns_node.build_default_agent();
    block_on(async {
        let msg_can = MessageCanister::new(&agent, nns_node.effective_canister_id()).await;
        let canister_id = PrincipalId::from(msg_can.canister_id());
        for key_id in &key_ids {
            let public_key = get_public_key_with_retries(key_id, &msg_can, &log, 100)
                .await
                .expect("Failed to get the public key");
            assert_eq!(
                derive_canister_public_key(&master_public_keys[key_id], canister_id),
                public_key,
                "The public key derived from the extracted master public key of {key_id} \
                differs from the one returned by the management canister",
            );
        }
    });
}

/// Derives the public key of the given canister from the given master public key, in the same way
/// as the management canister does for an empty derivation path (or an empty context for vetKD).
fn derive_canister_public_key(
    master_public_key: &MasterPublicKey,
    canister_id: PrincipalId,
) -> Vec<u8> {
    if master_public_key.algorithm_id == AlgorithmId::VetKD {
        ic_vetkeys::MasterPublicKey::deserialize(&master_public_key.public_key)
            .expect("Failed to deserialize the vetKD master public key")
            .derive_canister_key(canister_id.as_slice())
            .derive_sub_key(&[])
            .serialize()
    } else {
        derive_threshold_public_key(
            master_public_key,
            ExtendedDerivationPath {
                caller: canister_id,
                derivation_path: vec![],
            },
        )
        .expect("Failed to derive the public key")
        .public_key
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(test))
                .add_test(systest!(test_extract_master_public_keys)),
        )
        // The replica is restarted when the orchestrator observes the recovery CUP in the registry
        .update_orchestrator_metrics_to_check("orchestrator_processes_start_attempts_total", 2)
        .execute_from_args()?;
    Ok(())
}
