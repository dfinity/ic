/* tag::catalog[]
Title:: CUP explorer test

Goal:: Test that the CUP explorer tool can download and verify CUPs of a subnet

Runbook::
. Setup:
    . App subnet comprising 4 nodes.
. Download the latest CUP of the subnet using the CUP explorer
. Check that the CUP verification correctly returns that the subnet is still running
. Halt the subnet at the next CUP height
. Download und verify the latest CUP of the subnet until the CUP explorer correctly determines
  that the subnet was halted
. Recover the subnet using the same state hash as in the downloaded CUP
. Ensure that the CUP explorer finds the new recovery CUP and confirms that the subnet was
  recovered correctly

end::catalog[] */
use anyhow::bail;
use canister_test::Canister;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_threshold_sig_system_test_utils::{
    empty_subnet_update, execute_recover_subnet_proposal, execute_update_subnet_proposal,
};
use ic_cup_explorer::{SubnetStatus, explore, verify};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::types::v1 as pb;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::HasIcPrepDir;
use ic_system_test_driver::driver::test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF};
use ic_system_test_driver::util::{get_app_subnet_and_node, get_nns_node, runtime_from_url};
use ic_system_test_driver::{
    driver::ic::{InternetComputer, Subnet},
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot},
    },
    util::block_on,
};
use ic_system_test_driver::{retry_with_msg, systest};
use ic_types::Height;
use ic_types::consensus::{CatchUpPackage, HasHeight};

use anyhow::Result;
use prost::Message;
use registry_canister::mutations::do_recover_subnet::RecoverSubnetPayload;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::info;
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

const DKG_INTERVAL: u64 = 14;
const NODES_COUNT: usize = 4;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
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

    info!(log, "Downloading initial CUP...");
    block_on(explore(
        nns_node.get_public_url(),
        app_subnet.subnet_id,
        Some(cup_path.into()),
    ));
    let runtime = Runtime::new().unwrap();
    info!(log, "Verifying that subnet is running according to CUP");
    let status = verify(
        runtime.handle().clone(),
        nns_node.get_public_url(),
        Some(nns_public_key.clone()),
        cup_path,
    );
    assert_eq!(status, SubnetStatus::Running);

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(log, "Halt subnet {} at CUP height", app_subnet.subnet_id);
    let halt_at_cup_height_payload = UpdateSubnetPayload {
        subnet_id: app_subnet.subnet_id,
        halt_at_cup_height: Some(true),
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
                app_subnet.subnet_id,
                Some(cup_path.into()),
            ));
            let status = verify(
                runtime.handle().clone(),
                nns_node.get_public_url(),
                Some(nns_public_key.clone()),
                cup_path,
            );
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
        dkg_interval_length: Some(14),
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
        runtime.handle().clone(),
        nns_node.get_public_url(),
        Some(nns_public_key.clone()),
        cup_path,
    );
    assert_eq!(status, SubnetStatus::Recovered);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
