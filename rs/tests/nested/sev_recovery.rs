use anyhow::{Result, bail};
use candid::Encode;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_system_test_driver::driver::test_env_api::get_guestos_launch_measurements;
use ic_system_test_driver::nns::{
    get_governance_canister, submit_bless_alternative_guest_os_version_proposal,
    vote_and_execute_proposal,
};
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, nested::HasNestedVms, test_env::TestEnv, test_env_api::*},
    retry_with_msg, systest,
    util::{block_on, runtime_from_url},
};

use ic_system_test_driver::driver::nested::NestedNodes;
use ic_system_test_driver::driver::resource::BootImage;
use nested::util::{
    NODE_UPGRADE_BACKOFF, NODE_UPGRADE_TIMEOUT, setup_ic_infrastructure,
    try_logging_guestos_diagnostics,
};
use nested::{HOST_VM_NAME, create_bare_metal_tee_node, get_bare_metal_login_info};
use slog::info;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tempfile::NamedTempFile;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_alternative_guestos_recovery))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(40 * 60))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    setup_ic_infrastructure(&env, /*dkg_interval=*/ None, /*is_fast=*/ true);
    let bare_metal = nested::create_bare_metal_session(&env);
    let mut nodes = NestedNodes {
        nodes: vec![
            create_bare_metal_tee_node(&bare_metal)
                .with_boot_image(BootImage::Image(get_tagged_guestos_disk_image("recovery"))),
        ],
    };
    nodes.setup_and_start(&env).unwrap();
}

/// Test the alternative Guest OS recovery process by proposing and accepting a recovery GuestOS
/// and verifying that it boots successfully.
pub fn test_alternative_guestos_recovery(env: TestEnv) {
    let logger = env.logger();

    let _initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");

    info!(logger, "Creating recovery proposal CBOR file");
    let recovery_proposal_file =
        block_on(submit_and_get_alternative_guestos_proposal(&env, &logger));

    info!(
        logger,
        "Copying recovery proposal to host at /tmp/test_recovery_proposal.cbor"
    );
    let session = host
        .block_on_ssh_session()
        .expect("Failed to establish SSH session to host");

    scp_send_to(
        logger.clone(),
        &session,
        recovery_proposal_file.path(),
        Path::new("/tmp/test_recovery_proposal.cbor"),
        0o644,
    );

    info!(
        logger,
        "Installing recovery proposal and restarting GuestOS"
    );
    host.block_on_bash_script_from_session(
        &session,
        r#"
            set -e
            sudo systemctl stop guestos

            sudo partprobe /dev/hostlvm/guestos

            # Guest A_boot partition (see guestos/partitions.csv)
            GUEST_A_BOOT_UUID="ddf618fe-7244-b446-a175-3296e6b9d02e"
            mkdir -p /tmp/guest_boot

            sudo mount "/dev/disk/by-partuuid/${GUEST_A_BOOT_UUID}" /tmp/guest_boot
            sudo cp /tmp/test_recovery_proposal.cbor /tmp/guest_boot/alternative_guestos_proposal.cbor
            sudo umount /tmp/guest_boot
            sudo systemctl start guestos
        "#,
    )
    .expect("Failed to install recovery proposal and restart guestos");

    info!(logger, "Waiting for GuestOS to come back up");
    if let Err(e) = retry_with_msg!(
        "Waiting for Orchestrator dashboard to become accessible",
        logger.clone(),
        NODE_UPGRADE_TIMEOUT,
        NODE_UPGRADE_BACKOFF,
        || {
            if host.await_orchestrator_dashboard_accessible().is_ok() {
                Ok(())
            } else {
                bail!("Orchestrator dashboard not yet accessible")
            }
        }
    ) {
        try_logging_guestos_diagnostics(&host, &logger);
        panic!("Failed to see GuestOS come back up: {e}");
    }

    host.block_on_bash_script_from_session(
        &session,
        "journalctl -t guestos-serial | grep 'Successfully opened root device with recovery root hash';
        exit $?",
    )
    .expect("Failed to check guestos logs for recovery success");

    info!(
        logger,
        "Alternative GuestOS recovery test completed successfully"
    );
}

/// Submits and accepts a proposal for an alternative GuestOS and returns the proposal CBOR file
/// containing the accepted proposal.
async fn submit_and_get_alternative_guestos_proposal(
    env: &TestEnv,
    logger: &slog::Logger,
) -> NamedTempFile {
    info!(
        logger,
        "Creating and submitting BlessAlternativeGuestOsVersion proposal"
    );

    // Get NNS node
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("No NNS node found");

    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns);
    let nns_agent = ic_agent::Agent::builder()
        .with_url(nns_node.get_public_url())
        .build()
        .expect("Failed to build agent");

    nns_agent
        .fetch_root_key()
        .await
        .expect("Failed to fetch root key");

    let bare_metal_login_info = get_bare_metal_login_info();
    let chip_ids = vec![
        hex::decode(bare_metal_login_info.chip_id_hex)
            .expect("Chip id in baremetal secrets is not valid hex"),
    ];

    // Submit the proposal
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let neuron_id = NeuronId(TEST_NEURON_1_ID);

    let proposal_id = submit_bless_alternative_guest_os_version_proposal(
        &governance_canister,
        proposal_sender,
        neuron_id,
        chip_ids,
        get_tagged_guestos_rootfs_hash("recovery"),
        get_guestos_launch_measurements(),
    )
    .await;

    info!(logger, "Submitted proposal {}", proposal_id);

    // Vote and execute the proposal
    block_on(vote_and_execute_proposal(&governance_canister, proposal_id));

    info!(logger, "Proposal {} executed successfully", proposal_id);

    // Get a certificate containing the ProposalInfo by making an update call to get_proposal_info
    let certificate = nns_agent
        .update(
            &ic_nns_constants::GOVERNANCE_CANISTER_ID.get().0,
            "get_proposal_info",
        )
        .with_arg(Encode!(&proposal_id).expect("Failed to encode proposal_id"))
        .call()
        .and_wait()
        .await
        .expect("Failed to execute update")
        .1;

    // Encode the certificate as CBOR
    let cbor_bytes =
        serde_cbor::to_vec(&certificate).expect("Failed to encode certificate as CBOR");

    // Write to temporary file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    temp_file
        .write_all(&cbor_bytes)
        .expect("Failed to write CBOR to temporary file");
    temp_file.flush().expect("Failed to flush temporary file");

    temp_file
}
