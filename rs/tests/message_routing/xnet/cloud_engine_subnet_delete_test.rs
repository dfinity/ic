/* tag::catalog[]
Title:: CloudEngine subnet deletion with in-flight XNet messages.

Goal:: Verify that deleting a CloudEngine subnet correctly causes in-flight
XNet messages to be rejected, and that messages from the deleted CloudEngine
subnet that are still in the engine's stream are not pulled after subnet
deletion.

Runbook::
0. Set up an IC with NNS subnet, two Application subnets S and T, one
   CloudEngine subnet C.
1. Install universal canisters US on S, UT on T, UC on C.
2. Halt T.  Wait until T makes no progress.
3. From UC make two bounded-wait (best-effort) update calls to UT that would
   set UT's global data to a fixed blob.  The calls are fire-and-forget (UC
   replies to its ingress immediately).
4. Halt C.  Wait until C makes no progress.
5. From US fire 10 bounded-wait update calls to UC with 2 MB payload each
   (generated at runtime, ingress stays small).  Each call's on_reject handler
   replies with the reject code as a 4-byte LE integer.
6. Concurrently: delete C, unhalt T, verify T's registry version is the version
   at which C was deleted, check UT global data is still empty, wait for all
   10 calls from US to complete.
7. Assert at least one call from US was rejected with DestinationInvalid (call
   did not reach the stream) and at least one with SysUnknown (call reached
   the stream but C is gone).

Success::
All assertions pass.

end::catalog[] */

use anyhow::{Result, bail};
use candid::Encode;
use futures::future::join_all;
use ic_consensus_system_test_utils::rw_message::cert_state_makes_no_progress_with_retries;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, READY_WAIT_TIMEOUT,
    RETRY_BACKOFF, SubnetSnapshot, install_registry_canister_with_testnet_topology,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MetricsFetcher, UniversalCanister, assert_create_agent, block_on,
};
use ic_types::Height;
use ic_universal_canister::{call_args, wasm};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use std::time::Duration;

const NUM_NODES: usize = 1;
const NUM_ENGINE_NODES: usize = 4;
const DKG_INTERVAL_LENGTH: u64 = 29;
const CALL_TIMEOUT_SECS: u32 = 300;
const FIXED_BLOB: &[u8] = b"cloud-engine-test-fixed-blob";
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(1200);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(1200);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        // Nodes on the deleted CloudEngine subnet panic when consensus can no
        // longer find their subnet record in the registry.
        .add_unallowed_log_pattern_except(
            "panicked",
            "rs/consensus/src/consensus/allowed_panics.rs",
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_subnet(
            Subnet::fast(SubnetType::System, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::Application, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::Application, NUM_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::CloudEngine, NUM_ENGINE_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    install_registry_canister_with_testnet_topology(
        &env,
        None::<fn(&mut RegistryCanisterInitPayloadBuilder)>,
    );
    block_on(test_async(env));
}

async fn test_async(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    let nns_subnet = topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect();
    let s_subnet = &app_subnets[0];
    let t_subnet = &app_subnets[1];
    let c_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::CloudEngine)
        .unwrap();

    let s_node = s_subnet.nodes().next().unwrap();
    let t_node = t_subnet.nodes().next().unwrap();
    let c_node = c_subnet.nodes().next().unwrap();

    let nns_agent = assert_create_agent(nns_node.get_public_url().as_str()).await;
    let s_agent = assert_create_agent(s_node.get_public_url().as_str()).await;
    let t_agent = assert_create_agent(t_node.get_public_url().as_str()).await;
    let c_agent = assert_create_agent(c_node.get_public_url().as_str()).await;

    // Install governance UC at canister position 1 on NNS.
    slog::info!(logger, "Installing universal canisters on NNS, S, T, C");
    let governance = UniversalCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

    let us = UniversalCanister::new_with_retries(&s_agent, s_node.effective_canister_id(), &logger)
        .await;
    let ut = UniversalCanister::new_with_retries(&t_agent, t_node.effective_canister_id(), &logger)
        .await;
    let uc = UniversalCanister::new_with_retries(&c_agent, c_node.effective_canister_id(), &logger)
        .await;
    slog::info!(
        logger,
        "Canisters installed: governance={}, US={}, UT={}, UC={}",
        governance.canister_id(),
        us.canister_id(),
        ut.canister_id(),
        uc.canister_id(),
    );

    // Step 1: Halt subnet T and wait until T makes no progress.
    slog::info!(logger, "Step 1: Halting subnet T ({})", t_subnet.subnet_id);
    set_subnet_halted(&governance, t_subnet.subnet_id, true).await;
    cert_state_makes_no_progress_with_retries(
        &t_node.get_public_url(),
        ut.canister_id().into(),
        &logger,
        Duration::from_secs(120),
        Duration::from_secs(5),
    );
    slog::info!(logger, "Step 1 done: subnet T is halted");

    // Step 2: Fire two bounded-wait calls from UC to UT that set UT's global
    // data to FIXED_BLOB.  UC replies to its ingress immediately (fire-and-forget).
    slog::info!(
        logger,
        "Step 2: Firing 2 bounded-wait UC->UT calls (fire-and-forget)"
    );
    for i in 0..2 {
        uc.update(
            wasm()
                .call_simple_with_cycles_and_best_effort_response(
                    ut.canister_id(),
                    "update",
                    call_args()
                        .other_side(wasm().set_global_data(FIXED_BLOB).reply_data(&[]))
                        .on_reply(wasm().noop())
                        .on_reject(wasm().noop()),
                    0_u128,
                    CALL_TIMEOUT_SECS,
                )
                .reply_data(&[]),
        )
        .await
        .expect("UC fire-and-forget call to UT should succeed");
        slog::info!(logger, "Step 2: UC->UT fire-and-forget call {} sent", i + 1);
    }
    slog::info!(logger, "Step 2 done: both UC->UT calls fired");

    // Step 3: Halt subnet C and wait until C makes no progress.
    slog::info!(logger, "Step 3: Halting subnet C ({})", c_subnet.subnet_id);
    set_subnet_halted(&governance, c_subnet.subnet_id, true).await;
    cert_state_makes_no_progress_with_retries(
        &c_node.get_public_url(),
        uc.canister_id().into(),
        &logger,
        Duration::from_secs(120),
        Duration::from_secs(5),
    );
    slog::info!(logger, "Step 3 done: subnet C is halted");

    // Step 4: Submit 10 bounded-wait calls from US to UC each with 2 MB payload
    // (generated at runtime on S; the ingress itself is small).
    // The on_reject handler replies with the reject code as a 4-byte LE integer.
    // We submit all 10 calls before proceeding to step 5 so that they are
    // in-flight in the S→C stream before C is deleted.
    slog::info!(
        logger,
        "Step 4: Submitting 10 bounded-wait US->UC calls (2 MB payload each)"
    );
    let us_uc_wasm: Vec<u8> = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            uc.canister_id(),
            "update",
            call_args()
                .eval_other_side(wasm().push_equal_bytes(0, 2 * 1000 * 1000).build())
                .on_reply(wasm().reply_data(&[]))
                .on_reject(
                    wasm()
                        .reject_code()
                        .int_to_blob()
                        .reply_data_append()
                        .reply(),
                ),
            0_u128,
            CALL_TIMEOUT_SECS,
        )
        .build();
    let us_canister_id = us.canister_id();
    let us_uc_request_ids: Vec<_> = join_all((0..10).map(|i| {
        let s_agent = s_agent.clone();
        let us_uc_wasm = us_uc_wasm.clone();
        async move {
            match s_agent
                .update(&us_canister_id, "update")
                .with_arg(us_uc_wasm)
                .call()
                .await
                .unwrap_or_else(|e| panic!("US->UC call {} submission failed: {e}", i + 1))
            {
                ic_agent::agent::CallResponse::Poll(id) => id,
                ic_agent::agent::CallResponse::Response(_) => {
                    panic!(
                        "US->UC call {} completed synchronously, expected Poll",
                        i + 1
                    )
                }
            }
        }
    }))
    .await;
    slog::info!(logger, "Step 4 done: {} pending", us_uc_request_ids.len());

    // Step 5: Delete subnet C.
    slog::info!(logger, "Step 5: Deleting subnet C ({})", c_subnet.subnet_id);
    let delete_arg = DeleteSubnetPayload {
        subnet_id: c_subnet.subnet_id.get().into(),
    };
    governance
        .forward_to(
            &REGISTRY_CANISTER_ID.get().0,
            "delete_subnet",
            Encode!(&delete_arg).unwrap(),
        )
        .await
        .expect("delete_subnet should succeed");

    // Record the registry version at which C was deleted.
    let topo_after_delete = topology
        .block_for_newer_registry_version()
        .await
        .expect("registry should update after delete_subnet");
    let c_delete_registry_version = topo_after_delete.get_registry_version().get();
    slog::info!(
        logger,
        "Step 5 done: subnet C deleted at registry version {}",
        c_delete_registry_version,
    );

    // Step 6: Unhalt subnet T.
    slog::info!(
        logger,
        "Step 6: Unhalting subnet T ({})",
        t_subnet.subnet_id
    );
    set_subnet_halted(&governance, t_subnet.subnet_id, false).await;
    slog::info!(logger, "Step 6 done: subnet T unhalted");

    // Step 7: Wait until T has observed the registry version at which C was deleted.
    slog::info!(
        logger,
        "Step 7: Waiting for subnet T to observe registry version {}",
        c_delete_registry_version,
    );
    wait_for_subnet_registry_version(t_subnet, c_delete_registry_version, &logger).await;
    slog::info!(
        logger,
        "Step 7 done: subnet T has observed registry version {}",
        c_delete_registry_version,
    );

    // Step 8: One more round on T (dummy call to advance state).
    slog::info!(logger, "Step 8: Advancing T state with a dummy call to UT");
    ut.update(wasm().reply_data(&[]).build())
        .await
        .expect("dummy round-trip to UT should succeed");
    slog::info!(logger, "Step 8 done: T state advanced");

    // Step 9: Check that UT global data is still empty.
    slog::info!(
        logger,
        "Step 9: Checking that UT global data is still empty"
    );
    let global_data = ut
        .query(wasm().get_global_data().reply_data_append().reply().build())
        .await
        .expect("query to UT should succeed");
    assert!(
        global_data.is_empty(),
        "UT global data should be empty but got {} bytes: {global_data:?}",
        global_data.len()
    );
    slog::info!(logger, "Step 9 done: UT global data is empty as expected");

    // Step 10: Verify that all 10 calls from US to UC were rejected.
    // At least one must have DestinationInvalid (3) and at least one must have
    // SysUnknown (6).
    let us_uc_results = join_all(
        us_uc_request_ids
            .iter()
            .map(|req_id| s_agent.wait(req_id, us.canister_id())),
    )
    .await;
    slog::info!(
        logger,
        "Step 10: Analyzing reject codes for 10 US->UC calls"
    );
    let mut dest_invalid_count = 0_usize;
    let mut sys_unknown_count = 0_usize;
    for result in us_uc_results {
        let (bytes, _) = result.expect("US->UC call should have returned a reply with reject code");
        assert_eq!(
            bytes.len(),
            4,
            "Expected exactly 4 bytes (reject code), got {} bytes: {bytes:?}",
            bytes.len()
        );
        let code = u32::from_le_bytes(bytes.try_into().unwrap());
        slog::info!(logger, "Step 10: US->UC reject code {}", code);
        match code {
            3 => dest_invalid_count += 1,
            6 => sys_unknown_count += 1,
            _ => panic!("Unexpected reject code {code} from US->UC call"),
        }
    }
    slog::info!(
        logger,
        "Step 10: DestinationInvalid={}, SysUnknown={}",
        dest_invalid_count,
        sys_unknown_count,
    );
    assert!(
        dest_invalid_count >= 1,
        "Expected at least one DestinationInvalid rejection, got {dest_invalid_count}"
    );
    assert!(
        sys_unknown_count >= 1,
        "Expected at least one SysUnknown rejection, got {sys_unknown_count}"
    );
    slog::info!(logger, "Test passed: all assertions satisfied");
}

async fn set_subnet_halted(
    governance: &UniversalCanister<'_>,
    subnet_id: ic_types::SubnetId,
    is_halted: bool,
) {
    let payload = UpdateSubnetPayload {
        subnet_id,
        is_halted: Some(is_halted),
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_ingress_bytes_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        halt_at_cup_height: None,
        features: None,
        resource_limits: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        subnet_admins: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
    };
    governance
        .forward_to(
            &REGISTRY_CANISTER_ID.get().0,
            "update_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .expect("update_subnet should succeed");
}

async fn wait_for_subnet_registry_version(
    subnet: &SubnetSnapshot,
    target_version: u64,
    logger: &slog::Logger,
) {
    let subnet_id = subnet.subnet_id;
    let metrics = MetricsFetcher::new(subnet.nodes(), vec!["mr_registry_version".into()]);
    retry_with_msg_async!(
        format!(
            "waiting for subnet {subnet_id} to reach MR registry version {target_version}"
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let values = metrics
                .fetch::<u64>()
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch metrics from {subnet_id}: {e}"))?;
            let node_versions = values
                .get("mr_registry_version")
                .ok_or_else(|| anyhow::anyhow!("mr_registry_version not yet exposed on {subnet_id}"))?;
            if let Some(v) = node_versions.iter().find(|&&v| v < target_version) {
                bail!("subnet {subnet_id} node still at MR registry version {v} (target: {target_version})");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!("subnet {subnet_id} did not reach MR registry version {target_version}: {e}")
    });
}
