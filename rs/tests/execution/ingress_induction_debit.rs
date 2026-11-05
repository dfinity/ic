/* tag::catalog[]
end::catalog[] */

use anyhow::Result;
use candid::{Decode, Encode, Principal};
use futures::future::join_all;
use ic_agent::Agent;
use ic_management_canister_types_private::{CanisterIdRecord, CanisterStatusResultV2};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    NnsInstallationBuilder,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, block_on};
use ic_types::{CanisterId, PrincipalId};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

const T: u128 = 1_000_000_000_000;

/// Number of universal canisters deployed to fill up the subnet memory.
const NUM_MEMORY_HOGS: usize = 20;

/// Cycles and reserved cycles limit of each memory-hog canister: 100,000T.
const MEMORY_HOG_CYCLES: u128 = 100_000 * T;
const MEMORY_HOG_RESERVED_CYCLES_LIMIT: u128 = 100_000 * T;

/// Cycles and reserved cycles limit of the canister `C`: 100T.
const C_CYCLES: u128 = 100 * T;
const C_RESERVED_CYCLES_LIMIT: u128 = 100 * T;

/// A WASM page is 64 KiB.
const WASM_PAGE_SIZE: u64 = 64 * 1024;
/// 50 GiB expressed in WASM pages (`ic0.stable64_grow` operates on pages).
const FIFTY_GIB_IN_PAGES: u64 = 50 * 1024 * 1024 * 1024 / WASM_PAGE_SIZE;
/// 1 GiB expressed in WASM pages.
const ONE_GIB_IN_PAGES: u64 = 1024 * 1024 * 1024 / WASM_PAGE_SIZE;

/// Number of instructions the cleanup callback of `C` spins for.
const SPIN_INSTRUCTIONS: u64 = 30_000_000_000;

/// The message the reply callback of `C` traps with.
const REPLY_CALLBACK_TRAP_MESSAGE: &str = "trapping-in-reply-callback";

/// How often we keep submitting update calls to `C` during the concurrent phase.
const SUBMIT_INTERVAL: Duration = Duration::from_millis(500);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    // Install the NNS canisters on the (system) root subnet.
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("NNS canisters not installed");
    info!(env.logger(), "NNS canisters installed");
}

/// Creates a canister via the provisional management canister API with the given
/// amount of cycles, reserved cycles limit and (optional) freezing threshold,
/// and installs the universal canister onto it (with the given init payload).
async fn create_universal_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    cycles: u128,
    reserved_cycles_limit: u128,
    freezing_threshold: Option<u64>,
    init_payload: Vec<u8>,
) -> PrincipalId {
    let mgr = ManagementCanister::create(agent);

    let mut create_builder = mgr
        .create_canister()
        .as_provisional_create_with_amount(Some(cycles))
        .with_effective_canister_id(effective_canister_id)
        .with_reserved_cycles_limit(reserved_cycles_limit);
    if let Some(freezing_threshold) = freezing_threshold {
        create_builder = create_builder.with_freezing_threshold(freezing_threshold);
    }
    let canister_id = create_builder
        .call_and_wait()
        .await
        .expect("failed to create canister")
        .0;

    mgr.install_code(&canister_id, &UNIVERSAL_CANISTER_WASM)
        .with_raw_arg(init_payload)
        .call_and_wait()
        .await
        .expect("failed to install universal canister");

    PrincipalId::from(canister_id)
}

/// Deploys a single memory-hog universal canister and grows its stable memory
/// to 50 GiB via an update call.
async fn deploy_memory_hog(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    log: &Logger,
    index: usize,
) -> PrincipalId {
    info!(
        log,
        "Creating and installing memory-hog canister {index}/{NUM_MEMORY_HOGS}"
    );
    let canister_id = create_universal_canister(
        agent,
        effective_canister_id,
        MEMORY_HOG_CYCLES,
        MEMORY_HOG_RESERVED_CYCLES_LIMIT,
        None,
        vec![],
    )
    .await;

    info!(
        log,
        "Created memory-hog canister {index}/{NUM_MEMORY_HOGS} ({canister_id}); \
         growing its stable memory to 50 GiB"
    );
    // `ic0.stable64_grow` returns the previous number of stable memory pages on
    // success and `u64::MAX` on failure. We reply with it and assert success.
    let reply = agent
        .update(&canister_id.into(), "update")
        .with_arg(
            wasm()
                .stable64_grow(FIFTY_GIB_IN_PAGES)
                .reply_int64()
                .build(),
        )
        .call_and_wait()
        .await
        .expect("failed to grow stable memory to 50 GiB");
    let previous_pages = u64::from_le_bytes(reply.try_into().expect("expected an 8-byte reply"));
    assert_ne!(
        previous_pages,
        u64::MAX,
        "growing stable memory of canister {canister_id} to 50 GiB failed"
    );
    info!(
        log,
        "Grew stable memory of memory-hog canister {index}/{NUM_MEMORY_HOGS} ({canister_id}) \
         to 50 GiB (previous size: {previous_pages} pages)"
    );

    canister_id
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let effective_canister_id = app_node.effective_canister_id();
    let agent = app_node.build_default_agent();

    block_on(async move {
        // Phase I: deploy 20 memory-hog canisters, each growing to 50 GiB. This
        // pushes the subnet memory usage above the reservation threshold, so the
        // canisters need a high reserved cycles limit and balance.
        info!(
            log,
            "[Phase I] Deploying {NUM_MEMORY_HOGS} memory-hog canisters"
        );
        let memory_hogs = join_all(
            (0..NUM_MEMORY_HOGS)
                .map(|index| deploy_memory_hog(&agent, effective_canister_id, &log, index)),
        )
        .await;
        info!(
            log,
            "Deployed {} memory-hog canisters growing stable memory to 50 GiB each",
            memory_hogs.len()
        );

        // Phase II: deploy the canister `C` with a freezing threshold of 0.
        info!(log, "[Phase II] Deploying canister C");
        let c_id = create_universal_canister(
            &agent,
            effective_canister_id,
            C_CYCLES,
            C_RESERVED_CYCLES_LIMIT,
            Some(0),
            vec![],
        )
        .await;
        info!(log, "Deployed canister C ({c_id})");

        // The cleanup callback of `C`: grow stable memory to 1 GiB, burn all the
        // remaining liquid cycles balance (whose exact amount is determined via
        // `ic0.canister_liquid_cycle_balance128`) and spin for 30B instructions.
        // This cleanup runs exactly once, for the single self-call update below;
        // the background update calls do not trigger it (see below).
        let cleanup = wasm()
            .stable64_grow(ONE_GIB_IN_PAGES)
            .cycles_burn_liquid_balance()
            .instruction_counter_is_at_least(SPIN_INSTRUCTIONS)
            .build();

        // The update call executed on `C`: perform a self-call whose callee
        // replies with an empty blob; the reply callback traps and the cleanup
        // callback above runs afterwards.
        let self_call_payload = wasm()
            .inter_update(
                c_id,
                call_args()
                    .other_side(wasm().reply_data(&[]))
                    .on_reply(wasm().trap_with_blob(REPLY_CALLBACK_TRAP_MESSAGE.as_bytes()))
                    .on_cleanup(cleanup),
            )
            .build();

        // The payload of the background update calls: a plain update call that
        // simply replies. These calls only serve to keep inducting ingress
        // messages into `C` (and paying the ingress induction cost); they do not
        // perform a self-call, so they do not trigger `C`'s cleanup callback.
        let background_payload = wasm().reply().build();

        // Phase III: concurrently execute the self-call update on `C` and keep
        // submitting further (plain) update calls to `C` (once every 500ms)
        // without blocking on their result.
        info!(
            log,
            "[Phase III] Concurrently exercising canister C: submitting a plain update call \
             every {}ms in the background while executing the self-call update on C",
            SUBMIT_INTERVAL.as_millis()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let submitted = Arc::new(AtomicU64::new(0));
        let submitter = {
            let submitter_agent = agent.clone();
            let submitter_payload = background_payload.clone();
            let submitter_canister_id = c_id.into();
            let submitter_log = log.clone();
            let stop = stop.clone();
            let submitted = submitted.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    // Submit an update call without blocking on its result: the
                    // agent's `call()` uses the synchronous call endpoint, which
                    // only returns once the message has been certified. To keep the
                    // submission cadence independent of how long each call takes, we
                    // fire it off in a detached task and never await it.
                    let call_agent = submitter_agent.clone();
                    let call_payload = submitter_payload.clone();
                    tokio::spawn(async move {
                        let _ = call_agent
                            .update(&submitter_canister_id, "update")
                            .with_arg(call_payload)
                            .call()
                            .await;
                    });
                    let count = submitted.fetch_add(1, Ordering::Relaxed) + 1;
                    // Emit a log every 10 submitted calls (~5s) so that
                    // progress can be monitored while the self-call update blocks.
                    if count.is_multiple_of(10) {
                        info!(
                            submitter_log,
                            "Submitted {count} background update calls to canister C so far"
                        );
                    }
                    tokio::time::sleep(SUBMIT_INTERVAL).await;
                }
            })
        };

        info!(
            log,
            "Executing the self-call update on C (blocks until C's reply callback traps and \
             its cleanup callback finishes spinning {SPIN_INSTRUCTIONS} instructions)"
        );
        let c = UniversalCanister::from_canister_id(&agent, c_id.into());
        let result = c.update(self_call_payload.clone()).await;
        info!(
            log,
            "The self-call update on C returned; stopping background submitter"
        );

        // Stop the background submitter.
        stop.store(true, Ordering::Relaxed);
        submitter.await.expect("background submitter panicked");
        info!(
            log,
            "Submitted {} background update calls to canister C",
            submitted.load(Ordering::Relaxed)
        );

        // The update call is rejected because the reply callback traps. Note that
        // this rejection is produced by the reply callback trap regardless of
        // whether the cleanup callback subsequently succeeds or itself traps, so
        // it alone does not tell us anything about the cleanup callback.
        let err = result.expect_err("the update call on C should have been rejected");
        info!(log, "The update call on C was rejected as expected: {err}");
        assert!(
            err.to_string().contains(REPLY_CALLBACK_TRAP_MESSAGE),
            "the update call on C should have been rejected due to the reply callback trapping \
             with {REPLY_CALLBACK_TRAP_MESSAGE:?}, but got: {err}"
        );

        // Verify that the cleanup callback ran to completion (i.e., did not trap).
        // A trap anywhere in the cleanup callback rolls back all of its state
        // changes, so C's stable memory being 1 GiB proves that the whole cleanup
        // callback (grow stable memory + burn liquid cycles + spin) succeeded.
        // Queries are not charged cycles, so this works even though the cleanup
        // burned all of C's liquid cycles balance.
        let stable_size_reply = c
            .query(wasm().stable64_size().reply_int64())
            .await
            .expect("failed to query the stable memory size of C");
        let stable_pages = u64::from_le_bytes(
            stable_size_reply
                .try_into()
                .expect("expected an 8-byte reply"),
        );
        assert_eq!(
            stable_pages, ONE_GIB_IN_PAGES,
            "C's cleanup callback did not grow the stable memory to 1 GiB ({ONE_GIB_IN_PAGES} \
             pages), i.e., it did not run to completion"
        );
        info!(
            log,
            "C's cleanup callback ran to completion: its stable memory grew to 1 GiB \
             ({stable_pages} pages)"
        );

        // The cleanup callback kept the cycles it reserved for growing its stable
        // memory. Query `canister_status` to assert that C ends up with non-zero
        // reserved cycles.
        let status_bytes = agent
            .query(&Principal::management_canister(), "canister_status")
            .with_effective_canister_id(c_id.0)
            .with_arg(
                Encode!(&CanisterIdRecord::from(
                    CanisterId::unchecked_from_principal(c_id)
                ))
                .unwrap(),
            )
            .call()
            .await
            .expect("failed to query the status of C");
        let status = Decode!(&status_bytes, CanisterStatusResultV2).unwrap();
        assert!(
            status.reserved_cycles() > 0,
            "C should have non-zero reserved cycles, got {}",
            status.reserved_cycles()
        );
        info!(
            log,
            "C ended with non-zero reserved cycles ({})",
            status.reserved_cycles()
        );
    });
}
