pub mod common;

use common::{
    arb_canister_config, induct_from_head_of_stream, stream_snapshot, DebugInfo, SubnetPair,
    SubnetPairConfig, KB, MB,
};
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
};
use proptest::prelude::*;
use random_traffic_test::Config as CanisterConfig;

const MAX_PAYLOAD_BYTES: u32 = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as u32;

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_message_memory_limits_are_respected(
    #[strategy(proptest::collection::vec(any::<u64>().no_shrink(), 3))] seeds: Vec<u64>,
    #[strategy(arb_canister_config(MAX_PAYLOAD_BYTES, 5))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_message_memory_limits_are_respected_impl(
        30,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seeds.as_slice(),
        config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 1 canister installed.
///
/// In the first phase `chatter_phase_round_count` rounds are executed on both subnets, including XNet
/// traffic with 'chatter' enabled, i.e. the installed canisters are making random calls (including
/// downstream calls depending on `config`).
///
/// For the second phase, the 'chatter' is disabled by putting a canister into `Stopping` state
/// every 10 rounds. In addition to shutting down traffic altogether from that canister (including
/// downstream calls) this will also induce a lot asynchronous rejections for requests. If any
/// canister fails to reach `Stopped` state (i.e. no pending calls), something went wrong in
/// message routing, most likely a bug connected to reject signals for requests.
///
/// In the final phase, up to `shutdown_phase_max_rounds` additional rounds are executed after
/// 'chatter' has been turned off to conclude all calls (or else return `Err(_)` if any call fails
/// to do so).
///
/// During all these phases, a check ensures that neither guaranteed response nor best-effort message
/// memory usage exceed the limits imposed on the respective subnets.
fn check_message_memory_limits_are_respected_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seeds: &[u64],
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    // Limit imposed on both guaranteed response and best-effort message memory on `local_env`.
    const LOCAL_MESSAGE_MEMORY_CAPACITY: u64 = 100 * MB;
    // Limit imposed on both guaranteed response and best-effort message memory on `remote_env`.
    const REMOTE_MESSAGE_MEMORY_CAPACITY: u64 = 50 * MB;

    let subnets = SubnetPair::new(SubnetPairConfig {
        local_canisters_count: 2,
        local_message_memory_capacity: LOCAL_MESSAGE_MEMORY_CAPACITY,
        remote_canisters_count: 1,
        remote_message_memory_capacity: REMOTE_MESSAGE_MEMORY_CAPACITY,
        ..SubnetPairConfig::default()
    });

    config.receivers = subnets.canisters();

    // Send configs to canisters, seed the rng.
    for (index, canister) in subnets.canisters().into_iter().enumerate() {
        subnets.set_config(canister, config.clone());
        subnets.seed_rng(canister, seeds[index]);
    }

    // Build up backlog and keep up chatter for while.
    for _ in 0..chatter_phase_round_count {
        subnets.tick();

        // Check message memory limits are respected.
        subnets.expect_message_memory_taken_at_most(
            "Chatter",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;
    }

    // Shut down chatter by putting a canister into `Stopping` state every 10 ticks until they are
    // all `Stopping` or `Stopped`.
    for canister in subnets.canisters().into_iter() {
        subnets.stop_chatter(canister);
        subnets.stop_canister_non_blocking(canister);
        for _ in 0..10 {
            subnets.tick();

            // Check message memory limits are respected.
            subnets.expect_message_memory_taken_at_most(
                "Shutdown",
                LOCAL_MESSAGE_MEMORY_CAPACITY,
                REMOTE_MESSAGE_MEMORY_CAPACITY,
            )?;
        }
    }

    // Tick until all calls have concluded; or else fail the test.
    subnets.tick_to_conclusion(shutdown_phase_max_rounds, || {
        subnets.expect_message_memory_taken_at_most(
            "Wrap up",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )
    })
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_calls_conclude_with_migrating_canister(
    #[strategy(any::<u64>().no_shrink())] seed: u64,
    #[strategy(arb_canister_config(KB as u32, 10))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_calls_conclude_with_migrating_canister_impl(
        30,  // msgs_in_stream_min_count
        300, // shutdown_phase_max_rounds
        seed, config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 5 canisters installed. All remote canisters are stopped.
///
/// In the first phase a number of rounds are executed on the local subnet only to accumulate
/// at least `msgs_in_stream_min_count` requests in the stream to the remote subnet.
///
/// For the second phase, the messages in the stream are inducted into the remote subnet. This will
/// generate reject signals for requests because all remote canisters are stopped.
/// Then the first local canister is migrated from the local subnet to the remote subnet.
/// Finally the reverse stream header is inducted which triggers reject responses, some of which
/// can not be inducted because the corresponding canister was just migrated.
///
/// For the third phase all local canisters and the migrated canister stop making calls; then
/// regular XNet traffic is simulated until all calls have concluded.
///
/// If there are pending calls after a threshold number of rounds, there is most likely a bug
/// connected to reject signals for requests, specifically with the corresponding exceptions due to
/// canister migration.
fn check_calls_conclude_with_migrating_canister_impl(
    msgs_in_stream_min_count: usize,
    shutdown_phase_max_rounds: usize,
    seed: u64,
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    let subnets = SubnetPair::new(SubnetPairConfig {
        local_canisters_count: 2,
        remote_canisters_count: 5,
        ..SubnetPairConfig::default()
    });

    config.receivers = subnets.canisters();

    // Stop all remote canisters.
    for canister in subnets.remote_canisters() {
        subnets.remote_env.stop_canister(canister).unwrap();
    }

    // Send `config` to local canisters and seed the rng.
    for canister in subnets.local_canisters() {
        subnets.set_config(canister, config.clone());
        subnets.seed_rng(canister, seed)
    }

    // Tick on `local_env` only until at least `msgs_in_stream_min_count` messages
    // are accumulated in the stream from `local_env` to `remote_env`.
    subnets.repeat_until(3 * msgs_in_stream_min_count, || {
        subnets.local_env.tick();
        Ok(matches!(
            stream_snapshot(&subnets.local_env, &subnets.remote_env),
            Some((_, messages)) if messages.len() >= msgs_in_stream_min_count
        ))
    })?;

    // Induct the stream into `remote_env` and ensure that there are reject signals in the
    // reverse stream header.
    if let Err(err) = induct_from_head_of_stream(&subnets.local_env, &subnets.remote_env, None) {
        return subnets.failed_with_reason(format!("{err}"));
    }
    if let Some((header, _)) = stream_snapshot(&subnets.remote_env, &subnets.local_env) {
        if header.reject_signals().is_empty() {
            return subnets.failed_with_reason("no reject signals in the reverse stream");
        }
    }

    // Migrate the first local canister.
    let migrating_canister = subnets.local_canister();
    subnets.migrate_local_canister_to_remote_env(migrating_canister);

    // Induct the reverse stream header of `remote_env` to trigger gc.
    induct_from_head_of_stream(&subnets.remote_env, &subnets.local_env, None).unwrap();

    // Stop chatter on all local canisters and the migrating canister; then tick until all calls
    // have concluded.
    for canister in subnets
        .local_canisters()
        .into_iter()
        .chain(std::iter::once(migrating_canister))
    {
        subnets.stop_chatter(canister);
    }
    subnets.tick_to_conclusion(shutdown_phase_max_rounds, || Ok(()))
}

#[test_strategy::proptest(ProptestConfig::with_cases(3))]
fn check_canister_can_be_stopped_with_remote_subnet_stalling(
    #[strategy(proptest::collection::vec(any::<u64>().no_shrink(), 2))] seeds: Vec<u64>,
    #[strategy(arb_canister_config(MAX_PAYLOAD_BYTES, 5))] config: CanisterConfig,
) {
    if let Err((err_msg, nfo)) = check_canister_can_be_stopped_with_remote_subnet_stalling_impl(
        30,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seeds.as_slice(),
        config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with one canister installed that
/// only makes best-effort calls and a remote subnet with one canister installed that makes random
/// calls of all kinds.
///
/// In the first phase a number of rounds are executed on both subnet, including XNet traffic
/// between both canisters.
///
/// For the second phase the local canister is put into `Stopping` state and the remote subnet
/// stalls, i.e. no more ticks are made on it. The local canister should reject any incoming calls
/// and since it made only best-effort calls, all pending calls should be rejected or timed out
/// eventually making the transition to `Stopped` state possible even with the remote subnet stalling.
///
/// If the local canister fails to reach `Stopped` state, there is most likely a bug with timing
/// out best-effort messages.
fn check_canister_can_be_stopped_with_remote_subnet_stalling_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seeds: &[u64],
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    let (local_canister, remote_canister, subnets) = SubnetPair::with_local_and_remote_canister();
    config.receivers = subnets.canisters();

    subnets.seed_rng(local_canister, seeds[0]);
    subnets.seed_rng(remote_canister, seeds[1]);

    // Set the local `config` adapted such that only best-effort calls are made.
    subnets.set_config(
        local_canister,
        CanisterConfig {
            best_effort_call_percentage: 100,
            ..config.clone()
        },
    );
    // Set the remote `config` as is.
    subnets.set_config(remote_canister, config);

    // Make calls on both canisters.
    for _ in 0..chatter_phase_round_count {
        subnets.tick();
    }
    // Stop chatter on the local canister.
    subnets.stop_chatter(local_canister);

    // Put local canister into `Stopping` state.
    let msg_id = subnets.stop_canister_non_blocking(local_canister);

    // Tick for up to `shutdown_phase_max_rounds` times on the local subnet only
    // or until the local canister has stopped.
    for _ in 0..shutdown_phase_max_rounds {
        match subnets.local_env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            } => return subnets.check_canister_traps(),
            _ => {
                subnets.local_env.tick();
                subnets
                    .local_env
                    .advance_time(std::time::Duration::from_secs(1));
            }
        }
    }

    subnets.failed_with_reason(format!(
        "failed to stop local canister after {shutdown_phase_max_rounds} ticks"
    ))
}
