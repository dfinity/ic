mod fixture;

use crate::fixture::{DebugInfo, Fixture, FixtureConfig, KB, MB};
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
};
use proptest::prelude::*;
use random_traffic_test::{arb_config as arb_canister_config, Config as CanisterConfig};

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

    let fixture = Fixture::new(FixtureConfig {
        local_canisters_count: 2,
        local_message_memory_capacity: LOCAL_MESSAGE_MEMORY_CAPACITY,
        remote_canisters_count: 1,
        remote_message_memory_capacity: REMOTE_MESSAGE_MEMORY_CAPACITY,
        ..FixtureConfig::default()
    });

    config.receivers = fixture.canisters();

    // Send configs to canisters, seed the rng.
    for (index, canister) in fixture.canisters().into_iter().enumerate() {
        fixture.set_config(canister, config.clone());
        fixture.seed_rng(canister, seeds[index]);
    }

    // Build up backlog and keep up chatter for while.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();

        // Check message memory limits are respected.
        fixture.expect_message_memory_taken_at_most(
            "Chatter",
            LOCAL_MESSAGE_MEMORY_CAPACITY,
            REMOTE_MESSAGE_MEMORY_CAPACITY,
        )?;
    }

    // Shut down chatter by putting a canister into `Stopping` state every 10 ticks until they are
    // all `Stopping` or `Stopped`.
    for canister in fixture.canisters().into_iter() {
        fixture.stop_chatter(canister);
        fixture.stop_canister_non_blocking(canister);
        for _ in 0..10 {
            fixture.tick();

            // Check message memory limits are respected.
            fixture.expect_message_memory_taken_at_most(
                "Shutdown",
                LOCAL_MESSAGE_MEMORY_CAPACITY,
                REMOTE_MESSAGE_MEMORY_CAPACITY,
            )?;
        }
    }

    // Tick until all calls have concluded; or else fail the test.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |fixture| {
        fixture.expect_message_memory_taken_at_most(
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
        10,  // chatter_phase_round_count
        300, // shutdown_phase_max_rounds
        seed, config,
    ) {
        unreachable!("\nerr_msg: {err_msg}\n{:#?}", nfo.records);
    }
}

/// Runs a state machine test with two subnets, a local subnet with 2 canisters installed and a
/// remote subnet with 5 canisters installed. All canisters, except one local canister referred to
/// as `migrating_canister`, are stopped.
///
/// In the first phase a number of rounds are executed on both subnets, including XNet traffic with
/// the `migrating_canister` making random calls to all installed canisters (since all calls are
/// rejected except those to self).
///
/// For the second phase, `migrating_canister` stops making calls and is then migrated to the
/// remote subnet. Since all other canisters are stopped, there are bound to be a number of reject
/// signals for requests in the stream to the local_subnet. But since we migrated the `migrating_canister`
/// to the remote subnet, the locally generated reject responses fail to induct and are rerouted into the
/// stream to the remote subnet. The remote subnet eventually picks them up and inducts them into
/// `migrating_canister` leaving no pending calls after some more rounds.
///
/// If there are pending calls after a threshold number of rounds, there is most likely a bug
/// connected to reject signals for requests, specifically with the corresponding exceptions due to
/// canister migration.
fn check_calls_conclude_with_migrating_canister_impl(
    chatter_phase_round_count: usize,
    shutdown_phase_max_rounds: usize,
    seed: u64,
    mut config: CanisterConfig,
) -> Result<(), (String, DebugInfo)> {
    let mut fixture = Fixture::new(FixtureConfig {
        local_canisters_count: 2,
        remote_canisters_count: 5,
        ..FixtureConfig::default()
    });

    config.receivers = fixture.canisters();

    let migrating_canister = *fixture.local_canisters.first().unwrap();

    // Send config to `migrating_canister` and seed its rng.
    fixture.set_config(migrating_canister, config);
    fixture.seed_rng(migrating_canister, seed);

    // Stop all canisters except `migrating_canister`.
    for canister in fixture.canisters() {
        if canister != migrating_canister {
            // Make sure the canister doesn't make calls when it is
            // put into running state to read its records.
            fixture.stop_chatter(canister);
            fixture.stop_canister_non_blocking(canister);
        }
    }
    // Make calls on `migrating_canister`.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();
    }

    // Stop making calls and migrate `migrating_canister`.
    fixture.stop_chatter(migrating_canister);
    fixture.migrate_canister(migrating_canister);

    // Tick until all calls have concluded; or else fail the test.
    fixture.tick_to_conclusion(shutdown_phase_max_rounds, |_| Ok(()))
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
    let fixture = Fixture::new(FixtureConfig {
        local_canisters_count: 1,
        remote_canisters_count: 1,
        ..FixtureConfig::default()
    });

    config.receivers = fixture.canisters();

    let local_canister = *fixture.local_canisters.first().unwrap();
    let remote_canister = *fixture.remote_canisters.first().unwrap();

    fixture.seed_rng(local_canister, seeds[0]);
    fixture.seed_rng(remote_canister, seeds[1]);

    // Set the local `config` adapted such that only best-effort calls are made.
    fixture.set_config(
        local_canister,
        CanisterConfig {
            best_effort_call_percentage: 100,
            ..config.clone()
        },
    );
    // Set the remote `config` as is.
    fixture.set_config(remote_canister, config);

    // Make calls on both canisters.
    for _ in 0..chatter_phase_round_count {
        fixture.tick();
    }
    // Stop chatter on the local canister.
    fixture.stop_chatter(local_canister);

    // Put local canister into `Stopping` state.
    let msg_id = fixture.stop_canister_non_blocking(local_canister);

    // Tick for up to `shutdown_phase_max_rounds` times on the local subnet only
    // or until the local canister has stopped.
    for _ in 0..shutdown_phase_max_rounds {
        match fixture.local_env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            } => return Ok(()),
            _ => {
                fixture.local_env.tick();
                fixture
                    .local_env
                    .advance_time(std::time::Duration::from_secs(1));
            }
        }
    }

    fixture.failed_with_reason(format!(
        "failed to stop local canister after {shutdown_phase_max_rounds} ticks"
    ))
}
