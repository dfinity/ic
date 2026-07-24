use std::{fs::read_to_string, io::Write, str::FromStr};

use candid::Encode;
use ic_management_canister_types_private::{CanisterHttpResponsePayload, HttpMethod};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_machine_tests::{StateMachine, two_subnets_simple};
use ic_subnet_splitting::post_split_estimations::{LoadEstimates, StateSizeEstimates};
use ic_test_utilities_logger::with_test_logger;
use ic_test_utilities_types::ids::user_test_id;
use ic_types::CanisterId;
use ic_types_cycles::Cycles;
use ic_universal_canister::{call_args, wasm};
use proxy_canister::{RemoteHttpRequest, UnvalidatedCanisterHttpRequestArgs};
use slog::{Logger, info};

const EPSILON: f64 = 0.005;
const MAX_CUTS: usize = 10;

/// Checks whether the first argument is equal to the second argument with a relative error
/// tolerance up to the third argument.
macro_rules! assert_near {
    ($left:expr, $right:expr, $max_relative_error:expr) => {
        let relative_error = ($left.abs_diff($right) as f64) / ($right as f64);
        assert!(
            relative_error <= $max_relative_error,
            "The relative error of {} {} exceeds {}",
            stringify!($left),
            relative_error,
            $max_relative_error
        );
    };
}

#[test]
/// Tests that three tools needed for subnet splitting are compatible with each other:
/// 1. `state-tool`, which extracts load metrics and manifest from the replicated state,
/// 2. `split-finder`, which takes the output of the `state-tool` and proposes a good split,
/// 3. `subnet-splitting-tool`, which takes the outputs from the above two tools, and returns
///    estimated loads/sizes after splitting a subnet.
fn load_metrics_e2e_test() {
    with_test_logger(|logger| {
        info!(logger, "Creating state machines");
        let dir = ic_test_utilities_tmpdir::tmpdir("testdir");
        let (state_machine, other_state_machine) = two_subnets_simple();

        // Use `state-tool` to extract the canister metrics baseline from the replicated state.
        state_machine.checkpointed_tick();
        state_machine.state_manager.flush_tip_channel();
        let checkpoint_dir =
            std::fs::read_dir(state_machine.state_manager.state_layout().checkpoints())
                .unwrap()
                .last()
                .expect("There should be at least one checkpoint")
                .unwrap()
                .path();
        let load_samples_baseline_path = dir.path().join("load_samples_baseline.csv");
        ic_state_tool::commands::canister_metrics::get(checkpoint_dir, &load_samples_baseline_path)
            .expect("Should compute canister metrics for a valid checkpoint");

        info!(logger, "Setting up state machines");
        set_up(
            state_machine.as_ref(),
            other_state_machine.as_ref(),
            /*canisters_count=*/ 10,
            logger,
        );
        info!(logger, "Creating a checkpoint");
        state_machine.checkpointed_tick();
        state_machine.state_manager.flush_tip_channel();
        let state_layout = state_machine.state_manager.state_layout();
        let mut checkpoint_dirs = std::fs::read_dir(state_layout.checkpoints())
            .unwrap()
            .map(|dir| dir.unwrap().path())
            .collect::<Vec<_>>();
        // Note: there could be multiple checkpoints so we sort them and take the latest one.
        checkpoint_dirs.sort();
        let checkpoint_dir = checkpoint_dirs.last().expect(
            "There should be at least one checkpoint because we did `checkpointed_tick()` above",
        );

        info!(logger, "Using `state-tool` to compute the state manifest.");
        let manifest_path = dir.path().join("manifest.data");
        let content = ic_state_tool::commands::manifest::compute_manifest(checkpoint_dir)
            .expect("Should compute the manifest for a valid checkpoint");
        let mut output_file = std::fs::File::create(&manifest_path).unwrap();
        write!(output_file, "{content}").unwrap();

        info!(
            logger,
            "Using `state-tool` to extract the canister metrics from the replicated state."
        );
        let load_samples_path = dir.path().join("load_samples.csv");
        ic_state_tool::commands::canister_metrics::get(checkpoint_dir.clone(), &load_samples_path)
            .expect("Should compute canister metrics for a valid checkpoint");
        let communication_samples_path = dir.path().join("comm_samples.csv");
        // TODO(CON-1569): use actual connectivity metrics
        {
            let communication_data = include_str!("../test_data/fake_communication_sample.csv");
            let mut communication_samples_file =
                std::fs::File::create(&communication_samples_path).unwrap();
            write!(communication_samples_file, "{communication_data}").unwrap();
        }

        info!(
            logger,
            "Using `split-finder` to find candidate canister ranges to be migrated"
        );
        let split_output_path = dir.path().join("split_output.csv");
        let split_finder_path =
            std::env::var("SPLIT_FINDER_PATH").expect("SPLIT_FINDER_PATH not set");
        let output = std::process::Command::new(split_finder_path)
            .args(["--load-path", &load_samples_path.display().to_string()])
            .args([
                "--load-baseline-path",
                &load_samples_baseline_path.display().to_string(),
            ])
            .args([
                "--communication-data-path",
                &communication_samples_path.display().to_string(),
            ])
            .args(["--output-path", &split_output_path.display().to_string()])
            .args(["--load-type", "instructions_executed"])
            .args(["--epsilon-load", &EPSILON.to_string()])
            .args(["--max-cuts", &MAX_CUTS.to_string()])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "The script returned a non-zero value:\n\n === stdout ===\n{}\n\n === stderr ===\n{}",
            str::from_utf8(&output.stdout).unwrap(),
            str::from_utf8(&output.stderr).unwrap(),
        );
        let canister_id_ranges: Vec<CanisterIdRange> = read_to_string(&split_output_path)
            .expect("The split-finder script should have produced a valid output")
            .lines()
            .map(|line| CanisterIdRange::from_str(line).expect("Not a valid CanisterIdRange"))
            .collect();
        assert!(
            canister_id_ranges.len() <= MAX_CUTS.div_ceil(2),
            "The split-finder script should have produced at most {MAX_CUTS} because we \
            passed {MAX_CUTS} as the `--max-cuts` argument"
        );

        // And finally use the `subnet-splitting-tool` to estimate the loads on each subnet after a
        // split.
        let (
            StateSizeEstimates { states_sizes_bytes },
            LoadEstimates {
                canisters_installed,
                instructions_executed,
                ingress_messages_executed,
                remote_subnet_messages_executed_lower_bound,
                local_subnet_messages_executed_upper_bound,
                http_outcalls_executed,
                heartbeats_and_global_timers_executed,
            },
        ) = dbg!(
            ic_subnet_splitting::post_split_estimations::estimate(
                canister_id_ranges,
                manifest_path,
                load_samples_path,
                load_samples_baseline_path,
            )
            .expect("Should succeed given valid inputs")
        );

        // The `split-finder` solves a symmetric MILP, so the two resulting canister groups are
        // interchangeable: which one is reported as `source` and which as `destination` is
        // arbitrary and may flip across CBC solver versions/platforms. We therefore accept either
        // orientation, but require it to be *consistent* across all metrics. Rather than checking
        // each metric's orientation in isolation (which would also accept a physically impossible
        // per-metric mix), we track which of the two global labelings — original or fully swapped —
        // remains viable, and assert at the end that at least one does.
        //
        // `orientation_unflipped` stays `true` only while every metric matches with
        // `source == $a && destination == $b`; `orientation_flipped` only while every metric
        // matches the swapped labeling. Symmetric metrics (`$a == $b`) satisfy both and thus do
        // not constrain the orientation.
        let mut orientation_unflipped = true;
        let mut orientation_flipped = true;
        macro_rules! assert_eq_oriented {
            ($actual:expr, $a:expr, $b:expr) => {
                let actual = &$actual;
                let unflipped_ok = actual.source == $a && actual.destination == $b;
                let flipped_ok = actual.source == $b && actual.destination == $a;
                assert!(
                    unflipped_ok || flipped_ok,
                    "{} = {actual:?} does not match the expected {{{}, {}}} (in either orientation)",
                    stringify!($actual),
                    $a,
                    $b,
                );
                orientation_unflipped &= unflipped_ok;
                orientation_flipped &= flipped_ok;
            };
        }

        assert_eq_oriented!(canisters_installed, 10, 10);
        // Accept up to 10% error. The precise values are not important here and they're very sensitive
        // to the changes to the replicated state / execution. It's mostly a sanity check that the
        // returned values are not too ridiculous and they might have to be updated once in a while.
        // These metrics are near-symmetric, so they do not pin down the orientation; the
        // orientation is determined and checked for consistency by the exact `assert_eq_oriented`
        // checks below, and these `assert_near` checks pass in either orientation.
        assert_near!(states_sizes_bytes.source, 4778330, 0.1);
        assert_near!(states_sizes_bytes.destination, 4473176, 0.1);
        assert_near!(instructions_executed.source, 144966571, 0.1);
        assert_near!(instructions_executed.destination, 144966571, 0.1);
        assert_eq_oriented!(ingress_messages_executed, 17, 22);
        assert_eq_oriented!(remote_subnet_messages_executed_lower_bound, 4, 6);
        assert_eq_oriented!(local_subnet_messages_executed_upper_bound, 13, 15);
        assert_eq_oriented!(http_outcalls_executed, 6, 4);
        assert_eq_oriented!(heartbeats_and_global_timers_executed, 355, 339);
        // A single split cannot report some metrics in the original orientation and others in the
        // swapped one, so require all the orientation-sensitive metrics to agree on one labeling.
        assert!(
            orientation_unflipped || orientation_flipped,
            "The source/destination orientation is inconsistent across metrics: some match only \
             the original labeling and others only the swapped labeling, which cannot arise from \
             a single split."
        );
        // Check if the split finder found a split satisfying the load constraints
        assert_near!(
            instructions_executed.source,
            instructions_executed.total() / 2,
            EPSILON
        );
        assert_near!(
            instructions_executed.destination,
            instructions_executed.total() / 2,
            EPSILON
        );
    })
}

/// Sets up two state machines which talk to each other and sends a couple of ingress messages to
/// them.
fn set_up(
    state_machine: &StateMachine,
    other_state_machine: &StateMachine,
    canisters_count: usize,
    logger: &Logger,
) {
    let uc_wasm_path = std::env::var("UNIVERSAL_CANISTER_WASM_PATH")
        .expect("UNIVERSAL_CANISTER_WASM_PATH not set");
    let uc_wasm = std::fs::read(&uc_wasm_path).unwrap();

    let http_outcalls_wasm_path =
        std::env::var("PROXY_WASM_PATH").expect("PROXY_WASM_PATH not set");
    let http_outcalls_wasm = std::fs::read(&http_outcalls_wasm_path).unwrap();

    let canister_id_on_the_other_subnet = create_canister(other_state_machine, uc_wasm.to_vec());

    let mut previous_canister_id = None;
    for i in 1..=canisters_count {
        info!(logger, "Setting up {i}th canister");
        let canister_id = create_canister(state_machine, uc_wasm.to_vec());
        let http_outcalls_canister_id = create_canister(state_machine, http_outcalls_wasm.to_vec());

        // Grow the canister a bit and set a global timer
        state_machine
            .execute_ingress(
                canister_id,
                "update",
                wasm()
                    .stable_grow(100)
                    .stable_write(0, &vec![1; 100_000])
                    .set_global_timer_method(wasm().inc_global_counter())
                    .api_global_timer_set(1)
                    .reply()
                    .build(),
            )
            .unwrap();

        // Tell the canister to make an http outcall.
        let msg_id = state_machine
            .submit_ingress_as(
                user_test_id(0).get(),
                http_outcalls_canister_id,
                "send_request",
                Encode!(&RemoteHttpRequest {
                    request: UnvalidatedCanisterHttpRequestArgs {
                        url: String::from("http://this.url.should_be.invalid"),
                        max_response_bytes: None,
                        headers: vec![],
                        body: None,
                        method: HttpMethod::GET,
                        transform: None,
                        is_replicated: None,
                        pricing_version: None,
                    },
                    cycles: 1_000_000_000_000,
                })
                .unwrap(),
            )
            .unwrap();
        state_machine.execute_round();
        state_machine.execute_round();
        state_machine.handle_http_call("unused", |_| CanisterHttpResponsePayload {
            status: 200,
            headers: vec![],
            body: vec![],
        });
        state_machine
            .await_ingress(msg_id, /*max_ticks=*/ 100)
            .unwrap();

        // Tell the canister to send a xnet message
        let msg_id = state_machine
            .submit_ingress_as(
                user_test_id(0).get(),
                canister_id,
                "update",
                wasm()
                    .inter_update(
                        canister_id_on_the_other_subnet,
                        call_args().other_side(wasm().build()),
                    )
                    .build(),
            )
            .unwrap();
        state_machine.execute_round();
        state_machine.execute_xnet();
        other_state_machine.execute_round();
        other_state_machine.execute_xnet();
        state_machine.execute_round();
        state_machine
            .await_ingress(msg_id, /*max_ticks=*/ 100)
            .unwrap();

        // Send a subnet-local message
        if let Some(previous_canister_id) = previous_canister_id {
            state_machine
                .execute_ingress(
                    canister_id,
                    "update",
                    wasm()
                        .inter_update(previous_canister_id, call_args().other_side(wasm().build()))
                        .build(),
                )
                .unwrap();
        }

        previous_canister_id = Some(canister_id);
    }
}

fn create_canister(state_machine: &StateMachine, module: Vec<u8>) -> CanisterId {
    let canister_id = state_machine.create_canister_with_cycles(
        /*specified_id=*/ None,
        Cycles::new(u128::MAX),
        /*settings=*/ None,
    );

    state_machine
        .install_existing_canister(canister_id, module, /*payload=*/ vec![])
        .unwrap();

    canister_id
}
