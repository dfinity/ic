use criterion::Criterion;
use ic_base_types::PrincipalId;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_metrics::fetch_histogram_vec_stats;
use ic_types_cycles::Cycles;
use pprof::ProfilerGuard;
use pprof::protos::Message;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

const NUM_CREATOR_CANISTERS: usize = 10;
const NUM_CANISTERS_PER_CREATOR_CANISTER: usize = 10_000;

lazy_static::lazy_static! {
    static ref STATE_MACHINE: Arc<Mutex<StateMachine>> = {
        let mut env = StateMachine::new();
        // Don't wait for the Replicated State metrics thread every round.
        env.flush_replicated_state_metrics = false;

        let features = [];
        // let wasm =
        //     canister_test::Project::cargo_bin_maybe_from_env("canister_creator_canister", &features);
        let wasm = canister_test::Project::new().cargo_bin_with_package(Some("canister-creator"), "canister_creator_canister", &features);

        let mut canister_ids = vec![];
        for _ in 0..NUM_CREATOR_CANISTERS {
            let canister_id = env
                .install_canister_with_cycles(wasm.clone().bytes(), vec![], None, Cycles::new(1 << 64))
                .unwrap();
            canister_ids.push(canister_id);
        }

        println!("Creating 100k canisters. It may take a couple of minutes.");

        let mut ingress_ids = vec![];
        for canister_id in canister_ids.into_iter() {
            let ingress_id = env.send_ingress(
                PrincipalId::new_anonymous(),
                canister_id,
                "create_canisters",
                format!("{NUM_CANISTERS_PER_CREATOR_CANISTER}")
                    .as_bytes()
                    .to_vec(),
            );
            ingress_ids.push(ingress_id);
        }

        for ingress_id in ingress_ids.into_iter() {
            env.await_ingress(ingress_id, 1_000).unwrap();
        }
        Arc::new(Mutex::new(env))
    };
}

fn round(c: &mut Criterion) {
    let env = STATE_MACHINE.lock().unwrap();
    c.bench_function("round", |bench| {
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(false);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn checkpoint(c: &mut Criterion) {
    let env = STATE_MACHINE.lock().unwrap();
    c.bench_function("checkpoint", |bench| {
        bench.iter_batched(
            || {
                env.set_checkpoints_enabled(true);
            },
            |_| {
                env.tick();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion::criterion_group! {
    name = bench_round;
    config = Criterion::default().sample_size(50);
    targets = round
}

criterion::criterion_group! {
    name = bench_checkpoint;
    config = Criterion::default().sample_size(10);
    targets = checkpoint
}

// criterion::criterion_main!(bench_clone, bench_round, bench_checkpoint);
// criterion::criterion_main!(bench_clone, bench_round);

fn main() {
    println!("Current working directory: {:?}", std::env::current_dir());
    let guard = pprof::ProfilerGuard::new(100).unwrap();

    bench_round();
    bench_checkpoint();

    criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
    finalize_report(&guard);

    let env = STATE_MACHINE.lock().unwrap();
    for metric in &[
        "execution_round_phase_duration_seconds",
        "execution_round_inner_phase_duration_seconds",
        "execution_round_finalization_phase_duration_seconds",
        "state_manager_checkpoint_op_duration_seconds",
        "state_manager_tip_handler_request_duration_seconds",
        "mr_process_batch_phase_duration_seconds",
    ] {
        println!(
            "\"{metric}\": {:?},",
            fetch_histogram_vec_stats(&env.metrics_registry, metric)
        );
    }
}

fn finalize_report(guard: &ProfilerGuard) {
    if let Ok(report) = guard.report().build() {
        let file = File::create("flamegraph.svg").unwrap();
        report.flamegraph(file).unwrap();

        let mut file = File::create("profile.pb").unwrap();
        let profile = report.pprof().unwrap();

        let mut content = Vec::new();
        profile.encode(&mut content).unwrap();
        file.write_all(&content).unwrap();
    };
}
