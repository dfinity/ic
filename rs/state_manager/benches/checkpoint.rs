use criterion::{criterion_group, criterion_main, Criterion};

use ic_base_types::NumSeconds;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_layout::StateLayout;
use ic_state_manager::{
    checkpoint::make_checkpoint, CheckpointMetrics, NUMBER_OF_CHECKPOINT_THREADS,
};
use ic_test_utilities::{
    state::new_canister_state,
    types::ids::{canister_test_id, subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{Cycles, Height};
use std::rc::Rc;
use tempfile::Builder;

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);
const DEFAULT_FREEZE_THRESHOLD: NumSeconds = NumSeconds::new(1 << 30);

fn criterion_make_checkpoint(c: &mut Criterion) {
    #[derive(Clone)]
    struct BenchData {
        state: ReplicatedState,
        height: Height,
        layout: StateLayout,
        metrics: CheckpointMetrics,
        thread_pool: Rc<scoped_threadpool::Pool>, // Rc is needed for `Clone`
    }

    let mut group = c.benchmark_group("state manager");

    group.bench_function("empty state", |b| {
        b.iter_with_setup(
            // Setup input data for measurement
            || {
                with_test_replica_logger(|log| {
                    let tmp = Builder::new().prefix("test").tempdir().unwrap();
                    let root = tmp.path().to_path_buf();
                    let layout = StateLayout::new(log, root);
                    let subnet_type = SubnetType::Application;

                    const HEIGHT: Height = Height::new(42);
                    let canister_id = canister_test_id(8);

                    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
                    let mut state = ReplicatedState::new_rooted_at(
                        subnet_test_id(1),
                        subnet_type,
                        tmpdir.path().into(),
                    );
                    state.put_canister_state(new_canister_state(
                        canister_id,
                        user_test_id(24).get(),
                        INITIAL_CYCLES,
                        DEFAULT_FREEZE_THRESHOLD,
                    ));
                    let metrics_registry = MetricsRegistry::new();
                    let metrics = CheckpointMetrics::new(&metrics_registry);
                    let thread_pool =
                        Rc::new(scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS));
                    BenchData {
                        state,
                        height: HEIGHT,
                        layout,
                        metrics,
                        thread_pool,
                    }
                })
            },
            // Do the actual measurement
            |mut data| {
                with_test_replica_logger(|log| {
                    let _node_state = make_checkpoint(
                        &data.state,
                        data.height,
                        &data.layout,
                        &log,
                        &data.metrics,
                        Rc::get_mut(&mut data.thread_pool).unwrap(),
                    );
                });
            },
        )
    });

    group.finish();
}

fn criterion_only_once() -> Criterion {
    Criterion::default().sample_size(20) // long running benchmark, use only 20
                                         // samples
}

criterion_group! {
    name = benches;
    config = criterion_only_once();
    targets = criterion_make_checkpoint
}

criterion_main!(benches);
