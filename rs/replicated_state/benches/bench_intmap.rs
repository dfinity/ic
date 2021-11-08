use criterion::{black_box, BatchSize, BenchmarkId, Criterion};
use criterion_time::ProcessTime;

use ic_replicated_state::page_map::int_map::IntMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

type Value = Arc<Vec<u8>>;

fn value(k: u64) -> Value {
    Arc::new(k.to_be_bytes().to_vec())
}

fn bench_intmap(c: &mut Criterion<ProcessTime>) {
    let mut group = c.benchmark_group("Insert");
    for n in [10u64, 100, 1000].iter().cloned() {
        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter(|| {
                let m: IntMap<_> = (0..n).map(|x| (x, value(x))).collect();
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter(|| {
                let m: Arc<BTreeMap<_, _>> = Arc::new((0..n).map(|x| (x, value(x))).collect());
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter(|| {
                let m: Arc<HashMap<_, _>> = Arc::new((0..n).map(|x| (x, value(x))).collect());
                black_box(m);
            })
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Lookup");
    for n in [10u64, 100, 1000].iter().cloned() {
        let patricia_map: IntMap<Value> = (0..n).map(|x| (x, value(x))).collect();
        let btree_map: Arc<BTreeMap<u64, Value>> =
            Arc::new((0..n).map(|x| (x, value(x))).collect());
        let hash_map: Arc<HashMap<u64, Value>> = Arc::new((0..n).map(|x| (x, value(x))).collect());
        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(patricia_map.get(i));
                    black_box(patricia_map.get(i + n));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(btree_map.get(&i));
                    black_box(btree_map.get(&(i + n)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(hash_map.get(&i));
                    black_box(hash_map.get(&(i + n)));
                }
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Union");
    for n in [10u64, 100, 1000].iter().cloned() {
        let patricia_lmap: IntMap<Value> = (0..n).map(|x| (x, value(x))).collect();
        let patricia_rmap: IntMap<Value> = (n / 2..n + n / 2).map(|x| (x, value(x))).collect();

        let btree_lmap: Arc<BTreeMap<u64, Value>> =
            Arc::new((0..n).map(|x| (x, value(x))).collect());
        let btree_rmap: Arc<BTreeMap<u64, Value>> =
            Arc::new((n / 2..n + n / 2).map(|x| (x, value(x))).collect());

        let hash_lmap: Arc<HashMap<u64, Value>> = Arc::new((0..n).map(|x| (x, value(x))).collect());
        let hash_rmap: Arc<HashMap<u64, Value>> =
            Arc::new((n / 2..n + n / 2).map(|x| (x, value(x))).collect());

        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter_batched(
                || (patricia_lmap.clone(), patricia_rmap.clone()),
                |(l, r)| {
                    black_box(l.union(r));
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter_batched(
                || (Arc::clone(&btree_lmap), Arc::clone(&btree_rmap)),
                |(mut l, r)| {
                    let dst = Arc::make_mut(&mut l);
                    for (k, v) in r.iter() {
                        dst.insert(*k, v.clone());
                    }
                    black_box(l);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter_batched(
                || (Arc::clone(&hash_lmap), Arc::clone(&hash_rmap)),
                |(mut l, r)| {
                    let dst = Arc::make_mut(&mut l);
                    for (k, v) in r.iter() {
                        dst.insert(*k, v.clone());
                    }
                    black_box(l);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Iter");
    for n in [10u64, 100, 1000].iter().cloned() {
        let patricia_map: IntMap<Value> = (0..n).map(|x| (x, value(x))).collect();
        let btree_map: Arc<BTreeMap<u64, Value>> =
            Arc::new((0..n).map(|x| (x, value(x))).collect());
        let hash_map: Arc<HashMap<u64, Value>> = Arc::new((0..n).map(|x| (x, value(x))).collect());

        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter(|| {
                for e in patricia_map.iter() {
                    black_box(e);
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter(|| {
                for e in btree_map.iter() {
                    black_box(e);
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter(|| {
                for e in hash_map.iter() {
                    black_box(e);
                }
            });
        });
    }
    group.finish();
}

fn main() {
    let mut c = Criterion::default()
        .with_measurement(ProcessTime::UserTime)
        .sample_size(20)
        .configure_from_args();
    bench_intmap(&mut c);
    c.final_summary();
}
