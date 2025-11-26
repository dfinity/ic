use criterion::{BatchSize, BenchmarkId, Criterion, black_box};
use criterion_time::ProcessTime;

use ic_replicated_state::page_map::int_map::{AsInt, IntMap, MutableIntMap};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

type Value = Arc<Vec<u8>>;

fn value(k: u64) -> Value {
    Arc::new(k.to_be_bytes().to_vec())
}

const BENCH_SIZES: &[u64] = &[10, 100, 1000];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key128(i32, usize);

impl AsInt for Key128 {
    type Repr = u128;

    #[inline]
    fn as_int(&self) -> u128 {
        ((self.0 as u128) << 64) | self.1 as u128
    }
}

fn key128(i: u64) -> Key128 {
    Key128(i as i32 / 4, i as usize % 4)
}

fn bench_intmap(c: &mut Criterion<ProcessTime>) {
    let mut group = c.benchmark_group("Insert");
    for &n in BENCH_SIZES.iter() {
        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter(|| {
                let m: IntMap<u64, _> = (0..n).map(|x| (x * 13 % n, value(x))).collect();
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("mpatricia", n), |b| {
            b.iter(|| {
                let m: MutableIntMap<u64, _> = (0..n).map(|x| (x * 13 % n, value(x))).collect();
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("mpatricia_128", n), |b| {
            b.iter(|| {
                let m: MutableIntMap<Key128, _> =
                    (0..n).map(|x| (key128(x * 13 % n), value(x))).collect();
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter(|| {
                let m: Arc<BTreeMap<_, _>> =
                    Arc::new((0..n).map(|x| (x * 13 % n, value(x))).collect());
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_btree_128", n), |b| {
            b.iter(|| {
                let m: Arc<BTreeMap<_, _>> =
                    Arc::new((0..n).map(|x| (key128(x * 13 % n), value(x))).collect());
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter(|| {
                let m: Arc<HashMap<_, _>> =
                    Arc::new((0..n).map(|x| (x * 13 % n, value(x))).collect());
                black_box(m);
            })
        });
        group.bench_function(BenchmarkId::new("cow_hash_128", n), |b| {
            b.iter(|| {
                let m: Arc<HashMap<_, _>> =
                    Arc::new((0..n).map(|x| (key128(x * 13 % n), value(x))).collect());
                black_box(m);
            })
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Remove");
    for &n in BENCH_SIZES.iter() {
        let patricia_map: IntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
        let mpatricia_map: MutableIntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
        let btree_map: Arc<BTreeMap<u64, Value>> =
            Arc::new((0..n).map(|x| (x, value(x))).collect());
        let hash_map: Arc<HashMap<u64, Value>> = Arc::new((0..n).map(|x| (x, value(x))).collect());

        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter_batched(
                || patricia_map.clone(),
                |mut map| {
                    for i in 0..n {
                        map = map.remove(&(i * 13 % n)).0;
                        map = map.remove(&(i * 13 % n + n)).0;
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("mpatricia", n), |b| {
            b.iter_batched(
                || mpatricia_map.clone(),
                |mut map| {
                    for i in 0..n {
                        map.remove(&(i * 13 % n));
                        map.remove(&(i * 13 % n + n));
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter_batched(
                || Arc::clone(&btree_map),
                |mut map| {
                    let map = Arc::make_mut(&mut map);
                    for i in 0..n {
                        map.remove(&(i * 13 % n));
                        map.remove(&(i * 13 % n + n));
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter_batched(
                || Arc::clone(&hash_map),
                |mut map| {
                    let map = Arc::make_mut(&mut map);
                    for i in 0..n {
                        map.remove(&(i * 13 % n));
                        map.remove(&(i * 13 % n + n));
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Lookup");
    for &n in BENCH_SIZES.iter() {
        const N: u64 = 5;
        let kv = |x| (N * x, value(x));
        let kv128 = |x| (key128(N * x), value(x));

        let patricia_map: IntMap<u64, Value> = (0..n).map(kv).collect();
        let mpatricia_map: MutableIntMap<u64, Value> = (0..n).map(kv).collect();
        let patricia_128_map: MutableIntMap<Key128, Value> = (0..n).map(kv128).collect();
        let btree_map: Arc<BTreeMap<u64, Value>> = Arc::new((0..n).map(kv).collect());
        let btree_128_map: Arc<BTreeMap<Key128, Value>> = Arc::new((0..n).map(kv128).collect());
        let hash_map: Arc<HashMap<u64, Value>> = Arc::new((0..n).map(kv).collect());
        let hash_128_map: Arc<HashMap<Key128, Value>> = Arc::new((0..n).map(kv128).collect());
        group.bench_function(BenchmarkId::new("patricia", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(patricia_map.get(&(i * N)));
                    black_box(patricia_map.get(&(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("mpatricia", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(mpatricia_map.get(&(i * N)));
                    black_box(mpatricia_map.get(&(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("mpatricia_128", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(patricia_128_map.get(&key128(i * N)));
                    black_box(patricia_128_map.get(&key128(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_btree", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(btree_map.get(&(i * N)));
                    black_box(btree_map.get(&(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_btree_128", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(btree_128_map.get(&key128(i * N)));
                    black_box(btree_128_map.get(&key128(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_hash", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(hash_map.get(&(i * N)));
                    black_box(hash_map.get(&(i * N + 3)));
                }
            });
        });
        group.bench_function(BenchmarkId::new("cow_hash_128", n), |b| {
            b.iter(|| {
                for i in 0..n {
                    black_box(hash_128_map.get(&key128(i * N)));
                    black_box(hash_128_map.get(&key128(i * N + 3)));
                }
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Union");
    for &n in BENCH_SIZES.iter() {
        let patricia_lmap: IntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
        let patricia_rmap: IntMap<u64, Value> = (n / 2..n + n / 2).map(|x| (x, value(x))).collect();

        let mpatricia_lmap: MutableIntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
        let mpatricia_rmap: MutableIntMap<u64, Value> =
            (n / 2..n + n / 2).map(|x| (x, value(x))).collect();

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
        group.bench_function(BenchmarkId::new("mpatricia", n), |b| {
            b.iter_batched(
                || (mpatricia_lmap.clone(), mpatricia_rmap.clone()),
                |(mut l, r)| {
                    l.union(r);
                    black_box(l);
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
    for &n in BENCH_SIZES.iter() {
        let patricia_map: IntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
        let mpatricia_map: MutableIntMap<u64, Value> = (0..n).map(|x| (x, value(x))).collect();
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
        group.bench_function(BenchmarkId::new("mpatricia", n), |b| {
            b.iter(|| {
                for e in mpatricia_map.iter() {
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
