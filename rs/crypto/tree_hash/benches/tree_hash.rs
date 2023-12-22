use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use ic_crypto_tree_hash::{
    flatmap, lookup_path, FlatMap, HashTree, HashTreeBuilder, Label, LabeledTree, LabeledTree::*,
    MixedHashTree, WitnessGenerator,
};
use ic_crypto_tree_hash_test_utils::{
    hash_tree_builder_from_labeled_tree, mixed_hash_tree_digest_recursive,
};

// Do something similar to what ic_types_test_utils::ids::message_test_id() does
// because it compiles *much* faster than importing the function.
fn message_test_id(v: u64) -> Vec<u8> {
    let mut id = vec![0; 32];
    id[0..8].copy_from_slice(&v.to_be_bytes());
    id
}

fn new_request_status_tree(num_subtrees: usize) -> LabeledTree<Vec<u8>> {
    let replied_tree = LabeledTree::SubTree(flatmap! {
        Label::from("reply") => Leaf(vec![1; 100]),
        Label::from("status") => Leaf(b"replied".to_vec()),
    });

    let entries: Vec<_> = (0..num_subtrees)
        .map(|i| {
            (
                Label::from(message_test_id(1 + 6 * i as u64)),
                replied_tree.clone(),
            )
        })
        .collect();

    SubTree(flatmap! {
        Label::from("request_status") => SubTree(FlatMap::from_key_values(entries))
    })
}

pub fn criterion_benchmark(c: &mut Criterion) {
    for num_subtrees in [100, 1_000, 10_000] {
        let labeled_tree = new_request_status_tree(num_subtrees);
        let hash_tree_builder = hash_tree_builder_from_labeled_tree(&labeled_tree);
        let hash_tree = hash_tree_builder.as_hash_tree().unwrap();
        let witness_generator = hash_tree_builder.witness_generator().unwrap();
        let mixed_hash_tree = witness_generator
            .mixed_hash_tree(&labeled_tree)
            .expect("failed to create MixedHashTree");
        let witness = witness_generator
            .witness(&labeled_tree)
            .expect("failed to create Witness");

        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("drop");

            g.throughput(Throughput::Elements(num_subtrees as u64));

            g.bench_function(BenchmarkId::new("labeled_tree", num_subtrees), |b| {
                b.iter_batched(
                    || labeled_tree.clone(),
                    std::mem::drop,
                    BatchSize::SmallInput,
                )
            });
        }

        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("hash_tree");

            g.bench_function(BenchmarkId::new("generation", num_subtrees), |b| {
                b.iter(|| {
                    black_box(
                        hash_tree_builder_from_labeled_tree(&labeled_tree)
                            .into_hash_tree()
                            .expect("failed to build hash tree"),
                    )
                })
            });
        }

        {
            let mut g = c.benchmark_group("cbor_serialization");

            g.bench_function(BenchmarkId::new("hash_tree", num_subtrees), |b| {
                b.iter(|| black_box(serde_cbor::to_vec(&hash_tree).unwrap()))
            });

            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| black_box(serde_cbor::to_vec(&mixed_hash_tree).unwrap()))
            });

            g.bench_function(BenchmarkId::new("labeled_tree", num_subtrees), |b| {
                b.iter(|| black_box(serde_cbor::to_vec(&labeled_tree).unwrap()))
            });

            g.finish();
        }

        {
            let mut g = c.benchmark_group("cbor_deserialization");

            let serialized_hash_tree = serde_cbor::to_vec(&hash_tree).unwrap();
            g.bench_function(BenchmarkId::new("hash_tree", num_subtrees), |b| {
                b.iter(|| {
                    black_box(serde_cbor::from_slice::<HashTree>(&serialized_hash_tree).unwrap())
                })
            });

            let serialized_mixed_hash_tree = serde_cbor::to_vec(&mixed_hash_tree).unwrap();
            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| {
                    black_box(
                        serde_cbor::from_slice::<MixedHashTree>(&serialized_mixed_hash_tree)
                            .unwrap(),
                    )
                })
            });

            let serialized_labeled_tree = serde_cbor::to_vec(&labeled_tree).unwrap();
            g.bench_function(BenchmarkId::new("labeled_tree", num_subtrees), |b| {
                b.iter(|| {
                    black_box(
                        serde_cbor::from_slice::<LabeledTree<Vec<u8>>>(&serialized_labeled_tree)
                            .unwrap(),
                    )
                })
            });

            g.finish();
        }

        {
            use ic_protobuf::messaging::xnet::v1::MixedHashTree as PbTree;
            use ic_protobuf::proxy::ProtoProxy;

            let mut g = c.benchmark_group("protobuf_serialization");

            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| black_box(PbTree::proxy_encode(mixed_hash_tree.clone())))
            });

            g.finish();
        }

        {
            use ic_protobuf::messaging::xnet::v1::MixedHashTree as PbTree;
            use ic_protobuf::proxy::ProtoProxy;

            let mut g = c.benchmark_group("protobuf_deserialization");

            let serialized_hash_tree = PbTree::proxy_encode(mixed_hash_tree.clone());
            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| {
                    black_box(|| {
                        let t: MixedHashTree = PbTree::proxy_decode(&serialized_hash_tree).unwrap();
                        t
                    })
                })
            });

            g.finish();
        }

        {
            let mut g = c.benchmark_group("lookup");

            let path = [message_test_id(121), b"reply".to_vec()];

            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| black_box(mixed_hash_tree.lookup(&path)));
            });

            g.bench_function(BenchmarkId::new("labeled_tree", num_subtrees), |b| {
                b.iter(|| black_box(lookup_path(&labeled_tree, &[&path[0][..], &path[1][..]])));
            });

            g.finish();
        }

        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("witness");

            g.bench_function(
                BenchmarkId::new("from_witness_generator", num_subtrees),
                |b| {
                    b.iter(|| {
                        black_box(
                            witness_generator
                                .witness(&labeled_tree)
                                .expect("failed to create Witness"),
                        )
                    });
                },
            );

            g.finish();
        }

        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("mixed_hash_tree");

            g.bench_function(
                BenchmarkId::new("from_witness_generator", num_subtrees),
                |b| {
                    b.iter(|| {
                        black_box(
                            witness_generator
                                .mixed_hash_tree(&labeled_tree)
                                .expect("failed to create MixedHashTree"),
                        )
                    });
                },
            );

            g.finish();
        }

        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("compute_digest");

            g.bench_function(BenchmarkId::new("mixed_hash_tree", num_subtrees), |b| {
                b.iter(|| {
                    black_box(
                        mixed_hash_tree_digest_recursive(&mixed_hash_tree)
                            .expect("too deep recursion"),
                    )
                });
            });

            g.bench_function(
                BenchmarkId::new("mixed_hash_tree_iterative", num_subtrees),
                |b| {
                    b.iter(|| black_box(mixed_hash_tree.digest()));
                },
            );

            g.bench_function(BenchmarkId::new("witness", num_subtrees), |b| {
                b.iter(|| {
                    black_box(ic_crypto_tree_hash::recompute_digest(
                        &labeled_tree,
                        &witness,
                    ))
                });
            });

            g.finish();
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
