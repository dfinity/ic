use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ic_crypto_tree_hash::{LabeledTree, lookup_path};
use ic_logger::no_op_logger;
use ic_nns_delegation_reader::{
    CanisterRangesCheck, CanisterRangesFilter, NNSDelegationBuilder, NNSDelegationReader,
};
use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
use ic_registry_routing_table::CanisterIdRanges;
use ic_test_utilities_types::ids::SUBNET_0;
use ic_types::{
    CanisterId,
    messages::{Blob, Certificate},
};
use tokio::sync::watch;

fn get_delegation_with_flat_canister_ranges(criterion: &mut Criterion) {
    get_delegation_bench(
        criterion,
        CanisterRangesFilter::Flat,
        "get_delegation_with_flat_canister_ranges",
    );
}

fn get_delegation_without_canister_ranges(criterion: &mut Criterion) {
    get_delegation_bench(
        criterion,
        CanisterRangesFilter::None,
        "get_delegation_without_canister_ranges",
    );
}

fn get_delegation_with_tree_canister_ranges(criterion: &mut Criterion) {
    get_delegation_bench(
        criterion,
        CanisterRangesFilter::Tree(CanisterId::from(42)),
        "get_delegation_with_tree_canister_ranges",
    );
}

fn get_delegation_bench(
    criterion: &mut Criterion,
    canister_ranges_filter: CanisterRangesFilter,
    group_name: &str,
) {
    let mut group = criterion.benchmark_group(group_name);

    let mut bench_function = |canister_id_ranges_count| {
        let canister_id_ranges = (0..canister_id_ranges_count)
            .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
            .collect();
        let (delegation, _root_public_key) =
            create_fake_certificate_delegation(&canister_id_ranges, SUBNET_0);
        let certificate: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
        // TODO: Review this file again
        let labeled_tree = LabeledTree::try_from(certificate.tree.clone()).unwrap();
        // Extract the public key certified in the delegation so that the (trivial,
        // `NoCheck`) verification performed by `build_verified` succeeds; the benchmark
        // thus measures the cost of building the delegation.
        let certified_public_key = match lookup_path(
            &labeled_tree,
            &[b"subnet", SUBNET_0.get().as_ref(), b"public_key"],
        ) {
            Some(LabeledTree::Leaf(public_key)) => public_key.clone(),
            _ => panic!("The fake delegation should certify a public key"),
        };
        let builder = NNSDelegationBuilder::new(
            certificate.clone(),
            labeled_tree,
            Blob(vec![]),
            SUBNET_0,
            &no_op_logger(),
        );

        let build_verified = || {
            builder
                .build_verified(
                    canister_ranges_filter,
                    CanisterRangesCheck::NoCheck,
                    |_subnet_id| {
                        Some((
                            certified_public_key.clone(),
                            // TODO: especially this line
                            CanisterIdRanges::try_from(vec![]).unwrap(),
                        ))
                    },
                )
                .expect("The delegation should pass the NoCheck verification")
        };

        println!(
            "The delegation size in bytes with {} canister ranges: {}",
            canister_id_ranges_count,
            build_verified().0.certificate.len()
        );

        group.bench_function(
            format!("{canister_id_ranges_count}_canister_id_ranges"),
            |bencher| {
                bencher.iter(|| black_box(build_verified()));
            },
        );
    };

    bench_function(1);
    bench_function(1_000);
    bench_function(120_000);
}

fn get_delegation_on_nns(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("get_delegation_on_nns");

    // On NNS there is no delegation
    let (_, rx) = watch::channel(None);
    let reader = NNSDelegationReader::new(rx, no_op_logger());

    group.bench_function("tree", |bencher| {
        bencher.iter(|| black_box(reader.builder()));
    });

    group.bench_function("flat", |bencher| {
        bencher.iter(|| black_box(reader.builder()));
    });

    group.bench_function("none", |bencher| {
        bencher.iter(|| black_box(reader.builder()));
    });
}

criterion_group!(
    benches,
    get_delegation_with_flat_canister_ranges,
    get_delegation_without_canister_ranges,
    get_delegation_with_tree_canister_ranges,
    get_delegation_on_nns,
);

criterion_main!(benches);
