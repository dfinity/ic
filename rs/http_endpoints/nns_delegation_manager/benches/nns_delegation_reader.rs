use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ic_crypto_tree_hash::LabeledTree;
use ic_logger::no_op_logger;
use ic_nns_delegation_manager::{CanisterRangesFilter, NNSDelegationBuilder, NNSDelegationReader};
use ic_nns_delegation_manager_test_utils::create_fake_certificate_delegation;
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
        let builder = NNSDelegationBuilder::new(
            certificate.clone(),
            LabeledTree::try_from(certificate.tree.clone()).unwrap(),
            Blob(vec![]),
            SUBNET_0,
            &no_op_logger(),
        );
        let (_sender, receiver) = watch::channel(Some(builder));

        let reader = NNSDelegationReader::new(receiver, no_op_logger());

        println!(
            "The delegation size in bytes with {} canister ranges: {}",
            canister_id_ranges_count,
            reader
                .get_delegation(canister_ranges_filter)
                .expect("We just set a delegation above")
                .certificate
                .len()
        );

        group.bench_function(
            format!("{canister_id_ranges_count}_canister_id_ranges"),
            |bencher| {
                bencher.iter(|| black_box(reader.get_delegation(canister_ranges_filter)));
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
        bencher.iter(|| {
            black_box(reader.get_delegation(CanisterRangesFilter::Tree(CanisterId::from(0))))
        });
    });

    group.bench_function("flat", |bencher| {
        bencher.iter(|| black_box(reader.get_delegation(CanisterRangesFilter::Flat)));
    });

    group.bench_function("none", |bencher| {
        bencher.iter(|| black_box(reader.get_delegation(CanisterRangesFilter::None)));
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
