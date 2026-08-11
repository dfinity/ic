use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ic_crypto_tree_hash::{LabeledTree, lookup_path};
use ic_nns_delegation_reader::{CanisterRangesCheck, NNSDelegationBuilder};
use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
use ic_registry_routing_table::CanisterIdRange;
use ic_test_utilities_types::ids::SUBNET_0;
use ic_types::{
    CanisterId,
    messages::{Blob, Certificate},
};

fn build_delegation_verify_all_subnet_ranges(criterion: &mut Criterion) {
    build_delegation_bench(
        criterion,
        CanisterRangesCheck::AllSubnetRanges,
        "build_delegation_verify_all_subnet_ranges",
    );
}

fn build_delegation_verify_canister_in_flat(criterion: &mut Criterion) {
    build_delegation_bench(
        criterion,
        CanisterRangesCheck::CanisterInFlat(CanisterId::from(42)),
        "build_delegation_verify_canister_in_flat",
    );
}

fn build_delegation_verify_canister_in_tree(criterion: &mut Criterion) {
    build_delegation_bench(
        criterion,
        CanisterRangesCheck::CanisterInTree(CanisterId::from(42)),
        "build_delegation_verify_canister_in_tree",
    );
}

fn build_delegation_no_ranges_check(criterion: &mut Criterion) {
    build_delegation_bench(
        criterion,
        CanisterRangesCheck::NoCheck,
        "build_delegation_no_ranges_check",
    );
}

fn build_delegation_bench(
    criterion: &mut Criterion,
    ranges_check: CanisterRangesCheck,
    group_name: &str,
) {
    let mut group = criterion.benchmark_group(group_name);

    let mut bench_function = |canister_id_ranges_count| {
        let canister_id_ranges = (0..canister_id_ranges_count)
            // Leaving gaps on purpose between ranges to simulate a fragmented routing table
            .map(|i| (CanisterId::from(3 * i), CanisterId::from(3 * i + 1)))
            .collect();
        let (delegation, _root_public_key) =
            create_fake_certificate_delegation(&canister_id_ranges, SUBNET_0);
        let certificate: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
        let labeled_tree = LabeledTree::try_from(certificate.tree.clone()).unwrap();
        // Extract the public key certified in the delegation so that the verification performed by
        // `build_verified` succeeds
        let certified_public_key = match lookup_path(
            &labeled_tree,
            &[b"subnet", SUBNET_0.get().as_ref(), b"public_key"],
        ) {
            Some(LabeledTree::Leaf(public_key)) => public_key.clone(),
            _ => panic!("The fake delegation should certify a public key"),
        };
        let routing_table = canister_id_ranges
            .into_iter()
            .map(|(start, end)| (CanisterIdRange { start, end }, SUBNET_0))
            .collect::<BTreeMap<_, _>>()
            .try_into()
            .unwrap();

        let builder = NNSDelegationBuilder::new(certificate, labeled_tree, Blob(vec![]), SUBNET_0);

        let build_verified = || {
            builder
                .build_verified(
                    ranges_check,
                    &routing_table,
                    |_subnet_id| {
                        Some(&certified_public_key)
                    },
                )
                .unwrap_or_else(|err| panic!("Failed to build verified delegation (ranges check: {ranges_check:?}): {err:?}"))
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

criterion_group!(
    benches,
    build_delegation_verify_all_subnet_ranges,
    build_delegation_verify_canister_in_flat,
    build_delegation_verify_canister_in_tree,
    build_delegation_no_ranges_check,
);

criterion_main!(benches);
