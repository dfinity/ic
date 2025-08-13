use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use ic_certification_test_utils::{
    encoded_time, generate_root_of_trust, serialize_to_cbor, CertificateBuilder, CertificateData,
};
use ic_crypto_tree_hash::{flatmap, FlatMap, Label, LabeledTree};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_nns_delegation_manager::NNSDelegationReader;
use ic_test_utilities_types::ids::SUBNET_0;
use ic_types::{messages::Certificate, CanisterId, SubnetId};
use rand::thread_rng;

fn get_delegation_with_flat_canister_ranges(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("get_delegation_with_flat_canister_ranges");

    let mut bench_function = |canister_id_ranges_count| {
        let canister_id_ranges = (0..canister_id_ranges_count)
            .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
            .collect();
        let certificate = create_fake_certificate(&canister_id_ranges, SUBNET_0);
        let reader = NNSDelegationReader::new_for_test_only(Some(certificate), SUBNET_0);

        group.bench_function(
            format!("{canister_id_ranges_count}_canister_id_ranges"),
            |bencher| {
                bencher.iter(|| black_box(reader.get_delegation_with_flat_canister_ranges()));
            },
        );
    };

    bench_function(1);
    bench_function(1_000);
    bench_function(120_000);
}

fn get_delegation_without_canister_ranges(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("get_delegation_without_canister_ranges");

    let mut bench_function = |canister_id_ranges_count| {
        let canister_id_ranges = (0..canister_id_ranges_count)
            .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
            .collect();
        let certificate = create_fake_certificate(&canister_id_ranges, SUBNET_0);
        let reader = NNSDelegationReader::new_for_test_only(Some(certificate), SUBNET_0);

        group.bench_function(
            format!("{canister_id_ranges_count}_canister_id_ranges"),
            |bencher| {
                bencher.iter(|| black_box(reader.get_delegation_without_canister_ranges()));
            },
        );
    };

    bench_function(1);
    bench_function(1_000);
    bench_function(120_000);
}

fn get_delegation_with_tree_canister_ranges(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("get_delegation_with_tree_canister_ranges");

    let mut bench_function = |canister_id_ranges_count| {
        let canister_id_ranges = (0..canister_id_ranges_count)
            .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
            .collect();
        let certificate = create_fake_certificate(&canister_id_ranges, SUBNET_0);
        let reader = NNSDelegationReader::new_for_test_only(Some(certificate), SUBNET_0);

        group.bench_function(
            format!("{canister_id_ranges_count}_canister_id_ranges"),
            |bencher| {
                bencher.iter(|| {
                    black_box(
                        reader
                            .get_delegation_with_tree_canister_ranges(CanisterId::from(42))
                            .unwrap(),
                    )
                });
            },
        );
    };

    bench_function(1);
    bench_function(1_000);
    bench_function(120_000);
}

fn create_fake_certificate(
    canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
    subnet_id: SubnetId,
) -> Certificate {
    let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
    let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());

    const MAX_RANGES_PER_ROUTING_TABLE_LEAF: usize = 5;

    let canister_ranges_subnet_0_subtree = LabeledTree::SubTree(FlatMap::from_key_values(
        canister_id_ranges
            .chunks(MAX_RANGES_PER_ROUTING_TABLE_LEAF)
            .map(|chunk| {
                (
                    Label::from(chunk[0].0),
                    LabeledTree::Leaf(serialize_to_cbor(&chunk)),
                )
            })
            .collect(),
    ));
    let canister_ranges_subtree = LabeledTree::SubTree(flatmap![
        Label::from(subnet_id.get_ref().to_vec()) => canister_ranges_subnet_0_subtree,
    ]);

    let (_certificate, _root_pk, cbor) =
             CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                 Label::from("subnet") => LabeledTree::SubTree(flatmap![
                     Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                         Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(canister_id_ranges)),
                         Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&non_nns_public_key.into_bytes()).unwrap()),
                     ])
                 ]),
                 Label::from("canister_ranges") => canister_ranges_subtree,
                 Label::from("time") => LabeledTree::Leaf(encoded_time(42))
             ])))
             .with_root_of_trust(nns_public_key, nns_secret_key)
             .build();

    serde_cbor::from_slice(&cbor).unwrap()
}

criterion_group!(
    benches,
    get_delegation_with_flat_canister_ranges,
    get_delegation_without_canister_ranges,
    get_delegation_with_tree_canister_ranges,
);

criterion_main!(benches);
