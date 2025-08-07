use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use ic_certification_test_utils::{
    encoded_time, generate_root_of_trust, serialize_to_cbor, CertificateBuilder, CertificateData,
};
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree};
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_nns_delegation_manager::NNSDelegationReader;
use ic_test_utilities_types::ids::SUBNET_0;
use ic_types::{
    messages::{Blob, CertificateDelegation},
    CanisterId,
};
use rand::thread_rng;

fn read_flat_delegation_bench(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("read_flat_delegation");

    let delegation = create_fake_delegation(&vec![(CanisterId::from(1), CanisterId::from(10))]);
    let (_tx, rx) = tokio::sync::watch::channel(Some(delegation));
    let reader = NNSDelegationReader::new(rx);

    group.bench_function("1_range", |b| {
        b.iter(|| black_box(reader.get_delegation_with_flat_canister_ranges()));
    });

    let ranges = (0..1_000)
        .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
        .collect();
    let delegation = create_fake_delegation(&ranges);
    let (_tx, rx) = tokio::sync::watch::channel(Some(delegation));
    let reader = NNSDelegationReader::new(rx);

    group.bench_function("1000_ranges", |b| {
        b.iter(|| black_box(reader.get_delegation_with_flat_canister_ranges()));
    });

    let ranges = (0..10_000)
        .map(|i| (CanisterId::from(2 * i), CanisterId::from(2 * i + 1)))
        .collect();
    let delegation = create_fake_delegation(&ranges);
    let (_tx, rx) = tokio::sync::watch::channel(Some(delegation));
    let reader = NNSDelegationReader::new(rx);

    group.bench_function("10000_ranges", |b| {
        b.iter(|| black_box(reader.get_delegation_with_flat_canister_ranges()));
    });
}

fn create_fake_delegation(
    canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
) -> CertificateDelegation {
    let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
    let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());

    let (_certificate, _root_pk, cbor) =
             CertificateBuilder::new(CertificateData::CustomTree(LabeledTree::SubTree(flatmap![
                 Label::from("subnet") => LabeledTree::SubTree(flatmap![
                     Label::from(SUBNET_0.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                         Label::from("canister_ranges") => LabeledTree::Leaf(serialize_to_cbor(canister_id_ranges)),
                         Label::from("public_key") => LabeledTree::Leaf(public_key_to_der(&non_nns_public_key.into_bytes()).unwrap()),
                     ])
                 ]),
                 Label::from("time") => LabeledTree::Leaf(encoded_time(42))
             ])))
             .with_root_of_trust(nns_public_key, nns_secret_key)
             .build();

    dbg!(cbor.len());
    CertificateDelegation {
        subnet_id: Blob(SUBNET_0.get().to_vec()),
        certificate: Blob(cbor),
    }
}

criterion_group!(benches, read_flat_delegation_bench);

criterion_main!(benches);
