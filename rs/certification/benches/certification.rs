use criterion::*;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_certification::{verify_certified_data, verify_certified_data_with_cache};
use ic_certification_test_utils::CertificateData::*;
use ic_certification_test_utils::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::Digest;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use rand::{CryptoRng, Rng};

criterion_main!(benches);
criterion_group!(benches, canister_sig, invalid_canister_sig);

fn canister_sig(c: &mut Criterion) {
    let group = c.benchmark_group("canister_signatures");
    canister_signature_bench_impl(group, false);
}

fn invalid_canister_sig(c: &mut Criterion) {
    let group = c.benchmark_group("invalid_canister_signatures");
    canister_signature_bench_impl(group, true);
}

fn canister_signature_bench_impl(
    mut group: BenchmarkGroup<criterion::measurement::WallTime>,
    corrupt: bool,
) {
    let rng = &mut reproducible_rng();

    let closure_rng = &mut rng.fork();
    group.bench_function("subnet_delegation_no_caching_no", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_without_delegation(closure_rng);
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result =
                    verify_certified_data(&cbor[..], &GLOBAL_CANISTER_ID, &pk, digest.as_bytes());
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    let closure_rng = &mut rng.fork();
    group.bench_function("subnet_delegation_yes_cache_no", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_with_delegation(closure_rng);
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result =
                    verify_certified_data(&cbor[..], &GLOBAL_CANISTER_ID, &pk, digest.as_bytes());
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    let closure_rng = &mut rng.fork();
    group.bench_function("subnet_delegation_no_cache_yes", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_without_delegation(closure_rng);
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert!(result.is_ok());
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("subnet_delegation_yes_caching_yes", move |b| {
        b.iter_batched(
            || {
                let (digest, pk, cbor) = new_random_cert_with_delegation(rng);
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert!(result.is_ok());
                (digest, conditionally_corrupt_pk(&pk, corrupt), cbor)
            },
            |(digest, pk, cbor)| {
                let result = verify_certified_data_with_cache(
                    &cbor[..],
                    &GLOBAL_CANISTER_ID,
                    &pk,
                    digest.as_bytes(),
                );
                assert_eq!(result.is_err(), corrupt);
            },
            BatchSize::SmallInput,
        )
    });
}

/// Random data as a [`Digest`] to be used as "certified data".
///
/// The reason the data can be random is that we don't need it to be valid for some data,
/// we just need some digest that exists in the state tree's path "/canister/<canister_id>/certified_data"
/// to successfully verify the signature.
fn new_random_certified_data<R: Rng + CryptoRng>(rng: &mut R) -> Digest {
    let mut random_certified_data: [u8; 32] = [0; 32];
    rng.fill(&mut random_certified_data);
    Digest(random_certified_data)
}

fn new_random_cert_without_delegation<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (Digest, ThresholdSigPublicKey, Vec<u8>) {
    let certified_data = new_random_certified_data(rng);
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: GLOBAL_CANISTER_ID,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .build();
    (certified_data, pk, cbor)
}

fn new_random_cert_with_delegation<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (Digest, ThresholdSigPublicKey, Vec<u8>) {
    let certified_data = new_random_certified_data(rng);
    let (_cert, pk, cbor) = CertificateBuilder::new_with_rng(
        CanisterData {
            canister_id: GLOBAL_CANISTER_ID,
            certified_data: certified_data.clone(),
        },
        rng,
    )
    .with_delegation(CertificateBuilder::new_with_rng(
        SubnetData {
            subnet_id: subnet_id(123),
            canister_id_ranges: vec![(canister_id(0), canister_id(10))],
        },
        rng,
    ))
    .build();
    (certified_data, pk, cbor)
}

fn conditionally_corrupt_pk(pk: &ThresholdSigPublicKey, corrupt: bool) -> ThresholdSigPublicKey {
    if corrupt {
        let mut corrupted_pk: [u8; 96] = pk.into_bytes();
        corrupted_pk[0] ^= 1;
        ThresholdSigPublicKey::from(
            ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes(
                corrupted_pk,
            ),
        )
    } else {
        *pk
    }
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

const fn canister_id(id: u64) -> CanisterId {
    CanisterId::from_u64(id)
}

const GLOBAL_CANISTER_ID: CanisterId = canister_id(1);
