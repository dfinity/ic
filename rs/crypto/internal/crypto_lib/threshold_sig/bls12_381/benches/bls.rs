use criterion::*;
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::{api::*, types::*};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

const DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG: &[u8; 43] =
    b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Hashes `msg` to a point in `G1`.
fn hash_message_to_g1(msg: &[u8]) -> G1Projective {
    G1Projective::hash(&DOMAIN_HASH_MSG_TO_G1_BLS12381_SIG[..], msg)
}

fn valid_bls_12_381_signature<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Vec<u8>, CombinedSignatureBytes, PublicKeyBytes) {
    let secret_key = Scalar::random(rng);
    let public_key = G2Affine::generator() * &secret_key;
    let msg = rng.gen::<[u8; 32]>().to_vec();
    let msg_hash = hash_message_to_g1(&msg);
    let signature = msg_hash * secret_key;

    let signature = CombinedSignatureBytes(signature.serialize());
    let public_key = PublicKeyBytes(public_key.serialize());

    (msg, signature, public_key)
}

// Return random signatures from a small set to more easily simulate cache hits
fn valid_bls_12_381_signature_small_set<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Vec<u8>, CombinedSignatureBytes, PublicKeyBytes) {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(rng.gen::<u64>() % 2000);
    valid_bls_12_381_signature(&mut rng)
}

fn invalid_bls_12_381_signature<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Vec<u8>, CombinedSignatureBytes, PublicKeyBytes) {
    let (mut msg, sig, pk) = valid_bls_12_381_signature(rng);
    msg[0] ^= 1;
    (msg, sig, pk)
}

fn bls_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_signature_verification");

    let mut rng = reproducible_rng();

    group.bench_function("verify_combined_signature_valid", |b| {
        b.iter_batched_ref(
            || valid_bls_12_381_signature(&mut rng),
            |(msg, sig, pk)| assert!(verify_combined_signature(msg, *sig, *pk).is_ok()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("verify_combined_signature_with_cache_valid", |b| {
        b.iter_batched_ref(
            || valid_bls_12_381_signature_small_set(&mut rng),
            |(msg, sig, pk)| assert!(verify_combined_signature_with_cache(msg, *sig, *pk).is_ok()),
            BatchSize::SmallInput,
        )
    });

    println!("{:?}", bls_signature_cache_statistics());

    group.bench_function(
        "verify_combined_signature_with_cache_valid_all_in_cache",
        |b| {
            b.iter_batched_ref(
                || valid_bls_12_381_signature_small_set(&mut rng),
                |(msg, sig, pk)| {
                    assert!(verify_combined_signature_with_cache(msg, *sig, *pk).is_ok())
                },
                BatchSize::SmallInput,
            )
        },
    );

    println!("{:?}", bls_signature_cache_statistics());

    let (msg, sig, pk) = valid_bls_12_381_signature(&mut rng);

    group.bench_function(
        "verify_combined_signature_with_cache_valid_repeated_same_item",
        |b| {
            b.iter(|| {
                assert!(verify_combined_signature_with_cache(&msg, sig, pk).is_ok());
            })
        },
    );

    println!("{:?}", bls_signature_cache_statistics());

    group.bench_function("verify_combined_signature_invalid", |b| {
        b.iter_batched_ref(
            || invalid_bls_12_381_signature(&mut rng),
            |(msg, sig, pk)| assert!(verify_combined_signature(msg, *sig, *pk).is_err()),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("verify_combined_signature_with_cache_invalid", |b| {
        b.iter_batched_ref(
            || invalid_bls_12_381_signature(&mut rng),
            |(msg, sig, pk)| assert!(verify_combined_signature_with_cache(msg, *sig, *pk).is_err()),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bls_verification);
criterion_main!(benches);
