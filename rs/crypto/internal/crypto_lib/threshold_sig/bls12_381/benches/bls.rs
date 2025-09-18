use criterion::*;
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::{api::*, types::*};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng, RngCore};

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
    let msg = rng.r#gen::<[u8; 32]>().to_vec();
    let msg_hash = hash_message_to_g1(&msg);
    let signature = msg_hash * secret_key;

    let signature = CombinedSignatureBytes(signature.serialize());
    let public_key = PublicKeyBytes(public_key.serialize());

    (msg, signature, public_key)
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

    let rng = &mut reproducible_rng();

    // Benchmark uncached verification
    group.bench_function("verify_combined_signature_nocache", |b| {
        b.iter_batched(
            || valid_bls_12_381_signature(rng),
            |(msg, sig, pk)| assert!(verify_combined_signature(&msg, sig, pk).is_ok()),
            BatchSize::SmallInput,
        )
    });

    // A new signature is generated for each test, which tests cost
    // of a cache miss (eg verification plus cache management).
    // The overhead of the cache can be estimated by subtracting
    // the result of verify_combined_signature_nocache from this result.
    group.bench_function("verify_combined_signature_miss", |b| {
        b.iter_batched(
            || valid_bls_12_381_signature(rng),
            |(msg, sig, pk)| assert!(verify_combined_signature_with_cache(&msg, sig, pk).is_ok()),
            BatchSize::SmallInput,
        )
    });

    println!("{:?}", bls_signature_cache_statistics());

    group.bench_function("verify_combined_signature_hit", |b| {
        b.iter_batched(
            || {
                let (msg, sig, pk) = valid_bls_12_381_signature(rng);
                assert!(verify_combined_signature_with_cache(&msg, sig, pk).is_ok());
                (msg, sig, pk)
            },
            |(msg, sig, pk)| assert!(verify_combined_signature_with_cache(&msg, sig, pk).is_ok()),
            BatchSize::SmallInput,
        )
    });

    println!("{:?}", bls_signature_cache_statistics());

    // These are always slow because invalid signatures are not cached
    group.bench_function("verify_combined_signature_invalid", |b| {
        b.iter_batched_ref(
            || invalid_bls_12_381_signature(rng),
            |(msg, sig, pk)| assert!(verify_combined_signature(msg, *sig, *pk).is_err()),
            BatchSize::SmallInput,
        )
    });

    println!("{:?}", bls_signature_cache_statistics());
}

criterion_group!(benches, bls_verification);
criterion_main!(benches);
