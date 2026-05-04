use criterion::*;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::canister_threshold_sig::MasterPublicKey;

fn key_derivation(c: &mut Criterion) {
    let mut rng = reproducible_rng();

    // Add P256 here when key derivation is defined for that curve:
    for curve in [EccCurveType::K256] {
        let algorithm_id = match curve {
            EccCurveType::K256 => AlgorithmId::EcdsaSecp256k1,
            _ => unreachable!(),
        };

        let sk = EccScalar::random(curve, &mut rng);
        let pk = EccPoint::generator_g(curve).scalar_mul(&sk).unwrap();

        let mpk = MasterPublicKey {
            algorithm_id,
            public_key: pk.serialize(),
        };

        let mut group = c.benchmark_group(format!("key_derivation_{curve}"));

        for path_len in [1, 10, 100, 255] {
            group.bench_with_input(
                BenchmarkId::new("derive_public_key", path_len),
                &path_len,
                |b, size| {
                    b.iter_batched_ref(
                        || create_path_of_len(*size),
                        |path| derive_threshold_public_key(&mpk, path),
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }
}

fn create_path_of_len(len: usize) -> DerivationPath {
    let mut path = Vec::with_capacity(len);
    for i in 0..len {
        path.push(i as u32);
    }
    DerivationPath::new_bip32(&path)
}

criterion_group!(benches, key_derivation);
criterion_main!(benches);
