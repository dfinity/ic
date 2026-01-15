use criterion::*;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::NumberOfNodes;
use ic_types::crypto::AlgorithmId;
use rand::{CryptoRng, Rng};

fn create_random_dealing<R: CryptoRng + Rng>(
    threshold: u32,
    recipients: usize,
    rng: &mut R,
) -> Result<IDkgDealingInternal, IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let associated_data = vec![1, 2, 3];
    let dealer_index = 0;

    let mut public_keys = Vec::with_capacity(recipients);
    let mut private_keys = Vec::with_capacity(recipients);

    for _i in 0..recipients {
        let sk = MEGaPrivateKey::generate(curve, rng);
        public_keys.push(sk.public_key());
        private_keys.push(sk);
    }

    let shares = SecretShares::Random;

    create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold),
        &public_keys,
        &shares,
        Seed::from_rng(rng),
    )
}

fn dealings(c: &mut Criterion) {
    let rng = &mut reproducible_rng();

    c.bench_function("create_dealing(Random, 3/5)", |b| {
        b.iter(|| create_random_dealing(3, 5, rng))
    });

    c.bench_function("create_dealing(Random, 5/9)", |b| {
        b.iter(|| create_random_dealing(5, 9, rng))
    });
}

criterion_group!(benches, dealings);
criterion_main!(benches);
