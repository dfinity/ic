use criterion::*;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_types::crypto::AlgorithmId;
use ic_types::*;
use rand::Rng;

fn create_random_dealing(
    threshold: u32,
    recipients: usize,
) -> Result<IDkgDealingInternal, IdkgCreateDealingInternalError> {
    let curve = EccCurveType::K256;
    let mut rng = rand::thread_rng();
    let associated_data = vec![1, 2, 3];
    let dealer_index = 0;

    let mut private_keys = Vec::with_capacity(recipients);

    for _i in 0..recipients {
        private_keys.push(MEGaPrivateKey::generate(curve, &mut rng)?);
    }

    let public_keys = private_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Result<Vec<_>, _>>()?;

    let randomness = Randomness::from(rng.gen::<[u8; 32]>());

    let shares = SecretShares::Random;

    create_dealing(
        AlgorithmId::ThresholdEcdsaSecp256k1,
        &associated_data,
        dealer_index,
        NumberOfNodes::from(threshold),
        &public_keys,
        &shares,
        randomness,
    )
}

fn dealings(c: &mut Criterion) {
    c.bench_function("create_dealing(Random, 3/5)", |b| {
        b.iter(|| create_random_dealing(3, 5))
    });

    c.bench_function("create_dealing(Random, 5/9)", |b| {
        b.iter(|| create_random_dealing(5, 9))
    });
}

criterion_group!(benches, dealings);
criterion_main!(benches);
