use criterion::*;
use ic_crypto_internal_bls12_381_vetkd::*;
use rand::{CryptoRng, Rng, RngCore};

/// A Polynomial whose coefficients are scalars in an elliptic curve group
///
/// The coefficients are stored in little-endian ordering, ie a_0 is
/// self.coefficients\[0\]
#[derive(Clone, Debug)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Eq for Polynomial {}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        // Accept leading zero elements
        let max_coef = std::cmp::max(self.coefficients.len(), other.coefficients.len());

        for i in 0..max_coef {
            if self.coeff(i) != other.coeff(i) {
                return false;
            }
        }

        true
    }
}

impl Polynomial {
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Self::new(vec![])
    }

    /// Creates a random polynomial with the specified number of coefficients
    fn random<R: CryptoRng + RngCore>(num_coefficients: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(num_coefficients);

        for _ in 0..num_coefficients {
            coefficients.push(Scalar::random(rng))
        }

        Self { coefficients }
    }

    fn coeff(&self, idx: usize) -> Scalar {
        match self.coefficients.get(idx) {
            Some(s) => s.clone(),
            None => Scalar::zero(),
        }
    }

    fn evaluate_at(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::zero();
        }

        let mut coefficients = self.coefficients.iter().rev();
        let mut ans = coefficients
            .next()
            .expect("Iterator was unexpectedly empty")
            .clone();

        for coeff in coefficients {
            ans *= x;
            ans += coeff;
        }
        ans
    }
}

fn transport_key_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_transport_key");

    let mut rng = rand::thread_rng();

    group.bench_function("TransportSecretKey::generate", |b| {
        b.iter(|| TransportSecretKey::generate(&mut rng))
    });

    group.bench_function("TransportSecretKey::serialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(&mut rng),
            |key| key.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportSecretKey::deserialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(&mut rng).serialize(),
            |key| TransportSecretKey::deserialize(&key),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportSecretKey::public_key", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(&mut rng),
            |key| key.public_key(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportPublicKey::serialize", |b| {
        b.iter_batched(
            || TransportSecretKey::generate(&mut rng).public_key(),
            |key| key.serialize(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("TransportPublicKey::deserialize", |b| {
        b.iter_batched(
            || {
                TransportSecretKey::generate(&mut rng)
                    .public_key()
                    .serialize()
            },
            |key| TransportPublicKey::deserialize(&key),
            BatchSize::SmallInput,
        )
    });
}

fn vetkd_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_vetkd");

    let mut rng = rand::thread_rng();

    let tsk = TransportSecretKey::generate(&mut rng);
    let tpk = tsk.public_key();

    let derivation_path = DerivationPath::new(&[1, 2, 3, 4], &[&[1, 2, 3]]);
    let did = rng.gen::<[u8; 32]>();

    for threshold in [9, 19] {
        let nodes = threshold + threshold / 2;

        let poly = Polynomial::random(threshold, &mut rng);

        let master_sk = poly.coeff(0);
        let master_pk = G2Affine::from(G2Affine::generator() * &master_sk);

        let node_id = (rng.gen::<usize>() % nodes) as u32;
        let node_sk = poly.evaluate_at(&Scalar::from_node_index(node_id));
        let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

        let dpk = DerivedPublicKey::compute_derived_key(&master_pk, &derivation_path);

        if threshold == 9 {
            group.bench_function("EncryptedKeyShare::create", |b| {
                b.iter(|| {
                    EncryptedKeyShare::create(
                        &mut rng,
                        &master_pk,
                        &node_sk,
                        &tpk,
                        &derivation_path,
                        &did,
                    )
                })
            });

            let eks = EncryptedKeyShare::create(
                &mut rng,
                &master_pk,
                &node_sk,
                &tpk,
                &derivation_path,
                &did,
            );

            group.bench_function("EncryptedKeyShare::serialize", |b| {
                b.iter(|| eks.serialize())
            });

            group.bench_function("EncryptedKeyShare::deserialize", |b| {
                b.iter_batched(
                    || eks.serialize(),
                    |bytes| EncryptedKeyShare::deserialize(bytes),
                    BatchSize::SmallInput,
                )
            });

            group.bench_function("EncryptedKeyShare::is_valid", |b| {
                b.iter(|| eks.is_valid(&master_pk, &node_pk, &derivation_path, &did, &tpk))
            });
        }

        let mut node_info = Vec::with_capacity(nodes);

        for node in 0..nodes {
            let node_sk = poly.evaluate_at(&Scalar::from_node_index(node as u32));
            let node_pk = G2Affine::from(G2Affine::generator() * &node_sk);

            let eks = EncryptedKeyShare::create(
                &mut rng,
                &master_pk,
                &node_sk,
                &tpk,
                &derivation_path,
                &did,
            );

            node_info.push((node as u32, node_pk, eks));
        }

        group.bench_function(format!("EncryptedKey::combine (n={})", nodes), |b| {
            b.iter(|| {
                EncryptedKey::combine(
                    &node_info,
                    threshold,
                    &master_pk,
                    &tpk,
                    &derivation_path,
                    &did,
                )
                .unwrap()
            })
        });

        if threshold == 9 {
            let ek = EncryptedKey::combine(
                &node_info,
                threshold,
                &master_pk,
                &tpk,
                &derivation_path,
                &did,
            )
            .unwrap();

            group.bench_function("TransportSecretKey::decrypt", |b| {
                b.iter(|| tsk.decrypt(&ek, &dpk, &did).unwrap())
            });
        }
    }
}

fn ibe_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_bls12_381_vetkd");

    let mut rng = rand::thread_rng();

    let derivation_path = DerivationPath::new(&[1, 2, 3, 4], &[&[1, 2, 3]]);
    let did = rng.gen::<[u8; 32]>();

    // Ordinarily the master secret key would be f(0) where f is a
    // suitable polynomial, but since we do not need to recombine
    // shares in this benchmark, just create a random key directly.
    let master_sk = Scalar::random(&mut rng);
    let master_pk = G2Affine::from(G2Affine::generator() * &master_sk);

    let msg = rng.gen::<[u8; 32]>();

    let dpk = DerivedPublicKey::compute_derived_key(&master_pk, &derivation_path);

    group.bench_function("IBECiphertext::encrypt", |b| {
        b.iter(|| IBECiphertext::encrypt(&dpk, &did, &msg, &mut rng))
    });

    let ctext = IBECiphertext::encrypt(&dpk, &did, &msg, &mut rng);

    group.bench_function("IBECiphertext::serialize", |b| b.iter(|| ctext.serialize()));

    let ctext_bytes = ctext.serialize();

    group.bench_function("IBECiphertext::deserialize", |b| {
        b.iter(|| IBECiphertext::deserialize(&ctext_bytes).unwrap())
    });

    let ctext = IBECiphertext::deserialize(&ctext_bytes).unwrap();

    let k = G1Affine::from(G1Affine::generator() * Scalar::random(&mut rng));
    group.bench_function("IBECiphertext::decrypt", |b| b.iter(|| ctext.decrypt(&k)));
}

criterion_group!(benches, transport_key_bench, vetkd_bench, ibe_bench);
criterion_main!(benches);
