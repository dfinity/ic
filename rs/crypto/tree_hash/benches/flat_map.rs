use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::{FlatMap, Label};
use rand::{CryptoRng, Rng};

const INPUT_SIZE: usize = 32;

pub fn criterion_benchmark(c: &mut Criterion) {
    let rng = &mut reproducible_rng();
    for len in [100, 1_000, 10_000] {
        {
            let mut g: criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> =
                c.benchmark_group("from_key_values");

            g.bench_function(BenchmarkId::new("sorted_without_duplicates", len), |b| {
                b.iter_batched(
                    || {
                        let mut input = random_inputs(len, INPUT_SIZE, rng);
                        input.sort_unstable();
                        input
                    },
                    FlatMap::from_key_values,
                    BatchSize::SmallInput,
                );
            });

            g.bench_function(BenchmarkId::new("sorted_with_duplicates", len), |b| {
                b.iter_batched(
                    || {
                        let mut input = random_inputs_with_dups(len, INPUT_SIZE, rng);
                        input.sort_unstable();
                        input
                    },
                    FlatMap::from_key_values,
                    BatchSize::SmallInput,
                );
            });

            g.bench_function(BenchmarkId::new("unsorted", len), |b| {
                b.iter_batched(
                    || random_inputs(len, INPUT_SIZE, rng),
                    FlatMap::from_key_values,
                    BatchSize::SmallInput,
                );
            });

            g.finish();
        }
    }
}

fn random_label<R: Rng + CryptoRng>(input_size: usize, rng: &mut R) -> Label {
    Label::from(random_value(input_size, rng))
}

fn random_value<R: Rng + CryptoRng>(input_size: usize, rng: &mut R) -> Vec<u8> {
    let mut value = vec![0; input_size];
    rng.fill_bytes(&mut value);
    value
}

/// Random unsorted inputs without duplicates.
fn random_inputs<R: Rng + CryptoRng>(
    len: usize,
    input_size: usize,
    rng: &mut R,
) -> Vec<(Label, Vec<u8>)> {
    let mut result = Vec::<(Label, Vec<u8>)>::with_capacity(len);
    while result.len() < len {
        let label = random_label(input_size, rng);
        let does_not_contain_label = result.binary_search_by(|pair| pair.0.cmp(&label)).is_err();
        if does_not_contain_label {
            result.push((label, random_value(input_size, rng)));
        }
    }
    result
}

/// Random unsorted inputs without duplicates.
fn random_inputs_with_dups<R: Rng + CryptoRng>(
    len: usize,
    input_size: usize,
    rng: &mut R,
) -> Vec<(Label, Vec<u8>)> {
    assert!(len > 1);
    let num_dups = rng.gen_range(1..len - 1);
    let num_wo_dups = len - num_dups;

    let mut result = random_inputs(num_wo_dups, input_size, rng);

    // append duplicates
    for _ in 0..num_dups {
        let idx = rng.gen_range(0..num_wo_dups);
        result.push((result[idx].0.clone(), random_value(32, rng)));
    }

    result
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
