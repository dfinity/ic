#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(unused_variables)]

use criterion::{criterion_group, criterion_main, Criterion};

use log_analyzer::*;

/// Speed tests for the log analyzer.
pub fn criterion_benchmark(c: &mut Criterion) {
    // Test `gr_it`: As a baseline, we want to see how quickly the analyzer
    // can apply a basic boolean predicate to series of integers. It should be
    // roughly the same.
    fn gr_it(n: i64) -> bool {
        for i in 1..n {
            if i <= 0 {
                return false;
            }
        }
        true
    }

    c.bench_function("< 1_000_000_000", |b| {
        b.iter(|| (1..1_000_000_000).all(|x| x >= 0))
    });
    c.bench_function("gr_it 1_000_000_000", |b| b.iter(|| gr_it(1_000_000_000)));

    fn odd(x: &u64) -> bool {
        x % 2 == 1
    }
    fn even(x: &u64) -> bool {
        x % 2 == 0
    }

    // Simple formula that ensure that all numbers are either odd or even,
    // and if even, the next number after is odd.
    let formula1 = always(or(is(&odd), and(is(&even), next(is(&odd)))));

    // Simpler formula to ensure all numbers are either odd or even.
    let formula2 = always(until(is(&odd), is(&even)));

    // A more complex formula ensuring that for every number there is another
    // after it that is larger by at least 10. This causes "forking" such that
    // there will always be 10 pending formulas active at any given time, and
    // stresses the heap a little more than the other tests.
    let formula3 = always(examine(|x: &u64| {
        eventually(examine({
            let n = *x;
            move |y: &u64| truth(*y - n > 10)
        }))
    }));

    c.bench_function("formula1 1_000", |b| {
        b.iter(|| run(formula1.clone(), 1..1_000))
    });
    c.bench_function("formula2 1_000", |b| {
        b.iter(|| run(formula2.clone(), 1..1_000))
    });
    c.bench_function("formula3 1_000", |b| {
        b.iter(|| run(formula3.clone(), 1..1_000))
    });
}

criterion_group!(benches, criterion_benchmark);

criterion_main!(benches);
