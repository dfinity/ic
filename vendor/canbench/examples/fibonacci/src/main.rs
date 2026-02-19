// A version of fibonacci that's efficient.
#[ic_cdk::query]
fn fibonacci(n: u32) -> u32 {
    if n == 0 {
        return 0;
    } else if n == 1 {
        return 1;
    }

    let mut a = 0;
    let mut b = 1;
    let mut result = 0;

    for _ in 2..=n {
        result = a + b;
        a = b;
        b = result;
    }

    result
}

// Try this inefficient version instead and run `canbench`.
// `canbench` will detect and report the regression.
/*
#[ic_cdk::query]
fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 1,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}*/

#[cfg(feature = "canbench-rs")]
mod benches {
    use super::*;
    use canbench_rs::bench;

    #[bench]
    fn fibonacci_20() {
        // Prevent the compiler from optimizing the call and propagating constants.
        std::hint::black_box(fibonacci(std::hint::black_box(20)));
    }

    // Note how the results of the following three functions differ:
    #[bench]
    fn fibonacci_8a() {
        // this takes 454 instructions,
        std::hint::black_box(fibonacci(std::hint::black_box(8)));
    }
    #[bench]
    fn fibonacci_8b() {
        // this takes 207 instructions,
        std::hint::black_box(fibonacci(8));
    }
    #[bench]
    fn fibonacci_8c() {
        // and this takes 395 instructions.
        fibonacci(std::hint::black_box(8));
    }

    #[bench]
    fn fibonacci_45() {
        // Prevent the compiler from optimizing the call and propagating constants.
        std::hint::black_box(fibonacci(std::hint::black_box(45)));
    }
}

fn main() {}
