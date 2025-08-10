#![no_main]
// Clippy is, for a good reason, convinced that due to the following line in the
// `fuzz_mutator` expansion, its generated function `rust_fuzzer_custom_mutator` should also be
// marked unsafe. But since this is part of the fuzzer, let's just disable the corresponding lint.
// let $data: &mut [u8] = unsafe { std::slice::from_raw_parts_mut($data, len) };"
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use ic_crypto_tree_hash_fuzz_check_witness_equality_utils::test_absence_witness;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

mod common;

fuzz_target!(|data: &[u8]| {
    common::fuzz_target(data, test_absence_witness);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    common::fuzz_mutator(data, size, max_size, seed)
});
