#![no_main]
mod execute_with_wasm_executor;
mod ic_wasm;

use arbitrary::{Arbitrary, Unstructured};
use execute_with_wasm_executor::do_fuzz_task;
use ic_wasm::ICWasmConfig;
use std::slice;
use wasm_smith::ConfiguredModule;

enum Corpus {
    Keep = 0,
    Reject = -1,
}

#[no_mangle]
/// # Safety
///
/// This function allows to expose the libFuzzer fuzzing harness function
/// LLVMFuzzerTestOneInput for the fuzzing target to link with AFL at
/// compile time and utilize AFL's persistent (in-process) mode.
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(
    input_bytes: *const u8,
    input_size: libc::size_t,
) -> i32 {
    let data = unsafe { slice::from_raw_parts(input_bytes, input_size) };
    if data.len() < <ConfiguredModule<ICWasmConfig> as Arbitrary>::size_hint(0).0 {
        return Corpus::Reject as i32;
    }
    let u = Unstructured::new(data);
    let data = <ConfiguredModule<ICWasmConfig> as Arbitrary>::arbitrary_take_rest(u);

    let module = match data {
        Ok(d) => d,
        Err(_) => return Corpus::Reject as i32,
    };

    let wasm = module.module.to_bytes();
    do_fuzz_task(wasm);
    Corpus::Keep as i32
}
