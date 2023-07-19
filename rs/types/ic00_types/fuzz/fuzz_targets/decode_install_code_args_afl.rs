#![no_main]
use std::slice;
mod decode_install_code_args;
use decode_install_code_args::do_fuzz_task;

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
    do_fuzz_task(data);
    0
}
