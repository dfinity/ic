#![no_main]
use libfuzzer_sys::fuzz_target;

mod decode_install_code_args;
use decode_install_code_args::do_fuzz_task;

fuzz_target!(|data: &[u8]| {
    do_fuzz_task(data);
});
