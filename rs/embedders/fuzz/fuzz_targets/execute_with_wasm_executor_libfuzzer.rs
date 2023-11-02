#![no_main]
mod execute_with_wasm_executor;
mod ic_wasm;

use execute_with_wasm_executor::do_fuzz_task;
use ic_wasm::ICWasmConfig;
use libfuzzer_sys::fuzz_target;
use wasm_smith::ConfiguredModule;

fuzz_target!(|module: ConfiguredModule<ICWasmConfig>| {
    let wasm = module.module.to_bytes();
    do_fuzz_task(wasm);
});
