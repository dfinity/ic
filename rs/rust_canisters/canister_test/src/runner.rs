use crate::canister::Wasm;
use std::env::args;

/// Normally when you use cargo run, cargo builds your target then runs the
/// generated artifact. When we write canisters this doesn't work normally
/// because the artifact is wasm rather than a binary. You can change this
/// behavior by changing your "cargo runner" in .cargo/config, this allows you
/// to prepend a command to the binary invocation. In the starter project this
/// command is
/// cargo run --bin runner -- <artifact path>
/// This function picks up that artifact path and outputs it as wasm to be used
/// in your runner function.
pub fn cargo_run(arg_number: Option<usize>) -> Wasm {
    let mut args = args();
    let wasm_arg_number = arg_number.unwrap_or(1);
    let wasm_filename =
        args
        .nth(wasm_arg_number)
        .ok_or_else(|| panic!(
            "Tried to get argument {0} but there are only {1} arguments, try changing from_args.wasm_arity",
            wasm_arg_number,
            args.len(),
        )).unwrap();
    Wasm::from_file(wasm_filename)
}
