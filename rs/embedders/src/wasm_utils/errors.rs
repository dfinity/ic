use ic_wasm_types::WasmError;
use parity_wasm::elements::Error;

/// Converts a `parity_wasm::elements::Error` to our own WasmError.
///
/// We purposefully do not define this function in `ic_wasm_types`.  This is
/// because `ic_interfaces` depends upon `ic_wasm_types` and a bulk of our code
/// depends upon `ic_interfaces`, hence if `ic_wasm_types` were to depend upon
/// `parity_wasm`, that will cause an unnecessary dependency for the bulk of our
/// code.
pub(crate) fn into_wasm_error(err: Error) -> WasmError {
    WasmError::new(err.to_string())
}
