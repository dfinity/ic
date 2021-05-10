use ic_wasm_types::ParityWasmError;
use parity_wasm::elements::Error;

/// Converts a `parity_wasm::elements::Error` to our own ParityWasmError.
///
/// We purposefully do not define this function in `ic_wasm_types`.  This is
/// because `ic_interfaces` depends upon `ic_wasm_utils` and a bulk of our code
/// depends upon `ic_interfaces`, hence if `ic_wasm_utils` were to depend upon
/// `parity_wasm`, that will cause an unnecessary dependency for the bulk of our
/// code.
pub(crate) fn into_parity_wasm_error(err: Error) -> ParityWasmError {
    ParityWasmError::new(err.to_string())
}
