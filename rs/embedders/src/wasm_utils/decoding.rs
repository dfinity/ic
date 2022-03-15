use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use std::io::Read;
use std::sync::Arc;

/// Maximum size of a WebAssembly module.
pub const MAX_WASM_MODULE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Decodes a WebAssembly module, uncompressing it if required.
pub fn decode_wasm(module: Arc<Vec<u8>>) -> Result<BinaryEncodedWasm, WasmValidationError> {
    fn make_module_too_large_error() -> WasmValidationError {
        WasmValidationError::DecodingError(format!(
            "Wasm module is too large, it can be at most {} bytes",
            MAX_WASM_MODULE_SIZE_BYTES
        ))
    }
    let module_bytes = module.as_slice();
    // \0asm is WebAssembly module magic bytes.
    // https://webassembly.github.io/spec/core/binary/modules.html#binary-module
    if module_bytes.starts_with(b"\x00asm") {
        if module.len() > MAX_WASM_MODULE_SIZE_BYTES {
            return Err(make_module_too_large_error());
        }
        return Ok(BinaryEncodedWasm::new_shared(module));
    }
    // 1f 8b is GZIP magic number, 08 is DEFLATE algorithm.
    // https://datatracker.ietf.org/doc/html/rfc1952.html#page-6
    if module_bytes.starts_with(b"\x1f\x8b\x08") {
        // There should be at least an 8-byte header and an 8-byte footer.
        if module.len() < 16 {
            return Err(WasmValidationError::DecodingError(
                "invalid Wasm module: gzip stream is too short".to_string(),
            ));
        }

        // Get the uncompressed size from the footer.
        // The size is in the last 4 bytes in little-endian encoding.
        // https://datatracker.ietf.org/doc/html/rfc1952.html#page-5
        let mut isize_bytes = [0u8; 4];
        // We checked the size in advance so it's safe to access the last 4 bytes.
        isize_bytes.copy_from_slice(&module_bytes[module.len() - 4..module.len()]);
        let uncompressed_size = u32::from_le_bytes(isize_bytes) as usize;

        if uncompressed_size > MAX_WASM_MODULE_SIZE_BYTES {
            return Err(make_module_too_large_error());
        }

        let decoder = libflate::gzip::Decoder::new(module_bytes).map_err(|e| {
            WasmValidationError::DecodingError(format!(
                "failed to decode compressed Wasm module: {}",
                e
            ))
        })?;

        let mut buf = Vec::with_capacity(uncompressed_size);
        // We cannot trust that the uncompressed size is set correctly.
        // Even if the size bytes are correct, they are only size modulo 2^32.
        // To handle gzip bombs gracefully, we don't read more than the module
        // size limit from the uncompressed stream.
        decoder
            .take(MAX_WASM_MODULE_SIZE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| {
                WasmValidationError::DecodingError(format!(
                    "failed to decode compressed Wasm module: {}",
                    e
                ))
            })?;

        if buf.len() > MAX_WASM_MODULE_SIZE_BYTES {
            return Err(make_module_too_large_error());
        }
        if buf.len() != uncompressed_size {
            return Err(WasmValidationError::DecodingError(format!(
                "specified uncompressed size {} does not match extracted size {}",
                uncompressed_size,
                buf.len()
            )));
        }
        return Ok(BinaryEncodedWasm::new(buf));
    }
    Err(WasmValidationError::DecodingError(
        "unsupported canister module format".to_string(),
    ))
}
