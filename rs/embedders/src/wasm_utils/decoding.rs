use ic_types::NumBytes;
use ic_wasm_types::{BinaryEncodedWasm, WasmValidationError};
use std::io::Read;
use std::sync::Arc;

enum WasmEncoding {
    Wasm,
    Gzip,
}

/// # Warning
///
/// If the Wasm is gzipped, then the returned size cannot be trusted. It would
/// come from the gzip footer which could have been manipulated.
fn wasm_encoding_and_size(
    module_bytes: &[u8],
) -> Result<(WasmEncoding, usize), WasmValidationError> {
    // \0asm is WebAssembly module magic bytes.
    // https://webassembly.github.io/spec/core/binary/modules.html#binary-module
    if module_bytes.starts_with(b"\x00asm") {
        return Ok((WasmEncoding::Wasm, module_bytes.len()));
    }

    // 1f 8b is GZIP magic number, 08 is DEFLATE algorithm.
    // https://datatracker.ietf.org/doc/html/rfc1952.html#page-6
    if module_bytes.starts_with(b"\x1f\x8b\x08") {
        // There should be at least an 8-byte header and an 8-byte footer.
        if module_bytes.len() < 16 {
            return Err(WasmValidationError::DecodingError(
                "invalid Wasm module: gzip stream is too short".to_string(),
            ));
        }

        // Get the uncompressed size from the footer.
        // The size is in the last 4 bytes in little-endian encoding.
        // https://datatracker.ietf.org/doc/html/rfc1952.html#page-5
        let mut isize_bytes = [0u8; 4];
        // We checked the size in advance so it's safe to access the last 4 bytes.
        isize_bytes.copy_from_slice(&module_bytes[module_bytes.len() - 4..module_bytes.len()]);
        let uncompressed_size = u32::from_le_bytes(isize_bytes) as usize;
        return Ok((WasmEncoding::Gzip, uncompressed_size));
    }

    Err(WasmValidationError::DecodingError(
        "unsupported canister module format".to_string(),
    ))
}

/// Returns the expected size of the Wasm that will result from decoding this module
/// (which may require uncompressing it).
///
/// # Warning
/// The returned size cannot be trusted. If the canisters is compressed, the
/// size in the gzip file may have been manipulated.
///
/// This function doesn't actually unzip the module - it just reads the header
/// and footer, so is safe to run outside of the sandbox.
pub fn decoded_wasm_size(module_bytes: &[u8]) -> Result<usize, WasmValidationError> {
    wasm_encoding_and_size(module_bytes).map(|(_, s)| s)
}

/// Decodes a WebAssembly module, uncompressing it if required.
pub fn decode_wasm(
    max_size: NumBytes,
    module: Arc<Vec<u8>>,
) -> Result<BinaryEncodedWasm, WasmValidationError> {
    let module_bytes = module.as_slice();
    let (encoding, uncompressed_size) = wasm_encoding_and_size(module_bytes)?;
    if uncompressed_size as u64 > max_size.get() {
        return Err(WasmValidationError::ModuleTooLarge {
            size: uncompressed_size as u64,
            allowed: max_size.get(),
        });
    }

    match encoding {
        WasmEncoding::Wasm => Ok(BinaryEncodedWasm::new_shared(module)),
        WasmEncoding::Gzip => {
            let decoder = libflate::gzip::Decoder::new(module_bytes).map_err(|e| {
                WasmValidationError::DecodingError(format!(
                    "failed to decode compressed Wasm module: {e}"
                ))
            })?;

            let mut buf = Vec::with_capacity(uncompressed_size);
            // We cannot trust that the uncompressed size is set correctly.
            // Even if the size bytes are correct, they are only size modulo
            // 2^32.  To handle gzip bombs gracefully, we don't read more than
            // the uncompressed size from the uncompressed stream. We've already
            // checked that the uncompressed size is less than the maximum
            // module size.
            decoder
                .take(uncompressed_size as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(|e| {
                    WasmValidationError::DecodingError(format!(
                        "failed to decode compressed Wasm module: {e}"
                    ))
                })?;

            if buf.len() != uncompressed_size {
                return Err(WasmValidationError::DecodingError(format!(
                    "specified uncompressed size {} does not match extracted size {}",
                    uncompressed_size,
                    buf.len()
                )));
            }
            Ok(BinaryEncodedWasm::new(buf))
        }
    }
}
