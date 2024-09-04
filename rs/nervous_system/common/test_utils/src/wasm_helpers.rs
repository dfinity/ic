use ic_wasm;
use libflate::gzip;

/// A small, valid WASM suitable for tests.
pub const SMALLEST_VALID_WASM_BYTES: &[u8; 8] = &[0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];

/// Return a version of `wasm` extended with a metadata section
/// "icp:[public|private] $name$contents".
pub fn annotate_wasm_with_metadata(
    wasm: &[u8],
    is_public: bool,
    name: &str,
    contents: Vec<u8>,
) -> Vec<u8> {
    use ic_wasm::{metadata, utils};

    let kind = if is_public {
        metadata::Kind::Public
    } else {
        metadata::Kind::Private
    };

    let mut wasm_module = utils::parse_wasm(wasm, false).expect("Cannot parse WASM");
    metadata::add_metadata(&mut wasm_module, kind, name, contents);
    wasm_module.emit_wasm()
}

// Gzips a wasm, returning the hash of its compressed representation.
pub fn gzip_wasm(wasm: &[u8]) -> Vec<u8> {
    let mut encoder = gzip::Encoder::new(Vec::new()).expect("Failed to create gzip encoder.");
    std::io::copy(&mut &wasm[..], &mut encoder).expect("Failed to copy WASM bytes.");
    encoder
        .finish()
        .into_result()
        .expect("Failed to finish gzip encoding.")
}
