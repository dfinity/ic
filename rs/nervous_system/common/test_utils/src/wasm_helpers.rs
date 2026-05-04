use ic_crypto_sha2::Sha256;
use ic_wasm;
use lazy_static::lazy_static;
use libflate::gzip;
use std::io::Read;

/// A small, valid WASM suitable for tests.
pub const SMALLEST_VALID_WASM_BYTES: &[u8; 8] = &[0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];

lazy_static! {
    static ref SMALLEST_VALID_WASM_HASH: [u8; 32] = Sha256::hash(SMALLEST_VALID_WASM_BYTES);
}

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

/// Gzips a wasm, returning the hash of its compressed representation.
pub fn gzip_wasm(wasm: &[u8]) -> Vec<u8> {
    let mut encoder = gzip::Encoder::new(Vec::new()).expect("Failed to create gzip encoder.");
    std::io::copy(&mut &wasm[..], &mut encoder).expect("Failed to copy WASM bytes.");
    encoder
        .finish()
        .into_result()
        .expect("Failed to finish gzip encoding.")
}

/// Decompresses a previously gzipped wasm.
pub fn ungzip_wasm(gzipped_bytes: &[u8]) -> Vec<u8> {
    let mut decoder = gzip::Decoder::new(gzipped_bytes).expect("Failed to create gzip decoder.");
    let mut wasm_buf = Vec::new();
    decoder
        .read_to_end(&mut wasm_buf)
        .expect("Failed decoding Wasm.");
    wasm_buf
}
