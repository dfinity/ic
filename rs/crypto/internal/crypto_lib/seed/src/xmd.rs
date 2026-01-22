use ic_crypto_sha2::{Sha256, Sha512};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum XmdError {
    InvalidOutputLength(String),
}

pub type XmdResult<T> = std::result::Result<T, XmdError>;

pub trait XmdHashFunction {
    const BLOCK_BYTES: usize;
    const OUTPUT_BYTES: usize;

    fn new() -> Self;
    fn write(&mut self, data: &[u8]);

    // Ideally in the future this would return [u8; Self::OUTPUT_BYTES]
    // but this requires unstable features.
    fn finish(self) -> Vec<u8>;
}

impl XmdHashFunction for Sha256 {
    const BLOCK_BYTES: usize = 64;
    const OUTPUT_BYTES: usize = 32;

    fn new() -> Self {
        Sha256::new()
    }
    fn write(&mut self, data: &[u8]) {
        self.write(data);
    }
    fn finish(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

impl XmdHashFunction for Sha512 {
    const BLOCK_BYTES: usize = 128;
    const OUTPUT_BYTES: usize = 64;

    fn new() -> Self {
        Sha512::new()
    }
    fn write(&mut self, data: &[u8]) {
        self.write(data);
    }
    fn finish(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

struct SizeCheck<const L: usize>;

impl<const L: usize> SizeCheck<L> {
    // This assumes no XmdHashFunction has a DIGEST_LEN < 32
    const XMD_CAN_PRODUCE_THIS_OUTPUT: usize = 255 * 32 - L;
}

/// XMD function
///
/// See section 5.4.1 of RFC 9380
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmd>
///
/// Produces a uniformly random byte string of a given length using a hash
/// from a message and domain separator.
///
/// The output length is upper bounded by 8160 bytes; SHA-512 can produce
/// more but it's not possible to write the compile-time assertion to cover
/// this case.
///
pub fn xmd<const N: usize, H: XmdHashFunction>(msg: &[u8], dst: &[u8]) -> [u8; N] {
    // Compile time assertion that XMD can output the requested bytes
    let _ = SizeCheck::<N>::XMD_CAN_PRODUCE_THIS_OUTPUT;

    let mut output = [0u8; N];
    inner_xmd::<H>(&mut output[..], msg, dst);
    output
}

/// XMD function
///
/// See section 5.4.1 of RFC 9380
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmd>
///
/// Produces a uniformly random byte string of a given length using a hash
/// from a message and domain separator.
///
/// This function errors if the desired output length exceeds the maximum
/// allowable for XMD, which is 255 times the output length of the hash;
/// 8160 bytes for SHA-256 or 16320 bytes for SHA-512.
///
pub fn varlen_xmd<H: XmdHashFunction>(msg: &[u8], dst: &[u8], len: usize) -> XmdResult<Vec<u8>> {
    if len > 255 * H::OUTPUT_BYTES {
        return Err(XmdError::InvalidOutputLength(format!(
            "Requested XMD output length {} too large (max: {})",
            len,
            255 * H::OUTPUT_BYTES
        )));
    }

    let mut output = vec![0u8; len];
    inner_xmd::<H>(&mut output, msg, dst);
    Ok(output)
}

/// XMD function
///
/// See section 5.4.1 of RFC 9380
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmd>
///
/// Produces a uniformly random byte string of a given length using a hash
/// from a message and domain separator.
///
/// This function panics if the desired output length exceeds the maximum
/// allowable for XMD, which is 255 times the output length of the hash;
/// 8160 bytes for SHA-256 or 16320 bytes for SHA-512. It i
///
fn inner_xmd<H: XmdHashFunction>(out: &mut [u8], msg: &[u8], dst: &[u8]) {
    let len = out.len();

    if len > 255 * H::OUTPUT_BYTES {
        // unreachable because we assume our callers checked this already
        unreachable!("Invalid XMD output length");
    }

    if dst.len() >= 256 {
        let mut state = H::new();
        state.write(b"H2C-OVERSIZE-DST-");
        state.write(dst);
        inner_xmd::<H>(out, msg, &state.finish());
        return;
    }

    // len ≤ 255*H::OUTPUT_BYTES ⭢ ell ≤ 255
    // thus values ≤ ell can be safely cast to u8
    let ell = len.div_ceil(H::OUTPUT_BYTES);

    let mut state = H::new();
    state.write(&vec![0; H::BLOCK_BYTES]);
    state.write(msg);
    state.write(&[(len / 256) as u8, (len % 256) as u8, 0]);
    state.write(dst);
    state.write(&[dst.len() as u8]);

    let b_0 = state.finish();

    state = H::new();
    state.write(&b_0);
    state.write(&[1]);
    state.write(dst);
    state.write(&[dst.len() as u8]);

    let first_block = std::cmp::min(H::OUTPUT_BYTES, len);
    out[0..first_block].copy_from_slice(&state.finish()[0..first_block]);

    // Has to be a Vec rather than an array due to const generics limitations
    let mut tmp = vec![0; H::OUTPUT_BYTES];

    for i in 2..=ell {
        let offset = (i - 1) * H::OUTPUT_BYTES;
        let remaining = out.len() - offset;
        let to_copy = std::cmp::min(H::OUTPUT_BYTES, remaining);

        for j in 0..H::OUTPUT_BYTES {
            tmp[j] = b_0[j] ^ out[offset - H::OUTPUT_BYTES + j];
        }

        state = H::new();
        state.write(&tmp);
        state.write(&[i as u8]);
        state.write(dst);
        state.write(&[dst.len() as u8]);
        let h = state.finish();

        out[offset..offset + to_copy].copy_from_slice(&h[0..to_copy]);
    }
}
