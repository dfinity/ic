use ic_crypto_sha2::{Sha256, Sha512};

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

pub trait XmdHashFunctionWithSizeCheck<const N: usize>: XmdHashFunction {
    const XMD_CAN_PRODUCE_THIS_OUTPUT: () = if N > 255 * Self::OUTPUT_BYTES {
        panic!("XMD output length exceeds maximum allowed length");
    };
}
impl<const N: usize, T: XmdHashFunction> XmdHashFunctionWithSizeCheck<N> for T {}

/// XMD function
///
/// See section 5.4.1 of RFC 9380
/// <https://www.rfc-editor.org/rfc/rfc9380.html#name-expand_message_xmd>
///
/// Produces a uniformly random byte string of a given length using a hash
/// from a message and domain separator.
///
/// As defined, XMD can only produce outputs up to 255 times the length
/// of the hash output: for SHA-256 that's 8160 bytes, for SHA-512 16320 bytes.
/// Values of N larger than this will fail to compile.
///
pub fn xmd<const N: usize, H: XmdHashFunctionWithSizeCheck<N>>(msg: &[u8], dst: &[u8]) -> [u8; N] {
    // Compile time assertion that XMD can output the requested bytes
    #[allow(clippy::let_unit_value)]
    let _ = H::XMD_CAN_PRODUCE_THIS_OUTPUT;

    let mut out = [0u8; N];

    if dst.len() >= 256 {
        let mut state = H::new();
        state.write(b"H2C-OVERSIZE-DST-");
        state.write(dst);
        return xmd::<N, H>(msg, &state.finish());
    }

    // len ≤ 255*H::OUTPUT_BYTES ⭢ ell ≤ 255
    // thus values ≤ ell can be safely cast to u8
    let ell: usize = N.div_ceil(H::OUTPUT_BYTES);

    let mut state = H::new();
    state.write(&vec![0; H::BLOCK_BYTES]);
    state.write(msg);
    state.write(&[(N / 256) as u8, (N % 256) as u8, 0]);
    state.write(dst);
    state.write(&[dst.len() as u8]);

    let b_0 = state.finish();

    state = H::new();
    state.write(&b_0);
    state.write(&[1]);
    state.write(dst);
    state.write(&[dst.len() as u8]);

    let first_block = std::cmp::min(H::OUTPUT_BYTES, N);
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

    out
}
