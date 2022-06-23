use ic_crypto_sha::Sha256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum XmdError {
    InvalidOutputLength(String),
}

pub type XmdResult<T> = std::result::Result<T, XmdError>;

// Section 5.4.1 of https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-14.html
// Produces a uniformly random byte string of a given length using SHA-256
// from a message and domain separator.
// The desired length `len` must not exceed 255*32 = 8160 bytes.
pub fn expand_message_xmd(msg: &[u8], domain_separator: &[u8], len: usize) -> XmdResult<Vec<u8>> {
    const MAX_LEN: usize = 255 * 32;
    if len > MAX_LEN {
        return Err(XmdError::InvalidOutputLength(format!(
            "Requested XMD output length {} too large (max: {})",
            len, MAX_LEN
        )));
    }

    // len ≤ 8160 ⭢ ell ≤ 255
    // thus values ≤ ell can be safely cast to u8
    let ell = (len - 1) / 32 + 1;

    let xmd = |dst| {
        let mut out = Vec::with_capacity(ell * 32);

        let mut state = Sha256::new();
        state.write(&[0; 64]);
        state.write(msg);
        state.write(&[(len / 256) as u8, (len % 256) as u8, 0]);
        state.write(dst);
        state.write(&[dst.len() as u8]);

        let b_0: [u8; 32] = state.finish();

        state = Sha256::new();
        state.write(&b_0);
        state.write(&[1]);
        state.write(dst);
        state.write(&[dst.len() as u8]);
        out.extend_from_slice(&state.finish());

        for i in 2..=ell {
            let mut tmp = [0u8; 32];
            for j in 0..32 {
                tmp[j] = b_0[j] ^ out[out.len() - 32 + j];
            }
            state = Sha256::new();
            state.write(&tmp);
            state.write(&[i as u8]);
            state.write(dst);
            state.write(&[dst.len() as u8]);
            out.extend_from_slice(&state.finish());
        }

        out
    };

    let mut out = if domain_separator.len() >= 256 {
        let mut state = Sha256::new();
        state.write(b"H2C-OVERSIZE-DST-");
        state.write(domain_separator);
        xmd(&state.finish())
    } else {
        xmd(domain_separator)
    };

    out.truncate(len);
    Ok(out)
}
