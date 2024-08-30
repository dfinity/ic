use crate::tx;
use std::borrow::Cow;
use std::fmt;

/// The length of the transaction signature.
pub const MAX_ENCODED_SIGNATURE_LEN: usize = 73;

const FAKE_SIG: [u8; MAX_ENCODED_SIGNATURE_LEN] = [
    0x30, 70, 0x02, 33, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 33, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// DER-encoded ECDSA signature with an trailing byte indicating
// the signature type (SIGHASH_ALL in our case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSignature(Cow<'static, [u8]>);

impl fmt::Display for EncodedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl EncodedSignature {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, String> {
        validate_encoded_signature(bytes)?;
        Ok(Self(Cow::Owned(bytes.to_vec())))
    }

    /// Encodes a SEC1 signature to the format that the Bitcoin network expects.
    pub fn from_sec1(sec1: &[u8]) -> Self {
        let mut sig = sec1_to_der(sec1);
        // The signature must end with a single byte indicating the SIGHASH type.
        sig.push(tx::SIGHASH_ALL as u8);
        debug_assert_eq!(Ok(()), validate_encoded_signature(&sig));
        Self(Cow::Owned(sig))
    }

    /// Returns the longest valid encoded signature.
    pub fn fake() -> Self {
        Self(Cow::Borrowed(&FAKE_SIG[..]))
    }
}

/// Converts a SEC1 ECDSA signature to the DER format.
///
/// # Panics
///
/// This function panics if:
/// * The input slice is not 64 bytes long.
/// * Either S or R signature components are zero.
pub fn sec1_to_der(sec1: &[u8]) -> Vec<u8> {
    // See:
    // * https://github.com/bitcoin/bitcoin/blob/5668ccec1d3785632caf4b74c1701019ecc88f41/src/script/interpreter.cpp#L97-L170
    // * https://github.com/bitcoin/bitcoin/blob/d08b63baa020651d3cc5597c85d5316cb39aaf59/src/secp256k1/src/ecdsa_impl.h#L183-L205
    // * https://security.stackexchange.com/questions/174095/convert-ecdsa-signature-from-plain-to-der-format
    // * "Mastering Bitcoin", 2nd edition, p. 140, "Serialization of signatures (DER)".

    fn push_integer(buf: &mut Vec<u8>, mut bytes: &[u8]) -> u8 {
        while !bytes.is_empty() && bytes[0] == 0 {
            bytes = &bytes[1..];
        }

        assert!(
            !bytes.is_empty(),
            "bug: one of the signature components is zero"
        );

        assert_ne!(bytes[0], 0);

        let neg = bytes[0] & 0x80 != 0;
        let n = if neg { bytes.len() + 1 } else { bytes.len() };
        debug_assert!(n <= u8::MAX as usize);

        buf.push(0x02);
        buf.push(n as u8);
        if neg {
            buf.push(0);
        }
        buf.extend_from_slice(bytes);
        n as u8
    }

    assert_eq!(
        sec1.len(),
        64,
        "bug: a SEC1 signature must be 64 bytes long"
    );

    let r = &sec1[..32];
    let s = &sec1[32..];

    let mut buf = Vec::with_capacity(72);
    // Start of the DER sequence.
    buf.push(0x30);
    // The length of the sequence:
    // Two bytes for integer markers and two bytes for lengths of the integers.
    buf.push(4);
    let rlen = push_integer(&mut buf, r);
    let slen = push_integer(&mut buf, s);
    buf[1] += rlen + slen; // Update the sequence length.
    buf
}

pub fn validate_encoded_signature(sig: &[u8]) -> Result<(), String> {
    // Ported to Rust from
    // https://github.com/bitcoin/bitcoin/blob/5668ccec1d3785632caf4b74c1701019ecc88f41/src/script/interpreter.cpp#L97-L170.

    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integer (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if sig.len() < 9 {
        return Err(format!(
            "expected the signature to have at least 9 bytes, got: {}",
            hex::encode(sig)
        ));
    }
    if sig.len() > MAX_ENCODED_SIGNATURE_LEN {
        return Err(format!(
            "expected the signature to have at most {} bytes, got: {}",
            MAX_ENCODED_SIGNATURE_LEN,
            hex::encode(sig)
        ));
    };

    // A signature is of type 0x30 (compound).
    if sig[0] != 0x30 {
        return Err(format!("the first byte must be {}, got: {}", 0x30, sig[0]));
    };

    // Make sure the length covers the entire signature.
    if sig[1] as usize != sig.len() - 3 {
        return Err(format!(
            "DER sequence length is incorrect: encoded {}, actual: {}",
            sig[1],
            sig.len() - 3
        ));
    };

    // Extract the length of the R element.
    let rlen = sig[3] as usize;

    // Make sure the length of the S element is still inside the signature.
    if 5 + rlen >= sig.len() {
        return Err("the S element is not inside the signature".to_string());
    }

    // Extract the length of the S element.
    let slen = sig[5 + rlen] as usize;

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if rlen + slen + 7 != sig.len() {
        return Err("the signature length does not match the length of the elements".to_string());
    }

    // Check whether the R element is an integer.
    if sig[2] != 0x02 {
        return Err("R is not an integer".to_string());
    }

    // Zero-length integers are not allowed for R.
    if rlen == 0 {
        return Err("zero-length integers are not allowed for R".to_string());
    }

    // Negative numbers are not allowed for R.
    if sig[4] & 0x80 != 0 {
        return Err("R is negative".to_string());
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if rlen > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return Err("unnecessary zero padding in R".to_string());
    }

    // Check whether the S element is an integer.
    if sig[rlen + 4] != 0x02 {
        return Err("S is not an integer".to_string());
    }

    // Zero-length integers are not allowed for S.
    if slen == 0 {
        return Err("S has zero length".to_string());
    }

    // Negative numbers are not allowed for S.
    if sig[rlen + 6] & 0x80 != 0 {
        return Err("S is negative".to_string());
    }

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if slen > 1 && sig[rlen + 6] == 0x00 && sig[rlen + 7] & 0x80 == 0 {
        return Err("unnecessary zero padding in S".to_string());
    }

    Ok(())
}
