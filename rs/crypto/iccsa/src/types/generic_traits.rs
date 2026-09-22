//! Generic traits for basic_sig iccsa types.

use super::*;
use base64::prelude::*;

use std::fmt;

#[cfg(test)]
mod tests;

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignatureBytes({:?})",
            BASE64_STANDARD.encode(&self.0[..])
        )
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKeyBytes({:?})",
            BASE64_STANDARD.encode(&self.0[..])
        )
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey{{ signing_canister_id: {:?}, seed: {} }}",
            self.signing_canister_id,
            BASE64_STANDARD.encode(&self.seed[..])
        )
    }
}
