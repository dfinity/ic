//! This module defines well-known CBOR tags used for block decoding.

/// Tag for Self-described CBOR; see https://www.rfc-editor.org/rfc/rfc8949.html#name-self-described-cbor.
pub const SELF_DESCRIBED: u64 = 55799;

/// Tag for CBOR bignums; see https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums.
pub const BIGNUM: u64 = 2;

/// Tag for negative CBOR bignums; see https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums.
pub const NEG_BIGNUM: u64 = 3;
