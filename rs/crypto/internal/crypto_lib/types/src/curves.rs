//! Elliptic curve data types.
//!
//! Note: These are used in threshold signatures, multisignatures and
//! distributed key generation.

pub mod bls12_381 {
    //! Data types for the BLS12_381 elliptic curve.
    //!
    //! This is a pairing curve from which we use two groups, "G1" and "G2".

    use std::fmt;
    use zeroize::DefaultIsZeroes;

    /// A field representative in serialised, library independent form.
    ///
    /// # Content
    /// - bytes [0..32]: A big endian number
    ///
    /// # Interoperability
    /// - The IETF draft does not specify a serialisation for this:
    ///   https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/>
    #[derive(Copy, Clone, PartialEq, Eq, Hash)]
    pub struct FrBytes(pub [u8; FrBytes::SIZE]);
    crate::derive_serde!(FrBytes, FrBytes::SIZE);
    impl FrBytes {
        pub const SIZE: usize = 32;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; FrBytes::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for FrBytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Fr({:?})", hex::encode(&self.0[..]))
        }
    }
    impl Default for FrBytes {
        fn default() -> Self {
            FrBytes([0; FrBytes::SIZE])
        }
    }
    impl DefaultIsZeroes for FrBytes {}

    impl AsRef<[u8]> for FrBytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl From<[u8; FrBytes::SIZE]> for FrBytes {
        fn from(b: [u8; FrBytes::SIZE]) -> Self {
            Self(b)
        }
    }

    /// A point in the group "G1" in serialised, library independent form.
    ///
    /// # Content
    /// - bit (`byte[0]>>7`): compression flag: Should always be set to 1 as the
    ///   48 byte representation is compressed.
    /// - bit (`byte[0]>>6`): infinity: 1 if the point is at infinity, zero
    ///   otherwise.
    /// - bit (`byte[0]>>5`): sort flag: In the compressed form, where only x is
    ///   provided, this gives the sign of y.
    /// - all remaining bits and bytes: ( `byte[0]&0x1f` concat `byte[1..=47]` )
    ///   The x coordinate in big endian format.
    ///
    /// # Interoperability
    /// - This representation is consistent with IETF draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
    ///   which specifies the "compressed serialization formats for E1 and E2
    ///   defined by [ZCash]"
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct G1Bytes(pub [u8; G1Bytes::SIZE]);
    crate::derive_serde!(G1Bytes, G1Bytes::SIZE);

    impl G1Bytes {
        pub const SIZE: usize = 48;
        pub const COMPRESSED_FLAG: u8 = 1 << 7;
        pub const INFINITY_FLAG: u8 = 1 << 6;
        pub const SIGN_FLAG: u8 = 1 << 5;
        pub const NON_FLAG_BITS: u8 = 0x1f;
        pub const FLAG_BYTE_OFFSET: usize = 0;
        pub const X_BYTES_OFFSET: usize = 0;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; G1Bytes::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for G1Bytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "G1(0x{})", hex::encode(&self.0[..]))
        }
    }
    impl AsRef<[u8]> for G1Bytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl Default for G1Bytes {
        fn default() -> Self {
            G1Bytes([0; G1Bytes::SIZE])
        }
    }
    impl DefaultIsZeroes for G1Bytes {}
    impl From<[u8; G1Bytes::SIZE]> for G1Bytes {
        fn from(b: [u8; G1Bytes::SIZE]) -> Self {
            Self(b)
        }
    }

    /// A point in the group "G2".
    ///
    /// # Content
    /// - bit (`byte[0]>>7`): compression flag: Should always be set to 1 as the
    ///   96 byte representation is compressed.
    /// - bit (`byte[0]>>6`): infinity: 1 if the point is at infinity, zero
    ///   otherwise.
    /// - bit (`byte[0]>>5`): sort flag: In the compressed form, where only x is
    ///   provided, this gives the sign of y.
    /// - first 48 bytes excluding flags (`byte[0]&0x1f` concat `byte[1..=47]`):
    ///   The part "c1" of the x coordinate in big endian format.
    /// - next 48 bytes (`byte[48..=95]`): The part "c0" of the x coordinate in
    ///   big endian format
    ///
    /// # Interoperability
    /// - This representation is consistent with IETF draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1
    ///   which specifies the "compressed serialization formats for E1 and E2
    ///   defined by [ZCash]"
    /// - Ordering is by c1, or by c0 if the c1 are identical.
    #[derive(Copy, Clone, Eq, PartialEq, Hash)]
    pub struct G2Bytes(pub [u8; G2Bytes::SIZE]);
    crate::derive_serde!(G2Bytes, G2Bytes::SIZE);

    impl G2Bytes {
        pub const SIZE: usize = 96;
        pub const COMPRESSED_FLAG: u8 = 1 << 7;
        pub const INFINITY_FLAG: u8 = 1 << 6;
        pub const SIGN_FLAG: u8 = 1 << 5;
        pub const NON_FLAG_BITS: u8 = 0x1f;
        pub const FLAG_BYTE_OFFSET: usize = 0;
        pub const X1_BYTES_OFFSET: usize = 0;
        pub const X0_BYTES_OFFSET: usize = 48;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; G2Bytes::SIZE] {
            &self.0
        }
    }
    impl fmt::Debug for G2Bytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let hex_sig = hex::encode(&self.0[..]);
            write!(f, "G2(0x{})", hex_sig)
        }
    }
    impl AsRef<[u8]> for G2Bytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl Default for G2Bytes {
        fn default() -> Self {
            G2Bytes([0; G2Bytes::SIZE])
        }
    }
    impl DefaultIsZeroes for G2Bytes {}
    impl From<[u8; G2Bytes::SIZE]> for G2Bytes {
        fn from(b: [u8; G2Bytes::SIZE]) -> Self {
            Self(b)
        }
    }
}

#[cfg(test)]
mod test {
    use super::bls12_381::*;
    use zeroize::Zeroize;

    #[test]
    fn test_fr_zeroize_leaves_zero() {
        let mut fr = FrBytes([42u8; FrBytes::SIZE]);
        assert_ne!(fr, FrBytes::default());
        fr.zeroize();
        assert_eq!(fr, FrBytes::default());
    }

    #[test]
    fn test_g1_zeroize_leaves_zero() {
        let mut g1 = G1Bytes([42u8; G1Bytes::SIZE]);
        assert_ne!(g1, G1Bytes::default());
        g1.zeroize();
        assert_eq!(g1, G1Bytes::default());
    }

    #[test]
    fn test_g2_zeroize_leaves_zero() {
        let mut g2 = G2Bytes([42u8; G2Bytes::SIZE]);
        assert_ne!(g2, G2Bytes::default());
        g2.zeroize();
        assert_eq!(g2, G2Bytes::default());
    }
}
