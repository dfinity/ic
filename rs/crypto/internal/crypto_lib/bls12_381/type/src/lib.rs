//! Wrapper for BLS12-381 operations

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]

mod miracl;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use pairing::group::{ff::Field, Group};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

macro_rules! ctoption_ok_or {
    ($val:expr, $err:expr) => {
        if bool::from($val.is_some()) {
            Ok(Self::new($val.unwrap()))
        } else {
            Err($err)
        }
    };
}

/// Error returned if a point encoding is invalid
#[derive(Copy, Clone, Debug)]
pub enum PairingInvalidPoint {
    /// The point encoding was invalid
    InvalidPoint,
}

/// Error returned if a scalar encoding is invalid
#[derive(Copy, Clone, Debug)]
pub enum PairingInvalidScalar {
    /// The scalar encoding was invalid
    InvalidScalar,
}

/// An integer of the order of the groups G1/G2/Gt
#[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
pub struct Scalar {
    value: bls12_381::Scalar,
}

impl Scalar {
    /// The size in bytes of this type
    pub const BYTES: usize = 32;

    /// Create a new Scalar from the inner type
    pub(crate) fn new(value: bls12_381::Scalar) -> Self {
        Self { value }
    }

    /// Return the inner value
    pub(crate) fn inner(&self) -> &bls12_381::Scalar {
        &self.value
    }

    /// Create a scalar from a small integer value
    pub fn from_u64(v: u64) -> Self {
        let value: [u64; 4] = [v, 0, 0, 0];
        Self::new(bls12_381::Scalar::from_raw(value))
    }

    /// Create a scalar from a small integer value
    pub fn from_u32(v: u32) -> Self {
        Self::from_u64(v as u64)
    }

    /// Create a scalar from a small integer value
    pub fn from_i32(v: i32) -> Self {
        if v < 0 {
            Self::from_u64((v as i64).abs() as u64).neg()
        } else {
            Self::from_u64(v.abs() as u64)
        }
    }

    /// Deterministically hash an input onto a BLS12-381 scalar
    ///
    /// The input ``digest`` should be the output of SHA-256
    pub fn legacy_hash_to_fr(digest: [u8; 32]) -> Self {
        use rand::SeedableRng;

        let mut rng = rand_chacha::ChaChaRng::from_seed(digest);
        Self::legacy_random_generation(&mut rng)
    }

    /// Randomly generate a scalar in a way that is compatible with zkcrypto/pairing 0.4.0
    ///
    /// This should not be used for new code but only for compatability in situations where
    /// Fr::random was previously used
    pub fn legacy_random_generation<R: RngCore>(rng: &mut R) -> Self {
        loop {
            let mut repr = [0u64; 4];
            for r in repr.iter_mut() {
                *r = rng.next_u64();
            }

            /*
            Since the modulus is 255 bits, we clear out the most significant bit to
            reduce number of repetitions for the rejection sampling.

            (This also matches the logic used in the old version of zcrypto/pairing,
            which we are attempting to maintain bit-for-bit compatability with)
             */
            repr[3] &= 0xffffffffffffffff >> 1;

            let mut repr8 = [0u8; 32];
            repr8[..8].copy_from_slice(&repr[0].to_le_bytes());
            repr8[8..16].copy_from_slice(&repr[1].to_le_bytes());
            repr8[16..24].copy_from_slice(&repr[2].to_le_bytes());
            repr8[24..].copy_from_slice(&repr[3].to_le_bytes());

            let scalar = bls12_381::Scalar::from_bytes(&repr8);

            if bool::from(scalar.is_none()) {
                continue; // out of range
            }

            let mut scalar = scalar.unwrap();

            /*
            The purpose of this function is to maintain bit-compatability with old
            versions of zkcrypto/pairing's Fr::random. That function generates random
            values by generating a random integer, then treating it as if it was already
            in Montgomery format; that is, x is stored as xR where R == 2**256, and so
            the value that Fr::random produces is really z*R^-1 where z is the RNG
            output.

            To produce this value using the public API we have to first generate the
            value, then multiply by R^-1 mod p, which is the constant below using
            little-endian convention, ie the value is really 0x1bbe869...5c040.
            Here R == 2**256 and p is the order of the BLS12-381 subgroup.
             */
            let montgomery_fixup = [
                0x13f75b69fe75c040,
                0xab6fca8f09dc705f,
                0x7204078a4f77266a,
                0x1bbe869330009d57,
            ];

            let montgomery_fixup = bls12_381::Scalar::from_raw(montgomery_fixup);
            scalar *= montgomery_fixup;

            return Self::new(scalar);
        }
    }

    /// Return the scalar 0
    pub fn zero() -> Self {
        Self::new(bls12_381::Scalar::zero())
    }

    /// Return the scalar 1
    pub fn one() -> Self {
        Self::new(bls12_381::Scalar::one())
    }

    /// Return true iff this value is zero
    pub fn is_zero(&self) -> bool {
        bool::from(self.value.is_zero())
    }

    /// Return the additive inverse of this scalar
    pub fn neg(&self) -> Self {
        Self::new(self.value.neg())
    }

    /// Return the multiplicative inverse of this scalar if it exists
    pub fn inverse(&self) -> Option<Self> {
        let inv = self.value.invert();
        if bool::from(inv.is_some()) {
            Some(Self::new(inv.unwrap()))
        } else {
            None
        }
    }

    /// Return a random scalar
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            /*
            A BLS12-381 scalar is 255 bits long. Generate the scalar using
            rejection sampling by creating a 255 bit random bitstring then
            checking if it is less than the group order.
            */
            let mut buf = [0u8; Self::BYTES];
            rng.fill_bytes(&mut buf);
            buf[0] &= 0b0111_1111; // clear the 256th bit

            if let Ok(s) = Self::deserialize(&buf) {
                return s;
            }
        }
    }

    /// Decode a scalar as a big-endian byte string, accepting out of range elements
    ///
    /// Out of range elements are reduced modulo the group order
    pub fn deserialize_unchecked(bytes: [u8; Self::BYTES]) -> Self {
        let mut le_bytes = [0u8; 64];

        for i in 0..Self::BYTES {
            le_bytes[i] = bytes[Self::BYTES - i - 1];
        }
        // le_bytes[32..64] left as zero
        Self::new(bls12_381::Scalar::from_bytes_wide(&le_bytes))
    }

    /// Deserialize a scalar from a big-endian byte string
    pub fn deserialize(bytes: &[u8]) -> Result<Self, PairingInvalidScalar> {
        let mut bytes: [u8; Self::BYTES] = bytes
            .try_into()
            .map_err(|_| PairingInvalidScalar::InvalidScalar)?;
        bytes.reverse();
        let scalar = bls12_381::Scalar::from_bytes(&bytes);
        ctoption_ok_or!(scalar, PairingInvalidScalar::InvalidScalar)
    }

    /// Serialize the scalar to a big-endian byte string
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        let mut bytes = self.value.to_bytes();
        bytes.reverse();
        bytes
    }
}

macro_rules! declare_addsub_ops_for {
    ( $typ:ty ) => {
        impl std::ops::Add for $typ {
            type Output = Self;

            fn add(self, other: Self) -> Self {
                Self::new(self.inner() + other.inner())
            }
        }

        impl std::ops::Sub for $typ {
            type Output = Self;

            fn sub(self, other: Self) -> Self {
                Self::new(self.inner() - other.inner())
            }
        }

        impl std::ops::AddAssign for $typ {
            fn add_assign(&mut self, other: Self) {
                self.value += other.inner()
            }
        }

        impl std::ops::AddAssign<&$typ> for $typ {
            fn add_assign(&mut self, other: &Self) {
                self.value += other.inner()
            }
        }

        impl std::ops::SubAssign for $typ {
            fn sub_assign(&mut self, other: Self) {
                self.value -= other.inner()
            }
        }

        impl std::ops::SubAssign<&$typ> for $typ {
            fn sub_assign(&mut self, other: &Self) {
                self.value -= other.inner()
            }
        }
    };
}

macro_rules! declare_mul_scalar_ops_for {
    ( $typ:ty ) => {
        impl std::ops::Mul<Scalar> for $typ {
            type Output = Self;
            fn mul(self, scalar: Scalar) -> Self {
                Self::new(self.inner() * scalar.inner())
            }
        }

        impl std::ops::Mul<&Scalar> for $typ {
            type Output = Self;
            fn mul(self, scalar: &Scalar) -> Self {
                Self::new(self.inner() * scalar.inner())
            }
        }

        impl std::ops::MulAssign<Scalar> for $typ {
            fn mul_assign(&mut self, other: Scalar) {
                self.value *= other.inner()
            }
        }

        impl std::ops::MulAssign<&Scalar> for $typ {
            fn mul_assign(&mut self, other: &Scalar) {
                self.value *= other.inner()
            }
        }
    };
}

declare_addsub_ops_for!(Scalar);
declare_mul_scalar_ops_for!(Scalar);

macro_rules! define_affine_and_projective_types {
    ( $affine:ident, $projective:ident, $size:expr ) => {
        /// An element of the group in affine form
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
        pub struct $affine {
            value: bls12_381::$affine
        }

        impl $affine {
            /// The size in bytes of this type
            pub const BYTES: usize = $size;

            /// Create a struct from the inner type
            pub(crate) fn new(value: bls12_381::$affine) -> Self {
                Self { value }
            }

            /// Return the inner value
            pub(crate) fn inner(&self) -> &bls12_381::$affine {
                &self.value
            }

            /// Return the identity element in this group
            pub fn identity() -> Self {
                Self::new(bls12_381::$affine::identity())
            }

            /// Return the generator element in this group
            pub fn generator() -> Self {
                Self::new(bls12_381::$affine::generator())
            }

            /// Hash into the group
            ///
            /// This follows draft-irtf-cfrg-hash-to-curve-16 using the
            /// BLS12381G1_XMD:SHA-256_SSWU_RO_ or
            /// BLS12381G2_XMD:SHA-256_SSWU_RO_ suite.
            ///
            /// # Arguments
            /// * `domain_sep` - some protocol specific domain seperator
            /// * `input` - the input which will be hashed
            pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
                $projective::hash(domain_sep, input).into()
            }

            /// Deserialize a point (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs.
            pub fn deserialize(bytes: &[u8]) -> Result<Self, PairingInvalidPoint> {
                let bytes : &[u8; Self::BYTES] = bytes
                    .try_into()
                    .map_err(|_| PairingInvalidPoint::InvalidPoint)?;
                let pt = bls12_381::$affine::from_compressed(bytes);
                ctoption_ok_or!(pt, PairingInvalidPoint::InvalidPoint)
            }

            /// Deserialize a point (compressed format only), trusted bytes edition
            ///
            /// As only compressed format is accepted, it is not possible to
            /// create a point which is not on the curve. However it is possible
            /// using this function to create a point which is not within the
            /// prime-order subgroup. This can be detected by calling is_torsion_free
            pub fn deserialize_unchecked(bytes: &[u8]) -> Result<Self, PairingInvalidPoint> {
                let bytes : &[u8; Self::BYTES] = bytes
                    .try_into()
                    .map_err(|_| PairingInvalidPoint::InvalidPoint)?;
                let pt = bls12_381::$affine::from_compressed_unchecked(bytes);
                ctoption_ok_or!(pt, PairingInvalidPoint::InvalidPoint)
            }

            /// Serialize this point in compressed format
            pub fn serialize(&self) -> [u8; Self::BYTES] {
                self.value.to_compressed()
            }

            /// Return true if this is the identity element
            pub fn is_identity(&self) -> bool {
                bool::from(self.value.is_identity())
            }

            /// Return true if this value is in the prime-order subgroup
            ///
            /// This will always be true unless the unchecked deserialization
            /// routine is used.
            pub fn is_torsion_free(&self) -> bool {
                bool::from(self.value.is_torsion_free())
            }

            /// Return the inverse of this point
            pub fn neg(&self) -> Self {
                use std::ops::Neg;
                Self::new(self.value.neg())
            }
        }

        /// An element of the group in projective form
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Zeroize)]
        pub struct $projective {
            value: bls12_381::$projective
        }

        impl $projective {
            /// The size in bytes of this type
            pub const BYTES: usize = $size;

            /// Create a new struct from the inner type
            pub(crate) fn new(value: bls12_381::$projective) -> Self {
                Self { value }
            }

            /// Return the inner value
            pub(crate) fn inner(&self) -> &bls12_381::$projective {
                &self.value
            }

            /// Sum some points
            pub fn sum(pts: &[Self]) -> Self {
                let mut sum = bls12_381::$projective::identity();
                for pt in pts {
                    sum += pt.inner();
                }
                Self::new(sum)
            }

            /// Deserialize a point (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs.
            pub fn deserialize(bytes: &[u8]) -> Result<Self, PairingInvalidPoint> {
                let pt = $affine::deserialize(bytes)?;
                Ok(pt.into())
            }

            /// Deserialize a point (compressed format only), trusted bytes edition
            ///
            /// As only compressed format is accepted, it is not possible to
            /// create a point which is not on the curve. However it is possible
            /// using this function to create a point which is not within the
            /// prime-order subgroup. This can be detected by calling is_torsion_free
            pub fn deserialize_unchecked(bytes: &[u8]) -> Result<Self, PairingInvalidPoint> {
                let pt = $affine::deserialize_unchecked(bytes)?;
                Ok(pt.into())
            }

            /// Serialize this point in compressed format
            pub fn serialize(&self) -> [u8; Self::BYTES] {
                $affine::from(self).serialize()
            }

            /// Return the identity element in this group
            pub fn identity() -> Self {
                Self::new(bls12_381::$projective::identity())
            }

            /// Return the generator element in this group
            pub fn generator() -> Self {
                Self::new(bls12_381::$projective::generator())
            }

            /// Hash into the group
            ///
            /// This follows draft-irtf-cfrg-hash-to-curve-16 using the
            /// BLS12381G1_XMD:SHA-256_SSWU_RO_ or
            /// BLS12381G2_XMD:SHA-256_SSWU_RO_ suite.
            ///
            /// # Arguments
            /// * `domain_sep` - some protocol specific domain seperator
            /// * `input` - the input which will be hashed
            pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
                let pt =
                    <bls12_381::$projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
                        input, domain_sep,
                    );
                Self::new(pt)
            }

            /// Return true if this is the identity element
            pub fn is_identity(&self) -> bool {
                bool::from(self.value.is_identity())
            }

            /// Return the inverse of this point
            pub fn neg(&self) -> Self {
                use std::ops::Neg;
                Self::new(self.value.neg())
            }
        }

        impl std::ops::Mul<Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: Scalar) -> $projective {
                <$projective>::new(self.inner() * scalar.inner())
            }
        }

        impl std::ops::Mul<&Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: &Scalar) -> $projective {
                <$projective>::new(self.inner() * scalar.inner())
            }
        }

        impl std::convert::From<$affine> for $projective {
            fn from(pt: $affine) -> Self {
                Self::new(pt.inner().into())
            }
        }

        impl std::convert::From<&$affine> for $projective {
            fn from(pt: &$affine) -> Self {
                Self::new(pt.inner().into())
            }
        }

        impl std::convert::From<$projective> for $affine {
            fn from(pt: $projective) -> Self {
                Self::new(pt.inner().into())
            }
        }

        impl std::convert::From<&$projective> for $affine {
            fn from(pt: &$projective) -> Self {
                Self::new(pt.inner().into())
            }
        }

    }
}

define_affine_and_projective_types!(G1Affine, G1Projective, 48);
declare_addsub_ops_for!(G1Projective);
declare_mul_scalar_ops_for!(G1Projective);

define_affine_and_projective_types!(G2Affine, G2Projective, 96);
declare_addsub_ops_for!(G2Projective);
declare_mul_scalar_ops_for!(G2Projective);

/// An element of the group Gt
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Gt {
    value: bls12_381::Gt,
}

impl Gt {
    /// Create a new Gt from the inner type
    pub(crate) fn new(value: bls12_381::Gt) -> Self {
        Self { value }
    }

    pub(crate) fn inner(&self) -> &bls12_381::Gt {
        &self.value
    }

    /// Return the identity element in the group
    pub fn identity() -> Self {
        Self::new(bls12_381::Gt::identity())
    }

    /// Return the generator element in the group
    pub fn generator() -> Self {
        Self::new(bls12_381::Gt::generator())
    }

    /// Compute the pairing function e(g1,g2) -> gt
    pub fn pairing(g1: &G1Affine, g2: &G2Affine) -> Self {
        Self::new(bls12_381::pairing(&g1.value, &g2.value))
    }

    /// Return true if this is the identity element
    pub fn is_identity(&self) -> bool {
        bool::from(self.value.is_identity())
    }
}

declare_addsub_ops_for!(Gt);
declare_mul_scalar_ops_for!(Gt);

/// Perform BLS signature verification
///
/// The naive version of this function requires two pairings, but it
/// is possible to use optimizations to reduce this overhead somewhat.
pub fn verify_bls_signature(
    signature: &G1Affine,
    public_key: &G2Affine,
    message: &G1Affine,
) -> bool {
    // faster version of
    // Gt::pairing(&signature, &G2Affine::generator()) == Gt::pairing(&message, &public_key)

    use std::ops::Neg;

    // TODO: cache the prepared form of the G2 generator
    let g2_gen = bls12_381::G2Prepared::from(bls12_381::G2Affine::generator().neg());
    let pub_key_prepared = bls12_381::G2Prepared::from(*public_key.inner());
    let res = bls12_381::multi_miller_loop(&[
        (signature.inner(), &g2_gen),
        (message.inner(), &pub_key_prepared),
    ]);
    bool::from(res.final_exponentiation().is_identity())
}

/*
The following is to work around a problem with getrandom 0.2 which
is a dependency of the bls12_381 crate.

For wasm32-unknown-unknown target, getrandom 0.2 will refuse to compile. This is
an intentional policy decision on the part of the getrandom developers. As a
consequence, it would not be possible to compile the crypto component into wasm
for use in canister code.

Convert the compile time error into a runtime error, by registering a custom
getrandom implementation which always fails.
*/

#[cfg(target_arch = "wasm32")]
/// A getrandom implementation that always fails
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(always_fail);
