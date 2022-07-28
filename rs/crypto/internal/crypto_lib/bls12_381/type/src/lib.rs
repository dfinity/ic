//! Wrapper for BLS12-381 operations

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![allow(clippy::needless_range_loop)]

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

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // We assume ct_compare returns < 0 for less than, == 0 for equals
        // and > 0 for greater than. This is a looser contract than what
        // ct_compare actually does but it avoids having to include a
        // panic or unreachable! invocation.
        self.ct_compare(other).cmp(&0)
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
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

    /// Compare a Scalar with another
    ///
    /// If self < other returns -1
    /// If self == other returns 0
    /// If self > other returns 1
    pub(crate) fn ct_compare(&self, other: &Self) -> i8 {
        use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

        const IS_LT: u8 = 0xff; // -1i8 as u8
        const IS_EQ: u8 = 0;
        const IS_GT: u8 = 1;

        let a = self.serialize();
        let b = other.serialize();

        /*
        bls12_381::Scalar does not implement comparisons natively.

        Perform this operation by comparing the serializations of the Scalar
        instead.

        This function is equivalent to self.serialize().cmp(other.serialize())
        except that it runs in constant time to avoid leaking information about
        the values.

        The logic works by examining each byte, starting from the least
        significant (in a[Self::BYTES-1]) and working up to the most significant
        (in a[0]).  At each step we track (in variable `result`) what the
        comparison would have resulted in had we just compared up to that point
        (ignoring the higher order bytes)

        If the two bytes we are comparing are the same, then whatever their
        value is does not change the result. As an example, XY and XZ have the
        same comparison result as Y and Z would, for any three bytes X, Y, Z.

        If they are not the same then either x is less than y, or it is not
        (which implies, since we know x != y, that x is strictly greater than
        y).  Additionally, since the byte we are examining at this point has
        greater magnitude than any byte we have looked at previously, the result
        we have computed so far no longer matters.

        Pseudo-code for this loop would be:

        let mut result = IS_EQ;
        for (x,y) in (&a, &b) {
           if x == y { continue; }
           else if x < y { result = IS_LT; }
           else { result = IS_GT; }
        }
        */

        // Return a if c otherwise b
        fn ct_select(c: subtle::Choice, a: u8, b: u8) -> u8 {
            let mut r = b;
            r.conditional_assign(&a, c);
            r
        }

        let mut result = IS_EQ;

        for i in (0..Self::BYTES).rev() {
            let is_lt = u8::ct_lt(&a[i], &b[i]);
            let is_eq = u8::ct_eq(&a[i], &b[i]);

            result = ct_select(is_eq, result, ct_select(is_lt, IS_LT, IS_GT));
        }

        result as i8
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

struct WindowInfo<const WINDOW_SIZE: usize> {}

impl<const WINDOW_SIZE: usize> WindowInfo<WINDOW_SIZE> {
    const SIZE: usize = WINDOW_SIZE;
    const WINDOWS: usize = (Scalar::BYTES * 8) / WINDOW_SIZE;

    const MASK: u8 = 0xFFu8 >> (8 - WINDOW_SIZE);
    const ELEMENTS: usize = 1 << WINDOW_SIZE;
    const WINDOWS_IN_BYTE: usize = 8 / WINDOW_SIZE;

    #[inline(always)]
    fn window_bit_offset(w: usize) -> usize {
        8 - Self::SIZE - Self::SIZE * (w % Self::WINDOWS_IN_BYTE)
    }

    #[inline(always)]
    /// Extract a window from a serialized scalar value
    ///
    /// Treat the scalar as if it was a sequence of windows, each of WINDOW_SIZE bits,
    /// and return the `w`th one of them. For 8 bit windows, this is simply the byte
    /// value. For smaller windows this is some subset of a single byte.
    ///
    /// Only window sizes which are a power of 2 are supported which simplifies the
    /// implementation to not require creating windows that cross byte boundaries.
    fn extract(scalar: &[u8; Scalar::BYTES], w: usize) -> u8 {
        assert!(WINDOW_SIZE == 1 || WINDOW_SIZE == 2 || WINDOW_SIZE == 4 || WINDOW_SIZE == 8);

        let window_byte = scalar[w / Self::WINDOWS_IN_BYTE];
        (window_byte >> Self::window_bit_offset(w)) & Self::MASK
    }
}

impl G1Projective {
    /// Constant time selection
    ///
    /// Equivalent to from[index] except avoids leaking the index
    /// through side channels.
    ///
    /// If index is out of range, returns the identity element
    pub(crate) fn ct_select(from: &[Self], index: usize) -> Self {
        use subtle::{ConditionallySelectable, ConstantTimeEq};
        let mut val = bls12_381::G1Projective::identity();

        for v in 0..from.len() {
            val.conditional_assign(from[v].inner(), usize::ct_eq(&v, &index));
        }

        Self::new(val)
    }

    /// Return the doubling of this point
    pub(crate) fn double(&self) -> Self {
        Self::new(self.value.double())
    }

    /// Multiscalar multiplication
    ///
    /// Equivalent to x*a + y*b
    ///
    /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
    /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
    ///
    /// This function is intended to work in constant time, and not
    /// leak information about the points or scalars.
    pub fn mul2(x: &Self, a: &Scalar, y: &Self, b: &Scalar) -> Self {
        // Configurable window size: can be 1, 2, or 4
        type Window = WindowInfo<2>;

        // Derived constants
        const TABLE_SIZE: usize = Window::ELEMENTS * Window::ELEMENTS;

        // Indexing helpers
        fn tbl_col(i: usize) -> usize {
            i
        }
        fn tbl_row(i: usize) -> usize {
            i << Window::SIZE
        }

        /*
        A table which can be viewed as a 2^WINDOW_SIZE x 2^WINDOW_SIZE matrix

        Each element is equal to a small linear combination of x and y:

        tbl[(yi:xi)] = x*xi + y*yi

        where xi is the lowest bits of the index and yi is the upper bits.  Each
        xi and yi is WINDOW_SIZE bits long (and thus at most 2^WINDOW_SIZE).

        We build up the table incrementally using additions and doubling, to
        avoid the cost of full scalar mul.
        */
        let mut tbl = [Self::identity(); TABLE_SIZE];

        // Precompute the table (tbl[0] is left as the identity)
        for i in 1..TABLE_SIZE {
            // The indexing here depends just on i, which is a public loop index

            let xi = i % Window::ELEMENTS;
            let yi = (i >> Window::SIZE) % Window::ELEMENTS;

            if xi % 2 == 0 && yi % 2 == 0 {
                tbl[i] = tbl[i / 2].double();
            } else if xi > 0 && yi > 0 {
                tbl[i] = tbl[tbl_col(xi)] + tbl[tbl_row(yi)];
            } else if xi > 0 {
                tbl[i] = tbl[tbl_col(xi - 1)] + *x;
            } else if yi > 0 {
                tbl[i] = tbl[tbl_row(yi - 1)] + *y;
            }
        }

        let s1 = a.serialize();
        let s2 = b.serialize();

        let mut accum = Self::identity();

        for i in 0..Window::WINDOWS {
            // skip on first iteration: doesn't leak secrets as index is public
            if i > 0 {
                for _ in 0..Window::SIZE {
                    accum = accum.double();
                }
            }

            let w1 = Window::extract(&s1, i);
            let w2 = Window::extract(&s2, i);
            let window = tbl_col(w1 as usize) + tbl_row(w2 as usize);

            accum += G1Projective::ct_select(&tbl, window);
        }

        accum
    }

    /// Multiscalar multiplication using Pippenger's algorithm
    ///
    /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn
    ///
    /// Returns the identity element if terms is empty.
    ///
    /// Warning: this function leaks information about the scalars via
    /// memory-based side channels. Do not use this function with secret
    /// scalars.
    pub fn muln_vartime(terms: &[(Self, Scalar)]) -> Self {
        // Configurable window size: can be 1, 2, 4, or 8
        type Window = WindowInfo<4>;

        let mut windows = Vec::with_capacity(terms.len());
        for (_pt, scalar) in terms {
            let sb = scalar.serialize();

            let mut window = [0u8; Window::WINDOWS];
            for i in 0..Window::WINDOWS {
                window[i] = Window::extract(&sb, i);
            }
            windows.push(window);
        }

        let id = Self::identity();
        let mut accum = id;

        let mut buckets = [id; Window::ELEMENTS];

        for i in 0..Window::WINDOWS {
            let mut max_bucket = 0;
            for j in 0..terms.len() {
                let bucket_index = windows[j][i] as usize;
                if bucket_index > 0 {
                    buckets[bucket_index] += terms[j].0;
                    max_bucket = std::cmp::max(max_bucket, bucket_index);
                }
            }

            if i > 0 {
                for _ in 0..Window::SIZE {
                    accum = accum.double();
                }
            }

            let mut t = id;

            for j in (1..=max_bucket).rev() {
                t += buckets[j];
                accum += t;
                buckets[j] = id;
            }
        }

        accum
    }
}

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

    /// Perform multi-pairing computation
    ///
    /// This is equivalent to computing the pairing from each element of
    /// `terms` then summing the result.
    pub fn multipairing(terms: &[(&G1Affine, &G2Prepared)]) -> Self {
        let mut inners = Vec::with_capacity(terms.len());
        for (g1, g2) in terms {
            inners.push((g1.inner(), g2.inner()));
        }

        Self::new(bls12_381::multi_miller_loop(&inners).final_exponentiation())
    }

    /// Return true if this is the identity element
    pub fn is_identity(&self) -> bool {
        bool::from(self.value.is_identity())
    }

    /// Return the additive inverse of this Gt
    pub fn neg(&self) -> Self {
        use std::ops::Neg;
        Self::new(self.value.neg())
    }
}

declare_addsub_ops_for!(Gt);
declare_mul_scalar_ops_for!(Gt);

/// An element of the group G2 prepared for the Miller loop
#[derive(Clone, Debug)]
pub struct G2Prepared {
    value: bls12_381::G2Prepared,
}

lazy_static::lazy_static! {
    static ref G2PREPARED_G : G2Prepared = G2Affine::generator().into();
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

impl G2Prepared {
    /// Create a new G2Prepared from the inner type
    pub(crate) fn new(value: bls12_381::G2Prepared) -> Self {
        Self { value }
    }

    pub(crate) fn inner(&self) -> &bls12_381::G2Prepared {
        &self.value
    }

    /// Return the generator element in the group
    pub fn generator() -> Self {
        G2PREPARED_G.clone()
    }

    /// Return the inverse of the generator element in the group
    pub fn neg_generator() -> Self {
        G2PREPARED_NEG_G.clone()
    }
}

impl From<&G2Affine> for G2Prepared {
    fn from(v: &G2Affine) -> Self {
        Self::new((*v.inner()).into())
    }
}

impl From<&G2Projective> for G2Prepared {
    fn from(v: &G2Projective) -> Self {
        Self::from(G2Affine::from(v))
    }
}

impl From<G2Affine> for G2Prepared {
    fn from(v: G2Affine) -> Self {
        Self::from(&v)
    }
}

impl From<G2Projective> for G2Prepared {
    fn from(v: G2Projective) -> Self {
        Self::from(&v)
    }
}

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

    let g2_gen = G2Prepared::neg_generator();
    let pub_key_prepared = G2Prepared::from(public_key);
    Gt::multipairing(&[(signature, &g2_gen), (message, &pub_key_prepared)]).is_identity()
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
