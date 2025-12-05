//! BLS12-381 wrapper types and common operations
//!
//! This crate provides a stable API for various operations relevant
//! both to generic uses of BLS12-381 (point multiplication, pairings, ...)
//! as well as Internet Computer specific functionality, especially functions
//! necessary to implement the Non Interactive Distributed Key Generation
//!
//! It also offers optimized implementations of point multiplication and
//! multiscalar multiplication which are substantially faster than the basic
//! implementations from the bls12_381 crate, which this crate uses for
//! its underlying arithmetic
//!
//! It also includes implementations of polynomial arithmetic and
//! Lagrange interpolation.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![allow(clippy::needless_range_loop)]

mod cache;
mod interpolation;
mod poly;

pub use interpolation::{InterpolationError, LagrangeCoefficients, NodeIndices};
pub use poly::Polynomial;

/// The index of a node.
pub type NodeIndex = u32;

#[cfg(test)]
mod tests;

use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use itertools::multiunzip;
use pairing::group::{Group, ff::Field};
use paste::paste;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::{Arc, LazyLock};
use std::{collections::HashMap, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! ctoption_ok_or {
    ($val:expr_2021, $err:expr_2021) => {
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
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    value: ic_bls12_381::Scalar,
}
static SCALAR_ZERO: LazyLock<Scalar> = LazyLock::new(|| Scalar::new(ic_bls12_381::Scalar::zero()));

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

macro_rules! impl_debug_using_serialize_for {
    ( $typ:ty ) => {
        impl fmt::Debug for $typ {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($typ), hex::encode(self.serialize()))
            }
        }
    };
}

impl_debug_using_serialize_for!(Scalar);

impl Scalar {
    /// The size in bytes of this type
    pub const BYTES: usize = 32;

    /// Create a new Scalar from the inner type
    pub(crate) fn new(value: ic_bls12_381::Scalar) -> Self {
        Self { value }
    }

    /// Return the inner value
    pub(crate) fn inner(&self) -> &ic_bls12_381::Scalar {
        &self.value
    }

    /// Create a scalar from a small integer value
    pub fn from_u64(v: u64) -> Self {
        let value: [u64; 4] = [v, 0, 0, 0];
        Self::new(ic_bls12_381::Scalar::from_raw(value))
    }

    /// Create a scalar from a small integer value
    pub fn from_u32(v: u32) -> Self {
        Self::from_u64(v as u64)
    }

    /// Create a scalar from a small integer value
    pub fn from_i32(v: i32) -> Self {
        if v < 0 {
            Self::from_u64((v as i64).unsigned_abs()).neg()
        } else {
            Self::from_u64(v.unsigned_abs() as u64)
        }
    }

    /// Create a scalar from a small integer value
    pub fn from_usize(v: usize) -> Self {
        Self::from_u64(v as u64)
    }

    /// Create a scalar used for threshold polynomial evaluation
    ///
    /// Normally this is used in threshold schemes, where a polynomial
    /// `f` is evaluated as `f(x)` where `x` is an integer > 0 which
    /// is unique to the node. In this scenario, `f(0)` reveals the
    /// full secret and is never computed. Thus, we number the nodes
    /// starting from index 1 instead of 0.
    pub fn from_node_index(node_index: NodeIndex) -> Self {
        Self::from_u64(node_index as u64 + 1)
    }

    /// Create a scalar from a small integer value
    pub fn from_isize(v: isize) -> Self {
        if v < 0 {
            Self::from_u64((v as i64).unsigned_abs()).neg()
        } else {
            Self::from_u64(v.unsigned_abs() as u64)
        }
    }

    /// Return `cnt` consecutive powers of `x`
    pub fn xpowers(x: &Self, cnt: usize) -> Vec<Self> {
        let mut r = Vec::with_capacity(cnt);

        let mut xpow = Self::one();
        for _ in 0..cnt {
            xpow *= x;
            r.push(xpow.clone());
        }

        r
    }

    /// Randomly generate a scalar in a way that is compatible with MIRACL
    ///
    /// This should not be used for new code but only for compatibility in
    /// situations where MIRACL's BIG::randomnum was previously used
    pub fn miracl_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        /*
        MIRACL's BIG::randomnum implementation uses an unusually inefficient
        approach to generating a random integer in a prime field. Effectively it
        generates a random bitstring of length twice the length of that of the
        prime (here, the 255-bit BLS12-381 prime subgroup order), and executes a
        double-and-add algorithm, one bit at a time. As a result, the final bit
        that was generated is equal to the *lowest order bit* in the result.
        Finally, it performs a modular reduction on the generated 510 bit
        integer.

        To replicate this behavior we have to reverse the bits within each byte,
        and then reverse the bytes as well. This creates `val` which is equal
        to MIRACL's result after 504 iterations of the loop in randomnum.

        The final 6 bits are handled by using 6 doublings to shift the Scalar value
        up to provide space, followed by a scalar addition.
        */

        let mut bytes = [0u8; 64];

        // We can't use fill_bytes here because that results in incompatible output.
        for i in 0..64 {
            bytes[i] = rng.r#gen::<u8>();
        }

        let mut rbuf = [0u8; 64];
        for j in 0..63 {
            rbuf[j] = bytes[62 - j].reverse_bits();
        }

        let mut val = Self::new(ic_bls12_381::Scalar::from_bytes_wide(&rbuf));

        for _ in 0..6 {
            val = val.double();
        }
        val += Scalar::from_u32((bytes[63].reverse_bits() >> 2) as u32);

        val
    }

    /// Return the scalar 0
    pub fn zero() -> Self {
        Self::new(ic_bls12_381::Scalar::zero())
    }

    /// Return the scalar 0, as a static reference
    pub fn zero_ref() -> &'static Self {
        &SCALAR_ZERO
    }

    /// Return the scalar 1
    pub fn one() -> Self {
        Self::new(ic_bls12_381::Scalar::one())
    }

    /// Hash to scalar
    ///
    /// Uses the same mechanism as RFC 9380's hash_to_field except
    /// targeting the scalar group.
    pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
        let mut s = [ic_bls12_381::Scalar::zero()];
        <ic_bls12_381::Scalar as HashToField>::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(
            input, domain_sep, &mut s,
        );
        Self::new(s[0])
    }

    /// Return true iff this value is zero
    pub fn is_zero(&self) -> bool {
        bool::from(self.value.is_zero())
    }

    /// Return the additive inverse of this scalar
    pub fn neg(&self) -> Self {
        Self::new(self.value.neg())
    }

    /// Double this scalar
    pub fn double(&self) -> Self {
        Self::new(self.value.double())
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

    /// Return the multiplicative inverse of the various scalar if each inverse exists
    pub fn batch_inverse_vartime(values: &[Self]) -> Option<Vec<Self>> {
        if values.is_empty() {
            return Some(vec![]);
        }

        let n = values.len();
        let mut accum = Scalar::one();
        let mut products = Vec::with_capacity(n);

        /*
         * This uses Montgomery's Trick to compute many inversions using just a
         * single field inversion. This is worthwhile because field inversions
         * are quite expensive (for BLS12-381, an inversion costs approximately 52
         * field multiplications plus 255 field squarings)
         *
         * The basic idea here (for n=2) is taking advantage of the fact that if
         * x and y both have inverses then so does x*y, and (x*y)^-1 * x = y^-1
         * and (x*y)^-1 * y = x^-1
         *
         * This is described in more detail in various texts such as
         *  - <https://eprint.iacr.org/2008/199.pdf> section 2
         *  - "Guide to Elliptic Curve Cryptography" Algorithm 2.26
         */

        for v in values {
            accum *= v;
            products.push(accum.clone());
        }

        if let Some(mut inv) = accum.inverse() {
            let mut result = Vec::with_capacity(n);

            for i in (1..n).rev() {
                result.push(&inv * &products[i - 1]);
                inv *= &values[i];
            }

            result.push(inv);
            result.reverse();

            Some(result)
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
                buf.zeroize();
                return s;
            }
        }
    }

    /// Randomly sample exactly `amount` unbiased indices from `0..range` using an inplace partial Fisher-Yates method.
    ///
    /// This method is adopted from the std::rand crate including some comments, see
    /// https://github.com/rust-random/rand/blob/19169cbce9931eea5ccb4f2cbf174fc9d3e8759d/src/seq/index.rs#L425.
    ///
    /// If `amount > range`, then `range` is internally used as `amount`.
    ///
    /// This allocates the entire range of indices (`range`) and randomizes
    /// only the first `amount`.
    ///
    /// It then truncates to `amount` and returns.
    fn random_bit_indices<R>(rng: &mut R, amount: u8, range: u8) -> Vec<u8>
    where
        R: Rng + RngCore + CryptoRng + ?Sized,
    {
        let amount = std::cmp::min(amount, range);

        let mut indices: Vec<u8> = Vec::with_capacity(range as usize);
        indices.extend(0..range);
        for i in 0..amount {
            let j: u8 = rng.gen_range(i..range);
            indices.swap(i as usize, j as usize);
        }
        indices.truncate(amount as usize);
        debug_assert_eq!(indices.len(), amount as usize);
        indices
    }

    /// Returns a sparse random [`Scalar`] with a fixed Hamming weight.
    ///
    /// # Arguments
    /// * `rng` - RNG object.
    /// * `num_bits` - the Hamming weight of each [`Scalar`].
    ///
    /// Note that
    /// * If `num_bits` overflows 254 (the floored [`Scalar`] bit length), then
    ///   internally the `num_bits` is set to 254.
    /// * The MSB of the returned [`Scalar`] is always 0.
    pub fn random_sparse(rng: &mut (impl Rng + CryptoRng), num_bits: u8) -> Scalar {
        let set_bit = |bytes: &mut [u8], i: u8| {
            bytes[Scalar::BYTES - (i as usize / 8) - 1] |= 1 << (i % 8);
        };

        let mut scalar = [0u8; Scalar::BYTES];
        const SCALAR_FLOORED_BIT_LENGTH: u8 = 254;

        for i in Self::random_bit_indices(rng, num_bits, SCALAR_FLOORED_BIT_LENGTH) {
            set_bit(&mut scalar, i);
        }
        // we always generate fewer bits than the max capacity of the scalar,
        // so `deserialize` never returns an error
        Scalar::deserialize(&scalar).unwrap()
    }

    /// Return several random scalars
    pub fn batch_random<R: RngCore + CryptoRng>(rng: &mut R, count: usize) -> Vec<Self> {
        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            result.push(Self::random(rng));
        }

        result
    }

    /// Return several random scalars
    pub fn batch_random_array<const N: usize, R: RngCore + CryptoRng>(rng: &mut R) -> [Self; N] {
        [(); N].map(|_| Self::random(rng))
    }

    /// Returns several sparse random scalars.
    ///
    /// # Arguments
    /// * `rng` - RNG object
    /// * `count` - number of generated scalars
    /// * `num_bits` - number of 1-bits that each scalar will have at random positions
    pub fn batch_sparse_random<R: RngCore + CryptoRng>(
        rng: &mut R,
        count: usize,
        num_bits: u8,
    ) -> Vec<Self> {
        (0..count)
            .map(|_| Self::random_sparse(rng, num_bits))
            .collect()
    }

    /// Return a random scalar within a small range
    ///
    /// Returns a scalar in range [0,n) using rejection sampling.
    pub fn random_within_range<R: RngCore + CryptoRng>(rng: &mut R, n: u64) -> Self {
        if n <= 1 {
            return Self::zero();
        }

        let t_bits = std::mem::size_of::<u64>() * 8;
        let n_bits = std::cmp::min(255, t_bits - n.leading_zeros() as usize);
        let n_bytes = n_bits.div_ceil(8);
        let n_mask = if n_bits.is_multiple_of(8) {
            0xFF
        } else {
            0xFF >> (8 - n_bits % 8)
        };

        let n = Scalar::from_u64(n);

        loop {
            let mut buf = [0u8; Self::BYTES];
            rng.fill_bytes(&mut buf[Self::BYTES - n_bytes..]);
            buf[Self::BYTES - n_bytes] &= n_mask;

            if let Ok(s) = Self::deserialize(&buf) {
                buf.zeroize();
                if s < n {
                    return s;
                }
            }
        }
    }

    /// Decode a scalar as a big-endian byte string, accepting out of range elements
    ///
    /// Out of range elements are reduced modulo the group order
    pub fn deserialize_unchecked(bytes: &[u8; Self::BYTES]) -> Self {
        let mut le_bytes = [0u8; 64];

        for i in 0..Self::BYTES {
            le_bytes[i] = bytes[Self::BYTES - i - 1];
        }
        // le_bytes[32..64] left as zero

        let s = ic_bls12_381::Scalar::from_bytes_wide(&le_bytes);
        le_bytes.zeroize();
        Self::new(s)
    }

    /// Decode a scalar as a big-endian byte string, reducing modulo group order
    pub fn from_bytes_wide(input: &[u8; 64]) -> Self {
        let mut le_bytes = {
            let mut buf = *input;
            buf.reverse();
            buf
        };
        let s = ic_bls12_381::Scalar::from_bytes_wide(&le_bytes);
        le_bytes.zeroize();
        Self::new(s)
    }

    /// Deserialize a scalar from a big-endian byte string
    pub fn deserialize<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidScalar> {
        let mut bytes: [u8; Self::BYTES] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| PairingInvalidScalar::InvalidScalar)?;
        bytes.reverse();
        let scalar = ic_bls12_381::Scalar::from_bytes(&bytes);
        bytes.zeroize();
        ctoption_ok_or!(scalar, PairingInvalidScalar::InvalidScalar)
    }

    /// Deserialize multiple scalars
    ///
    /// This function returns Ok only if all of the provided inputs
    /// represent a valid scalar.
    pub fn batch_deserialize<B: AsRef<[u8]>>(
        inputs: &[B],
    ) -> Result<Vec<Self>, PairingInvalidScalar> {
        let mut r = Vec::with_capacity(inputs.len());
        for input in inputs {
            r.push(Self::deserialize(input)?);
        }
        Ok(r)
    }

    /// Deserialize multiple scalars
    ///
    /// This function returns Ok only if all of the provided inputs
    /// represent a valid scalar.
    pub fn batch_deserialize_array<B: AsRef<[u8]>, const N: usize>(
        inputs: &[B; N],
    ) -> Result<[Self; N], PairingInvalidScalar> {
        // This could be made nicer, and avoid the heap allocation, by
        // using array::try_map (currently only available in nightly)

        let r = Self::batch_deserialize(inputs.as_ref())?;
        Ok(r.try_into()
            .expect("Input and output lengths are guaranteed same at compile time"))
    }

    /// Serialize the scalar to a big-endian byte string
    pub fn serialize(&self) -> [u8; Self::BYTES] {
        let mut bytes = self.value.to_bytes();
        bytes.reverse();
        bytes
    }

    /// Serialize the scalar to a big-endian byte string in some specific type
    pub fn serialize_to<T: From<[u8; Self::BYTES]>>(&self) -> T {
        T::from(self.serialize())
    }

    /// Serialize an array of scalars into some specific type
    pub fn serialize_array_to<T: From<[u8; Self::BYTES]>, const N: usize>(
        vals: &[Self; N],
    ) -> [T; N] {
        let iota: [usize; N] = std::array::from_fn(|i| i);
        iota.map(|i| T::from(vals[i].serialize()))
    }

    /// Serialize a slice of scalars into some specific type
    pub fn serialize_seq_to<T: From<[u8; Self::BYTES]>>(vals: &[Self]) -> Vec<T> {
        let mut result = Vec::with_capacity(vals.len());

        for v in vals {
            result.push(T::from(v.serialize()));
        }

        result
    }

    /// Multiscalar multiplication
    ///
    /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn
    ///
    /// Returns zero if terms is empty
    ///
    /// Warning: this function may leak information about the scalars via
    /// memory-based side channels. Do not use this function with secret
    /// scalars. For the purposes of this warning, the first element of
    /// the tuple may be a secret, while the values of the second element
    /// of the tuple could leak to an attacker.
    ///
    /// Warning: if lhs.len() != rhs.len() this function ignores trailing elements
    /// of the longer slice.
    ///
    /// Currently only a naive version is implemented.
    pub fn muln_vartime(lhs: &[Self], rhs: &[Self]) -> Self {
        let terms = std::cmp::min(lhs.len(), rhs.len());
        let mut accum = Self::zero();
        for i in 0..terms {
            accum += &lhs[i] * &rhs[i];
        }
        accum
    }

    /// Multiscalar multiplication with usize multiplicands
    ///
    /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn
    ///
    /// Returns zero if terms is empty
    ///
    /// Warning: this function may leak information about the usize values via
    /// memory-based side channels. Do not use this function with secret usize
    /// arguments.
    ///
    /// Warning: if lhs.len() != rhs.len() this function ignores trailing elements
    /// of the longer slice.
    ///
    /// Currently only a naive version is implemented.
    ///
    /// This function could take advantage of the fact that rhs is known to be
    /// at most 64 bits, limiting the number of doublings.
    pub fn muln_usize_vartime(lhs: &[Self], rhs: &[usize]) -> Self {
        let terms = std::cmp::min(lhs.len(), rhs.len());
        let mut accum = Self::zero();
        for i in 0..terms {
            accum += &lhs[i] * Scalar::from_usize(rhs[i]);
        }
        accum
    }

    /// Compare a Scalar with another
    ///
    /// If self < other returns -1
    /// If self == other returns 0
    /// If self > other returns 1
    pub fn ct_compare(&self, other: &Self) -> i8 {
        use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

        const IS_LT: u8 = 0xff; // -1i8 as u8
        const IS_EQ: u8 = 0;
        const IS_GT: u8 = 1;

        let a = self.serialize();
        let b = other.serialize();

        /*
        ic_bls12_381::Scalar does not implement comparisons natively.

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
        impl std::ops::Add<&$typ> for &$typ {
            type Output = $typ;

            fn add(self, other: &$typ) -> $typ {
                <$typ>::new(self.inner() + other.inner())
            }
        }

        impl std::ops::Add<$typ> for $typ {
            type Output = $typ;

            fn add(self, other: $typ) -> $typ {
                &self + &other
            }
        }

        impl std::ops::Add<&$typ> for $typ {
            type Output = $typ;

            fn add(self, other: &$typ) -> $typ {
                &self + other
            }
        }

        impl std::ops::Sub<&$typ> for &$typ {
            type Output = $typ;

            fn sub(self, other: &$typ) -> $typ {
                <$typ>::new(self.inner() - other.inner())
            }
        }

        impl std::ops::Sub<$typ> for $typ {
            type Output = $typ;

            fn sub(self, other: $typ) -> $typ {
                &self - &other
            }
        }

        impl std::ops::Sub<&$typ> for $typ {
            type Output = $typ;

            fn sub(self, other: &$typ) -> $typ {
                &self - other
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

macro_rules! declare_mixed_addition_ops_for {
    ( $proj:ty, $affine:ty ) => {
        impl std::ops::Add<&$affine> for &$proj {
            type Output = $proj;

            fn add(self, other: &$affine) -> $proj {
                <$proj>::new(self.inner().add_mixed(other.inner()))
            }
        }

        impl std::ops::Add<$affine> for $proj {
            type Output = $proj;

            fn add(self, other: $affine) -> $proj {
                &self + &other
            }
        }

        impl std::ops::Add<&$affine> for $proj {
            type Output = $proj;

            fn add(self, other: &$affine) -> $proj {
                &self + other
            }
        }

        impl std::ops::AddAssign<$affine> for $proj {
            fn add_assign(&mut self, other: $affine) {
                self.value = self.inner().add_mixed(other.inner());
            }
        }

        impl std::ops::AddAssign<&$affine> for $proj {
            fn add_assign(&mut self, other: &$affine) {
                self.value = self.inner().add_mixed(other.inner());
            }
        }
    };
}

macro_rules! declare_mul_scalar_ops_for {
    ( $typ:ty ) => {
        impl std::ops::Mul<&Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: &Scalar) -> $typ {
                <$typ>::new(self.inner() * scalar.inner())
            }
        }

        impl std::ops::Mul<&Scalar> for $typ {
            type Output = $typ;
            fn mul(self, scalar: &Scalar) -> $typ {
                &self * scalar
            }
        }

        impl std::ops::Mul<Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> $typ {
                self * &scalar
            }
        }

        impl std::ops::Mul<Scalar> for $typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> $typ {
                &self * &scalar
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
    ( $affine:ident, $projective:ident, $size:expr_2021 ) => {
        paste! {
            static [<$affine:upper _GENERATOR>] : LazyLock<$affine> = LazyLock::new(|| $affine::new_with_precomputation(ic_bls12_381::$affine::generator()));
        }

        paste! {
            #[derive(Zeroize, ZeroizeOnDrop)]
            /// Structure for fast multiplication for known/fixed points
            ///
            /// This algorithm works by precomputing a table such that by adding
            /// together selected elements of the table, a scalar multiplication is
            /// effected without any doublings.
            ///
            /// Each window of the scalar has its own set of elements in the table,
            /// which are not used for any other window. An implicit element of each
            /// set is the identity element, which is omitted to save space in the
            /// table. (However this does make some of the indexing operations less
            /// obvious.)
            ///
            /// The simplest version to understand is the 1-bit window case.  There, we
            /// compute a table containing P,P*2^1,...,P*2^255, and for each bit of the
            /// scalar conditionally add that power of P.  To make this constant time
            /// one must always add, choosing between the identity and the point.
            ///
            /// For the two bit case, we instead have a set of [P'*0,P'*1,P'*2,P'*3]
            /// where P' = P*2^(2*i). Note that P'*0 is always the identity, and can be
            /// omitted from the table.
            ///
            /// This approach expands similarly for the higher window sizes. The
            /// tradeoff becomes an issue of table size (and precomputation cost)
            /// versus the number of additions in the online phase.
            ///
            /// At larger window sizes, extracting the needed element from the table in
            /// constant time becomes the dominating cost.
            struct [<$affine PrecomputedTable>] {
                tbl: Vec<ic_bls12_381::$affine>,
            }

            impl [<$affine PrecomputedTable>] {
                /// The size of the windows
                ///
                /// This algorithm uses just `SUBGROUP_BITS/WINDOW_BITS` additions in
                /// the online phase, at the cost of storing a table of size
                /// `(SUBGROUP_BITS + WINDOW_BITS - 1)/WINDOW_BITS * (1 << WINDOW_BITS - 1)`
                ///
                /// This constant is configurable and can take values between 1 and 7
                /// (inclusive)
                ///
                /// | WINDOW_BITS | TABLE_SIZE | online additions |
                /// | ----------- | ---------- | ---------------- |
                /// |           1 |       255  |              255 |
                /// |           2 |       384  |              128 |
                /// |           3 |       595  |               85 |
                /// |           4 |       960  |               64 |
                /// |           5 |      1581  |               51 |
                /// |           6 |      2709  |               43 |
                /// |           7 |      4699  |               37 |
                ///
                const WINDOW_BITS: usize = 4;

                /// The bit length of the BLS12-381 subgroup
                const SUBGROUP_BITS: usize = 255;

                // A bitmask of all 1s that is WINDOW_BITS long
                const WINDOW_MASK: u8 = (1 << Self::WINDOW_BITS) - 1;

                // The total number of windows in a scalar
                const WINDOWS: usize = Self::SUBGROUP_BITS.div_ceil(Self::WINDOW_BITS);

                // We must select from 2^WINDOW_BITS elements in each table
                // group. However one element of the table group is always the
                // identity, and so can be omitted, which is the reason for the
                // subtraction by 1 here.
                const WINDOW_ELEMENTS : usize = (1 << Self::WINDOW_BITS) - 1;

                // The total size of the table we will use
                const TABLE_SIZE: usize = Self::WINDOW_ELEMENTS * Self::WINDOWS;

                /// Precompute a table for fast multiplication
                fn new(pt: &$affine) -> Self {
                    let mut ptbl = vec![ic_bls12_381::$projective::identity(); Self::TABLE_SIZE];

                    let mut accum = ic_bls12_381::$projective::from(pt.value);

                    for i in 0..Self::WINDOWS {
                        let tbl_i = &mut ptbl[Self::WINDOW_ELEMENTS*i..Self::WINDOW_ELEMENTS*(i+1)];

                        tbl_i[0] = accum;
                        for j in 1..Self::WINDOW_ELEMENTS {
                            // Our table indexes are off by one due to the omitted
                            // identity element. So here we are checking if we are
                            // about to compute a point that is a doubling of a point
                            // we have previously computed. If so we can compute it
                            // using a (faster) doubling rather than using addition.

                            tbl_i[j] = if j % 2 == 1 {
                                tbl_i[j / 2].double()
                            } else {
                                tbl_i[j - 1] + tbl_i[0]
                            };
                        }

                        // move on to the next power
                        accum = tbl_i[Self::WINDOW_ELEMENTS/2].double();
                    }

                    // batch convert the table to affine form, so we can use mixed addition
                    // in the online phase.
                    let mut tbl = vec![ic_bls12_381::$affine::identity(); Self::TABLE_SIZE];
                    <ic_bls12_381::$projective>::batch_normalize(&ptbl, &mut tbl);

                    Self { tbl }
                }

                /// Perform scalar multiplication using the precomputed table
                fn mul(&self, scalar: &Scalar) -> $projective {
                    let s = scalar.serialize();

                    let mut accum = <ic_bls12_381::$projective>::identity();

                    for i in 0..Self::WINDOWS {
                        let tbl_for_i = &self.tbl[Self::WINDOW_ELEMENTS*i..Self::WINDOW_ELEMENTS*(i+1)];

                        let b = Self::get_window(&s, Self::WINDOW_BITS*i);
                        accum += Self::ct_select(tbl_for_i, b as usize);
                    }

                    <$projective>::new(accum)
                }

                /// Perform scalar multiplication using the precomputed table
                fn mul_vartime(&self, scalar: &Scalar) -> $projective {
                    let s = scalar.serialize();

                    let mut accum = <ic_bls12_381::$projective>::identity();

                    for i in 0..Self::WINDOWS {
                        let tbl_for_i = &self.tbl[Self::WINDOW_ELEMENTS*i..Self::WINDOW_ELEMENTS*(i+1)];

                        let b = Self::get_window(&s, Self::WINDOW_BITS*i);
                        if b > 0 {
                            accum += tbl_for_i[(b - 1) as usize]; // variable time table lookup
                        }
                    }

                    <$projective>::new(accum)
                }

                // Extract a WINDOW_BITS sized window out of s, depending on offset.
                #[inline(always)]
                fn get_window(s: &[u8], offset: usize) -> u8 {
                    const BITS_IN_BYTE: usize = 8;

                    let shift = offset % BITS_IN_BYTE;
                    let byte_offset = s.len() - 1 - (offset / BITS_IN_BYTE);

                    let w0 = s[byte_offset];

                    let single_byte_window =
                        shift <= (BITS_IN_BYTE - Self::WINDOW_BITS) || byte_offset == 0;

                    let bits = if single_byte_window {
                        // If we can get the window out of single byte, do so
                        (w0 >> shift)
                    } else {
                        // Otherwise we must join two bytes and extract the result
                        let w1 = s[byte_offset - 1];
                        ((w0 >> shift) | (w1 << (BITS_IN_BYTE - shift)))
                    };

                    bits & Self::WINDOW_MASK
                }

                // Constant time table lookup
                //
                // This version is specifically adapted to this algorithm. If
                // index is zero, then it returns the identity element. Otherwise
                // it returns from[index-1].
                #[inline(always)]
                fn ct_select(from: &[ic_bls12_381::$affine], index: usize) -> ic_bls12_381::$affine {
                    use subtle::{ConditionallySelectable, ConstantTimeEq};

                    let mut val = ic_bls12_381::$affine::identity();

                    let index = index.wrapping_sub(1);
                    for v in 0..from.len() {
                        val.conditional_assign(&from[v], usize::ct_eq(&v, &index));
                    }

                    val
                }
            }
        }

        /// An element of the group in affine form
        #[derive(Clone)]
        pub struct $affine {
            value: ic_bls12_381::$affine,
            precomputed: Option<Arc<paste! { [<$affine PrecomputedTable>] }>>,
        }

        impl AsRef<$affine> for $affine {
            fn as_ref(&self) -> &Self{
                return &self
            }
        }

        impl Eq for $affine {}

        impl PartialEq for $affine {
            fn eq(&self, other: &Self) -> bool {
                self.value == other.value
            }
        }

        impl std::hash::Hash for $affine {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.serialize().hash(state)
            }
        }

        impl Zeroize for $affine {
            fn zeroize(&mut self) {
                self.value.zeroize();
                self.precomputed = None;
            }
        }

        impl Drop for $affine {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $affine {
            /// The size in bytes of this type
            pub const BYTES: usize = $size;

            /// Create a struct from the inner type
            pub(crate) fn new(value: ic_bls12_381::$affine) -> Self {
                Self { value, precomputed: None }
            }

            /// Create a struct from the inner type, with precomputation
            pub(crate) fn new_with_precomputation(value: ic_bls12_381::$affine) -> Self {
                let mut s = Self::new(value);
                s.precompute();
                s
            }

            /// Precompute values for multiplication
            pub fn precompute(&mut self) {
                if self.precomputed.is_some() {
                    // already precomputed, no need to redo
                    return;
                }

                let tbl = <paste! { [<$affine PrecomputedTable>] }>::new(self);
                self.precomputed = Some(Arc::new(tbl));
            }

            /// Perform point multiplication
            pub(crate) fn mul_dispatch(&self, scalar: &Scalar) -> $projective {
                if let Some(ref tbl) = self.precomputed {
                    tbl.mul(scalar)
                } else {
                    <$projective>::from(self).windowed_mul(scalar)
                }
            }

            /// Perform variable time point multiplication
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn mul_vartime(&self, scalar: &Scalar) -> $projective {
                if let Some(ref tbl) = self.precomputed {
                    tbl.mul_vartime(scalar)
                } else {
                    <$projective>::from(self).windowed_mul_vartime(scalar)
                }
            }

            /// Return the inner value
            pub(crate) fn inner(&self) -> &ic_bls12_381::$affine {
                &self.value
            }

            /// Return the identity element in this group
            pub fn identity() -> Self {
                Self::new(ic_bls12_381::$affine::identity())
            }

            /// Return the generator element in this group
            pub fn generator() -> &'static Self {
                paste! { &[<$affine:upper _GENERATOR>] }
            }

            /// Hash into the group
            ///
            /// This follows draft-irtf-cfrg-hash-to-curve-16 using the
            /// BLS12381G1_XMD:SHA-256_SSWU_RO_ or
            /// BLS12381G2_XMD:SHA-256_SSWU_RO_ suite.
            ///
            /// # Arguments
            /// * `domain_sep` - some protocol specific domain separator
            /// * `input` - the input which will be hashed
            pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
                $projective::hash(domain_sep, input).into()
            }

            /// Hash into the group, returning a point with precomputations
            ///
            /// This follows draft-irtf-cfrg-hash-to-curve-16 using the
            /// BLS12381G1_XMD:SHA-256_SSWU_RO_ or
            /// BLS12381G2_XMD:SHA-256_SSWU_RO_ suite.
            ///
            /// # Arguments
            /// * `domain_sep` - some protocol specific domain separator
            /// * `input` - the input which will be hashed
            pub fn hash_with_precomputation(domain_sep: &[u8], input: &[u8]) -> Self {
                let mut pt = Self::hash(domain_sep, input);
                pt.precompute();
                pt
            }

            /// Deserialize a point (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs.
            pub fn deserialize<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidPoint> {
                let bytes : &[u8; Self::BYTES] = bytes.as_ref()
                    .try_into()
                    .map_err(|_| PairingInvalidPoint::InvalidPoint)?;
                let pt = ic_bls12_381::$affine::from_compressed(bytes);
                ctoption_ok_or!(pt, PairingInvalidPoint::InvalidPoint)
            }

            /// Deserialize multiple points (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs. It returns Ok only
            /// if all of the provided bytes represent a valid point.
            pub fn batch_deserialize<B: AsRef<[u8]>>(inputs: &[B]) -> Result<Vec<Self>, PairingInvalidPoint> {
                let mut r = Vec::with_capacity(inputs.len());
                for input in inputs {
                    r.push(Self::deserialize(input)?);
                }
                Ok(r)
            }

            /// Deserialize multiple points (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs. It returns Ok only
            /// if all of the provided bytes represent a valid point.
            pub fn batch_deserialize_array<B: AsRef<[u8]>, const N: usize>(inputs: &[B; N]) -> Result<[Self; N], PairingInvalidPoint> {

                // This could be made nicer, and avoid the heap allocation, by
                // using array::try_map (currently only available in nightly)

                let r = Self::batch_deserialize(inputs.as_ref())?;

                Ok(r.try_into().expect("Input and output lengths are guaranteed same at compile time"))
            }

            /// Deserialize a point (compressed format only), trusted bytes edition
            ///
            /// As only compressed format is accepted, it is not possible to
            /// create a point which is not on the curve. However it is possible
            /// using this function to create a point which is not within the
            /// prime-order subgroup. This can be detected by calling is_torsion_free
            pub fn deserialize_unchecked<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidPoint> {
                let bytes : &[u8; Self::BYTES] = bytes.as_ref()
                    .try_into()
                    .map_err(|_| PairingInvalidPoint::InvalidPoint)?;
                let pt = ic_bls12_381::$affine::from_compressed_unchecked(bytes);
                ctoption_ok_or!(pt, PairingInvalidPoint::InvalidPoint)
            }

            /// Serialize this point in compressed format
            pub fn serialize(&self) -> [u8; Self::BYTES] {
                self.value.to_compressed()
            }

            /// Serialize a point in compressed format in some specific type
            pub fn serialize_to<T: From<[u8; Self::BYTES]>>(&self) -> T {
                T::from(self.serialize())
            }

            /// Serialize an array of points in compressed format in some specific type
            pub fn serialize_array_to<T: From<[u8; Self::BYTES]>, const N: usize>(vals: &[Self; N]) -> [T; N] {
                let iota: [usize; N] = std::array::from_fn(|i| i);
                iota.map(|i| T::from(vals[i].serialize()))
            }

            /// Serialize a slice of points into some specific type
            pub fn serialize_seq_to<T: From<[u8; Self::BYTES]>>(vals: &[Self]) -> Vec<T> {
                let mut result = Vec::with_capacity(vals.len());

                for v in vals {
                    result.push(T::from(v.serialize()));
                }

                result
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

            /// Batch multiplication
            pub fn batch_mul(&self, scalars: &[Scalar]) -> Vec<Self> {

                // It might be possible to optimize this function by taking advantage of
                // the fact that we are using the same point for several multiplications,
                // for example by using larger precomputed tables

                let mut result = Vec::with_capacity(scalars.len());
                for scalar in scalars {
                    result.push(self * scalar);
                }
                $projective::batch_normalize(&result)
            }

            /// Batch multiplication
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn batch_mul_vartime(&self, scalars: &[Scalar]) -> Vec<Self> {
                // It might be possible to optimize this function by taking advantage of
                // the fact that we are using the same point for several multiplications,
                // for example by using larger precomputed tables

                let mut result = Vec::with_capacity(scalars.len());
                for scalar in scalars {
                    result.push(self.mul_vartime(scalar));
                }
                $projective::batch_normalize(&result)
            }

            /// Batch multiplication
            pub fn batch_mul_array<const N: usize>(&self, scalars: &[Scalar; N]) -> [Self; N] {
                let v = scalars.clone().map(|s| self * s);
                $projective::batch_normalize_array(&v)
            }

            /// Sum some points
            pub fn sum(pts: &[Self]) -> $projective {
                let mut sum = ic_bls12_381::$projective::identity();
                for pt in pts {
                    sum += pt.inner();
                }
                $projective::new(sum)
            }
        }

        paste! {
            static [<$projective:upper _GENERATOR>] : LazyLock<$projective> = LazyLock::new(|| $projective::new(ic_bls12_381::$projective::generator()));
        }

        /// An element of the group in projective form
        #[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
        pub struct $projective {
            value: ic_bls12_381::$projective
        }

        impl AsRef<$projective> for $projective {
            fn as_ref(&self) -> &Self {
                return &self
            }
        }

        impl $projective {
            /// The size in bytes of this type
            pub const BYTES: usize = $size;

            /// Create a new struct from the inner type
            pub(crate) fn new(value: ic_bls12_381::$projective) -> Self {
                Self { value }
            }

            /// Return the inner value
            pub(crate) fn inner(&self) -> &ic_bls12_381::$projective {
                &self.value
            }

            /// Constant time selection
            ///
            /// Equivalent to from[index] except avoids leaking the index
            /// through side channels.
            ///
            /// If index is out of range, returns the identity element
            pub(crate) fn ct_select(from: &[Self], index: usize) -> Self {
                use subtle::{ConditionallySelectable, ConstantTimeEq};
                let mut val = ic_bls12_381::$projective::identity();

                for v in 0..from.len() {
                    val.conditional_assign(from[v].inner(), usize::ct_eq(&v, &index));
                }

                Self::new(val)
            }

            /// Return the doubling of this point
            pub fn double(&self) -> Self {
                Self::new(self.value.double())
            }

            /// Sum some points
            pub fn sum(pts: &[Self]) -> Self {
                let mut sum = ic_bls12_381::$projective::identity();
                for pt in pts {
                    sum += pt.inner();
                }
                Self::new(sum)
            }

            /// Deserialize a point (compressed format only)
            ///
            /// This version verifies that the decoded point is within the prime order
            /// subgroup, and is safe to call on untrusted inputs.
            pub fn deserialize<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidPoint> {
                let pt = $affine::deserialize(bytes)?;
                Ok(pt.into())
            }

            /// Serialize a point in compressed format in some specific type
            pub fn serialize_to<T: From<[u8; Self::BYTES]>>(&self) -> T {
                T::from(self.serialize())
            }

            /// Deserialize a point (compressed format only), trusted bytes edition
            ///
            /// As only compressed format is accepted, it is not possible to
            /// create a point which is not on the curve. However it is possible
            /// using this function to create a point which is not within the
            /// prime-order subgroup. This can be detected by calling is_torsion_free
            pub fn deserialize_unchecked<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidPoint> {
                let pt = $affine::deserialize_unchecked(bytes)?;
                Ok(pt.into())
            }

            /// Serialize this point in compressed format
            pub fn serialize(&self) -> [u8; Self::BYTES] {
                $affine::from(self).serialize()
            }

            /// Return the identity element in this group
            pub fn identity() -> Self {
                Self::new(ic_bls12_381::$projective::identity())
            }

            /// Return a list of n elements all of which are the identity element
            pub(crate) fn identities(count: usize) -> Vec<Self> {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(Self::identity());
                }
                v
            }

            /// Return the generator element in this group
            pub fn generator() -> &'static Self {
                paste! { &[<$projective:upper _GENERATOR>] }
            }

            /// Hash into the group
            ///
            /// This follows draft-irtf-cfrg-hash-to-curve-16 using the
            /// BLS12381G1_XMD:SHA-256_SSWU_RO_ or
            /// BLS12381G2_XMD:SHA-256_SSWU_RO_ suite.
            ///
            /// # Arguments
            /// * `domain_sep` - some protocol specific domain separator
            /// * `input` - the input which will be hashed
            pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
                let pt =
                    <ic_bls12_381::$projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
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

            /// Convert this point to affine format
            pub fn to_affine(&self) -> $affine {
                $affine::new(self.value.into())
            }

            /// Convert a group of points into affine format
            pub fn batch_normalize(points: &[Self]) -> Vec<$affine> {
                let mut inner_points = Vec::with_capacity(points.len());
                for point in points {
                    inner_points.push(*point.inner());
                }

                let mut inner_affine = vec![ic_bls12_381::$affine::identity(); points.len()];
                ic_bls12_381::$projective::batch_normalize(&inner_points, &mut inner_affine);

                let mut output = Vec::with_capacity(points.len());
                for point in inner_affine {
                    output.push($affine::new(point));
                }
                output
            }

            /// Convert a group of points into affine format
            pub fn batch_normalize_array<const N: usize>(points: &[Self; N]) -> [$affine; N] {
                let inner_points = points.clone().map(|p| *p.inner());

                let mut inner_affine = [ic_bls12_381::$affine::identity(); N];
                ic_bls12_381::$projective::batch_normalize(inner_points.as_ref(), &mut inner_affine);

                inner_affine.map(|p| $affine::new(p))
            }
        }

        impl std::ops::Mul<&Scalar> for &$affine {
            type Output = $projective;

            fn mul(self, scalar: &Scalar) -> $projective {
                self.mul_dispatch(scalar)
            }
        }

        impl std::ops::Mul<&Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: &Scalar) -> $projective {
                self.mul_dispatch(&scalar)
            }
        }

        impl std::ops::Mul<Scalar> for &$affine {
            type Output = $projective;

            fn mul(self, scalar: Scalar) -> $projective {
                self * &scalar
            }
        }

        impl std::ops::Mul<Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: Scalar) -> $projective {
                &self * &scalar
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

// declare the impl for the mul2 table struct
macro_rules! declare_mul2_table_impl {
    ($projective:ty, $tbl_typ:ident, $window:expr_2021) => {
        /// Table for storing linear combinations of two points.
        /// It is stored as a vector to reduce the amount of indirection for accessing cells.
        /// A table can be computed by calling the `compute_mul2_tbl` function of the corresponding
        /// projective `struct`, e.g., `G2Projective::mul2_prepared(...)`.
        impl $tbl_typ {
            // Compute the column offset in the vector from the column index.
            pub(crate) fn col(i: usize) -> usize {
                i
            }

            // Compute the row offset in the vector from the row index.
            pub(crate) fn row(i: usize) -> usize {
                // Configurable window size: an be in 1..=8
                type Window = WindowInfo<$window>;
                i << Window::SIZE
            }

            /// Multiscalar multiplication (aka sum-of-products)
            ///
            /// This table contains linear combinations of points x and y
            /// that allow for fast multiplication with scalars.
            /// The result of the computation is equivalent to x*a + y*b.
            /// It is intended and beneficial to call this function on multiple
            /// scalar pairs without recomputing this table.
            /// If `mul2` is called only once, consider using the associated
            /// `mul2` function of the respective projective struct, which
            /// computes a smaller mul2 table on the fly and might thus be more efficient.
            ///
            /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
            /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
            ///
            /// This function is intended to work in constant time, and not
            /// leak information about the inputs.
            pub fn mul2(&self, a: &Scalar, b: &Scalar) -> $projective {
                // Configurable window size: can be in 1..=8
                type Window = WindowInfo<$window>;

                let s1 = a.serialize();
                let s2 = b.serialize();

                let mut accum = <$projective>::identity();

                for i in 0..Window::WINDOWS {
                    // skip on first iteration: doesn't leak secrets as index is public
                    if i > 0 {
                        for _ in 0..Window::SIZE {
                            accum = accum.double();
                        }
                    }

                    let w1 = Window::extract(&s1, i);
                    let w2 = Window::extract(&s2, i);
                    let window = $tbl_typ::col(w1 as usize) + $tbl_typ::row(w2 as usize);

                    accum += <$projective>::ct_select(&self.0, window);
                }

                accum
            }

            /// Multiscalar multiplication (aka sum-of-products)
            ///
            /// This table contains linear combinations of points x and y
            /// that allow for fast multiplication with scalars.
            /// The result of the computation is equivalent to x*a + y*b.
            /// It is intended and beneficial to call this function on multiple
            /// scalar pairs without recomputing this table.
            /// If `mul2` is called only once, consider using the associated
            /// `mul2` function of the respective projective struct, which
            /// computes a smaller mul2 table on the fly and might thus be more efficient.
            ///
            /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
            /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn mul2_vartime(&self, a: &Scalar, b: &Scalar) -> $projective {
                // Configurable window size: can be in 1..=8
                type Window = WindowInfo<$window>;

                let s1 = a.serialize();
                let s2 = b.serialize();

                let mut accum = <$projective>::identity();

                for i in 0..Window::WINDOWS {
                    // skip on first iteration: doesn't leak secrets as index is public
                    if i > 0 {
                        for _ in 0..Window::SIZE {
                            accum = accum.double();
                        }
                    }

                    let w1 = Window::extract(&s1, i);
                    let w2 = Window::extract(&s2, i);
                    let window = $tbl_typ::col(w1 as usize) + $tbl_typ::row(w2 as usize);

                    // This is the only difference from the constant time version:
                    accum += &self.0[window];
                }

                accum
            }

            #[allow(dead_code)]
            /// Perform a sequence of sum-of-2-products operations and return the results
            pub fn mul2_array<const N: usize>(
                &self,
                a: &[Scalar; N],
                b: &[Scalar; N],
            ) -> [$projective; N] {
                let iota: [usize; N] = std::array::from_fn(|i| i);
                iota.map(|i| self.mul2(&a[i], &b[i]))
            }
        }
    };
}

macro_rules! declare_compute_mul2_table_inline {
    ($projective:ty, $tbl_typ:ident, $window_size:expr_2021, $x:expr_2021, $y:expr_2021) => {{
        // Configurable window size: can be in 1..=8
        type Window = WindowInfo<$window_size>;

        // Derived constants
        const TABLE_SIZE: usize = Window::ELEMENTS * Window::ELEMENTS;

        /*
        A table which can be viewed as a 2^WINDOW_SIZE x 2^WINDOW_SIZE matrix

        Each element is equal to a small linear combination of x and y:

        tbl[(yi:xi)] = x*xi + y*yi

        where xi is the lowest bits of the index and yi is the upper bits.  Each
        xi and yi is WINDOW_SIZE bits long (and thus at most 2^WINDOW_SIZE).

        We build up the table incrementally using additions and doubling, to
        avoid the cost of full scalar mul.
         */
        let mut tbl = <$projective>::identities(TABLE_SIZE);

        // Precompute the table (tbl[0] is left as the identity)
        for i in 1..TABLE_SIZE {
            // The indexing here depends just on i, which is a public loop index

            let xi = i % Window::ELEMENTS;
            let yi = (i >> Window::SIZE) % Window::ELEMENTS;

            if xi % 2 == 0 && yi % 2 == 0 {
                tbl[i] = tbl[i / 2].double();
            } else if xi > 0 && yi > 0 {
                tbl[i] = &tbl[$tbl_typ::col(xi)] + &tbl[$tbl_typ::row(yi)];
            } else if xi > 0 {
                tbl[i] = &tbl[$tbl_typ::col(xi - 1)] + $x;
            } else if yi > 0 {
                tbl[i] = &tbl[$tbl_typ::row(yi - 1)] + $y;
            }
        }

        $tbl_typ(tbl)
    }};
}

macro_rules! declare_mul2_impl_for {
    ( $projective:ty, $affine:ty, $tbl_typ:ident, $small_window_size:expr_2021, $big_window_size:expr_2021 ) => {
        paste! {
            /// Contains a small precomputed table with linear combinations of two points that
            /// can be used for faster mul2 computation. This table is called small because its
            /// parameters are optimized for computation on the fly, meaning that it this table
            /// is computed for each mul2 call without further optimizations.
            pub(crate) struct [< Small $tbl_typ >](Vec<$projective>);
            declare_mul2_table_impl!($projective, [< Small $tbl_typ >], $small_window_size);

            /// Contains a small precomputed table with linear combinations of two points that
            /// can be used for faster mul2 computation. This table is called large because
            /// its parameters are optimized for the best trade-off for pre-computing the table
            /// once and using it for multiplication of the points with multiple scalar pairs.
            /// For further information, see the rustdoc of `mul2` and `compute_mul2_tbl`.
            pub struct $tbl_typ(Vec<$projective>);
            declare_mul2_table_impl!($projective, $tbl_typ, $big_window_size);

            impl $projective {
                /// Multiscalar multiplication (aka sum-of-products)
                ///
                /// Equivalent to x*a + y*b
                ///
                /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
                /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
                ///
                /// This function is intended to work in constant time, and not
                /// leak information about the inputs.
                pub fn mul2(x: &Self, a: &Scalar, y: &Self, b: &Scalar) -> Self {
                    let tbl = Self::compute_small_mul2_tbl(x, y);
                    tbl.mul2(a, b)
                }

                /// Multiscalar multiplication (aka sum-of-products)
                ///
                /// Equivalent to x*a + y*b
                ///
                /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
                /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
                ///
                /// This function is intended to work in constant time, and not
                /// leak information about the inputs.
                pub fn mul2_affine(x: &$affine, a: &Scalar, y: &$affine, b: &Scalar) -> Self {
                    let tbl = Self::compute_small_mul2_affine_tbl(x, y);
                    tbl.mul2(a, b)
                }

                /// Multiscalar multiplication (aka sum-of-products)
                ///
                /// Equivalent to x*a + y*b
                ///
                /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
                /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
                ///
                /// Warning: this function leaks information about the scalars via
                /// memory-based side channels. Do not use this function with secret
                /// scalars.
                pub fn mul2_vartime(x: &Self, a: &Scalar, y: &Self, b: &Scalar) -> Self {
                    let tbl = Self::compute_small_mul2_tbl(x, y);
                    tbl.mul2_vartime(a, b)
                }

                /// Multiscalar multiplication (aka sum-of-products)
                ///
                /// Equivalent to x*a + y*b
                ///
                /// Uses the Simultaneous 2w-Ary Method following Section 2.1 of
                /// <https://www.bmoeller.de/pdf/multiexp-sac2001.pdf>
                ///
                /// Warning: this function leaks information about the scalars via
                /// memory-based side channels. Do not use this function with secret
                /// scalars.
                pub fn mul2_affine_vartime(x: &$affine, a: &Scalar, y: &$affine, b: &Scalar) -> Self {
                    let tbl = Self::compute_small_mul2_affine_tbl(x, y);
                    tbl.mul2_vartime(a, b)
                }

                /// Compute a small mul2 table for computing mul2 on the fly, i.e.,
                /// without amortizing the cost of the table computation by
                /// reusing it (calling mul2) on multiple scalar pairs.
                fn compute_small_mul2_tbl(x: &Self, y: &Self) -> [< Small $tbl_typ >] {
                    declare_compute_mul2_table_inline!($projective, [< Small $tbl_typ >], $small_window_size, x, y)
                }

                /// Compute a small mul2 table for computing mul2 on the fly, i.e.,
                /// without amortizing the cost of the table computation by
                /// reusing it (calling mul2) on multiple scalar pairs.
                fn compute_small_mul2_affine_tbl(x: &$affine, y: &$affine) -> [< Small $tbl_typ >] {
                    declare_compute_mul2_table_inline!($projective, [< Small $tbl_typ >], $small_window_size, x, y)
                }

                /// Compute a mul2 table that contains linear combinations of `x` and `y`,
                /// which is intended to be used for multiple mul2 calls with the same `x` and `y`
                /// but different scalar pairs. To call `mul2` only once, consider calling
                /// it directly, which might be more efficient.
                pub fn compute_mul2_tbl(x: &Self, y: &Self) -> $tbl_typ {
                    declare_compute_mul2_table_inline!($projective, $tbl_typ, $big_window_size, x, y)
                }

                /// Compute a mul2 table that contains linear combinations of `x` and `y`,
                /// which is intended to be used for multiple mul2 calls with the same `x` and `y`
                /// but different scalar pairs. To call `mul2` only once, consider calling
                /// it directly, which might be more efficient.
                pub fn compute_mul2_affine_tbl(x: &$affine, y: &$affine) -> $tbl_typ {
                    declare_compute_mul2_table_inline!($projective, $tbl_typ, $big_window_size, x, y)
                }
            }
        }
    };
}

/*
* This macro dispatches a multi-scalar multiplication to different
* algorithms, depending on the size of the problem.
*
* - Problems of size 1 are handled using trivial multiplication.
* - Problems of size 2 are handled using the (constant time) mul2 implementation
* - Problems larger than 2 but smaller than $naive_cutoff are done using
*   a simple loop
* - Problems larger than the naive cutoff, but smaller than w3_cutoff, are
*   handled using 3-bit Pippenger
* - Any larger problems are dispatched to 4-bit Pippenger
*
* For any fixed group, regardless of the number of elements (n), or the window
* size (w), Pippenger's uses effectively a constant number of doublings. (255 in
* the case of BLS12-381.) However the number of additions it uses varies, and
* this depends upon both n, w, and the average Hamming weight of the scalar.
* A randomized simulation demonstrates that it is only when n > 61 that the number
* of additions for w=4 is typically smaller than for w=3.
*/
macro_rules! declare_muln_vartime_dispatch_for {
    ( $typ:ty, $naive_cutoff:expr_2021, $w3_cutoff:expr_2021 ) => {
        impl $typ {
            /// Multiscalar multiplication using Pippenger's algorithm
            ///
            /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn,
            /// where `n = min(points.len(), scalars.len())`.
            ///
            /// Returns the identity element if terms is empty.
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn muln_vartime(points: &[Self], scalars: &[Scalar]) -> Self {
                if points.len() == 1 {
                    return &points[0] * &scalars[0];
                } else if points.len() == 2 {
                    return Self::mul2_vartime(&points[0], &scalars[0], &points[1], &scalars[1]);
                } else if points.len() < $naive_cutoff {
                    Self::muln_vartime_naive(points, scalars)
                } else if points.len() < $w3_cutoff {
                    Self::muln_vartime_window_3(points, scalars)
                } else {
                    Self::muln_vartime_window_4(points, scalars)
                }
            }

            fn muln_vartime_naive(points: &[Self], scalars: &[Scalar]) -> Self {
                let (accum, points, scalars) = if points.len() % 2 == 0 {
                    (Self::identity(), points, scalars)
                } else {
                    (&points[0] * &scalars[0], &points[1..], &scalars[1..])
                };
                points
                    .chunks(2)
                    .zip(scalars.chunks(2))
                    .fold(accum, |accum, (c_p, c_s)| {
                        accum + Self::mul2_vartime(&c_p[0], &c_s[0], &c_p[1], &c_s[1])
                    })
            }
        }
    };
}

/*
* This is exactly the same as the declare_muln_vartime_dispatch_for macro above
* except that it takes as input points in affine rather than projective form.
*/
macro_rules! declare_muln_affine_vartime_dispatch_for {
    ( $proj:ty, $affine:ty, $naive_cutoff:expr_2021, $w3_cutoff:expr_2021 ) => {
        impl $proj {
            /// Multiscalar multiplication using Pippenger's algorithm
            ///
            /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn,
            /// where `n = min(points.len(), scalars.len())`.
            ///
            /// Returns the identity element if terms is empty.
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn muln_affine_vartime(points: &[$affine], scalars: &[Scalar]) -> Self {
                if points.len() == 1 {
                    return &points[0] * &scalars[0];
                } else if points.len() == 2 {
                    return Self::mul2_affine_vartime(
                        &points[0],
                        &scalars[0],
                        &points[1],
                        &scalars[1],
                    );
                } else if points.len() < $naive_cutoff {
                    Self::muln_affine_vartime_naive(points, scalars)
                } else if points.len() < $w3_cutoff {
                    Self::muln_affine_vartime_window_3(points, scalars)
                } else {
                    Self::muln_affine_vartime_window_4(points, scalars)
                }
            }

            fn muln_affine_vartime_naive(points: &[$affine], scalars: &[Scalar]) -> Self {
                let (accum, points, scalars) = if points.len() % 2 == 0 {
                    (Self::identity(), points, scalars)
                } else {
                    (&points[0] * &scalars[0], &points[1..], &scalars[1..])
                };
                points
                    .chunks(2)
                    .zip(scalars.chunks(2))
                    .fold(accum, |accum, (c_p, c_s)| {
                        accum + Self::mul2_affine_vartime(&c_p[0], &c_s[0], &c_p[1], &c_s[1])
                    })
            }
        }
    };
}

macro_rules! declare_pippengers_for {
    ( $typ:ty, $fn_name:ident, $input:ty, $window:expr_2021 ) => {
        impl $typ {
            fn $fn_name(points: &[$input], scalars: &[Scalar]) -> Self {
                // Configurable window size: can be in 1..=8
                type Window = WindowInfo<$window>;

                let count = std::cmp::min(points.len(), scalars.len());

                let mut windows = Vec::with_capacity(count);
                for s in scalars {
                    let sb = s.serialize();

                    let mut window = [0u8; Window::WINDOWS];
                    for i in 0..Window::WINDOWS {
                        window[i] = Window::extract(&sb, i);
                    }
                    windows.push(window);
                }

                let mut accum = Self::identity();

                let mut buckets = Self::identities(Window::ELEMENTS);

                for i in 0..Window::WINDOWS {
                    let mut max_bucket = 0;
                    for j in 0..count {
                        let bucket_index = windows[j][i] as usize;
                        if bucket_index > 0 {
                            buckets[bucket_index] += &points[j];
                            max_bucket = std::cmp::max(max_bucket, bucket_index);
                        }
                    }

                    if i > 0 {
                        for _ in 0..Window::SIZE {
                            accum = accum.double();
                        }
                    }

                    let mut t = Self::identity();

                    for j in (1..=max_bucket).rev() {
                        t += &buckets[j];
                        accum += &t;
                        buckets[j] = Self::identity();
                    }
                }

                accum
            }
        }
    };
}

macro_rules! declare_muln_vartime_affine_sparse_impl_for {
    ( $proj:ty, $affine:ty ) => {
        impl $proj {
            /// Multiplies and adds together `points` and `scalars` as
            /// `points[0] * scalars[0] + ... + points[l] * scalars[l]`,
            /// where `l` is `min(points.len(), scalars.len())`.
            ///
            /// Returns the identity element if terms is empty.
            ///
            /// This function is more efficient with smaller Hamming
            /// weight of the scalars and with more point-scalar pairs
            /// in the input. Although less efficiently, this function works
            /// also with scalars having a large Hamming weight.
            ///
            /// Warning: this function leaks information about the scalars via
            /// side channels. Do not use this function with secret scalars.
            pub fn muln_affine_sparse_vartime(inputs: &[(&$affine, &Scalar)]) -> Self {
                let get_bit = |bytes: &[u8], i: usize| {
                    let target_byte = bytes[Scalar::BYTES - i / 8 - 1];
                    let target_bit = (target_byte >> (i % 8)) & 1;
                    target_bit == 1
                };

                let mut accum = Self::identity();
                for bit_i in (0..=Scalar::BYTES * 8 - 1).rev() {
                    for (p, s) in inputs.iter().map(|(p, s)| (*p, s.serialize())) {
                        if get_bit(&s[..], bit_i) {
                            accum = &accum + p;
                        }
                    }
                    if bit_i > 0 {
                        accum = accum.double();
                    }
                }
                accum
            }
        }
    };
}

macro_rules! declare_windowed_scalar_mul_ops_for {
    ( $typ:ty, $window:expr_2021 ) => {
        impl $typ {
            pub(crate) fn windowed_mul(&self, scalar: &Scalar) -> Self {
                // Configurable window size: can be in 1..=8
                type Window = WindowInfo<$window>;

                // Derived constants
                const TABLE_SIZE: usize = Window::ELEMENTS;

                let mut tbl = Self::identities(TABLE_SIZE);

                for i in 1..TABLE_SIZE {
                    tbl[i] = if i % 2 == 0 {
                        tbl[i / 2].double()
                    } else {
                        &tbl[i - 1] + self
                    };
                }

                let s = scalar.serialize();

                let mut accum = Self::identity();

                for i in 0..Window::WINDOWS {
                    // skip on first iteration: doesn't leak secrets as index is public
                    if i > 0 {
                        for _ in 0..Window::SIZE {
                            accum = accum.double();
                        }
                    }

                    let w = Window::extract(&s, i);
                    accum += Self::ct_select(&tbl, w as usize);
                }

                accum
            }

            pub(crate) fn windowed_mul_vartime(&self, scalar: &Scalar) -> Self {
                // Configurable window size: can be in 1..=8
                type Window = WindowInfo<$window>;

                // Derived constants
                const TABLE_SIZE: usize = Window::ELEMENTS;

                let mut tbl = Self::identities(TABLE_SIZE);

                for i in 1..TABLE_SIZE {
                    tbl[i] = if i % 2 == 0 {
                        tbl[i / 2].double()
                    } else {
                        &tbl[i - 1] + self
                    };
                }

                let s = scalar.serialize();

                let mut accum = Self::identity();

                for i in 0..Window::WINDOWS {
                    if i > 0 {
                        for _ in 0..Window::SIZE {
                            accum = accum.double();
                        }
                    }

                    let w = Window::extract(&s, i);
                    if w > 0 {
                        accum += &tbl[w as usize]; // variable time table lookup
                    }
                }

                accum
            }
        }

        impl std::ops::Mul<&Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: &Scalar) -> $typ {
                self.windowed_mul(scalar)
            }
        }

        impl std::ops::Mul<&Scalar> for $typ {
            type Output = $typ;
            fn mul(self, scalar: &Scalar) -> $typ {
                &self * scalar
            }
        }

        impl std::ops::Mul<Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> Self::Output {
                self * &scalar
            }
        }

        impl std::ops::Mul<Scalar> for $typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> Self::Output {
                &self * &scalar
            }
        }

        impl std::ops::MulAssign<Scalar> for $typ {
            fn mul_assign(&mut self, other: Scalar) {
                *self = self.windowed_mul(&other);
            }
        }

        impl std::ops::MulAssign<&Scalar> for $typ {
            fn mul_assign(&mut self, other: &Scalar) {
                *self = self.windowed_mul(other);
            }
        }
    };
}

/// These constants dictate which window sizes for Pippenger's
/// algorithm will be used for points in G1/G2, resp.
///
/// Inputs smaller than the W3 constant will instead use a naive
/// algorithm.
///
/// These values were derived from benchmarks on a single machine,
/// but seem to match fairly closely with simulated estimates of
/// the cost of Pippenger's
const G1_PROJECTIVE_USE_W3_IF_EQ_OR_GT: usize = 16;
const G1_PROJECTIVE_USE_W4_IF_EQ_OR_GT: usize = 64;
const G2_PROJECTIVE_USE_W3_IF_EQ_OR_GT: usize = 17;
const G2_PROJECTIVE_USE_W4_IF_EQ_OR_GT: usize = 64;

define_affine_and_projective_types!(G1Affine, G1Projective, 48);
declare_addsub_ops_for!(G1Projective);
declare_mixed_addition_ops_for!(G1Projective, G1Affine);
declare_windowed_scalar_mul_ops_for!(G1Projective, 4);
declare_mul2_impl_for!(G1Projective, G1Affine, G1Mul2Table, 2, 3);
declare_muln_vartime_dispatch_for!(
    G1Projective,
    G1_PROJECTIVE_USE_W3_IF_EQ_OR_GT,
    G1_PROJECTIVE_USE_W4_IF_EQ_OR_GT
);
declare_muln_affine_vartime_dispatch_for!(
    G1Projective,
    G1Affine,
    G1_PROJECTIVE_USE_W3_IF_EQ_OR_GT,
    G1_PROJECTIVE_USE_W4_IF_EQ_OR_GT
);
declare_pippengers_for!(G1Projective, muln_vartime_window_3, G1Projective, 3);
declare_pippengers_for!(G1Projective, muln_vartime_window_4, G1Projective, 4);
declare_pippengers_for!(G1Projective, muln_affine_vartime_window_3, G1Affine, 3);
declare_pippengers_for!(G1Projective, muln_affine_vartime_window_4, G1Affine, 4);
declare_muln_vartime_affine_sparse_impl_for!(G1Projective, G1Affine);
impl_debug_using_serialize_for!(G1Affine);
impl_debug_using_serialize_for!(G1Projective);

impl G1Affine {
    /// See draft-irtf-cfrg-bls-signature-05 §4.2.2 for details on BLS augmented signatures
    pub fn augmented_hash(pk: &G2Affine, data: &[u8]) -> Self {
        let domain_sep = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

        let mut signature_input = vec![];
        signature_input.extend_from_slice(&pk.serialize());
        signature_input.extend_from_slice(data);
        Self::hash(domain_sep, &signature_input)
    }
}

define_affine_and_projective_types!(G2Affine, G2Projective, 96);
declare_addsub_ops_for!(G2Projective);
declare_mixed_addition_ops_for!(G2Projective, G2Affine);
declare_windowed_scalar_mul_ops_for!(G2Projective, 4);
declare_mul2_impl_for!(G2Projective, G2Affine, G2Mul2Table, 2, 3);
declare_muln_vartime_dispatch_for!(
    G2Projective,
    G2_PROJECTIVE_USE_W3_IF_EQ_OR_GT,
    G2_PROJECTIVE_USE_W4_IF_EQ_OR_GT
);
declare_muln_affine_vartime_dispatch_for!(
    G2Projective,
    G2Affine,
    G2_PROJECTIVE_USE_W3_IF_EQ_OR_GT,
    G2_PROJECTIVE_USE_W4_IF_EQ_OR_GT
);
declare_pippengers_for!(G2Projective, muln_vartime_window_3, G2Projective, 3);
declare_pippengers_for!(G2Projective, muln_vartime_window_4, G2Projective, 4);
declare_pippengers_for!(G2Projective, muln_affine_vartime_window_3, G2Affine, 3);
declare_pippengers_for!(G2Projective, muln_affine_vartime_window_4, G2Affine, 4);
declare_muln_vartime_affine_sparse_impl_for!(G2Projective, G2Affine);
impl_debug_using_serialize_for!(G2Affine);
impl_debug_using_serialize_for!(G2Projective);

impl G2Affine {
    /// Deserialize a G2 element using a cache
    ///
    /// This function verifies that the decoded point is within the prime order
    /// subgroup, and is safe to call on untrusted inputs.
    ///
    /// This function is equivalent to `deserialize` but additionally caches
    /// that it has seen the key before; repeated deserializations will be much
    /// faster. This is mostly useful when deserializing public keys, which are
    /// potentially seen many times over the process lifetime.
    pub fn deserialize_cached<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidPoint> {
        let bytes: &[u8; Self::BYTES] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| PairingInvalidPoint::InvalidPoint)?;
        if let Some(pk) = crate::cache::G2PublicKeyCache::global().get(bytes) {
            return Ok(pk);
        }

        if let Some(pt) = ic_bls12_381::G2Affine::from_compressed(bytes).into_option() {
            let pt = Self::new(pt);
            crate::cache::G2PublicKeyCache::global().insert(*bytes, pt.clone());
            Ok(pt)
        } else {
            Err(PairingInvalidPoint::InvalidPoint)
        }
    }

    /// Return statistics related to the deserialize_cached cache
    pub fn deserialize_cached_statistics() -> crate::cache::G2PublicKeyCacheStatistics {
        crate::cache::G2PublicKeyCache::global().cache_statistics()
    }
}

/// An element of the group Gt
#[derive(Clone, Eq, PartialEq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Gt {
    value: ic_bls12_381::Gt,
}

static GT_GENERATOR: LazyLock<Gt> = LazyLock::new(|| Gt::new(ic_bls12_381::Gt::generator()));

impl Gt {
    /// The size in bytes of this type
    pub const BYTES: usize = 576;

    /// Create a new Gt from the inner type
    pub(crate) fn new(value: ic_bls12_381::Gt) -> Self {
        Self { value }
    }

    pub(crate) fn inner(&self) -> &ic_bls12_381::Gt {
        &self.value
    }

    /// Constant time selection
    ///
    /// Equivalent to from[index] except avoids leaking the index
    /// through side channels.
    ///
    /// If index is out of range, returns the identity element
    pub(crate) fn ct_select(from: &[Self], index: usize) -> Self {
        use subtle::{ConditionallySelectable, ConstantTimeEq};
        let mut val = ic_bls12_381::Gt::identity();

        for v in 0..from.len() {
            val.conditional_assign(from[v].inner(), usize::ct_eq(&v, &index));
        }

        Self::new(val)
    }

    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        use subtle::ConditionallySelectable;
        Self::new(ic_bls12_381::Gt::conditional_select(
            a.inner(),
            b.inner(),
            choice,
        ))
    }

    /// Return the identity element in the group
    pub fn identity() -> Self {
        Self::new(ic_bls12_381::Gt::identity())
    }

    /// Return a vector of the identity element
    pub(crate) fn identities(count: usize) -> Vec<Self> {
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            v.push(Self::identity());
        }
        v
    }

    /// Return the generator element in the group
    pub fn generator() -> &'static Self {
        &GT_GENERATOR
    }

    /// Compute the pairing function e(g1,g2) -> gt
    pub fn pairing(g1: &G1Affine, g2: &G2Affine) -> Self {
        Self::new(ic_bls12_381::pairing(&g1.value, &g2.value))
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

        Self::new(ic_bls12_381::multi_miller_loop(&inners).final_exponentiation())
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

    /// Return the doubling of this element
    pub fn double(&self) -> Self {
        Self::new(self.value.double())
    }

    /// Return some arbitrary bytes which represent this Gt element
    ///
    /// These are not deserializable, and serve only to uniquely identify
    /// the group element.
    ///
    /// We do guarantee that the tag of an element will remain stable over time
    pub fn tag(&self) -> [u8; Self::BYTES] {
        self.value.to_bytes()
    }

    /// Return a hash value of this element suitable for linear search
    ///
    /// # Warning
    ///
    /// This function is a perfect hash function (ie, has no collisions) for the
    /// set of elements gt*{0..2**16-1}, which is what is used to represent
    /// ciphertext elements in the NIDKG. It is not useful in other contexts.
    ///
    /// This function is not stable over time; it may change in the future.
    /// Do not serialize this value, or use it as an index in storage.
    pub fn short_hash_for_linear_search(&self) -> u32 {
        fn extract4(tag: &[u8], idx: usize) -> u32 {
            let mut fbytes = [0u8; 4];
            fbytes.copy_from_slice(&tag[idx..idx + 4]);
            u32::from_le_bytes(fbytes)
        }

        let tag = self.tag();
        extract4(&tag, 0) ^ extract4(&tag, 32)
    }

    /// Perform variable time point multiplication
    ///
    /// Warning: this function leaks information about the scalars via
    /// memory-based side channels. Do not use this function with secret
    /// scalars.
    pub fn mul_vartime(&self, scalar: &Scalar) -> Self {
        self.windowed_mul_vartime(scalar)
    }

    /// Return the result of g*val where g is the standard generator
    ///
    /// This function avoids leaking val through timing side channels,
    /// since it is used when decrypting NIDKG dealings.
    pub fn g_mul_u16(val: u16) -> Self {
        let g = Gt::generator().clone();
        let mut r = Gt::identity();

        for b in 0..16 {
            if b > 0 {
                r = r.double();
            }

            let choice = subtle::Choice::from(((val >> (15 - b)) as u8) & 1);
            r = Self::conditional_select(&r, &(&r + &g), choice);
        }

        r
    }
}

declare_addsub_ops_for!(Gt);
declare_windowed_scalar_mul_ops_for!(Gt, 4);

/// An element of the group G2 prepared for the Miller loop
#[derive(Clone, Debug)]
pub struct G2Prepared {
    value: ic_bls12_381::G2Prepared,
}

static G2PREPARED_G: LazyLock<G2Prepared> = LazyLock::new(|| G2Affine::generator().into());
static G2PREPARED_NEG_G: LazyLock<G2Prepared> =
    LazyLock::new(|| G2Affine::generator().neg().into());

impl G2Prepared {
    /// Create a new G2Prepared from the inner type
    pub(crate) fn new(value: ic_bls12_381::G2Prepared) -> Self {
        Self { value }
    }

    pub(crate) fn inner(&self) -> &ic_bls12_381::G2Prepared {
        &self.value
    }

    /// Return the generator element in the group
    pub fn generator() -> &'static Self {
        &G2PREPARED_G
    }

    /// Return the inverse of the generator element in the group
    pub fn neg_generator() -> &'static Self {
        &G2PREPARED_NEG_G
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
    Gt::multipairing(&[(signature, g2_gen), (message, &pub_key_prepared)]).is_identity()
}

/// Number of random bits in a [`Scalar`] that is used for batched signature
/// verification.
///
/// We generated a random [`Scalar`] for batched signature verification by (1)
/// reinterpreting a 0-[`Scalar`] as a bit string, 2) selecting
/// [`NUM_BITS_BATCH_VERIFICATION`] random locations in the bit string, and 3)
/// assigning 1-bits to those locations. This generates a set of |bit string|
/// choose [`NUM_BITS_BATCH_VERIFICATION`] [`Scalar`]s. The selected parameter
/// 30 generated a set of (254 choose 30) = 2^(129.37) [`Scalar`]s, which
/// satisfies our requirements for the batched signature verification.
///
/// Note that this constant could eventually be lowered to e.g. 16 if (254
/// choose 16) = 2^(81.91) [`Scalar`]s satisfies the security requirements.
const NUM_BITS_BATCH_VERIFICATION: u8 = 30;

/// Performs the verification of a batch of BLS signatures that is faster than
/// pairwise verification. For efficiency, the provided batch is automatically
/// dispatched into subcases: same message, same public key, distinct keys and
/// messages batches.
///
/// TODO(CRP-2013): use only one multi-pairing per call.
pub fn verify_bls_signature_batch<R: RngCore + CryptoRng>(
    sigs_pks_msgs: &[(&G1Affine, &G2Affine, &G1Affine)],
    rng: &mut R,
) -> bool {
    type Sig = G1Affine;
    type Pk = G2Affine;
    type Msg = G1Affine;

    // same-public-key verification is most efficient, so it comes first
    let mut same_pk = HashMap::<&Pk, Vec<(&Sig, &Msg)>>::with_capacity(sigs_pks_msgs.len());

    for (sig, pk, msg) in sigs_pks_msgs {
        match same_pk.get_mut(pk) {
            Some(v) => {
                v.push((sig, msg));
            }
            _ => {
                same_pk.insert(pk, vec![(sig, msg)]);
            }
        }
    }

    for (pk, sigs_and_msgs) in same_pk.iter().filter(|(_k, v)| v.len() > 1) {
        if !verify_bls_signature_batch_same_pk(&sigs_and_msgs[..], pk, rng) {
            return false;
        };
    }

    // same-message verification is second most efficient, so it comes second
    let mut same_msg = HashMap::<&Msg, Vec<(&Sig, &Pk)>>::with_capacity(
        same_pk.iter().filter(|(_k, v)| v.len() == 1).count(),
    );

    for (pk, sigs_and_msgs) in same_pk.iter().filter(|(_k, v)| v.len() == 1) {
        match same_msg.get_mut(sigs_and_msgs[0].1) {
            Some(v) => {
                v.push((sigs_and_msgs[0].0, pk));
            }
            None => {
                same_msg.insert(sigs_and_msgs[0].1, vec![(sigs_and_msgs[0].0, pk)]);
            }
        }
    }

    for (msg, sigs_and_pks) in same_msg.iter().filter(|(_k, v)| v.len() > 1) {
        if !verify_bls_signature_batch_same_msg(&sigs_and_pks[..], msg, rng) {
            return false;
        };
    }

    // the remainder contains distinct tuples and is least efficient to verify (although more efficient than one-by-one)
    let distinct_len = same_msg.iter().filter(|(_k, v)| v.len() == 1).count();
    let mut sigs_pks_msgs = Vec::<(&Sig, &Pk, &Msg)>::with_capacity(distinct_len);

    for (&msg, sigs_and_pks) in same_msg.iter().filter(|(_k, v)| v.len() == 1) {
        sigs_pks_msgs.push((sigs_and_pks[0].0, sigs_and_pks[0].1, msg));
    }

    verify_bls_signature_batch_distinct(&sigs_pks_msgs[..], rng)
}

/// Performs the verification of a batch of BLS signatures that is faster than
/// pairwise verification.
///
/// This works by adding together all signatures before computing the pairing,
/// and thus reduces the number of required pairings from 2n to n+1.
///
/// For details, see Section 5.1 in "Batch Verification of Short Signatures"
/// by J. Camenisch, S. Hohenberger, M. Ø. Pedersen. In Eurocrypt'07.
/// https://eprint.iacr.org/2007/172.pdf.
pub fn verify_bls_signature_batch_distinct<R: RngCore + CryptoRng>(
    sigs_pks_msgs: &[(&G1Affine, &G2Affine, &G1Affine)],
    rng: &mut R,
) -> bool {
    let random_scalars =
        Scalar::batch_sparse_random(rng, sigs_pks_msgs.len(), NUM_BITS_BATCH_VERIFICATION);
    let (sigs, pks, msgs): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(sigs_pks_msgs.to_vec());

    let sigs_scalars: Vec<_> = sigs.into_iter().zip(random_scalars.iter()).collect();
    let aggregate_sig = G1Projective::muln_affine_sparse_vartime(&sigs_scalars[..]).to_affine();
    let inv_g2_gen = G2Prepared::neg_generator();

    let msgs: Vec<_> = msgs
        .iter()
        .zip(random_scalars.iter())
        .map(|(&msg, s)| (msg * s).to_affine())
        .collect();

    let pks_prepared: Vec<_> = pks.into_iter().map(G2Prepared::from).collect();

    let mut multipairing_inputs = Vec::with_capacity(sigs_pks_msgs.len() + 1);
    multipairing_inputs.push((&aggregate_sig, inv_g2_gen));
    for (msg, pk) in msgs.iter().zip(pks_prepared.iter()) {
        multipairing_inputs.push((msg, pk));
    }

    Gt::multipairing(&multipairing_inputs[..]).is_identity()
}

/// Performs the verification of a batch of BLS signatures that is faster than
/// pairwise verification given the same public key
///
/// This works by adding together all signatures before computing the pairing,
/// and thus reduces the number of required pairings 2n to 2.
///
/// For details, see Section 5.2 in "Short Signatures from the Weil Pairing"
/// by Dan Boneh, Ben Lynn, and Hovav Shacham. In Journal of Cryptology'04.
/// https://link.springer.com/content/pdf/10.1007/s00145-004-0314-9.pdf.
pub fn verify_bls_signature_batch_same_pk<R: RngCore + CryptoRng>(
    sigs_msgs: &[(&G1Affine, &G1Affine)],
    public_key: &G2Affine,
    rng: &mut R,
) -> bool {
    let random_scalars =
        Scalar::batch_sparse_random(rng, sigs_msgs.len(), NUM_BITS_BATCH_VERIFICATION);
    let (sigs, msgs): (Vec<_>, Vec<_>) = sigs_msgs.iter().copied().unzip();
    let sigs_scalars: Vec<_> = sigs.into_iter().zip(random_scalars.iter()).collect();
    let aggregate_sig = G1Projective::muln_affine_sparse_vartime(&sigs_scalars[..]).to_affine();
    let inv_g2_gen = G2Prepared::neg_generator();

    let msgs_scalars: Vec<_> = msgs.into_iter().zip(random_scalars.iter()).collect();
    let aggregate_message = G1Projective::muln_affine_sparse_vartime(&msgs_scalars[..]).to_affine();
    let prepared_pk = G2Prepared::from(public_key);

    Gt::multipairing(&[
        (&aggregate_sig, inv_g2_gen),
        (&aggregate_message, &prepared_pk),
    ])
    .is_identity()
}

/// Performs a verification of a batch of BLS signatures that is faster than
/// pairwise verification given the same message
///
/// This works by adding together all signatures before computing the pairing,
/// and thus reduces the number of required pairings 2n to 2.
///
/// For details, see Section 5.2 in "Short Signatures from the Weil Pairing"
/// by Dan Boneh, Ben Lynn, and Hovav Shacham. In Journal of Cryptology'04.
/// https://link.springer.com/content/pdf/10.1007/s00145-004-0314-9.pdf.
pub fn verify_bls_signature_batch_same_msg<R: RngCore + CryptoRng>(
    sigs_pks: &[(&G1Affine, &G2Affine)],
    message: &G1Affine,
    rng: &mut R,
) -> bool {
    let random_scalars =
        Scalar::batch_sparse_random(rng, sigs_pks.len(), NUM_BITS_BATCH_VERIFICATION);
    let (sigs, pks): (Vec<_>, Vec<_>) = sigs_pks.iter().copied().unzip();
    let sigs_scalars: Vec<_> = sigs.into_iter().zip(random_scalars.iter()).collect();
    let aggregate_sig = G1Projective::muln_affine_sparse_vartime(&sigs_scalars[..]).to_affine();
    let inv_g2_gen = G2Prepared::neg_generator();

    let pks_scalars: Vec<_> = pks.into_iter().zip(random_scalars.iter()).collect();
    let aggregate_pk = G2Projective::muln_affine_sparse_vartime(&pks_scalars[..]);
    let pub_key_prepared = G2Prepared::from(aggregate_pk);

    Gt::multipairing(&[(&aggregate_sig, inv_g2_gen), (message, &pub_key_prepared)]).is_identity()
}

struct WindowInfo<const WINDOW_SIZE: usize> {}

impl<const WINDOW_SIZE: usize> WindowInfo<WINDOW_SIZE> {
    const SIZE: usize = WINDOW_SIZE;
    const WINDOWS: usize = (Scalar::BYTES * 8).div_ceil(Self::SIZE);

    const MASK: u8 = 0xFFu8 >> (8 - Self::SIZE);
    const ELEMENTS: usize = (1 << Self::SIZE) as usize;

    #[inline(always)]
    /// * `bit_len` denotes the total bit size
    /// * `inverted_w` denotes the window index counting from the least significant part of the scalar
    fn window_bit_offset(inverted_w: usize) -> usize {
        (inverted_w * Self::SIZE) % 8
    }

    #[inline(always)]
    /// Extract a window from a serialized scalar value
    ///
    /// Treat the scalar as if it was a sequence of windows, each of WINDOW_SIZE bits,
    /// and return the `w`th one of them. For 8 bit windows, this is simply the byte
    /// value. For smaller windows this is some subset of a single byte.
    /// Note that `w=0` is the window corresponding to the largest value, i.e., if
    /// out scalar spans one byte and is equal to 10101111_2=207_10, then it first, say
    /// 4-bit, window will be 1010_2=10_10.
    ///
    /// Only window sizes in 1..=8 are supported.
    fn extract(scalar: &[u8], w: usize) -> u8 {
        assert!((1..=8).contains(&Self::SIZE));
        const BITS_IN_BYTE: usize = 8;

        // to compute the correct bit offset for bit lengths that are not a power of 2,
        // we need to start from the inverted value or otherwise we will have multiple options
        // for the offset.
        let inverted_w = Self::WINDOWS - w - 1;
        let bit_offset = Self::window_bit_offset(inverted_w);
        let byte_offset = Scalar::BYTES - 1 - (inverted_w * Self::SIZE) / 8;
        let target_byte = scalar[byte_offset];

        let no_overflow = bit_offset + Self::SIZE <= BITS_IN_BYTE;

        let non_overflow_bits = target_byte >> bit_offset;

        if no_overflow || byte_offset == 0 {
            // If we can get the window out of single byte, do so
            non_overflow_bits & Self::MASK
        } else {
            // Otherwise we must join two bytes and extract the result
            let prev_byte = scalar[byte_offset - 1];
            let overflow_bits = prev_byte << (BITS_IN_BYTE - bit_offset);
            (non_overflow_bits | overflow_bits) & Self::MASK
        }
    }
}
