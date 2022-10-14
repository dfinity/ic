//! Wrapper for BLS12-381 operations

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]
#![allow(clippy::needless_range_loop)]

use ic_bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use pairing::group::{ff::Field, Group};
use paste::paste;
use rand::{CryptoRng, RngCore};
use std::fmt;
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
#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct Scalar {
    value: ic_bls12_381::Scalar,
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
            Self::from_u64((v as i64).abs() as u64).neg()
        } else {
            Self::from_u64(v.abs() as u64)
        }
    }

    /// Create a scalar from a small integer value
    pub fn from_usize(v: usize) -> Self {
        Self::from_u64(v as u64)
    }

    /// Create a scalar from a small integer value
    pub fn from_isize(v: isize) -> Self {
        if v < 0 {
            Self::from_u64((v as i64).abs() as u64).neg()
        } else {
            Self::from_u64(v.abs() as u64)
        }
    }

    /// Return `cnt` consecutive powers of `x`
    pub fn xpowers(x: &Self, cnt: usize) -> Vec<Self> {
        let mut r = Vec::with_capacity(cnt);

        let mut xpow = Self::one();
        for _ in 0..cnt {
            xpow *= x;
            r.push(xpow);
        }

        r
    }

    /// Randomly generate a scalar in a way that is compatible with MIRACL
    ///
    /// This should not be used for new code but only for compatability in
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

        use rand::Rng;

        let mut bytes = [0u8; 64];

        // We can't use fill_bytes here because that results in incompatible output.
        for i in 0..64 {
            bytes[i] = rng.gen::<u8>();
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

    /// Return the scalar 1
    pub fn one() -> Self {
        Self::new(ic_bls12_381::Scalar::one())
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

    /// Return a random scalar within a small range
    ///
    /// Returns a scalar in range [0,n) using rejection sampling.
    pub fn random_within_range<R: RngCore + CryptoRng>(rng: &mut R, n: u64) -> Self {
        if n <= 1 {
            return Self::zero();
        }

        let t_bits = std::mem::size_of::<u64>() * 8;
        let n_bits = std::cmp::min(255, t_bits - n.leading_zeros() as usize);
        let n_bytes = (n_bits + 7) / 8;
        let n_mask = if n_bits % 8 == 0 {
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
                if s < n {
                    return s;
                }
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
        Self::new(ic_bls12_381::Scalar::from_bytes_wide(&le_bytes))
    }

    /// Deserialize a scalar from a big-endian byte string
    pub fn deserialize<B: AsRef<[u8]>>(bytes: &B) -> Result<Self, PairingInvalidScalar> {
        let mut bytes: [u8; Self::BYTES] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| PairingInvalidScalar::InvalidScalar)?;
        bytes.reverse();
        let scalar = ic_bls12_381::Scalar::from_bytes(&bytes);
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
            accum += lhs[i] * rhs[i];
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
            accum += lhs[i] * Scalar::from_usize(rhs[i]);
        }
        accum
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

macro_rules! declare_mixed_addition_ops_for {
    ( $proj:ty, $affine:ty ) => {
        impl std::ops::Add<$affine> for $proj {
            type Output = Self;

            fn add(self, other: $affine) -> Self {
                Self::new(self.inner().add_mixed(other.inner()))
            }
        }

        impl std::ops::Add<&$affine> for $proj {
            type Output = Self;

            fn add(self, other: &$affine) -> Self {
                Self::new(self.inner().add_mixed(other.inner()))
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

        impl std::ops::Mul<Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> $typ {
                *self * scalar
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
        paste! {
            lazy_static::lazy_static! {
                static ref [<$affine:upper _GENERATOR>] : $affine = $affine::new(ic_bls12_381::$affine::generator());
                static ref [<$affine:upper _IDENTITY>] : $affine = $affine::new(ic_bls12_381::$affine::identity());
            }
        }

        /// An element of the group in affine form
        #[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
        pub struct $affine {
            value: ic_bls12_381::$affine
        }

        impl $affine {
            /// The size in bytes of this type
            pub const BYTES: usize = $size;

            /// Create a struct from the inner type
            pub(crate) fn new(value: ic_bls12_381::$affine) -> Self {
                Self { value }
            }

            /// Return the inner value
            pub(crate) fn inner(&self) -> &ic_bls12_381::$affine {
                &self.value
            }

            /// Return the identity element in this group
            pub fn identity() -> &'static Self {
                paste! { &[<$affine:upper _IDENTITY>] }
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
            /// * `domain_sep` - some protocol specific domain seperator
            /// * `input` - the input which will be hashed
            pub fn hash(domain_sep: &[u8], input: &[u8]) -> Self {
                $projective::hash(domain_sep, input).into()
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

            /// Deserialize multiple point (compressed format only)
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

        paste! {
            lazy_static::lazy_static! {
                static ref [<$projective:upper _GENERATOR>] : $projective = $projective::new(ic_bls12_381::$projective::generator());
                static ref [<$projective:upper _IDENTITY>] : $projective = $projective::new(ic_bls12_381::$projective::identity());
            }
        }

        /// An element of the group in projective form
        #[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
        pub struct $projective {
            value: ic_bls12_381::$projective
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
            pub fn identity() -> &'static Self {
                paste! { &[<$projective:upper _IDENTITY>] }
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
            /// * `domain_sep` - some protocol specific domain seperator
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
        }

        impl std::ops::Mul<Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: Scalar) -> $projective {
                <$projective>::from(self).windowed_mul(&scalar)
            }
        }

        impl std::ops::Mul<&Scalar> for $affine {
            type Output = $projective;

            fn mul(self, scalar: &Scalar) -> $projective {
                <$projective>::from(self).windowed_mul(scalar)
            }
        }

        impl std::ops::Mul<Scalar> for &$affine {
            type Output = $projective;

            fn mul(self, scalar: Scalar) -> $projective {
               *self * scalar
            }
        }

        impl std::ops::Mul<&Scalar> for &$affine {
            type Output = $projective;

            fn mul(self, scalar: &Scalar) -> $projective {
               *self * scalar
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

macro_rules! declare_mul2_impl_for {
    ( $typ:ty, $window:expr ) => {
        impl $typ {
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
                // Configurable window size: can be 1, 2, or 4
                type Window = WindowInfo<$window>;

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
                let mut tbl = [*Self::identity(); TABLE_SIZE];

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

                let mut accum = *Self::identity();

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

                    accum += Self::ct_select(&tbl, window);
                }

                accum
            }
        }
    };
}

macro_rules! declare_muln_vartime_impl_for {
    ( $typ:ty, $window:expr ) => {
        impl $typ {
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
                type Window = WindowInfo<$window>;

                let mut windows = Vec::with_capacity(terms.len());
                for (_pt, scalar) in terms {
                    let sb = scalar.serialize();

                    let mut window = [0u8; Window::WINDOWS];
                    for i in 0..Window::WINDOWS {
                        window[i] = Window::extract(&sb, i);
                    }
                    windows.push(window);
                }

                let id = *Self::identity();
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
    };
}

macro_rules! declare_muln_vartime_affine_impl_for {
    ( $proj:ty, $affine:ty ) => {
        impl $proj {
            /// Multiscalar multiplication
            ///
            /// Equivalent to p1*s1 + p2*s2 + p3*s3 + ... + pn*sn
            ///
            /// Returns the identity element if terms is empty.
            ///
            /// Warning: this function leaks information about the scalars via
            /// memory-based side channels. Do not use this function with secret
            /// scalars.
            pub fn muln_affine_vartime(points: &[$affine], scalars: &[Scalar]) -> Self {
                let count = std::cmp::min(points.len(), scalars.len());
                let mut terms = Vec::with_capacity(count);

                for i in 0..count {
                    terms.push((<$proj>::from(points[i]), scalars[i]));
                }

                Self::muln_vartime(&terms)
            }
        }
    };
}

macro_rules! declare_windowed_scalar_mul_ops_for {
    ( $typ:ty, $window:expr ) => {
        impl $typ {
            pub(crate) fn windowed_mul(&self, scalar: &Scalar) -> Self {
                // Configurable window size: can be 1, 2, or 4
                type Window = WindowInfo<$window>;

                // Derived constants
                const TABLE_SIZE: usize = Window::ELEMENTS;

                let mut tbl = [*Self::identity(); TABLE_SIZE];

                for i in 1..TABLE_SIZE {
                    tbl[i] = tbl[i - 1] + *self;
                }

                let s = scalar.serialize();

                let mut accum = *Self::identity();

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
        }

        impl std::ops::Mul<Scalar> for $typ {
            type Output = Self;
            fn mul(self, scalar: Scalar) -> Self {
                self.windowed_mul(&scalar)
            }
        }

        impl std::ops::Mul<&Scalar> for $typ {
            type Output = Self;
            fn mul(self, scalar: &Scalar) -> Self {
                self.windowed_mul(scalar)
            }
        }

        impl std::ops::Mul<Scalar> for &$typ {
            type Output = $typ;
            fn mul(self, scalar: Scalar) -> Self::Output {
                *self * scalar
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

define_affine_and_projective_types!(G1Affine, G1Projective, 48);
declare_addsub_ops_for!(G1Projective);
declare_mixed_addition_ops_for!(G1Projective, G1Affine);
declare_windowed_scalar_mul_ops_for!(G1Projective, 4);
declare_mul2_impl_for!(G1Projective, 2);
declare_muln_vartime_impl_for!(G1Projective, 4);
declare_muln_vartime_affine_impl_for!(G1Projective, G1Affine);
impl_debug_using_serialize_for!(G1Affine);
impl_debug_using_serialize_for!(G1Projective);

define_affine_and_projective_types!(G2Affine, G2Projective, 96);
declare_addsub_ops_for!(G2Projective);
declare_mixed_addition_ops_for!(G2Projective, G2Affine);
declare_windowed_scalar_mul_ops_for!(G2Projective, 4);
declare_mul2_impl_for!(G2Projective, 2);
declare_muln_vartime_impl_for!(G2Projective, 4);
impl_debug_using_serialize_for!(G2Affine);
impl_debug_using_serialize_for!(G2Projective);

/// An element of the group Gt
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Gt {
    value: ic_bls12_381::Gt,
}

lazy_static::lazy_static! {
    static ref GT_GENERATOR : Gt = Gt::new(ic_bls12_381::Gt::generator());
    static ref GT_IDENTITY : Gt = Gt::new(ic_bls12_381::Gt::identity());
}

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

    /// Return the identity element in the group
    pub fn identity() -> &'static Self {
        &GT_IDENTITY
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

    /// Return some arbitrary bytes which represent this Gt element
    ///
    /// These are not deserializable, and serve only to uniquely identify
    /// the group element.
    pub fn tag(&self) -> [u8; Self::BYTES] {
        self.value.to_bytes()
    }
}

declare_addsub_ops_for!(Gt);
declare_mul_scalar_ops_for!(Gt);

/// An element of the group G2 prepared for the Miller loop
#[derive(Clone, Debug)]
pub struct G2Prepared {
    value: ic_bls12_381::G2Prepared,
}

lazy_static::lazy_static! {
    static ref G2PREPARED_G : G2Prepared = G2Affine::generator().into();
    static ref G2PREPARED_NEG_G : G2Prepared = G2Affine::generator().neg().into();
}

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
