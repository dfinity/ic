use k256::elliptic_curve::{
    group::{ff::PrimeField, GroupEncoding},
    ops::{LinearCombination, Reduce},
    sec1::{FromEncodedPoint, ToEncodedPoint},
    Field, Group, IsHigh,
};
use std::ops::Neg;
use zeroize::Zeroize;

#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct Scalar {
    s: k256::Scalar,
}

impl Scalar {
    pub const BYTES: usize = 32;

    /// Internal constructor (private)
    fn new(s: k256::Scalar) -> Self {
        Self { s }
    }

    /// Deserialize a scalar
    ///
    /// If the input is not the correct length or is out of range
    /// then None is returned
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTES {
            return None;
        }

        let fb = k256::FieldBytes::from_slice(bytes);
        let s = k256::Scalar::from_repr(*fb);

        if bool::from(s.is_some()) {
            Some(Self::new(s.unwrap()))
        } else {
            None
        }
    }

    /// Compute the scalar from a larger value
    ///
    /// The input is allowed to be up to twice the length of a scalar. It is
    /// interpreted as a big-endian encoded integer, and reduced modulo the
    /// group order.
    pub fn from_wide_bytes(bytes: &[u8]) -> Option<Self> {
        /*
        As the k256 crates is lacking a native function that reduces an input
        modulo the group order we have to synthesize it using other operations.

        Do so by splitting up the input into two parts each of which is at most
        scalar_len bytes long. Then compute s0*2^X + s1
        */

        if bytes.len() > Self::BYTES * 2 {
            return None;
        }

        let mut extended = vec![0; 2 * Self::BYTES];
        let offset = extended.len() - bytes.len();
        extended[offset..].copy_from_slice(bytes); // zero pad

        let fb0 = k256::FieldBytes::from_slice(&extended[..Self::BYTES]);
        let fb1 = k256::FieldBytes::from_slice(&extended[Self::BYTES..]);

        let mut s0 = <k256::Scalar as Reduce<k256::U256>>::from_be_bytes_reduced(*fb0);
        let s1 = <k256::Scalar as Reduce<k256::U256>>::from_be_bytes_reduced(*fb1);

        for _bit in 1..=Self::BYTES * 8 {
            s0 = s0.double();
        }
        s0 += s1;

        Some(Self::new(s0))
    }

    /// Return constant zero
    pub fn zero() -> Self {
        Self::new(k256::Scalar::zero())
    }

    /// Return constant one
    pub fn one() -> Self {
        Self::new(k256::Scalar::one())
    }

    /// Create a scalar from a small integer
    pub fn from(v: u64) -> Self {
        Self::new(k256::Scalar::from(v))
    }

    /// Add two scalars
    pub fn add(&self, other: &Self) -> Self {
        Self::new(self.s.add(&other.s))
    }

    /// Subtract two scalars
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(self.s.sub(&other.s))
    }

    /// Multiply two scalars
    pub fn mul(&self, other: &Self) -> Self {
        Self::new(self.s.mul(&other.s))
    }

    /// Perform modular inversion
    ///
    /// Returns None if no modular inverse exists (ie because the
    /// scalar is zero)
    pub fn invert(&self) -> Option<Self> {
        let inv = self.s.invert();
        if bool::from(inv.is_some()) {
            Some(Self::new(inv.unwrap()))
        } else {
            None
        }
    }

    /// Check if the scalar is zero
    pub fn is_zero(&self) -> bool {
        bool::from(self.s.is_zero())
    }

    /// Return if the scalar is "high"
    ///
    /// This is false if s*2 would not overflow
    pub fn is_high(&self) -> bool {
        bool::from(self.s.is_high())
    }

    /// Return the negation of the scalar
    pub fn negate(&self) -> Self {
        Self::new(self.s.neg())
    }

    /// Return the encoding of the scalar as bytes
    ///
    /// The return value is fixed length big endian encoding, with
    /// zero padding if required
    pub fn as_bytes(&self) -> [u8; Self::BYTES] {
        self.s.to_bytes().into()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub struct Point {
    p: k256::ProjectivePoint,
}

impl Point {
    /// Internal constructor (private)
    fn new(p: k256::ProjectivePoint) -> Self {
        Self { p }
    }

    /// Deserialize a point
    ///
    /// Both compressed and uncompressed points are accepted
    ///
    /// If the value encoded is not a valid point on the curve, then
    /// None is returned
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        match k256::EncodedPoint::from_bytes(bytes) {
            Ok(ept) => {
                let apt = k256::AffinePoint::from_encoded_point(&ept);

                if bool::from(apt.is_some()) {
                    Some(Self::new(k256::ProjectivePoint::from(apt.unwrap())))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Return the identity element (aka the point at infinity)
    pub fn identity() -> Self {
        Self::new(k256::ProjectivePoint::IDENTITY)
    }

    /// Return the standard generator of the group
    pub fn generator() -> Self {
        Self::new(k256::ProjectivePoint::GENERATOR)
    }

    /// Perform multi-exponentiation
    ///
    /// Equivalent to p1*s1 + p2*s2
    pub fn lincomb(p1: &Point, s1: &Scalar, p2: &Point, s2: &Scalar) -> Self {
        Self::new(k256::ProjectivePoint::lincomb(&p1.p, &s1.s, &p2.p, &s2.s))
    }

    /// Add two points
    pub fn add(&self, other: &Self) -> Self {
        Self::new(self.p + other.p)
    }

    /// Subtract two points
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(self.p - other.p)
    }

    /// Perform point doubling
    pub fn double(&self) -> Self {
        Self::new(self.p.double())
    }

    /// Scalar multiplication
    pub fn mul(&self, scalar: &Scalar) -> Self {
        Self::new(self.p * scalar.s)
    }

    /// Serialize the point to bytes in compressed format
    pub fn serialize(&self) -> Vec<u8> {
        self.p.to_affine().to_bytes().to_vec()
    }

    /// Serialize the point to bytes in uncompressed format
    pub fn serialize_uncompressed(&self) -> Vec<u8> {
        self.p
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Check if the point is the point at infinity
    pub fn is_infinity(&self) -> bool {
        bool::from(self.p.is_identity())
    }
}
