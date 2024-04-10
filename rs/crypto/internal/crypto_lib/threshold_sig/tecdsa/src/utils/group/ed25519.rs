use curve25519_dalek::traits::MultiscalarMul;
use group::{ff::Field, Group, GroupEncoding};
use hex_literal::hex;
use std::ops::{Add, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    s: curve25519_dalek::Scalar,
}

impl Scalar {
    pub const BYTES: usize = 32;
    pub const BITS: usize = 255;

    /// Internal constructor (private)
    fn new(s: curve25519_dalek::Scalar) -> Self {
        Self { s }
    }

    /// Deserialize a scalar
    ///
    /// If the input is not the correct length or is out of range
    /// then None is returned
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let b = bytes.try_into().ok()?;
        curve25519_dalek::Scalar::from_canonical_bytes(b)
            .map(Self::new)
            .into()
    }

    /// Compute the scalar from a larger value
    ///
    /// The input is allowed to be up to twice the length of a scalar. It is
    /// interpreted as a big-endian encoded integer, and reduced modulo the
    /// group order.
    pub fn from_wide_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > Self::BYTES * 2 {
            return None;
        }

        let mut extended = [0; 2 * Self::BYTES];
        let offset = extended.len() - bytes.len();
        extended[offset..].copy_from_slice(bytes); // zero pad

        // dalek uses little-endian!
        extended.reverse();

        let s = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&extended);

        Some(Self::new(s))
    }

    /// Return constant zero
    pub fn zero() -> Self {
        Self::new(curve25519_dalek::Scalar::ZERO)
    }

    /// Return constant one
    pub fn one() -> Self {
        Self::new(curve25519_dalek::Scalar::ONE)
    }

    /// Create a scalar from a small integer
    pub fn from(v: u64) -> Self {
        Self::new(curve25519_dalek::Scalar::from(v))
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
        if self.is_zero() {
            return None;
        }

        Some(Self::new(self.s.invert()))
    }

    /// Check if the scalar is zero
    pub fn is_zero(&self) -> bool {
        bool::from(self.s.is_zero())
    }

    /// Return the negation of the scalar
    pub fn negate(&self) -> Self {
        Self::new(self.s.neg())
    }

    /// Return the encoding of the scalar as bytes
    ///
    /// The return value is fixed length big endian encoding, with
    /// zero padding if required
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.s.to_bytes()
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Point {
    p: curve25519_dalek::EdwardsPoint,
}

lazy_static::lazy_static! {

    /// Static deserialization of the fixed alternative group generator
    ///
    /// TODO(CRP-2458) this is generated using our current (non-standard)
    /// hash to curve implementation and will need to be changed once Elligator
    /// has been implemented.
    static ref ED25519_GENERATOR_H: Point = Point::deserialize(
        &hex!("0858a11e43d43013518cdd55c279d70dfa2b49e0b926e1e80b520d8803f2e99c"))
        .expect("The ed25519 generator_h point is invalid");

}

impl Point {
    pub const BYTES: usize = 32;

    /// Internal constructor (private)
    fn new(p: curve25519_dalek::EdwardsPoint) -> Self {
        Self { p }
    }

    /// Deserialize a point
    ///
    /// If the value encoded is not a valid point on the curve, then
    /// None is returned
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let b = bytes.try_into().ok()?;
        let pt = curve25519_dalek::EdwardsPoint::from_bytes(&b);

        if bool::from(pt.is_some()) {
            let pt = pt.unwrap();

            if pt.is_torsion_free() {
                Some(Self::new(pt))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Return the identity element (aka the point at infinity)
    pub fn identity() -> Self {
        Self::new(curve25519_dalek::EdwardsPoint::identity())
    }

    /// Return the standard generator of the group
    pub fn generator() -> Self {
        Self::new(curve25519_dalek::EdwardsPoint::generator())
    }

    /// Return the alternative generator of the group
    pub fn generator_h() -> Self {
        ED25519_GENERATOR_H.clone()
    }

    /// Perform multi-exponentiation
    ///
    /// Equivalent to p1*s1 + p2*s2
    #[inline]
    pub fn lincomb(p1: &Point, s1: &Scalar, p2: &Point, s2: &Scalar) -> Self {
        Self::new(curve25519_dalek::EdwardsPoint::multiscalar_mul(
            &[s1.s, s2.s],
            &[p1.p, p2.p],
        ))
    }

    pub fn pedersen(s1: &Scalar, s2: &Scalar) -> Self {
        let g = Self::generator();
        let h = Self::generator_h();
        Self::new(curve25519_dalek::EdwardsPoint::multiscalar_mul(
            &[s1.s, s2.s],
            &[g.p, h.p],
        ))
    }

    /// Add two points
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        Self::new(self.p + other.p)
    }

    /// Subtract two points
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        Self::new(self.p - other.p)
    }

    /// Perform point doubling
    #[inline]
    pub fn double(&self) -> Self {
        Self::new(self.p.double())
    }

    /// Perform point negation
    pub fn negate(&self) -> Self {
        Self::new(self.p.neg())
    }

    /// Scalar multiplication
    #[inline]
    pub fn mul(&self, scalar: &Scalar) -> Self {
        Self::new(self.p * scalar.s)
    }

    /// Scalar multiplication with the customary generator
    pub fn mul_by_g(scalar: &Scalar) -> Self {
        Self::new(curve25519_dalek::EdwardsPoint::mul_base(&scalar.s))
    }

    /// Serialize the point to bytes in compressed format
    pub fn serialize(&self) -> Vec<u8> {
        self.p.compress().0.to_vec()
    }

    /// Check if the point is the point at infinity
    pub fn is_infinity(&self) -> bool {
        bool::from(Group::is_identity(&self.p))
    }

    /// Constant time conditional selection
    #[inline(always)]
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            p: curve25519_dalek::EdwardsPoint::conditional_select(&a.p, &b.p, choice),
        }
    }

    /// Hash to curve (random oracle variant)
    pub fn hash2curve(input: &[u8], domain_sep: &[u8]) -> Self {
        // TODO(CRP-2458)
        // This is non-standard hash function used as a standin for
        // Elligator support

        let mut digest = {
            let mut hash = ic_crypto_sha2::Sha256::new();

            for input in [domain_sep, input] {
                hash.write(&(input.len() as u64).to_be_bytes());
                hash.write(input);
            }

            hash.finish()
        };

        loop {
            if let Some(pt) = Self::deserialize(&digest) {
                return pt;
            }

            digest = ic_crypto_sha2::Sha256::hash(&digest);
        }
    }
}
