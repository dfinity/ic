use hex_literal::hex;
use p256::elliptic_curve::{
    Field, Group,
    group::{GroupEncoding, ff::PrimeField},
    ops::{Invert, LinearCombination, Reduce},
    scalar::IsHigh,
    sec1::FromEncodedPoint,
};
use std::ops::{Mul, Neg};
use std::sync::LazyLock;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    s: p256::Scalar,
}

// The secp256r1 parameters are defined in FIPS 186-4, section D.1.2
// [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf]
//
// The SSWU parameters are defined in
// https://www.rfc-editor.org/rfc/rfc9380.html#name-suites-for-nist-p-256
fe_derive::derive_field_element!(
    FieldElement,
    Modulus = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    A = "-3",
    B = "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    SSWU_A = "A",
    SSWU_B = "B",
    SSWU_Z = "-10",
);

fn from_fe((x, y): &(FieldElement, FieldElement)) -> Point {
    let mut buf = Vec::with_capacity(1 + 2 * FieldElement::BYTES);
    buf.push(0x04);
    buf.extend_from_slice(&x.as_bytes());
    buf.extend_from_slice(&y.as_bytes());
    Point::deserialize(&buf).expect("hash2curve produced invalid point")
}

super::algos::declare_sswu_p_3_mod_4_map_to_curve_impl!(
    h2c_secp256r1,
    FieldElement,
    Point,
    from_fe
);

impl Scalar {
    pub const BYTES: usize = 32;
    pub const BITS: usize = 256;

    /// Internal constructor (private)
    fn new(s: p256::Scalar) -> Self {
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

        p256::Scalar::from_repr(*p256::FieldBytes::from_slice(bytes))
            .into_option()
            .map(Self::new)
    }

    /// Compute the scalar from a larger value
    ///
    /// The input is allowed to be up to twice the length of a scalar. It is
    /// interpreted as a big-endian encoded integer, and reduced modulo the
    /// group order.
    pub fn from_wide_bytes(bytes: &[u8]) -> Option<Self> {
        /*
        As the p256 crates is lacking a native function that reduces an input
        modulo the group order we have to synthesize it using other operations.

        Do so by splitting up the input into two parts each of which is at most
        scalar_len bytes long. Then compute s0*2^X + s1
        */

        if bytes.len() > Self::BYTES * 2 {
            return None;
        }

        let mut extended = [0; 2 * Self::BYTES];
        let offset = extended.len() - bytes.len();
        extended[offset..].copy_from_slice(bytes); // zero pad

        let fb0 = p256::FieldBytes::from_slice(&extended[..Self::BYTES]);
        let fb1 = p256::FieldBytes::from_slice(&extended[Self::BYTES..]);

        let mut s0 = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(fb0);
        let s1 = <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(fb1);

        for _bit in 1..=Self::BYTES * 8 {
            s0 = s0.double();
        }
        s0 += s1;

        Some(Self::new(s0))
    }

    /// Return constant zero
    pub fn zero() -> Self {
        Self::new(p256::Scalar::ZERO)
    }

    /// Return constant one
    pub fn one() -> Self {
        Self::new(p256::Scalar::ONE)
    }

    /// Create a scalar from a small integer
    pub fn from(v: u64) -> Self {
        Self::new(p256::Scalar::from(v))
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
        self.s.invert().into_option().map(Self::new)
    }

    /// Perform modular inversion
    ///
    /// Returns None if no modular inverse exists (ie because the
    /// scalar is zero)
    pub fn invert_vartime(&self) -> Option<Self> {
        self.s.invert_vartime().into_option().map(Self::new)
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
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.s.to_bytes().into()
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Point {
    p: p256::ProjectivePoint,
}

super::algos::declare_mul_by_g_impl!(Secp256r1MulByGenerator, Point, Scalar);
super::algos::declare_mul2_table_impl!(Secp256r1Mul2Table, Point, Scalar);

/// Static deserialization of the fixed alternative group generator
static SECP256R1_GENERATOR_H: LazyLock<Point> = LazyLock::new(|| {
    Point::deserialize(&hex!(
        "036774e87305efcb97c0ce289d57cd721972845ca33eccb8026c6d7c1c4182e7c1"
    ))
    .expect("The secp256r1 generator_h point is invalid")
});

/// Precomputed multiples of the group generator for fast multiplication
static SECP256R1_MUL_BY_GEN_TABLE: LazyLock<Secp256r1MulByGenerator> =
    LazyLock::new(|| Secp256r1MulByGenerator::new(&Point::generator()));

/// Precomputed linear combinations of the g and h generators
/// for fast Pedersen commitment computation
static SECP256R1_MUL2_GX_HY_TABLE: LazyLock<Secp256r1Mul2Table> =
    LazyLock::new(Secp256r1Mul2Table::for_standard_generators);

impl Point {
    /// Internal constructor (private)
    fn new(p: p256::ProjectivePoint) -> Self {
        Self { p }
    }

    /// Deserialize a point
    ///
    /// Both compressed and uncompressed points are accepted
    ///
    /// If the value encoded is not a valid point on the curve, then
    /// None is returned
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        match p256::EncodedPoint::from_bytes(bytes) {
            Ok(ept) => p256::AffinePoint::from_encoded_point(&ept)
                .into_option()
                .map(|p| Self::new(p256::ProjectivePoint::from(p))),
            Err(_) => None,
        }
    }

    /// Return the identity element (aka the point at infinity)
    pub fn identity() -> Self {
        Self::new(p256::ProjectivePoint::IDENTITY)
    }

    /// Return the standard generator of the group
    pub fn generator() -> Self {
        Self::new(p256::ProjectivePoint::GENERATOR)
    }

    /// Return the alternative generator of the group
    pub fn generator_h() -> Self {
        SECP256R1_GENERATOR_H.clone()
    }

    /// Perform multi-exponentiation
    ///
    /// Equivalent to p1*s1 + p2*s2
    pub fn lincomb(p1: &Point, s1: &Scalar, p2: &Point, s2: &Scalar) -> Self {
        // Use mul2 table here!
        Self::new(p256::ProjectivePoint::lincomb(&p1.p, &s1.s, &p2.p, &s2.s))
    }

    pub fn pedersen(s1: &Scalar, s2: &Scalar) -> Self {
        SECP256R1_MUL2_GX_HY_TABLE.mul2(s1, s2)
    }

    /// Add two points
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        Self::new(self.p + other.p)
    }

    /// Subtract two points
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
    ///
    /// Currently p256 does not support MulByGenerator trait
    pub fn mul_by_g(scalar: &Scalar) -> Self {
        SECP256R1_MUL_BY_GEN_TABLE.mul(scalar)
    }

    /// Serialize the point to bytes in compressed format
    pub fn serialize(&self) -> Vec<u8> {
        self.p.to_affine().to_bytes().to_vec()
    }

    /// Check if the point is the point at infinity
    pub fn is_infinity(&self) -> bool {
        bool::from(self.p.is_identity())
    }

    /// Constant time conditional selection
    #[inline(always)]
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            p: p256::ProjectivePoint::conditional_select(&a.p, &b.p, choice),
        }
    }

    /// Returns tbl[index-1] if index > 0 or otherwise identity element
    ///
    /// Namely if index is equal to zero, or is out of range, identity is returned
    #[inline]
    fn ct_select(tbl: &[Self], index: usize) -> Self {
        let mut result = Self::identity();
        let index = index.wrapping_sub(1);
        for (i, val) in tbl.iter().enumerate() {
            let choice = usize::ct_eq(&i, &index);
            result = Self::conditional_select(&result, val, choice);
        }

        result
    }

    /// Hash to curve (random oracle variant)
    pub fn hash2curve(input: &[u8], domain_sep: &[u8]) -> Self {
        h2c_secp256r1(input, domain_sep)
    }
}
