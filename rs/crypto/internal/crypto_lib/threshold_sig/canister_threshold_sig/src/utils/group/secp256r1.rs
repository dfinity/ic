use hex_literal::hex;
use p256::elliptic_curve::{
    Field, Group,
    group::{Curve as _, GroupEncoding, ff::PrimeField},
    ops::{LinearCombination, Reduce},
    scalar::IsHigh,
    sec1::FromSec1Point,
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

        p256::Scalar::from_repr(p256::FieldBytes::try_from(bytes).ok()?)
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
        As the p256 crate is lacking a native function that reduces an input
        modulo the group order we have to synthesize it using other operations.

        Do so by splitting up the input into two parts each of which is at most
        scalar_len bytes long. Then compute s0*2^256 + s1
        */

        if bytes.len() > Self::BYTES * 2 {
            return None;
        }

        let mut extended = [0; 2 * Self::BYTES];
        let offset = extended.len() - bytes.len();
        extended[offset..].copy_from_slice(bytes); // zero pad

        let fb0 = p256::FieldBytes::try_from(&extended[..Self::BYTES]).expect("Correct size");
        let fb1 = p256::FieldBytes::try_from(&extended[Self::BYTES..]).expect("Correct size");

        let s0 = <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&fb0);
        let s1 = <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&fb1);

        // 2^256 mod n (secp256r1 group order)
        let shift = p256::Scalar::from_repr(p256::FieldBytes::from(hex!(
            "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf"
        )))
        .unwrap();

        Some(Self::new(s0 * shift + s1))
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

/// Static deserialization of the fixed alternative group generator
static SECP256R1_GENERATOR_H: LazyLock<Point> = LazyLock::new(|| {
    Point::deserialize(&hex!(
        "036774e87305efcb97c0ce289d57cd721972845ca33eccb8026c6d7c1c4182e7c1"
    ))
    .expect("The secp256r1 generator_h point is invalid")
});

/// Precomputed multiples of the group generator for fast multiplication
static SECP256R1_MUL_BY_G_TABLE: LazyLock<Secp256r1FixedBaseTable> =
    LazyLock::new(|| Secp256r1FixedBaseTable::new(&Point::generator()));

/// Precomputed multiples of the alternative group generator, used together
/// with SECP256R1_MUL_BY_G_TABLE for fast Pedersen commitment computation
static SECP256R1_MUL_BY_H_TABLE: LazyLock<Secp256r1FixedBaseTable> =
    LazyLock::new(|| Secp256r1FixedBaseTable::new(&Point::generator_h()));

/// Precomputed multiples of a fixed point P, for constant-time multiplication
///
/// A scalar k is written in signed radix 16 as `k = sum(d[i] * 16^i)` with 65
/// digits `d[i]` in [-8, 8) (see `Self::digits`). Window i of the table holds the
/// affine points `P_i, 2*P_i, ..., 8*P_i` where `P_i = 16^i * P`; a negative
/// digit uses the negation of an entry. So `k*P` is the sum of the points
/// `d[i]*P_i`, which costs one constant-time lookup and one mixed (projective
/// plus affine) point addition per digit, and no doublings.
///
/// The precomputation is expensive, so this is only worth using for points
/// which are multiplied many times (the standard group generators).
struct Secp256r1FixedBaseTable {
    table: Vec<p256::AffinePoint>,
}

impl Secp256r1FixedBaseTable {
    /// The number of signed radix-16 digits of a 256-bit scalar: 64 plus a final carry
    const DIGITS: usize = 65;
    /// The number of table entries per digit: the largest absolute value of a digit
    const WINDOW_ELEM: usize = 8;

    fn new(p: &Point) -> Self {
        let mut multiples = Vec::with_capacity(Self::DIGITS * Self::WINDOW_ELEM);
        let mut p_i = p.p;
        for _ in 0..Self::DIGITS {
            let mut multiple = p256::ProjectivePoint::IDENTITY;
            for _ in 0..Self::WINDOW_ELEM {
                multiple += p_i;
                multiples.push(multiple);
            }
            // 16 * P_i = 2 * (8 * P_i)
            p_i = multiple.double();
        }
        let mut table = vec![p256::AffinePoint::IDENTITY; multiples.len()];
        p256::ProjectivePoint::batch_normalize(&multiples, &mut table);
        Self { table }
    }

    /// Returns the signed radix-16 digits of a scalar, least significant first
    ///
    /// Digits 0 to 63 are in [-8, 8) and digit 64 is 0 or 1.
    fn digits(scalar: &p256::Scalar) -> [i8; Self::DIGITS] {
        let mut digits = [0_i8; Self::DIGITS];
        for (i, byte) in scalar.to_bytes().iter().rev().enumerate() {
            digits[2 * i] = (byte & 0xf) as i8;
            digits[2 * i + 1] = (byte >> 4) as i8;
        }
        // Move each digit from [0, 16] to [-8, 8), carrying into the next one. This never
        // overflows; in builds with overflow checks, wrapping arithmetic keeps them off the
        // secret digits.
        let mut carry = 0_i8;
        for digit in &mut digits {
            let d = digit.wrapping_add(carry);
            carry = d.wrapping_add(8) >> 4;
            *digit = d.wrapping_sub(carry << 4);
        }
        digits
    }

    /// Returns digit * 16^i * P, for digit in [-8, 8]
    ///
    /// Runs in constant time: it reads every entry of window i, and negates
    /// the selected point with a conditional assignment.
    fn lookup(&self, i: usize, digit: i8) -> p256::AffinePoint {
        let window = &self.table[Self::WINDOW_ELEM * i..Self::WINDOW_ELEM * (i + 1)];
        let sign = digit >> 7; // -1 if the digit is negative, otherwise 0
        let abs = (digit ^ sign).wrapping_sub(sign) as u8;
        let mut result = p256::AffinePoint::IDENTITY;
        for (j, multiple) in window.iter().enumerate() {
            result.conditional_assign(multiple, abs.ct_eq(&(j as u8 + 1)));
        }
        let negated = -result;
        result.conditional_assign(&negated, Choice::from((sign & 1) as u8));
        result
    }

    /// Computes P*x
    fn mul(&self, x: &Scalar) -> Point {
        let digits = Self::digits(&x.s);
        let mut accum = p256::ProjectivePoint::from(self.lookup(0, digits[0]));
        for (i, digit) in digits.iter().enumerate().skip(1) {
            accum += self.lookup(i, *digit);
        }
        Point::new(accum)
    }

    /// Computes P*x + Q*y, where Q is the point of `other`
    fn mul2(&self, x: &Scalar, other: &Self, y: &Scalar) -> Point {
        let x_digits = Self::digits(&x.s);
        let y_digits = Self::digits(&y.s);
        let mut accum = p256::ProjectivePoint::from(self.lookup(0, x_digits[0]));
        accum += other.lookup(0, y_digits[0]);
        for (i, (x_digit, y_digit)) in x_digits.iter().zip(&y_digits).enumerate().skip(1) {
            accum += self.lookup(i, *x_digit);
            accum += other.lookup(i, *y_digit);
        }
        Point::new(accum)
    }
}

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
        match p256::Sec1Point::from_bytes(bytes) {
            Ok(ept) => p256::AffinePoint::from_sec1_point(&ept)
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
    pub fn lincomb_vartime(p1: &Point, s1: &Scalar, p2: &Point, s2: &Scalar) -> Self {
        Self::new(p256::ProjectivePoint::lincomb(&[
            (p1.p, s1.s),
            (p2.p, s2.s),
        ]))
    }

    /// Perform multi-exponentiation
    ///
    /// Equivalent to p1*s1 + p2*s2 + p3*s3
    pub fn lincomb3_vartime(
        p1: &Point,
        s1: &Scalar,
        p2: &Point,
        s2: &Scalar,
        p3: &Point,
        s3: &Scalar,
    ) -> Self {
        Self::new(p256::ProjectivePoint::lincomb(&[
            (p1.p, s1.s),
            (p2.p, s2.s),
            (p3.p, s3.s),
        ]))
    }

    pub fn pedersen(s1: &Scalar, s2: &Scalar) -> Self {
        SECP256R1_MUL_BY_G_TABLE.mul2(s1, &SECP256R1_MUL_BY_H_TABLE, s2)
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
    pub fn mul_by_g(scalar: &Scalar) -> Self {
        SECP256R1_MUL_BY_G_TABLE.mul(scalar)
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

    /// Hash to curve (random oracle variant)
    pub fn hash2curve(input: &[u8], domain_sep: &[u8]) -> Self {
        h2c_secp256r1(input, domain_sep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use rand::RngCore;

    fn scalar_from_digit(digit: i8) -> p256::Scalar {
        let abs = p256::Scalar::from(u64::from(digit.unsigned_abs()));
        if digit < 0 { -abs } else { abs }
    }

    #[test]
    fn test_signed_radix_16_digits_are_in_range_and_sum_to_the_scalar() {
        let rng = &mut reproducible_rng();

        let mut scalars = vec![Scalar::zero(), Scalar::one(), Scalar::one().negate()];
        // The 64 low digits of 0x7777...78 are all -8
        let mut bytes = [0x77; Scalar::BYTES];
        bytes[Scalar::BYTES - 1] = 0x78;
        scalars.push(Scalar::deserialize(&bytes).expect("Less than the group order"));
        for _ in 0..300 {
            let mut bytes = [0; 2 * Scalar::BYTES];
            rng.fill_bytes(&mut bytes);
            scalars.push(Scalar::from_wide_bytes(&bytes).expect("Valid length"));
        }

        let sixteen = p256::Scalar::from(16_u64);
        for scalar in &scalars {
            let digits = Secp256r1FixedBaseTable::digits(&scalar.s);
            let (final_carry, low_digits) = digits.split_last().expect("Not empty");
            assert!(low_digits.iter().all(|digit| (-8..8).contains(digit)));
            assert!((0..=1).contains(final_carry));

            let sum = digits.iter().rev().fold(p256::Scalar::ZERO, |sum, digit| {
                sum * sixteen + scalar_from_digit(*digit)
            });
            assert_eq!(sum, scalar.s);
        }
    }

    #[test]
    fn test_lookup_returns_every_multiple_of_every_window() {
        for (table, p) in [
            (&*SECP256R1_MUL_BY_G_TABLE, Point::generator()),
            (&*SECP256R1_MUL_BY_H_TABLE, Point::generator_h()),
        ] {
            let mut p_i = p.p;
            for i in 0..Secp256r1FixedBaseTable::DIGITS {
                for digit in -8..=8 {
                    let expected = p_i * scalar_from_digit(digit);
                    let looked_up = p256::ProjectivePoint::from(table.lookup(i, digit));
                    assert_eq!(looked_up, expected, "window {i}, digit {digit}");
                }
                p_i = p_i.double().double().double().double();
            }
        }
    }
}
