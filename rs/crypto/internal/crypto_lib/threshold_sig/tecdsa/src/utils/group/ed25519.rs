use curve25519_dalek::{edwards::CompressedEdwardsY, traits::MultiscalarMul};
use group::{ff::Field, Group, GroupEncoding};
use hex_literal::hex;
use ic_crypto_sha2::Sha512;
use std::ops::{Add, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

fe_derive::derive_field_element!(
    FieldElement,
    Modulus = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
    A = "486662",
    // Square root of -1 (computed offline using Sagemath)
    //
    // sage: F = GF(2**255-19)
    // sage: hex(F(-1).sqrt())
    //
    SQRT_NEG_1 = "0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
    // Square root of -486664 (computed offline using Sagemath)
    //
    // This is constant `c1` in map_to_curve_elligator2_edwards25519
    //
    // sage: F = GF(2**255-19)
    // sage: hex(F(-486664).sqrt())
    //
    // Sage might print either square root; the even one must be used
    // (see https://www.rfc-editor.org/rfc/rfc9380.html#name-edwards25519)
    //
    SQRT_NEG_486664 = "0xf26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06",
    // 2^((q+3)/8) mod p, C2 in https://www.rfc-editor.org/rfc/rfc9380.html#name-curve25519-q-5-mod-8-k-1
    ELL_C2 = "0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b1",
    // See https://www.rfc-editor.org/rfc/rfc9380.html#name-finding-z-for-elligator-2
    ELL2_Z = "2",
);

fn hash_to_curve_ed25519(input: &[u8], dst: &[u8]) -> Point {
    fn hash_to_fe(input: &[u8], dst: &[u8]) -> (FieldElement, FieldElement) {
        const P_BITS: usize = FieldElement::BYTES * 8;
        const SECURITY_LEVEL: usize = P_BITS / 2;

        const FIELD_BYTES: usize = (P_BITS + SECURITY_LEVEL + 7) / 8; // "L" in spec
        const XMD_BYTES: usize = 2 * FIELD_BYTES;
        const WIDE_BYTES_OFFSET: usize = 2 * FieldElement::BYTES - FIELD_BYTES;

        // Compile time assertion that XMD can output the requested bytes
        const _: () = assert!(XMD_BYTES <= 8160, "XMD output is sufficient");

        // XMD only fails if the requested output is too long, but we already checked
        // at compile time that the output length is within range.
        let u = ic_crypto_internal_seed::xmd::<Sha512>(input, dst, XMD_BYTES)
            .expect("XMD unexpected failed");

        fn extended_u(u: &[u8]) -> [u8; 2 * FieldElement::BYTES] {
            let mut ext_u = [0u8; 2 * FieldElement::BYTES];
            ext_u[WIDE_BYTES_OFFSET..].copy_from_slice(u);
            ext_u
        }

        let u0 = FieldElement::from_bytes_wide_exact(&extended_u(&u[..FIELD_BYTES]));
        let u1 = FieldElement::from_bytes_wide_exact(&extended_u(&u[FIELD_BYTES..]));

        (u0, u1)
    }

    fn map_to_curve_elligator2_curve25519(
        u: &FieldElement,
    ) -> (FieldElement, FieldElement, FieldElement, FieldElement) {
        // https://www.rfc-editor.org/rfc/rfc9380.html#name-curve25519-q-5-mod-8-k-1

        // RFC 9380 calls the Montgomery "A" field element J for whatever reason
        // Follow that notation here to make this a bit easier to follow.
        let j = FieldElement::a();
        let one = FieldElement::one();

        let mut tv1 = u.square();
        tv1 = tv1.mul(&FieldElement::ell2_z());
        let xd = tv1.add(&one);
        let x1n = j.negate();
        let mut tv2 = xd.square();
        let gxd = tv2.mul(&xd);
        let mut gx1 = tv1.mul(&j);
        gx1 = gx1.mul(&x1n);
        gx1 = gx1.add(&tv2);
        gx1 = gx1.mul(&x1n);
        let mut tv3 = gxd.square();
        tv2 = tv3.square();
        tv3 = tv3.mul(&gxd);
        tv3 = tv3.mul(&gx1);
        tv2 = tv2.mul(&tv3);
        let mut y11 = tv2.pow_vartime(&FieldElement::Q_MINUS5_DIV8);
        y11 = y11.mul(&tv3);
        let y12 = y11.mul(&FieldElement::sqrt_neg_1());
        tv2 = y11.square();
        tv2 = tv2.mul(&gxd);
        let e1 = tv2.ct_eq(&gx1);
        let y1 = FieldElement::cmov(&y12, &y11, e1);
        let x2n = x1n.mul(&tv1);
        let mut y21 = y11.mul(u);
        y21 = y21.mul(&FieldElement::ell_c2());
        let y22 = y21.mul(&FieldElement::sqrt_neg_1());
        let gx2 = gx1.mul(&tv1);
        tv2 = y21.square();
        tv2 = tv2.mul(&gxd);
        let e2 = tv2.ct_eq(&gx2);
        let y2 = FieldElement::cmov(&y22, &y21, e2);
        tv2 = y1.square();
        tv2 = tv2.mul(&gxd);
        let e3 = tv2.ct_eq(&gx1);
        let xn = FieldElement::cmov(&x2n, &x1n, e3);
        let y = FieldElement::cmov(&y2, &y1, e3);
        let e4 = y.sign().ct_eq(&1u8);
        let y = FieldElement::cmov(&y, &y.negate(), e3 ^ e4);
        (xn, xd, y, FieldElement::one())
    }

    fn map_to_curve_elligator2_edwards25519(u: &FieldElement) -> Point {
        // https://www.rfc-editor.org/rfc/rfc9380.html#name-edwards25519
        let (xmn, xmd, ymn, ymd) = map_to_curve_elligator2_curve25519(u);

        let mut xn = xmn.mul(&ymd).mul(&FieldElement::sqrt_neg_486664());
        let mut xd = xmd.mul(&ymn);
        let mut yn = xmn.sub(&xmd);
        let mut yd = xmn.add(&xmd);
        let tv1 = xd.mul(&yd);
        let e = tv1.is_zero();

        let zero = FieldElement::zero();
        let one = FieldElement::one();

        xn.ct_assign(&zero, e);
        xd.ct_assign(&one, e);
        yn.ct_assign(&one, e);
        yd.ct_assign(&one, e);

        // convert to affine:
        let x = xn.mul(&xd.invert());
        let y = yn.mul(&yd.invert());

        // Encode using Ed22519's retarded format
        let x_sign = x.sign();

        let mut y_bytes = y.as_bytes();
        y_bytes.reverse();

        y_bytes[31] ^= x_sign << 7;

        Point::new(
            CompressedEdwardsY(y_bytes)
                .decompress()
                .unwrap()
                .mul_by_cofactor(),
        )
    }

    let (u0, u1) = hash_to_fe(input, dst);

    let q0 = map_to_curve_elligator2_edwards25519(&u0);
    let q1 = map_to_curve_elligator2_edwards25519(&u1);

    q0.add(&q1)
}

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

/// The non-canonical identity elements of Ed25519
///
/// Ed25519 has a set of points which are considered valid but are not
/// the canonical encoding of the point. That is, implementations should
/// never generate them, but are expected to parse them.
///
/// We expect that all peers in the protocol behave correctly and do not
/// ever produce a non-canonical point encoding. Given this, we reject
/// such points immediately.
///
/// The other non-canonical points are all not within the prime order
/// subgroup; they are either in the subgroup of size 8, or the
/// subgroup of size 8*l where l is the size of the Ed25519 prime
/// order subgroup.  These points are caught by the checks for a
/// torsion component
///
const NON_CANONICAL_IDENTITIES: [[u8; 32]; 3] = [
    hex!("0100000000000000000000000000000000000000000000000000000000000080"),
    hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
];

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Point {
    p: curve25519_dalek::EdwardsPoint,
}

lazy_static::lazy_static! {

    /// Static deserialization of the fixed alternative group generator
    static ref ED25519_GENERATOR_H: Point = Point::deserialize(
        &hex!("d0509f80e5df2c3865f3b4cda82cc5b5c5b33f9c0ee151bbba1ad5a0f6e507db"))
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
        let b: [u8; Self::BYTES] = bytes.try_into().ok()?;

        for nci in &NON_CANONICAL_IDENTITIES {
            if bool::from(b.ct_eq(nci)) {
                return None;
            }
        }

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
        hash_to_curve_ed25519(input, domain_sep)
    }
}
