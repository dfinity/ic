use hex_literal::hex;
use k256::elliptic_curve::{
    Field, Group,
    group::{GroupEncoding, ff::PrimeField},
    ops::{Invert, LinearCombination, MulByGenerator, Reduce},
    scalar::IsHigh,
    sec1::FromEncodedPoint,
};
use std::ops::Neg;
use std::sync::LazyLock;
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Scalar {
    s: k256::Scalar,
}

// The secp256k1 parameters are defined in SEC2
// [https://www.secg.org/sec2-v2.pdf] section 2.4.1
//
// The SSWU parameters are defined in RFC 9380
// https://www.rfc-editor.org/rfc/rfc9380.html#name-suites-for-secp256k1
fe_derive::derive_field_element!(
    FieldElement,
    Modulus = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    A = "0",
    B = "7",
    SSWU_A = "0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533",
    SSWU_B = "1771",
    SSWU_Z = "-11",
);

/// The constants that define the isogeny mapping for secp256k1
static K256_C: LazyLock<[FieldElement; 13]> = LazyLock::new(|| {
    let fb = |bs| FieldElement::from_bytes(bs).expect("Constant was invalid");
    [
        fb(&hex!(
            "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C"
        )),
        fb(&hex!(
            "534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262"
        )),
        fb(&hex!(
            "07D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581"
        )),
        fb(&hex!(
            "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7"
        )),
        fb(&hex!(
            "EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14"
        )),
        fb(&hex!(
            "D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B"
        )),
        fb(&hex!(
            "2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84"
        )),
        fb(&hex!(
            "29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931"
        )),
        fb(&hex!(
            "C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3"
        )),
        fb(&hex!(
            "4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C"
        )),
        fb(&hex!(
            "6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F"
        )),
        fb(&hex!(
            "7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573"
        )),
        fb(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B"
        )),
    ]
});

/// Computes (x,y) where:
/// * x = x_num / x_den, where
///     * x_num = C0 * x'^3 + C1 * x'^2 + C2 * x' + C3
///     * x_den = x'^2 + C4 * x' + C5
/// * y = y' * y_num / y_den, where
///    * y_num = C6 * x'^3 + C7 * x'^2 + C8 * x' + C9
///    * y_den = x'^3 + C10 * x'^2 + C11 * x' + C12
///
/// where Ci refers to the constants in the variable K256_C[i]
fn from_fe((x, y): &(FieldElement, FieldElement)) -> Point {
    /// Return x**2 + x*c1 + c2
    fn x2_xc1_c2(x: &FieldElement, c1: &FieldElement, c2: &FieldElement) -> FieldElement {
        x.mul(&x.add(c1)).add(c2)
    }

    fn x3_x2c1_xc2_c3(
        x: &FieldElement,
        c1: &FieldElement,
        c2: &FieldElement,
        c3: &FieldElement,
    ) -> FieldElement {
        x.mul(&x2_xc1_c2(x, c1, c2)).add(c3)
    }

    /// Return x**3 * c1 + x**2 * c2 + x * c3 + c4
    fn x3c1_x2c2_xc3_c4(
        x: &FieldElement,
        c1: &FieldElement,
        c2: &FieldElement,
        c3: &FieldElement,
        c4: &FieldElement,
    ) -> FieldElement {
        x.mul(&x.mul(&x.mul(c1).add(c2)).add(c3)).add(c4)
    }

    let xnum = x3c1_x2c2_xc3_c4(x, &K256_C[0], &K256_C[1], &K256_C[2], &K256_C[3]);

    let xden = x2_xc1_c2(x, &K256_C[4], &K256_C[5]);

    let ynum = x3c1_x2c2_xc3_c4(x, &K256_C[6], &K256_C[7], &K256_C[8], &K256_C[9]);

    let yden = x3_x2c1_xc2_c3(x, &K256_C[10], &K256_C[11], &K256_C[12]);

    // We can perform both inversions in one step, using what is
    // usually called Montgomery's trick:
    //
    //   To compute x^-1 and y^-1 compute z=(x*y)^-1
    //   Then z*y = x^-1 and z*x = y^-1
    let inv = xden.mul(&yden).invert();

    let x = xnum.mul(&inv.mul(&yden));
    let y = y.mul(&ynum.mul(&inv.mul(&xden)));

    let mut buf = Vec::with_capacity(1 + 2 * FieldElement::BYTES);
    buf.push(0x04);
    buf.extend_from_slice(&x.as_bytes());
    buf.extend_from_slice(&y.as_bytes());
    Point::deserialize(&buf).expect("hash2curve produced invalid point")
}

super::algos::declare_sswu_p_3_mod_4_map_to_curve_impl!(
    h2c_secp256k1,
    FieldElement,
    Point,
    from_fe
);

impl Scalar {
    pub const BYTES: usize = 32;
    pub const BITS: usize = 256;

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

        k256::Scalar::from_repr(*k256::FieldBytes::from_slice(bytes))
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
        As the k256 crates is lacking a native function that reduces an input
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

        let fb0 = k256::FieldBytes::from_slice(&extended[..Self::BYTES]);
        let fb1 = k256::FieldBytes::from_slice(&extended[Self::BYTES..]);

        let mut s0 = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(fb0);
        let s1 = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(fb1);

        for _bit in 1..=Self::BYTES * 8 {
            s0 = s0.double();
        }
        s0 += s1;

        Some(Self::new(s0))
    }

    /// Return constant zero
    pub fn zero() -> Self {
        Self::new(k256::Scalar::ZERO)
    }

    /// Return constant one
    pub fn one() -> Self {
        Self::new(k256::Scalar::ONE)
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
    p: k256::ProjectivePoint,
}

/// Static deserialization of the fixed alternative group generator
static SECP256K1_GENERATOR_H: LazyLock<Point> = LazyLock::new(|| {
    Point::deserialize(&hex!(
        "037bdcfc024cf697a41fd3cda2436c843af5669e50042be3314a532d5b70572f59"
    ))
    .expect("The secp256k1 generator_h point is invalid")
});

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
            Ok(ept) => k256::AffinePoint::from_encoded_point(&ept)
                .into_option()
                .map(|p| Self::new(k256::ProjectivePoint::from(p))),
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

    /// Return the alternative generator of the group
    pub fn generator_h() -> Self {
        SECP256K1_GENERATOR_H.clone()
    }

    /// Perform multi-exponentiation
    ///
    /// Equivalent to p1*s1 + p2*s2
    #[inline]
    pub fn lincomb(p1: &Point, s1: &Scalar, p2: &Point, s2: &Scalar) -> Self {
        Self::new(k256::ProjectivePoint::lincomb(&p1.p, &s1.s, &p2.p, &s2.s))
    }

    pub fn pedersen(s1: &Scalar, s2: &Scalar) -> Self {
        let g = Self::generator();
        let h = Self::generator_h();
        Self::new(k256::ProjectivePoint::lincomb(&g.p, &s1.s, &h.p, &s2.s))
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
        Self::new(k256::ProjectivePoint::mul_by_generator(&scalar.s))
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
            p: k256::ProjectivePoint::conditional_select(&a.p, &b.p, choice),
        }
    }

    /// Hash to curve (random oracle variant)
    pub fn hash2curve(input: &[u8], domain_sep: &[u8]) -> Self {
        h2c_secp256k1(input, domain_sep)
    }
}
