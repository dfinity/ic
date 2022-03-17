use crate::*;
use fe::EccFieldElement;
use hex_literal::hex;
use ic_types::NodeIndex;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use zeroize::Zeroize;

mod secp256k1;
mod secp256r1;

/// Elliptic curve type enum
///
/// Enumerates the curves supported by this library, currently K256 (aka
/// secp256k1) and P256 (aka secp256r1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EccCurveType {
    K256,
    P256,
}

impl EccCurveType {
    /// Return the length of a scalar (in bits)
    ///
    /// Scalar here refers to the byte size of an integer which has the range
    /// [0,z) where z is the group order.
    pub fn scalar_bits(&self) -> usize {
        match self {
            EccCurveType::K256 => 256,
            EccCurveType::P256 => 256,
        }
    }

    /// Return the length of a scalar (in bytes, rounded up)
    ///
    /// Scalar here refers to the byte size of an integer which has the range
    /// [0,z) where z is the group order.
    pub fn scalar_bytes(&self) -> usize {
        (self.scalar_bits() + 7) / 8
    }

    /// Return the length of the underlying field (in bits)
    pub fn field_bits(&self) -> usize {
        match self {
            EccCurveType::K256 => 256,
            EccCurveType::P256 => 256,
        }
    }

    /// Return the length of the underlying field (in bytes)
    ///
    /// If the field size is not an even multiple of 8 it is rounded up to the
    /// next byte size.
    pub fn field_bytes(&self) -> usize {
        // Round up to the nearest byte length
        (self.field_bits() + 7) / 8
    }

    /// Security level of the curve, in bits
    ///
    /// This must match the value specified in the hash2curve specification
    pub fn security_level(&self) -> usize {
        match self {
            EccCurveType::K256 => 128,
            EccCurveType::P256 => 128,
        }
    }

    /// Return the size of encoded points, in bytes
    pub fn point_bytes(&self) -> usize {
        // 1 byte header with y parity plus an affine x field element
        1 + self.field_bytes()
    }

    /// Return a unique small integer for this curve type
    ///
    /// This is used in the RandomOracle implementation
    pub(crate) fn tag(&self) -> u8 {
        match self {
            EccCurveType::K256 => 1,
            EccCurveType::P256 => 2,
        }
    }

    /// Return a vector over all available curve types
    ///
    /// This is mostly useful for tests
    pub fn all() -> Vec<EccCurveType> {
        vec![EccCurveType::K256, EccCurveType::P256]
    }
}

impl fmt::Display for EccCurveType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let curve_name = match self {
            Self::K256 => "secp256k1",
            Self::P256 => "secp256r1",
        };

        write!(f, "{}", curve_name)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Zeroize)]
pub enum EccScalar {
    K256(secp256k1::Scalar),
    P256(secp256r1::Scalar),
}

impl fmt::Debug for EccScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(0x{})",
            self.curve_type(),
            hex::encode(self.serialize())
        )
    }
}

impl EccScalar {
    pub fn curve_type(&self) -> EccCurveType {
        match self {
            Self::K256(_) => EccCurveType::K256,
            Self::P256(_) => EccCurveType::P256,
        }
    }

    /// Return the sum of two scalar values
    pub fn add(&self, other: &EccScalar) -> ThresholdEcdsaResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.add(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.add(s2))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Return the difference of two scalar values
    pub fn sub(&self, other: &EccScalar) -> ThresholdEcdsaResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.sub(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.sub(s2))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Return the product of two scalar values
    pub fn mul(&self, other: &EccScalar) -> ThresholdEcdsaResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.mul(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.mul(s2))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Compute the modular inverse of Self
    ///
    /// Returns zero if self is equal to zero
    pub fn invert(&self) -> ThresholdEcdsaResult<Self> {
        match self {
            Self::K256(s) => {
                let s = s.invert().unwrap_or_else(secp256k1::Scalar::zero);
                Ok(Self::K256(s))
            }
            Self::P256(s) => {
                let s = s.invert().unwrap_or_else(secp256r1::Scalar::zero);
                Ok(Self::P256(s))
            }
        }
    }

    /// Serialize the scalar in SEC1 format
    ///
    /// In this context SEC1 format is just the big-endian fixed length encoding
    /// of the integer, with leading zero bytes included if necessary.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::K256(s) => s.as_bytes().to_vec(),
            Self::P256(s) => s.as_bytes().to_vec(),
        }
    }

    /// Hash an input to a Scalar value
    pub fn hash_to_scalar(
        curve: EccCurveType,
        input: &[u8],
        domain_separator: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        let h = hash2curve::hash_to_scalar(1, curve, input, domain_separator)?;
        Ok(h[0])
    }

    /// Hash an input into multiple Scalar values
    pub fn hash_to_several_scalars(
        curve: EccCurveType,
        count: usize,
        input: &[u8],
        domain_separator: &[u8],
    ) -> ThresholdEcdsaResult<Vec<Self>> {
        hash2curve::hash_to_scalar(count, curve, input, domain_separator)
    }

    /// Deserialize a SEC1 formatted scalar value
    pub fn deserialize(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        if bytes.len() != curve.scalar_bytes() {
            return Err(ThresholdEcdsaError::InvalidScalar);
        }

        match curve {
            EccCurveType::K256 => {
                let s = secp256k1::Scalar::deserialize(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidScalar)?;
                Ok(Self::K256(s))
            }
            EccCurveType::P256 => {
                let s = secp256r1::Scalar::deserialize(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidScalar)?;
                Ok(Self::P256(s))
            }
        }
    }

    /// Compute the scalar from a larger value
    ///
    /// The input is allowed to be up to twice the length of a scalar. It is
    /// interpreted as a big-endian encoded integer, and reduced modulo the
    /// group order.
    pub fn from_bytes_wide(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let s = secp256k1::Scalar::from_wide_bytes(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidScalar)?;
                Ok(Self::K256(s))
            }
            EccCurveType::P256 => {
                let s = secp256r1::Scalar::from_wide_bytes(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidScalar)?;
                Ok(Self::P256(s))
            }
        }
    }

    /// Generate a random scalar in [0,p)
    pub fn random<R: CryptoRng + RngCore>(
        curve: EccCurveType,
        rng: &mut R,
    ) -> ThresholdEcdsaResult<Self> {
        // Use rejection sampling to avoid biasing the output

        let mut buf = vec![0u8; curve.scalar_bytes()];

        loop {
            rng.fill_bytes(&mut buf);
            if let Ok(scalar) = Self::deserialize(curve, &buf) {
                return Ok(scalar);
            }
        }
    }

    /// Return true iff self is equal to zero
    pub fn is_zero(&self) -> bool {
        match self {
            Self::K256(s) => s.is_zero(),
            Self::P256(s) => s.is_zero(),
        }
    }

    /// Return true iff self is >= order / 2
    pub fn is_high(&self) -> bool {
        match self {
            Self::K256(s) => s.is_high(),
            Self::P256(s) => s.is_high(),
        }
    }

    /// Negation within the scalar field
    ///
    /// Effectively this returns p - self where p is the primefield
    /// order of the elliptic curve group, and the subtraction occurs
    /// within the integers modulo the curve order.
    pub fn negate(&self) -> Self {
        match self {
            Self::K256(s) => Self::K256(s.negate()),
            Self::P256(s) => Self::P256(s.negate()),
        }
    }

    /// Return the scalar 0
    ///
    /// Since scalars are simply integers modulo some prime this is
    /// just plain 0.
    pub fn zero(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::Scalar::zero()),
            EccCurveType::P256 => Self::P256(secp256r1::Scalar::zero()),
        }
    }

    /// Return the scalar 1
    ///
    /// Since scalars are simply integers modulo some prime this is
    /// just plain 1.
    pub fn one(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::Scalar::one()),
            EccCurveType::P256 => Self::P256(secp256r1::Scalar::one()),
        }
    }

    /// Return a small scalar value
    pub fn from_u64(curve: EccCurveType, n: u64) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::Scalar::from(n)),
            EccCurveType::P256 => Self::P256(secp256r1::Scalar::from(n)),
        }
    }

    /// Return a small scalar value corresponding to the `index+1`
    pub fn from_node_index(curve: EccCurveType, index: NodeIndex) -> Self {
        Self::from_u64(curve, 1 + (index as u64))
    }
}

#[derive(Deserialize, Serialize)]
struct EccScalarSerializationHelper {
    curve_type: EccCurveType,
    raw: Vec<u8>,
}

impl Serialize for EccScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = EccScalarSerializationHelper {
            curve_type: self.curve_type(),
            raw: self.serialize(),
        };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EccScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let helper: EccScalarSerializationHelper = Deserialize::deserialize(deserializer)?;
        EccScalar::deserialize(helper.curve_type, &helper.raw)
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub enum EccScalarBytes {
    K256([u8; 32]),
}

impl TryFrom<&EccScalarBytes> for EccScalar {
    type Error = ThresholdEcdsaError;

    fn try_from(bytes: &EccScalarBytes) -> ThresholdEcdsaResult<Self> {
        match bytes {
            EccScalarBytes::K256(raw) => EccScalar::deserialize(EccCurveType::K256, raw),
        }
    }
}

impl TryFrom<&EccScalar> for EccScalarBytes {
    type Error = ThresholdEcdsaError;

    fn try_from(scalar: &EccScalar) -> ThresholdEcdsaResult<Self> {
        match scalar.curve_type() {
            EccCurveType::K256 => {
                Ok(Self::K256(scalar.serialize().try_into().map_err(|e| {
                    ThresholdEcdsaError::SerializationError(format!("{:?}", e))
                })?))
            }
            _ => {
                panic!("we don't support other curves yet at the higher layers");
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EccPoint {
    K256(secp256k1::Point),
    P256(secp256r1::Point),
}

impl fmt::Debug for EccPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({})",
            self.curve_type(),
            hex::encode(self.serialize())
        )
    }
}

impl EccPoint {
    /// Return a point which is the identity element on the curve
    pub fn identity(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::Point::identity()),
            EccCurveType::P256 => Self::P256(secp256r1::Point::identity()),
        }
    }

    /// Return the "standard" generator for this curve
    pub fn generator_g(curve: EccCurveType) -> ThresholdEcdsaResult<Self> {
        match curve {
            EccCurveType::K256 => Ok(Self::K256(secp256k1::Point::generator())),
            EccCurveType::P256 => Ok(Self::P256(secp256r1::Point::generator())),
        }
    }

    /// Return a point which is unrelated to the standard generator on the curve
    ///
    /// The key point is that there is no known relation g*z = h as otherwise
    /// our commitment scheme would be insecure. Guarantee this relation is
    /// unknown by deriving h using a hash function.
    pub fn generator_h(curve: EccCurveType) -> ThresholdEcdsaResult<Self> {
        /*
        These points are generated by the hash2curve primitive:

        Input = "h"
        Domain Separator = format!("ic-crypto-tecdsa-{}-generator-h", self.curve)

        They are precomputed here to avoid invoking hash2curve many times. The
        test generator_h_has_expected_value compares these values to the output
        of hash2curve.
        */
        let h = match curve {
            EccCurveType::K256 => {
                hex!("037bdcfc024cf697a41fd3cda2436c843af5669e50042be3314a532d5b70572f59")
            }
            EccCurveType::P256 => {
                hex!("036774e87305efcb97c0ce289d57cd721972845ca33eccb8026c6d7c1c4182e7c1")
            }
        };

        Self::deserialize(curve, &h)
    }

    pub fn curve_type(&self) -> EccCurveType {
        match self {
            Self::K256(_) => EccCurveType::K256,
            Self::P256(_) => EccCurveType::P256,
        }
    }

    /// Hash an input to a valid elliptic curve point
    ///
    /// This uses the techniques described in the hash to curve internet draft
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.txt>
    ///
    /// Only the random oracle ("RO") variant is supplied as the non-uniform
    /// ("NU") variant is possibly insecure to use in some contexts. Only curves
    /// with extension degree of 1 are currently supported.
    pub fn hash_to_point(
        curve: EccCurveType,
        input: &[u8],
        domain_separator: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        hash2curve::hash2curve_ro(curve, input, domain_separator)
    }

    /// Create a point from two field elements
    ///
    /// The (x,y) pair must satisfy the curve equation
    pub fn from_field_elems(
        x: &EccFieldElement,
        y: &EccFieldElement,
    ) -> ThresholdEcdsaResult<Self> {
        if x.curve_type() != y.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let curve = x.curve_type();
        let x_bytes = x.as_bytes();
        let y_bytes = y.as_bytes();
        let mut encoded = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        encoded.push(0x04); // uncompressed
        encoded.extend_from_slice(&x_bytes);
        encoded.extend_from_slice(&y_bytes);
        Self::deserialize_any_format(curve, &encoded)
    }

    /// Add two elliptic curve points
    pub fn add_points(&self, other: &Self) -> ThresholdEcdsaResult<Self> {
        match (self, other) {
            (Self::K256(pt1), Self::K256(pt2)) => Ok(Self::K256(pt1.add(pt2))),
            (Self::P256(pt1), Self::P256(pt2)) => Ok(Self::P256(pt1.add(pt2))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Subtract two elliptic curve points
    pub fn sub_points(&self, other: &Self) -> ThresholdEcdsaResult<Self> {
        match (self, other) {
            (Self::K256(pt1), Self::K256(pt2)) => Ok(Self::K256(pt1.sub(pt2))),
            (Self::P256(pt1), Self::P256(pt2)) => Ok(Self::P256(pt1.sub(pt2))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Perform point*scalar multiplication
    pub fn scalar_mul(&self, scalar: &EccScalar) -> ThresholdEcdsaResult<Self> {
        match (self, scalar) {
            (Self::K256(pt), EccScalar::K256(s)) => Ok(Self::K256(pt.mul(s))),
            (Self::P256(pt), EccScalar::P256(s)) => Ok(Self::P256(pt.mul(s))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Perform point doubling
    fn double(&self) -> Self {
        match self {
            Self::K256(pt) => Self::K256(pt.double()),
            Self::P256(pt) => Self::P256(pt.double()),
        }
    }

    /// Perform point*scalar multiplication for node indexes (not constant time)
    ///
    /// Returns the result of a point multiplied by (index + 1)
    ///
    /// This is a non-constant-time equivalent to
    /// `pt.scalar_mul(EccScalar::from_node_index(scalar))`.
    ///
    /// When verifying commitments, the scalars used in evaluating the
    /// polynomials are small and public (namely, the nodex indexes). By taking
    /// advantage of this, it is possible to gain substantial performance
    /// improvements as compared to using a constant-time scalar multiplication.
    pub fn mul_by_node_index(&self, scalar: NodeIndex) -> ThresholdEcdsaResult<Self> {
        // This cannot overflow as NodeIndex is a u32
        let scalar = scalar as u64 + 1;
        let scalar_bits = 64 - scalar.leading_zeros();

        let mut res = Self::identity(self.curve_type());

        for b in 0..scalar_bits {
            res = res.double();
            if (scalar >> (scalar_bits - 1 - b)) & 1 == 1 {
                res = res.add_points(self)?;
            }
        }

        Ok(res)
    }

    /// Return pt1 * scalar1 + pt2 * scalar2
    pub fn mul_points(
        pt1: &EccPoint,
        scalar1: &EccScalar,
        pt2: &EccPoint,
        scalar2: &EccScalar,
    ) -> ThresholdEcdsaResult<Self> {
        match (pt1, scalar1, pt2, scalar2) {
            (Self::K256(pt1), EccScalar::K256(s1), Self::K256(pt2), EccScalar::K256(s2)) => {
                Ok(Self::K256(secp256k1::Point::lincomb(pt1, s1, pt2, s2)))
            }

            (Self::P256(pt1), EccScalar::P256(s1), Self::P256(pt2), EccScalar::P256(s2)) => {
                Ok(Self::P256(secp256r1::Point::lincomb(pt1, s1, pt2, s2)))
            }

            (_, _, _, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    pub fn pedersen(scalar1: &EccScalar, scalar2: &EccScalar) -> ThresholdEcdsaResult<Self> {
        let curve_type = scalar1.curve_type();
        let g = Self::generator_g(curve_type)?;
        let h = Self::generator_h(curve_type)?;
        Self::mul_points(&g, scalar1, &h, scalar2)
    }

    pub fn mul_by_g(scalar: &EccScalar) -> ThresholdEcdsaResult<Self> {
        let curve_type = scalar.curve_type();
        let g = Self::generator_g(curve_type)?;
        g.scalar_mul(scalar)
    }

    /// Serialize a point in compressed form
    ///
    /// The output is in SEC1 format, and will be 1 header byte
    /// followed by a single field element, which for K256 and P256 is
    /// 32 bytes long.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::K256(pt) => pt.serialize(),
            Self::P256(pt) => pt.serialize(),
        }
    }

    /// Serialize a point in uncompressed form
    ///
    /// The output is in SEC1 format, and will be 1 header byte
    /// followed by a two field elements, which for K256 and P256 is
    /// 32 bytes long each.
    fn serialize_uncompressed(&self) -> Vec<u8> {
        match self {
            Self::K256(pt) => pt.serialize_uncompressed(),
            Self::P256(pt) => pt.serialize_uncompressed(),
        }
    }

    /// Return the affine X coordinate of this point
    pub fn affine_x(&self) -> ThresholdEcdsaResult<EccFieldElement> {
        let curve_type = self.curve_type();
        let field_bytes = curve_type.field_bytes();
        let z = self.serialize_uncompressed();
        EccFieldElement::from_bytes(curve_type, &z[1..field_bytes + 1])
    }

    /// Return the affine Y coordinate of this point
    pub fn affine_y(&self) -> ThresholdEcdsaResult<EccFieldElement> {
        let curve_type = self.curve_type();
        let field_bytes = curve_type.field_bytes();
        let z = self.serialize_uncompressed();
        EccFieldElement::from_bytes(curve_type, &z[1 + field_bytes..])
    }

    /// Return true if this is the point at infinity
    pub fn is_infinity(&self) -> ThresholdEcdsaResult<bool> {
        match self {
            Self::K256(p) => Ok(p.is_infinity()),
            Self::P256(p) => Ok(p.is_infinity()),
        }
    }

    /// Deserialize a point. Only compressed points are accepted.
    pub fn deserialize(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        if bytes.len() != curve.point_bytes() || (bytes[0] != 2 && bytes[0] != 3) {
            return Err(ThresholdEcdsaError::InvalidPoint);
        }

        Self::deserialize_any_format(curve, bytes)
    }

    /// Deserialize a point. Both compressed and uncompressed points are accepted.
    fn deserialize_any_format(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let pt = secp256k1::Point::deserialize(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidPoint)?;
                Ok(Self::K256(pt))
            }
            EccCurveType::P256 => {
                let pt = secp256r1::Point::deserialize(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidPoint)?;
                Ok(Self::P256(pt))
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
struct EccPointSerializationHelper {
    curve_type: EccCurveType,
    raw: Vec<u8>,
}

impl Serialize for EccPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = EccPointSerializationHelper {
            curve_type: self.curve_type(),
            raw: self.serialize(),
        };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EccPoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let helper: EccPointSerializationHelper = Deserialize::deserialize(deserializer)?;
        EccPoint::deserialize(helper.curve_type, &helper.raw)
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

pub(crate) fn contains_duplicates(scalars: &[EccScalar]) -> bool {
    let mut set = std::collections::HashSet::new();

    // This function is only used in cases where we need to exclude duplicates
    // and will immediately return an error, so an early exit (leaking if there
    // are duplicates or not) does not have implications wrt side channels.
    for scalar in scalars {
        if !set.insert(scalar.serialize()) {
            return true;
        }
    }

    false
}
