use crate::*;
use fe::EccFieldElement;
use hex_literal::hex;
use ic_types::NodeIndex;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use zeroize::Zeroize;

mod secp256k1;
mod secp256r1;

#[cfg(test)]
mod tests;

/// Elliptic curve type enum
///
/// Enumerates the curves supported by this library, currently K256 (aka
/// secp256k1) and P256 (aka secp256r1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(EccCurveType::K256),
            2 => Some(EccCurveType::P256),
            _ => None,
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

    /// Serialize the scalar in SEC1 format (with curve tag)
    pub(crate) fn serialize_tagged(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.curve_type().scalar_bytes());
        bytes.push(self.curve_type().tag());
        bytes.extend_from_slice(&match self {
            Self::K256(s) => s.as_bytes(),
            Self::P256(s) => s.as_bytes(),
        });
        bytes
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

    /// Deserialize a SEC1 formatted scalar value (with tag)
    pub fn deserialize_tagged(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        if bytes.is_empty() {
            return Err(ThresholdEcdsaError::InvalidScalar);
        }

        match EccCurveType::from_tag(bytes[0]) {
            Some(curve) => Self::deserialize(curve, &bytes[1..]),
            None => Err(ThresholdEcdsaError::InvalidScalar),
        }
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
                buf.zeroize();
                return Ok(scalar);
            }
        }
    }

    pub fn from_seed(curve: EccCurveType, seed: Seed) -> ThresholdEcdsaResult<Self> {
        let mut rng = seed.into_rng();
        Self::random(curve, &mut rng)
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
struct EccScalarSerializationHelper(#[serde(with = "serde_bytes")] Vec<u8>);

impl Serialize for EccScalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let helper = EccScalarSerializationHelper(self.serialize_tagged());
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EccScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let helper: EccScalarSerializationHelper = Deserialize::deserialize(deserializer)?;
        EccScalar::deserialize_tagged(&helper.0)
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
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-14.txt>
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
    pub fn double(&self) -> Self {
        match self {
            Self::K256(pt) => Self::K256(pt.double()),
            Self::P256(pt) => Self::P256(pt.double()),
        }
    }

    /// Perform point negation
    pub fn negate(&self) -> Self {
        match self {
            Self::K256(pt) => Self::K256(pt.negate()),
            Self::P256(pt) => Self::P256(pt.negate()),
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
    pub fn mul_2_points(
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
        Self::mul_2_points(&g, scalar1, &h, scalar2)
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

    /// Serialize a point in compressed form with a curve ID tag
    ///
    /// The output is the same as serialize but prefixed with the
    /// (arbitrarily chosen) tag from EccCurveType::tag()
    pub(crate) fn serialize_tagged(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.curve_type().point_bytes());
        bytes.push(self.curve_type().tag());

        bytes.extend_from_slice(&match self {
            Self::K256(pt) => pt.serialize(),
            Self::P256(pt) => pt.serialize(),
        });

        bytes
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

    /// Deserialize a tagged point. Only compressed points are accepted.
    pub fn deserialize_tagged(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        if bytes.is_empty() {
            return Err(ThresholdEcdsaError::InvalidPoint);
        }

        match EccCurveType::from_tag(bytes[0]) {
            Some(curve) => Self::deserialize(curve, &bytes[1..]),
            None => Err(ThresholdEcdsaError::InvalidPoint),
        }
    }

    /// Deserialize a point. Only compressed points are accepted.
    pub fn deserialize(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        if bytes.len() != curve.point_bytes() {
            return Err(ThresholdEcdsaError::InvalidPoint);
        }

        // We encode the point at infinity as all-zero byte string of the same
        // length as a compressed point. This is non-standard (per SEC1) but a
        // fixed length point format is easier to reason about.
        //
        // This check is not constant time but is only triggered in the
        // event that the first byte is 0 which is otherwise invalid. So this
        // would leak the first non-zero byte in an invalid point, which
        // does not seem to be interesting from a side channel perspective.
        //
        // The initial check of bytes[0] == 0 may seem redundant, but
        // [`iter::all`] does not guarantee the direction it examines the
        // iterator. If it for example worked in the reverse order, it would
        // leak information about valid non-infinity points. The initial check
        // ensures that [`iter::all`] is only invoked in the case of a leading 0
        // byte and can only leak information about invalid points.
        if bytes[0] == 0 && bytes.iter().all(|x| *x == 0x00) {
            return Ok(Self::identity(curve));
        }

        // If not all zeros, then first byte should be 2 or 3 indicating sign of y
        if bytes[0] != 2 && bytes[0] != 3 {
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
struct EccPointSerializationHelper(#[serde(with = "serde_bytes")] Vec<u8>);

impl Serialize for EccPoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let helper = EccPointSerializationHelper(self.serialize_tagged());
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EccPoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let helper: EccPointSerializationHelper = Deserialize::deserialize(deserializer)?;
        EccPoint::deserialize_tagged(&helper.0)
            .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

/// Non-adjacent format (NAF)
///
/// Maps a 2-value representation (binary) to a 3-value (-1, 0, 1) representation,
/// where in NAF no *2* non-zero values can be adjacent, which reduces the Hamming weight.
///
/// Warning: NAF may require l + 1 bits for representing an l-bit number!
/// Because of that, the result *always* contains an additional byte -> (l / 8) + 1 bytes in total.
struct Naf {
    pub positive_bits: Vec<u8>,
    pub negative_bits: Vec<u8>,
}

impl Naf {
    /// Returns the bit length of the NAF representation.
    pub fn bit_len(&self) -> usize {
        self.positive_bits.len() * 8
    }

    /// Converts `scalar` to its NAF representation.
    pub fn from_scalar_vartime(scalar: &EccScalar) -> Self {
        let bytes = scalar.serialize();
        Naf::from_be_bytes_vartime(&bytes[..])
    }

    /// Converts big endian encoded `bytes` to its NAF representation.
    fn from_be_bytes_vartime(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self {
                positive_bits: vec![],
                negative_bits: vec![],
            };
        }

        // parse the input scalar
        // source: https://oeis.org/A184616
        //
        // Input:   scalar
        // Output:  p_bits, n_bits
        // 1) shifted = scalar >> 1;
        // 2) sum = scalar + shifted;
        // 3) c = shifted ^ sum;
        // 4) p_bits = sum & c;
        // 5) n_bits = shifted & c;

        // 1) shifted = scalar >> 1;
        let mut shifted = Vec::with_capacity(bytes.len());
        for i in (0..(bytes.len() - 1)).rev() {
            shifted.push((bytes[i + 1] >> 1) ^ (bytes[i] << 7));
        }
        shifted.push(bytes[0] >> 1);

        // 2) sum = scalar + shifted;
        let mut sum = Vec::with_capacity(bytes.len() + 1);
        let mut overflow = 0u8;

        for i in 0..bytes.len() {
            let result = bytes[bytes.len() - i - 1] as u16 + shifted[i] as u16 + overflow as u16;
            overflow = (result >> 8) as u8;
            sum.push((result & 0x00FFu16) as u8);
        }
        // the sum of the last bytes may overflow and we then need to add 1 more byte
        sum.push((overflow != 0) as u8);
        shifted.push(0u8);

        // 3) c = shifted ^ sum;
        let c: Vec<u8> = shifted
            .iter()
            .zip(sum.iter())
            .map(|(&x, &y)| x ^ y)
            .collect();

        // 4) p_bits = sum & c;
        let p_bits: Vec<u8> = sum.iter().zip(c.iter()).map(|(&x, &y)| x & y).collect();

        // 5) n_bits = shifted & c;
        let n_bits: Vec<u8> = shifted.iter().zip(c.iter()).map(|(&x, &y)| x & y).collect();
        Self {
            positive_bits: p_bits,
            negative_bits: n_bits,
        }
    }

    /// Internal function that converts a range of NAF digits to `i8` from their bit representation.
    /// The chosen range is interpreted as a new (smaller) NAF, e.g., if the complete representation is
    /// 2^(l - 1) * n_(l - 1) + ... + 2^1 * n_1 + 2^0 * n_0 where l == `self.bit_len()` and n_l is the NAF digit at position l,
    /// then `range_as_i8` interprets the range n_(`pos` + `bit_len`) ... n_(`pos`) as
    /// 2^(`bit_len` - 1) * n_(`pos` + `bit_len` - 1) + ... + 2^0 * n_(`pos`).
    ///
    /// # Warnings
    /// * The callee is responsible to guarantee that the invariant holds.
    /// * `bit_len` MUST be greater than 0 and less than 8.
    /// * Input arguments MUST be in bounds, i.e.
    /// `(pos + bit_len) <= self.bit_len()` must hold.
    ///
    /// # Panics
    /// * If the invariant doesn't hold.
    fn range_as_i8(&self, pos: usize, bit_len: usize) -> i8 {
        assert!(bit_len > 0 && bit_len < 8);
        assert!((pos + bit_len) <= self.bit_len());
        let byte_offset = pos / 8;
        let spans_two_bytes = ((pos % 8) + bit_len) > 8;
        let mask = 0xFFu8 >> (8 - bit_len);
        if spans_two_bytes {
            let extract = |byte_0, byte_1| {
                let shifted_0: u8 = byte_0 >> (pos % 8);
                let shifted_1: u8 = byte_1 << (8 - (pos % 8));
                (shifted_0 | shifted_1) & mask
            };
            let negative_byte = extract(
                self.negative_bits[byte_offset],
                self.negative_bits[byte_offset + 1],
            );
            let positive_byte = extract(
                self.positive_bits[byte_offset],
                self.positive_bits[byte_offset + 1],
            );
            positive_byte as i8 - negative_byte as i8
        } else {
            // spans one byte
            let extract = |byte| {
                let shifted: u8 = byte >> (pos % 8);
                shifted & mask
            };
            let negative_byte = extract(self.negative_bits[byte_offset]);
            let positive_byte = extract(self.positive_bits[byte_offset]);
            positive_byte as i8 - negative_byte as i8
        }
    }
}

/// `EccPoint` with a look-up table (LUT) for faster multiplication.
/// A LUT contains a precomputed mutliplication of `point` with particular small scalars.
/// Using the LUT, the multiplication is performed window-wise and not bit-wise.
pub struct EccPointWithLut {
    point: EccPoint,
    lut: NafLut,
}

impl EccPointWithLut {
    pub const MIN_WINDOW_SIZE: usize = NafLut::MIN_WINDOW_SIZE;
    pub const MAX_WINDOW_SIZE: usize = NafLut::MAX_WINDOW_SIZE;

    pub fn curve_type(&self) -> EccCurveType {
        self.point.curve_type()
    }

    /// Creates a new `Self` object and computes a look-up table (LUT) with multiplication
    /// with small scalars for `point`, which will be used for faster vartime (batch) multiplication.
    /// Multiplications stored in the LUT are for scalars represented in
    /// [`Naf`](https://en.wikipedia.org/wiki/Non-adjacent_form)
    /// of length `window_size` with the leading digit being non-zero.
    /// The supported values of `window_size` are in `3..=7`.
    ///
    /// # Errors
    /// * ThresholdEcdsaError::InvalidArguments if `window_size` is out of bounds.
    pub fn new(point: &EccPoint, window_size: usize) -> ThresholdEcdsaResult<Self> {
        let data = NafLut::new(point, window_size)?;
        Ok(Self {
            point: *point,
            lut: data,
        })
    }

    /// Takes in an NAF state for a scalar and an accumulator point,
    /// which must be initialized with the identity in the first call,
    /// and performs one step for the scalar-point multiplication.
    /// This function must be called as many times as the length of
    /// the NAF representation of the scalar.
    ///     
    /// Warning: this function leaks information about the scalars via
    /// side channels. Do not use this function with secret scalars.
    fn scalar_mul_step_vartime(
        &self,
        scalar_naf_state: &mut SlidingWindowMulState,
        accum: &mut EccPoint,
    ) -> ThresholdEcdsaResult<()> {
        let next = scalar_naf_state.next();
        match next {
            SlidingWindowStep::Continue => {}
            SlidingWindowStep::Window(window) => match window {
                1i8 => {
                    let sum = accum.add_points(&self.point)?;
                    *accum = sum;
                }
                -1i8 => {
                    let sum = accum.sub_points(&self.point)?;
                    *accum = sum;
                }
                w => {
                    let p = self.lut.get(w);
                    let sum = accum.add_points(p)?;
                    *accum = sum;
                }
            },
            SlidingWindowStep::Break => {}
        }
        Ok(())
    }

    /// Multiples `self.point` by `scalar` utilizing a precomputed LUT
    /// for efficiency.
    ///     
    /// Warning: this function leaks information about the scalars via
    /// side channels. Do not use this function with secret scalars.
    pub fn scalar_mul_vartime(&self, scalar: &EccScalar) -> ThresholdEcdsaResult<EccPoint> {
        let mut scalar_naf_state = SlidingWindowMulState::new(scalar, self.lut.window_size);
        let mut result = EccPoint::identity(self.point.curve_type());
        for _ in 0..(scalar_naf_state.naf.bit_len() - 1) {
            self.scalar_mul_step_vartime(&mut scalar_naf_state, &mut result)?;
            result = result.double();
        }
        self.scalar_mul_step_vartime(&mut scalar_naf_state, &mut result)?;
        Ok(result)
    }

    /// Multiplies and adds together `point_scalar_pairs` as
    /// `ps[0].0 * ps[0].1 + ... + ps[ps.len() - 1].0 * ps[ps.len() - 1].1`,
    /// where `ps` is `point_scalar_pairs`.
    /// The use of `EccPointWithLut` objects with different `window_size`s is supported.
    ///
    /// Warning: this function leaks information about the scalars via
    /// side channels. Do not use this function with secret scalars.
    pub fn mul_n_points_vartime_naf(
        point_scalar_pairs: &[(&EccPointWithLut, &EccScalar)],
    ) -> ThresholdEcdsaResult<EccPoint> {
        if point_scalar_pairs.is_empty() {
            return Err(ThresholdEcdsaError::InvalidArguments(String::from(
                "Trying to compute the sum of products with 0 inputs",
            )));
        }

        let mut mul_states: Vec<SlidingWindowMulState> = point_scalar_pairs
            .iter()
            .map(|&(p, s)| (SlidingWindowMulState::new(s, p.lut.window_size)))
            .collect();

        let mut accum = EccPoint::identity(point_scalar_pairs[0].0.curve_type());

        // for each digit in the NAF representation
        for _ in 0..(mul_states[0].naf.bit_len() - 1) {
            // iterate over all pairs and add all emitted LUT windows to the accumulator
            for (i, (p, _s)) in point_scalar_pairs.iter().enumerate() {
                p.scalar_mul_step_vartime(&mut mul_states[i], &mut accum)?;
            }
            // shift the accumulator by 1 bit to the left
            accum = accum.double();
        }
        // perform the last iteration without the shift
        for (i, (p, _s)) in point_scalar_pairs.iter().enumerate() {
            p.scalar_mul_step_vartime(&mut mul_states[i], &mut accum)?;
        }
        Ok(accum)
    }
}

/// Represents the action to be taken in the
/// [sliding window method](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Sliding-window_method)
/// step.
enum SlidingWindowStep {
    /// The index as `usize` of the precomputed window as `EccPoint`
    /// that is added to an accumulator point
    Window(i8),
    /// The algorithm skips the current iteration
    Continue,
    /// The algorithm has finished
    Break,
}

/// Represents the state of a scalar-point multiplication using the [sliding window
/// method](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Sliding-window_method).
struct SlidingWindowMulState {
    /// NAF representation of `scalar`.
    naf: Naf,
    /// Size of the NAF window.
    window_size: usize,
    /// Position in `scalar`.
    position: i64,
    /// Backward counter for multiplication of a precomputed value.
    continue_counter: usize,
    /// `EccPoint` from the LUT corresponding to `window` will be
    /// added to the accumulator after `continue_counter` reaches 0.
    window: i8,
}

impl SlidingWindowMulState {
    fn new(scalar: &EccScalar, window_size: usize) -> Self {
        let naf = Naf::from_scalar_vartime(scalar);
        let bit_length = naf.bit_len() as i64;
        Self {
            naf,
            window_size,
            position: bit_length - 1,
            continue_counter: 0,
            window: 0,
        }
    }

    /// Returns the next action to be taken in the [sliding window
    /// method](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Sliding-window_method).
    fn next(&mut self) -> SlidingWindowStep {
        if self.continue_counter == 0 && self.position == -1 {
            return SlidingWindowStep::Break;
        }

        if self.continue_counter > 0 {
            self.continue_counter -= 1;
            if self.continue_counter == 0 {
                let mut window = 0;
                std::mem::swap(&mut window, &mut self.window);
                return SlidingWindowStep::Window(window);
            } else {
                return SlidingWindowStep::Continue;
            }
        }

        let old_position = self.position as usize;

        let get_bit = |x: &[u8], i: usize| -> u8 {
            let target_byte = x[i / 8];
            (target_byte >> (i % 8)) & 1
        };

        let is_zero = |naf: &Naf, pos| {
            (get_bit(&naf.positive_bits[..], pos) == 0)
                && (get_bit(&naf.negative_bits[..], pos) == 0)
        };

        if is_zero(&self.naf, old_position) {
            self.position -= 1;
            SlidingWindowStep::Continue
        } else {
            let substring_bitlen = std::cmp::min(self.window_size, old_position + 1);
            if substring_bitlen == self.window_size {
                self.position -= substring_bitlen as i64;
                self.window = self
                    .naf
                    .range_as_i8((old_position + 1) - substring_bitlen, substring_bitlen);
                self.continue_counter = substring_bitlen - 1;
                SlidingWindowStep::Continue
            } else {
                self.position -= 1;
                // extract 1 digit
                SlidingWindowStep::Window(self.naf.range_as_i8(old_position, 1))
            }
        }
    }
}

/// Look-up table (LUT) that can be used to improve the efficiency of
/// multiplication of the input `EccPoint` by an `EccScalar`.
struct NafLut {
    multiplications: Vec<EccPoint>,
    window_size: usize,
}

impl NafLut {
    /// Inclusive bounds of the LUT.
    /// Manually the bounds can be computed as an "all-one" NAF value, e.g.,
    /// "1 0 1 0 1" for `window_size == 5` (recall that in NAF there can be no adjecent non-zero values)
    const BOUND: [usize; 8] = [0, 1, 2, 5, 10, 21, 42, 85];
    const MIN_WINDOW_SIZE: usize = 3;
    const MAX_WINDOW_SIZE: usize = 7;

    /// Generates a LUT with the values `BOUND[window_size - 1] + 1..=BOUND[window_size]` and their negations.
    /// The values are stored in the ascending order, e.g., for `window_size == 5` it stores
    /// "-1 0 -1 0 -1"..="-1 0 1 0 1","1 0 -1 0 -1"..="1 0 1 0 1" or as integers -21..=-11,11..=21
    ///
    /// # Errors
    /// * ThresholdEcdsaError::InvalidArguments if `window_size` is out of bounds.
    pub fn new(point: &EccPoint, window_size: usize) -> ThresholdEcdsaResult<Self> {
        if !(Self::MIN_WINDOW_SIZE..=Self::MAX_WINDOW_SIZE).contains(&window_size) {
            return Err(ThresholdEcdsaError::InvalidArguments(format!(
                "NAF LUT window sizes are only allowed in range {}..={} but got {}",
                Self::MIN_WINDOW_SIZE,
                Self::MAX_WINDOW_SIZE,
                window_size
            )));
        }

        Ok(Self {
            multiplications: Self::compute_table(point, window_size)?,
            window_size,
        })
    }

    /// Checks that the scalar index is in bounds, i.e., the multiplication with `i` has been
    /// computed and stored in `self.multiplications`.
    pub fn is_in_bounds(window_size: usize, i: i8) -> bool {
        (i.abs() as usize) > Self::BOUND[window_size - 1]
            && (i.abs() as usize) < (Self::BOUND[window_size] + 1)
    }

    /// Computes the LUT for NAF values of length of exactly `window_size`.
    ///
    /// # Errors
    /// * CurveMismatch in case of inconsistent points. However, this should generally not happen
    /// because the curve type of all computed points is derived from `point`.
    fn compute_table(point: &EccPoint, window_size: usize) -> ThresholdEcdsaResult<Vec<EccPoint>> {
        let lower_bound = Self::BOUND[window_size - 1];
        let upper_bound = Self::BOUND[window_size] + 1;
        // Offset is equal to the number of negative values
        let num_negatives: usize = Self::BOUND[window_size] - Self::BOUND[window_size - 1];

        let id = EccPoint::identity(point.curve_type());
        let mut result = vec![id; 2 * num_negatives];

        let mut point_in_bounds = *point;
        let mut index_in_bounds: i8 = 1;
        while index_in_bounds as usize <= lower_bound {
            point_in_bounds = point_in_bounds.double();
            index_in_bounds *= 2;
        }

        let to_array_index = |real_index: i8| -> usize {
            if real_index.is_negative() {
                num_negatives - (real_index.abs() as usize - lower_bound)
            } else {
                // is positive
                real_index as usize - lower_bound + num_negatives - 1
            }
        };

        // compute the point that we can get by doubling
        result[to_array_index(index_in_bounds)] = point_in_bounds;

        // compute positive points
        for i in (lower_bound + 1..index_in_bounds as usize).rev() {
            result[to_array_index(i as i8)] =
                result[to_array_index((i + 1) as i8)].sub_points(point)?;
        }
        for i in index_in_bounds as usize..upper_bound {
            result[to_array_index(i as i8)] =
                result[to_array_index((i - 1) as i8)].add_points(point)?;
        }

        // compute negative points
        for i in 0..=num_negatives {
            result[i] = result[result.len() - 1 - i].negate();
        }

        Ok(result)
    }

    /// Obtains a point multiplied by `i` from the precomputed LUT.
    ///
    /// # Panics
    /// * if `i` is out of bounds, i.e., if it has not been precomputed.
    pub fn get(&self, i: i8) -> &EccPoint {
        assert!(Self::is_in_bounds(self.window_size, i));
        let lower_bound = Self::BOUND[self.window_size - 1];
        let num_negatives = self.multiplications.len() / 2;
        let array_index: usize = if i.is_negative() {
            num_negatives - (i + (lower_bound as i8)).abs() as usize
        } else {
            num_negatives + (i.abs() as usize) - lower_bound - 1
        };
        &self.multiplications[array_index]
    }
}
