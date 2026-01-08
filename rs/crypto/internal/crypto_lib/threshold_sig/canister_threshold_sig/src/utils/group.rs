use crate::*;
use ic_types::NodeIndex;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::sync::Arc;
use subtle::Choice;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod algos;
mod ed25519;
mod secp256k1;
mod secp256r1;

#[cfg(test)]
mod tests;

/// Elliptic curve type enum
///
/// Enumerates the curves supported by this library, currently K256 (aka
/// secp256k1) and P256 (aka secp256r1)
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum EccCurveType {
    K256,
    P256,
    Ed25519,
}

impl EccCurveType {
    /// Return the length of a scalar (in bits)
    ///
    /// Scalar here refers to the byte size of an integer which has the range
    /// [0,z) where z is the group order.
    pub const fn scalar_bits(&self) -> usize {
        match self {
            EccCurveType::K256 => 256,
            EccCurveType::P256 => 256,
            EccCurveType::Ed25519 => 255,
        }
    }

    /// Return the length of a scalar (in bytes, rounded up)
    ///
    /// Scalar here refers to the byte size of an integer which has the range
    /// [0,z) where z is the group order.
    pub const fn scalar_bytes(&self) -> usize {
        self.scalar_bits().div_ceil(8)
    }

    /// Security level of the curve, in bits
    ///
    /// This must match the value specified in the hash2curve specification
    pub fn security_level(&self) -> usize {
        match self {
            EccCurveType::K256 => 128,
            EccCurveType::P256 => 128,
            EccCurveType::Ed25519 => 128,
        }
    }

    /// Return the size of encoded points, in bytes
    pub const fn point_bytes(&self) -> usize {
        match self {
            EccCurveType::K256 => 32 + 1,
            EccCurveType::P256 => 32 + 1,
            EccCurveType::Ed25519 => 32,
        }
    }

    /// Return the size of encoded points, in bytes. BIP340 supports only even y
    /// coordinates, omitting 1 byte for storing the y coordinate in the SEC1 format.
    ///
    /// Returns None for curves that do not support BIP340.
    pub const fn point_bytes_bip340(&self) -> Option<usize> {
        match self {
            EccCurveType::K256 => Some(self.point_bytes() - 1),
            _ => None,
        }
    }

    /// Return a unique small integer for this curve type
    ///
    /// This is used in the RandomOracle implementation
    pub(crate) fn tag(&self) -> u8 {
        match self {
            EccCurveType::K256 => 1,
            EccCurveType::P256 => 2,
            EccCurveType::Ed25519 => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(EccCurveType::K256),
            2 => Some(EccCurveType::P256),
            3 => Some(EccCurveType::Ed25519),
            _ => None,
        }
    }

    pub(crate) fn valid_for_ecdsa(&self) -> bool {
        match self {
            EccCurveType::K256 => true,
            EccCurveType::P256 => true,
            EccCurveType::Ed25519 => false,
        }
    }

    /// Return a vector over all available curve types
    ///
    /// This is mostly useful for tests
    pub fn all() -> Vec<EccCurveType> {
        vec![
            EccCurveType::K256,
            EccCurveType::P256,
            EccCurveType::Ed25519,
        ]
    }
}

impl fmt::Display for EccCurveType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let curve_name = match self {
            Self::K256 => "secp256k1",
            Self::P256 => "secp256r1",
            Self::Ed25519 => "ed25519",
        };

        write!(f, "{curve_name}")
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub enum EccScalar {
    K256(secp256k1::Scalar),
    P256(secp256r1::Scalar),
    Ed25519(ed25519::Scalar),
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
            Self::Ed25519(_) => EccCurveType::Ed25519,
        }
    }

    /// Return the sum of two scalar values
    pub fn add(&self, other: &EccScalar) -> CanisterThresholdResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.add(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.add(s2))),
            (Self::Ed25519(s1), Self::Ed25519(s2)) => Ok(Self::Ed25519(s1.add(s2))),
            (_, _) => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Return the difference of two scalar values
    pub fn sub(&self, other: &EccScalar) -> CanisterThresholdResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.sub(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.sub(s2))),
            (Self::Ed25519(s1), Self::Ed25519(s2)) => Ok(Self::Ed25519(s1.sub(s2))),
            (_, _) => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Return the product of two scalar values
    pub fn mul(&self, other: &EccScalar) -> CanisterThresholdResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.mul(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.mul(s2))),
            (Self::Ed25519(s1), Self::Ed25519(s2)) => Ok(Self::Ed25519(s1.mul(s2))),
            (_, _) => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Compute the modular inverse of Self
    ///
    /// Returns None if self is equal to zero
    pub fn invert(&self) -> Option<Self> {
        match self {
            Self::K256(s) => s.invert().map(Self::K256),
            Self::P256(s) => s.invert().map(Self::P256),
            Self::Ed25519(s) => s.invert().map(Self::Ed25519),
        }
    }

    /// Compute the modular inverse of Self
    ///
    /// This function may leak the value of self to side channels, and should only
    /// be used for public inputs
    ///
    /// Returns None if self is equal to zero
    pub fn invert_vartime(&self) -> Option<Self> {
        match self {
            Self::K256(s) => s.invert_vartime().map(Self::K256),
            Self::P256(s) => s.invert_vartime().map(Self::P256),
            Self::Ed25519(s) => s.invert_vartime().map(Self::Ed25519),
        }
    }

    /// Variable time batch inversion
    ///
    /// If all the scalars are invertible then returns the inverse of
    /// each. Same as calling `invert_vartime` but potentially faster.
    ///
    /// All of the scalars must be in the same group
    pub fn batch_invert_vartime(scalars: &[Self]) -> Result<Vec<Self>, CanisterThresholdError> {
        if scalars.is_empty() {
            return Ok(vec![]);
        }

        let curve = scalars[0].curve_type();

        let n = scalars.len();
        let mut accum = EccScalar::one(curve);
        let mut products = Vec::with_capacity(scalars.len());

        /*
         * This uses Montgomery's Trick to compute many inversions using just a
         * single field inversion. This is worthwhile because field inversions
         * are quite expensive.
         *
         * The basic idea here (for n=2) is taking advantage of the fact that if
         * x and y both have inverses then so does x*y, and (x*y)^-1 * x = y^-1
         * and (x*y)^-1 * y = x^-1
         *
         * This is described in more detail in various texts such as
         *  - <https://eprint.iacr.org/2008/199.pdf> section 2
         *  - "Guide to Elliptic Curve Cryptography" Algorithm 2.26
         */

        for s in scalars {
            // This will fail if any of the elements are not of the
            // expected curve type
            accum = accum.mul(s)?;
            products.push(accum.clone());
        }

        if let Some(mut inv) = accum.invert_vartime() {
            let mut result = Vec::with_capacity(n);

            for i in (1..n).rev() {
                result.push(inv.mul(&products[i - 1])?);
                inv = inv.mul(&scalars[i])?;
            }

            result.push(inv);
            result.reverse();

            Ok(result)
        } else {
            // There was a zero...
            Err(CanisterThresholdError::InvalidArguments(
                "Zero during batch inversion".to_string(),
            ))
        }
    }

    /// Serialize the scalar
    ///
    /// For P-256 and secp256k1 this uses a big-endian encoding.
    /// For Ed25519 a little endian encoding is used.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::K256(s) => s.to_bytes().to_vec(),
            Self::P256(s) => s.to_bytes().to_vec(),
            Self::Ed25519(s) => s.to_bytes().to_vec(),
        }
    }

    /// Access the bits of the scalar
    ///
    /// This always returns a big endian value
    pub(crate) fn scalar_bits_be(&self) -> Vec<u8> {
        let mut bits = self.serialize();

        if self.curve_type() == EccCurveType::Ed25519 {
            bits.reverse();
        }

        bits
    }

    /// Serialize the scalar (with curve tag prefix)
    pub(crate) fn serialize_tagged(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.curve_type().scalar_bytes());
        bytes.push(self.curve_type().tag());
        bytes.extend_from_slice(&match self {
            Self::K256(s) => s.to_bytes(),
            Self::P256(s) => s.to_bytes(),
            Self::Ed25519(s) => s.to_bytes(),
        });
        bytes
    }

    /// Hash an input to a Scalar value
    pub fn hash_to_scalar(
        curve: EccCurveType,
        input: &[u8],
        domain_separator: &[u8],
    ) -> CanisterThresholdResult<Self> {
        let h = Self::hash_to_several_scalars(curve, 1, input, domain_separator)?;
        Ok(h[0].clone())
    }

    /// Hash an input into multiple Scalar values
    pub fn hash_to_several_scalars(
        curve: EccCurveType,
        count: usize,
        input: &[u8],
        domain_separator: &[u8],
    ) -> CanisterThresholdResult<Vec<Self>> {
        let s_bits = curve.scalar_bits();
        let security_level = curve.security_level();

        let field_len = (s_bits + security_level).div_ceil(8); // "L" in spec
        let len_in_bytes = count * field_len;

        let uniform_bytes = ic_crypto_internal_seed::xmd::<ic_crypto_sha2::Sha256>(
            input,
            domain_separator,
            len_in_bytes,
        )?;

        let mut out = Vec::with_capacity(count);

        for i in 0..count {
            let s = EccScalar::from_bytes_wide(
                curve,
                &uniform_bytes[i * field_len..(i + 1) * field_len],
            )?;
            out.push(s);
        }

        Ok(out)
    }

    /// Deserialize a scalar value (with tag)
    pub fn deserialize_tagged(bytes: &[u8]) -> CanisterThresholdSerializationResult<Self> {
        if bytes.is_empty() {
            return Err(CanisterThresholdSerializationError(
                "failed to deserialize tagged EccScalar: empty bytestring".to_string(),
            ));
        }

        match EccCurveType::from_tag(bytes[0]) {
            Some(curve) => Self::deserialize(curve, &bytes[1..]),
            None => Err(CanisterThresholdSerializationError(
                "failed to deserialize tagged EccScalar: unknown curve tag".to_string(),
            )),
        }
    }

    /// Deserialize a scalar value
    pub fn deserialize(
        curve: EccCurveType,
        bytes: &[u8],
    ) -> CanisterThresholdSerializationResult<Self> {
        if bytes.len() != curve.scalar_bytes() {
            return Err(CanisterThresholdSerializationError(
                "failed to deserialize EccScalar: unexpected length".to_string(),
            ));
        }

        let deser_err_msg_fn = || {
            CanisterThresholdSerializationError(
                "failed to deserialize EccScalar: invalid encoding".to_string(),
            )
        };
        match curve {
            EccCurveType::K256 => {
                let s = secp256k1::Scalar::deserialize(bytes).ok_or_else(deser_err_msg_fn)?;
                Ok(Self::K256(s))
            }
            EccCurveType::P256 => {
                let s = secp256r1::Scalar::deserialize(bytes).ok_or_else(deser_err_msg_fn)?;
                Ok(Self::P256(s))
            }
            EccCurveType::Ed25519 => {
                let s = ed25519::Scalar::deserialize(bytes).ok_or_else(deser_err_msg_fn)?;
                Ok(Self::Ed25519(s))
            }
        }
    }

    /// Compute the scalar from a larger value
    ///
    /// The input is allowed to be up to twice the length of a scalar. It is
    /// interpreted as a big-endian encoded integer, and reduced modulo the
    /// group order.
    pub fn from_bytes_wide(curve: EccCurveType, bytes: &[u8]) -> CanisterThresholdResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let s = secp256k1::Scalar::from_wide_bytes(bytes)
                    .ok_or(CanisterThresholdError::InvalidScalar)?;
                Ok(Self::K256(s))
            }
            EccCurveType::P256 => {
                let s = secp256r1::Scalar::from_wide_bytes(bytes)
                    .ok_or(CanisterThresholdError::InvalidScalar)?;
                Ok(Self::P256(s))
            }
            EccCurveType::Ed25519 => {
                let s = ed25519::Scalar::from_wide_bytes(bytes)
                    .ok_or(CanisterThresholdError::InvalidScalar)?;
                Ok(Self::Ed25519(s))
            }
        }
    }

    /// Generate a random scalar in [0,p)
    pub fn random<R: CryptoRng + RngCore>(curve: EccCurveType, rng: &mut R) -> Self {
        // Use rejection sampling to avoid biasing the output

        let mut buf = vec![0u8; curve.scalar_bytes()];

        loop {
            rng.fill_bytes(&mut buf);
            if let Ok(scalar) = Self::deserialize(curve, &buf) {
                buf.zeroize();
                return scalar;
            }
        }
    }

    pub fn from_seed(curve: EccCurveType, seed: Seed) -> Self {
        let rng = &mut seed.into_rng();
        Self::random(curve, rng)
    }

    /// Return true iff self is equal to zero
    pub fn is_zero(&self) -> bool {
        match self {
            Self::K256(s) => s.is_zero(),
            Self::P256(s) => s.is_zero(),
            Self::Ed25519(s) => s.is_zero(),
        }
    }

    /// Return true iff self is >= order / 2
    pub fn is_high(&self) -> CanisterThresholdResult<bool> {
        match self {
            Self::K256(s) => Ok(s.is_high()),
            Self::P256(s) => Ok(s.is_high()),
            Self::Ed25519(_) => Err(CanisterThresholdError::CurveMismatch),
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
            Self::Ed25519(s) => Self::Ed25519(s.negate()),
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
            EccCurveType::Ed25519 => Self::Ed25519(ed25519::Scalar::zero()),
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
            EccCurveType::Ed25519 => Self::Ed25519(ed25519::Scalar::one()),
        }
    }

    /// Return a small scalar value
    pub fn from_u64(curve: EccCurveType, n: u64) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::Scalar::from(n)),
            EccCurveType::P256 => Self::P256(secp256r1::Scalar::from(n)),
            EccCurveType::Ed25519 => Self::Ed25519(ed25519::Scalar::from(n)),
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
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub enum EccScalarBytes {
    K256(Box<[u8; 32]>),
    P256(Box<[u8; 32]>),
    Ed25519(Box<[u8; 32]>),
}

impl EccScalarBytes {
    pub fn curve_type(&self) -> EccCurveType {
        match self {
            Self::K256(_) => EccCurveType::K256,
            Self::P256(_) => EccCurveType::P256,
            Self::Ed25519(_) => EccCurveType::Ed25519,
        }
    }
}

impl TryFrom<&EccScalarBytes> for EccScalar {
    type Error = CanisterThresholdSerializationError;

    fn try_from(bytes: &EccScalarBytes) -> CanisterThresholdSerializationResult<Self> {
        match bytes {
            EccScalarBytes::K256(raw) => EccScalar::deserialize(EccCurveType::K256, raw.as_ref()),
            EccScalarBytes::P256(raw) => EccScalar::deserialize(EccCurveType::P256, raw.as_ref()),
            EccScalarBytes::Ed25519(raw) => {
                EccScalar::deserialize(EccCurveType::Ed25519, raw.as_ref())
            }
        }
    }
}

impl TryFrom<&EccScalar> for EccScalarBytes {
    type Error = CanisterThresholdSerializationError;

    fn try_from(scalar: &EccScalar) -> CanisterThresholdSerializationResult<Self> {
        match scalar.curve_type() {
            EccCurveType::K256 => {
                Ok(Self::K256(scalar.serialize().try_into().map_err(|e| {
                    CanisterThresholdSerializationError(format!("{e:?}"))
                })?))
            }
            EccCurveType::P256 => {
                Ok(Self::P256(scalar.serialize().try_into().map_err(|e| {
                    CanisterThresholdSerializationError(format!("{e:?}"))
                })?))
            }
            EccCurveType::Ed25519 => {
                Ok(Self::Ed25519(scalar.serialize().try_into().map_err(
                    |e| CanisterThresholdSerializationError(format!("{e:?}")),
                )?))
            }
        }
    }
}

#[derive(Clone, Eq)]
pub struct EccPoint {
    point: EccPointInternal,
    precompute: Option<Arc<NafLut>>,
}

impl Zeroize for EccPoint {
    fn zeroize(&mut self) {
        self.point.zeroize();
        self.precompute = None;
    }
}

impl Drop for EccPoint {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PartialEq for EccPoint {
    fn eq(&self, other: &Self) -> bool {
        // comparison ignores the precomputed state
        self.point == other.point
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub enum EccPointInternal {
    K256(secp256k1::Point),
    P256(secp256r1::Point),
    Ed25519(ed25519::Point),
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
            EccCurveType::K256 => Self::from(secp256k1::Point::identity()),
            EccCurveType::P256 => Self::from(secp256r1::Point::identity()),
            EccCurveType::Ed25519 => Self::from(ed25519::Point::identity()),
        }
    }

    /// Return the "standard" generator for this curve
    pub fn generator_g(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::from(secp256k1::Point::generator()),
            EccCurveType::P256 => Self::from(secp256r1::Point::generator()),
            EccCurveType::Ed25519 => Self::from(ed25519::Point::generator()),
        }
    }

    /// Return a point which is unrelated to the standard generator on the curve
    ///
    /// The key point is that there is no known relation g*z = h as otherwise
    /// our commitment scheme would be insecure. Guarantee this relation is
    /// unknown by deriving h using a hash function.
    ///
    /// In this case the h generator is created using the IETF standard hash2curve
    /// algorithm as appropriate for that curve. The input string is "h" and
    /// the domain separator is
    /// `format!("ic-crypto-tecdsa-{}-generator-h", self.curve)`
    ///
    /// We precompute the generators to avoid wasted computation. The test
    /// generator_h_has_expected_value compares these hardcoded values with
    /// the output of hash2curve.
    pub fn generator_h(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::from(secp256k1::Point::generator_h()),
            EccCurveType::P256 => Self::from(secp256r1::Point::generator_h()),
            EccCurveType::Ed25519 => Self::from(ed25519::Point::generator_h()),
        }
    }

    pub fn curve_type(&self) -> EccCurveType {
        match self.point {
            EccPointInternal::K256(_) => EccCurveType::K256,
            EccPointInternal::P256(_) => EccCurveType::P256,
            EccPointInternal::Ed25519(_) => EccCurveType::Ed25519,
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
        dst: &[u8],
    ) -> CanisterThresholdResult<Self> {
        match curve {
            EccCurveType::K256 => Ok(Self::from(secp256k1::Point::hash2curve(input, dst))),
            EccCurveType::P256 => Ok(Self::from(secp256r1::Point::hash2curve(input, dst))),
            EccCurveType::Ed25519 => Ok(Self::from(ed25519::Point::hash2curve(input, dst))),
        }
    }

    /// Add two elliptic curve points
    pub fn add_points(&self, other: &Self) -> CanisterThresholdResult<Self> {
        match (&self.point, &other.point) {
            (EccPointInternal::K256(pt1), EccPointInternal::K256(pt2)) => {
                Ok(Self::from(pt1.add(pt2)))
            }
            (EccPointInternal::P256(pt1), EccPointInternal::P256(pt2)) => {
                Ok(Self::from(pt1.add(pt2)))
            }
            (EccPointInternal::Ed25519(pt1), EccPointInternal::Ed25519(pt2)) => {
                Ok(Self::from(pt1.add(pt2)))
            }
            _ => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Subtract two elliptic curve points
    pub fn sub_points(&self, other: &Self) -> CanisterThresholdResult<Self> {
        match (&self.point, &other.point) {
            (EccPointInternal::K256(pt1), EccPointInternal::K256(pt2)) => {
                Ok(Self::from(pt1.sub(pt2)))
            }
            (EccPointInternal::P256(pt1), EccPointInternal::P256(pt2)) => {
                Ok(Self::from(pt1.sub(pt2)))
            }
            (EccPointInternal::Ed25519(pt1), EccPointInternal::Ed25519(pt2)) => {
                Ok(Self::from(pt1.sub(pt2)))
            }
            (_, _) => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Perform point*scalar multiplication
    pub fn scalar_mul(&self, scalar: &EccScalar) -> CanisterThresholdResult<Self> {
        match (&self.point, scalar) {
            (EccPointInternal::K256(pt), EccScalar::K256(s)) => Ok(Self::from(pt.mul(s))),
            (EccPointInternal::P256(pt), EccScalar::P256(s)) => Ok(Self::from(pt.mul(s))),
            (EccPointInternal::Ed25519(pt), EccScalar::Ed25519(s)) => Ok(Self::from(pt.mul(s))),
            _ => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// Perform point doubling
    pub fn double(&self) -> Self {
        match &self.point {
            EccPointInternal::K256(pt) => Self::from(pt.double()),
            EccPointInternal::P256(pt) => Self::from(pt.double()),
            EccPointInternal::Ed25519(pt) => Self::from(pt.double()),
        }
    }

    /// Perform point negation
    pub fn negate(&self) -> Self {
        match &self.point {
            EccPointInternal::K256(pt) => Self::from(pt.negate()),
            EccPointInternal::P256(pt) => Self::from(pt.negate()),
            EccPointInternal::Ed25519(pt) => Self::from(pt.negate()),
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
    pub fn mul_by_node_index_vartime(
        &self,
        node_index: NodeIndex,
    ) -> CanisterThresholdResult<Self> {
        // This cannot overflow as NodeIndex is a u32
        let scalar = node_index as u64 + 1;
        let scalar_bits = 64 - scalar.leading_zeros();

        let mut res = self.clone();

        for b in 1..scalar_bits {
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
    ) -> CanisterThresholdResult<Self> {
        match (&pt1.point, scalar1, &pt2.point, scalar2) {
            (
                EccPointInternal::K256(pt1),
                EccScalar::K256(s1),
                EccPointInternal::K256(pt2),
                EccScalar::K256(s2),
            ) => Ok(Self::from(secp256k1::Point::lincomb(pt1, s1, pt2, s2))),

            (
                EccPointInternal::P256(pt1),
                EccScalar::P256(s1),
                EccPointInternal::P256(pt2),
                EccScalar::P256(s2),
            ) => Ok(Self::from(secp256r1::Point::lincomb(pt1, s1, pt2, s2))),

            (
                EccPointInternal::Ed25519(pt1),
                EccScalar::Ed25519(s1),
                EccPointInternal::Ed25519(pt2),
                EccScalar::Ed25519(s2),
            ) => Ok(Self::from(ed25519::Point::lincomb(pt1, s1, pt2, s2))),

            _ => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    pub const MIN_LUT_WINDOW_SIZE: usize = NafLut::MIN_WINDOW_SIZE;
    pub const MAX_LUT_WINDOW_SIZE: usize = NafLut::MAX_WINDOW_SIZE;
    pub const DEFAULT_LUT_WINDOW_SIZE: usize = NafLut::DEFAULT_WINDOW_SIZE;

    /// Creates a new `Self` object and computes a look-up table (LUT) with multiplication
    /// with small scalars for `point`, which will be used for faster vartime (batch) multiplication.
    /// Multiplications stored in the LUT are for scalars represented in
    /// [`Naf`](https://en.wikipedia.org/wiki/Non-adjacent_form)
    /// of length `window_size` with the leading digit being non-zero.
    /// The supported values of `window_size` are in `3..=7`.
    ///
    /// # Errors
    /// * CanisterThresholdError::InvalidArguments if `window_size` is out of bounds.
    pub fn precompute(&mut self, window_size: usize) -> CanisterThresholdResult<()> {
        self.precompute = Some(Arc::new(NafLut::new(&self.clone(), window_size)?));
        Ok(())
    }

    pub fn is_precomputed(&self) -> bool {
        self.precompute.is_some()
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
    ) -> CanisterThresholdResult<()> {
        match &self.precompute {
            Some(lut) => {
                let next = scalar_naf_state.next();
                match next {
                    SlidingWindowStep::Continue => {}
                    SlidingWindowStep::Window(window) => match window {
                        1i8 => {
                            let sum = accum.add_points(self)?;
                            *accum = sum;
                        }
                        -1i8 => {
                            let sum = accum.sub_points(self)?;
                            *accum = sum;
                        }
                        w => {
                            let p = lut.get(w);
                            let sum = accum.add_points(p)?;
                            *accum = sum;
                        }
                    },
                    SlidingWindowStep::Break => {}
                }
                Ok(())
            }
            None => Err(CanisterThresholdError::InvalidArguments(String::from(
                "No precomputed information in EccPoint. Forgot to call precompute()?",
            ))),
        }
    }

    /// Multiples `self.point` by `scalar` utilizing a precomputed LUT
    /// for efficiency.
    ///
    /// Warning: this function leaks information about the scalars via
    /// side channels. Do not use this function with secret scalars.
    pub fn scalar_mul_vartime(&self, scalar: &EccScalar) -> CanisterThresholdResult<EccPoint> {
        match &self.precompute {
            Some(lut) => {
                let mut scalar_naf_state = SlidingWindowMulState::new(scalar, lut.window_size);
                let mut result = Self::identity(self.curve_type());
                for _ in 0..(scalar_naf_state.naf.bit_len() - 1) {
                    self.scalar_mul_step_vartime(&mut scalar_naf_state, &mut result)?;
                    result = result.double();
                }
                self.scalar_mul_step_vartime(&mut scalar_naf_state, &mut result)?;
                Ok(result)
            }
            None => Ok(self.scalar_mul(scalar)?),
        }
    }

    /// Constant time point selection
    ///
    /// Equivalent to `points[index]` except avoids leaking the index
    /// through side channels.
    ///
    ///
    /// # Errors
    /// * [`CanisterThresholdResult::CurveMismatch`] in case of inconsistent points.
    /// * [`CanisterThresholdResult::InvalidArguments`] If `points.is_empty()`.
    pub(crate) fn ct_select_from_slice(
        points: &[Self],
        index: usize,
    ) -> CanisterThresholdResult<Self> {
        use subtle::ConstantTimeEq;
        if points.is_empty() {
            return Err(CanisterThresholdError::InvalidArguments(String::from(
                "The input to constant-time select from slice must contain at least one element",
            )));
        }
        let mut result = Self::identity(points[0].curve_type());

        for (i, point) in points.iter().enumerate() {
            result.conditional_assign(point, usize::ct_eq(&i, &index))?;
        }
        Ok(result)
    }

    /// Constant time point selection
    ///
    /// Equivalent to `points[index]` except avoids leaking the index
    /// through side channels.
    ///
    /// If the index is out of range, no assignment will happen, which will not be detectable using side channels.
    ///
    /// # Errors
    /// * [`CanisterThresholdResult::CurveMismatch`] in case of inconsistent points.
    pub(crate) fn ct_assign_in_slice(
        points: &mut [Self],
        input: &Self,
        index: usize,
    ) -> CanisterThresholdResult<()> {
        use subtle::ConstantTimeEq;
        for (i, point) in points.iter_mut().enumerate() {
            point.conditional_assign(input, usize::ct_eq(&i, &index))?;
        }
        Ok(())
    }

    /// Multiplies and adds together `point_scalar_pairs` as
    /// `ps[0].0 * ps[0].1 + ... + ps[ps.len() - 1].0 * ps[ps.len() - 1].1`,
    /// where `ps` is `point_scalar_pairs`.
    /// The use of `EccPointWithLut` objects with different `window_size`s is supported.
    ///
    /// Warning: this function leaks information about the scalars via
    /// side channels. Do not use this function with secret scalars.
    pub fn mul_n_points_vartime<'a>(
        point_scalar_pairs: &[(&'a EccPoint, &EccScalar)],
    ) -> CanisterThresholdResult<EccPoint> {
        if point_scalar_pairs.is_empty() {
            return Err(CanisterThresholdError::InvalidArguments(String::from(
                "Trying to compute the sum of products with 0 inputs",
            )));
        }

        let get_lut_or_return_error = |pt: &'a EccPoint| -> CanisterThresholdResult<&'a NafLut> {
            match &pt.precompute {
                Some(lut) => Ok(lut),
                None => Err(CanisterThresholdError::InvalidArguments(String::from(
                    "No precomputed information in EccPoint. Forgot to call precompute()?",
                ))),
            }
        };

        let luts: Vec<&NafLut> = point_scalar_pairs
            .iter()
            .map(|&(p, _s)| get_lut_or_return_error(p))
            .collect::<Result<Vec<_>, _>>()?;

        let mut mul_states: Vec<SlidingWindowMulState> = point_scalar_pairs
            .iter()
            .zip(luts.iter())
            .map(|(&(_p, s), lut)| SlidingWindowMulState::new(s, lut.window_size))
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

    /// Constant-time multiscalar multiplication using Pippenger's algorithm
    ///
    /// Return
    /// point_scalar_pairs[0].0 * point_scalar_pairs[1].1 + ...
    /// \+ point_scalar_pairs[n].0 * point_scalar_pairs[n].1
    /// where .0 is a point and .1 is a scalar
    ///
    /// # Errors
    /// * CurveMismatch in case of inconsistent points.
    /// * `CanisterThresholdError::InvalidArguments` if `point_scalar_pairs`
    ///   is empty because we cannot infer a curve type from the input arguments.
    pub fn mul_n_points_pippenger(
        point_scalar_pairs: &[(&EccPoint, &EccScalar)],
    ) -> CanisterThresholdResult<Self> {
        if point_scalar_pairs.is_empty() {
            return Err(CanisterThresholdError::InvalidArguments(
                "Trying to invoke batch-multiplication with an empty argument vector".to_string(),
            ));
        }

        // deduce the curve type from the 0th point
        let curve_type = point_scalar_pairs[0].0.curve_type();

        // Configurable window size: can be 1, 2, 4, or 8
        //
        // TODO: the current window size is taken from the variable time implementation of the Pippenger's algorithm,
        // this may not be optimal for the constant-time algorithm => re-evaluate on production hardware when
        // this function is used somewhere.
        type Window = WindowInfo<4>;
        let num_windows = Window::number_of_windows(curve_type);

        let mut windows = Vec::with_capacity(point_scalar_pairs.len());
        for (p, s) in point_scalar_pairs {
            if p.curve_type() != s.curve_type() {
                return Err(CanisterThresholdError::CurveMismatch);
            }
            let sb = (*s).scalar_bits_be();

            let mut window = vec![0u8; num_windows];
            for (i, w) in window.iter_mut().enumerate() {
                *w = Window::extract(&sb, i);
            }
            windows.push(window);
        }
        let id = Self::identity(curve_type);
        let mut accum = id.clone();

        let mut buckets: Vec<EccPoint> = (0..Window::MAX).map(|_| id.clone()).collect();

        #[allow(clippy::needless_range_loop)]
        for i in 0..num_windows {
            for j in 0..point_scalar_pairs.len() {
                let bucket_index = windows[j][i] as usize;
                // constant-time conditional read
                let mut selected = EccPoint::ct_select_from_slice(&buckets, bucket_index)?;
                // add points
                selected = selected.add_points(point_scalar_pairs[j].0)?;
                // constant-time conditional write
                EccPoint::ct_assign_in_slice(&mut buckets, &selected, bucket_index)?;
            }

            if i > 0 {
                for _ in 0..Window::SIZE {
                    accum = accum.double();
                }
            }
            let mut t = id.clone();

            for bucket in buckets[1..].iter_mut().rev() {
                t = t.add_points(bucket)?;
                accum = accum.add_points(&t)?;
                *bucket = id.clone();
            }
        }

        Ok(accum)
    }

    /// Compute a Pedersen commitment
    ///
    /// Equivalent to EccPoint::mul_2_points(g, x, h, y) but takes
    /// advantage of precomputation on g/h
    pub fn pedersen(x: &EccScalar, y: &EccScalar) -> CanisterThresholdResult<Self> {
        match (x, y) {
            (EccScalar::K256(x), EccScalar::K256(y)) => {
                Ok(Self::from(secp256k1::Point::pedersen(x, y)))
            }
            (EccScalar::P256(x), EccScalar::P256(y)) => {
                Ok(Self::from(secp256r1::Point::pedersen(x, y)))
            }
            (EccScalar::Ed25519(x), EccScalar::Ed25519(y)) => {
                Ok(Self::from(ed25519::Point::pedersen(x, y)))
            }
            (_, _) => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    pub fn mul_by_g(scalar: &EccScalar) -> Self {
        match scalar {
            EccScalar::K256(s) => Self::from(secp256k1::Point::mul_by_g(s)),
            EccScalar::P256(s) => Self::from(secp256r1::Point::mul_by_g(s)),
            EccScalar::Ed25519(s) => Self::from(ed25519::Point::mul_by_g(s)),
        }
    }

    /// Serialize a point in compressed form
    ///
    /// For most curves the output is in SEC1 format, and will be 1
    /// header byte followed by a single field element, which for K256
    /// and P256 is 32 bytes long.
    ///
    /// For Ed25519 the format is as defined in RFC 8032
    pub fn serialize(&self) -> Vec<u8> {
        match &self.point {
            EccPointInternal::K256(pt) => pt.serialize(),
            EccPointInternal::P256(pt) => pt.serialize(),
            EccPointInternal::Ed25519(pt) => pt.serialize(),
        }
    }

    /// Serialize a point's x coordinate
    ///
    /// This is a funky format for secp256k1 used by BIP340.
    /// This encoding format *requires* that the point have a y coordinate
    /// that is even. If the y coordinate of the point is odd, then this
    /// function will return an error. This function also requires
    /// that the point be on secp256k1 and not any other curve.
    ///
    /// This function computes the standard SEC1 compressed point format, then
    /// chops off the leading byte which is used to indicate the parity of y.
    /// That effectively returns just the affine x coordinate in a fixed with
    /// encoding.
    pub fn serialize_bip340(&self) -> CanisterThresholdResult<Vec<u8>> {
        if self.curve_type() != EccCurveType::K256 {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let mut encoding = self.serialize();

        // In the compressed SEC1 encoding, the parity of y is encoded in the
        // first byte; if the affine y coordinate is even, then the first byte
        // will be 0x02. If it is not, then we are attempting to compute the
        // BIP340 representative of a point where that is non-sensensical - by
        // design in BIP340 all points have even y.
        if encoding[0] != 0x02 {
            return Err(CanisterThresholdError::InvalidPoint);
        }

        encoding.remove(0);

        Ok(encoding)
    }

    pub fn deserialize_bip340(curve: EccCurveType, pt: &[u8]) -> CanisterThresholdResult<Self> {
        if curve != EccCurveType::K256 {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let mut sec1 = Vec::with_capacity(1 + pt.len());

        sec1.push(0x02);
        sec1.extend_from_slice(pt);

        Self::deserialize(curve, &sec1)
    }

    /// Serialize a point in compressed form with a curve ID tag
    ///
    /// The output is the same as serialize but prefixed with the
    /// (arbitrarily chosen) tag from EccCurveType::tag()
    pub(crate) fn serialize_tagged(&self) -> Vec<u8> {
        let curve = self.curve_type();
        let mut bytes = Vec::with_capacity(1 + curve.point_bytes());
        bytes.push(curve.tag());
        bytes.extend_from_slice(&self.serialize());
        bytes
    }

    /// Return the binary encoding of the affine X coordinate of this point
    pub fn affine_x_bytes(&self) -> CanisterThresholdResult<Vec<u8>> {
        if self.curve_type() == EccCurveType::Ed25519 {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        // We can just strip off the SEC1 header to get the encoding of x
        Ok(self.serialize()[1..].to_vec())
    }

    /// Return if the affine Y coordinate of this point is even
    pub fn is_y_even(&self) -> CanisterThresholdResult<bool> {
        if self.curve_type() == EccCurveType::Ed25519 {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let compressed = self.serialize();

        match compressed.first() {
            Some(0x02) => Ok(true),
            Some(0x03) => Ok(false),
            _ => Err(CanisterThresholdError::InvalidPoint),
        }
    }

    /// Return true if this is the point at infinity
    pub fn is_infinity(&self) -> CanisterThresholdResult<bool> {
        match &self.point {
            EccPointInternal::K256(pt) => Ok(pt.is_infinity()),
            EccPointInternal::P256(pt) => Ok(pt.is_infinity()),
            EccPointInternal::Ed25519(pt) => Ok(pt.is_infinity()),
        }
    }

    /// Deserialize a tagged point. Only compressed points are accepted.
    pub fn deserialize_tagged(bytes: &[u8]) -> CanisterThresholdResult<Self> {
        if bytes.is_empty() {
            return Err(CanisterThresholdError::InvalidPoint);
        }

        match EccCurveType::from_tag(bytes[0]) {
            Some(curve) => Self::deserialize(curve, &bytes[1..]),
            None => Err(CanisterThresholdError::InvalidPoint),
        }
    }

    /// Deserialize a point. Only compressed points are accepted.
    pub fn deserialize(curve: EccCurveType, bytes: &[u8]) -> CanisterThresholdResult<Self> {
        if bytes.len() != curve.point_bytes() {
            return Err(CanisterThresholdError::InvalidPoint);
        }

        if curve != EccCurveType::Ed25519 {
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
                return Err(CanisterThresholdError::InvalidPoint);
            }
        }

        Self::deserialize_any_format(curve, bytes)
    }

    /// Deserialize a point. Both compressed and uncompressed points are accepted.
    fn deserialize_any_format(curve: EccCurveType, bytes: &[u8]) -> CanisterThresholdResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let pt = secp256k1::Point::deserialize(bytes)
                    .ok_or(CanisterThresholdError::InvalidPoint)?;
                Ok(Self::from(pt))
            }
            EccCurveType::P256 => {
                let pt = secp256r1::Point::deserialize(bytes)
                    .ok_or(CanisterThresholdError::InvalidPoint)?;
                Ok(Self::from(pt))
            }
            EccCurveType::Ed25519 => {
                let pt = ed25519::Point::deserialize(bytes)
                    .ok_or(CanisterThresholdError::InvalidPoint)?;
                Ok(Self::from(pt))
            }
        }
    }

    /// # Errors
    /// * CurveMismatch in case of inconsistent points.
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> CanisterThresholdResult<Self> {
        match (&a.point, &b.point) {
            (EccPointInternal::K256(pt_a), EccPointInternal::K256(pt_b)) => Ok(Self::from(
                secp256k1::Point::conditional_select(pt_a, pt_b, choice),
            )),
            (EccPointInternal::P256(pt_a), EccPointInternal::P256(pt_b)) => Ok(Self::from(
                secp256r1::Point::conditional_select(pt_a, pt_b, choice),
            )),
            (EccPointInternal::Ed25519(pt_a), EccPointInternal::Ed25519(pt_b)) => Ok(Self::from(
                ed25519::Point::conditional_select(pt_a, pt_b, choice),
            )),
            _ => Err(CanisterThresholdError::CurveMismatch),
        }
    }

    /// # Errors
    /// * CurveMismatch in case of inconsistent points.
    #[inline(always)]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) -> CanisterThresholdResult<()> {
        *self = Self::conditional_select(self, other, choice)?;
        Ok(())
    }
}

/// Converts `ed25519` point to `EccPoint`
impl From<ed25519::Point> for EccPoint {
    fn from(point: ed25519::Point) -> Self {
        Self {
            point: EccPointInternal::Ed25519(point),
            precompute: None,
        }
    }
}

/// Converts `secp256r1` point to `EccPoint`
impl From<secp256r1::Point> for EccPoint {
    fn from(point: secp256r1::Point) -> Self {
        Self {
            point: EccPointInternal::P256(point),
            precompute: None,
        }
    }
}

/// Converts `secp256k1` point to `EccPoint`
impl From<secp256k1::Point> for EccPoint {
    fn from(point: secp256k1::Point) -> Self {
        Self {
            point: EccPointInternal::K256(point),
            precompute: None,
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
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

pub(crate) struct WindowInfo<const WINDOW_SIZE: usize> {}

impl<const WINDOW_SIZE: usize> WindowInfo<WINDOW_SIZE> {
    const SIZE: usize = WINDOW_SIZE;

    const MASK: u8 = 0xFFu8 >> (8 - WINDOW_SIZE);
    const MAX: usize = 1 << WINDOW_SIZE;

    /// * `bit_len` denotes the total bit size
    /// * `inverted_w` denotes the window index counting from the least significant part of the scalar
    #[inline(always)]
    fn window_bit_offset(inverted_w: usize) -> usize {
        (inverted_w * WINDOW_SIZE) % 8
    }

    /// Returns the number of windows in `curve_type`.
    #[inline(always)]
    fn number_of_windows(curve_type: EccCurveType) -> usize {
        Self::number_of_windows_for_bits(curve_type.scalar_bits())
    }

    /// Returns the number of windows if scalar_bits bits are used
    #[inline(always)]
    pub(crate) const fn number_of_windows_for_bits(scalar_bits: usize) -> usize {
        scalar_bits.div_ceil(WINDOW_SIZE)
    }

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
    #[inline(always)]
    pub(crate) fn extract(scalar: &[u8], w: usize) -> u8 {
        assert!((1..=8).contains(&WINDOW_SIZE));
        const BITS_IN_BYTE: usize = 8;

        let scalar_bytes = scalar.len();
        let windows = (scalar_bytes * 8).div_ceil(WINDOW_SIZE);

        // to compute the correct bit offset for bit lengths that are not a power of 2,
        // we need to start from the inverted value or otherwise we will have multiple options
        // for the offset.
        let inverted_w = windows - w - 1;
        let bit_offset = Self::window_bit_offset(inverted_w);
        let byte_offset = scalar_bytes - 1 - (inverted_w * WINDOW_SIZE) / 8;
        let target_byte = scalar[byte_offset];

        let no_overflow = bit_offset + WINDOW_SIZE <= BITS_IN_BYTE;

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
        let bytes = scalar.scalar_bits_be();
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
    ///   `(pos + bit_len) <= self.bit_len()` must hold.
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
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct NafLut {
    multiplications: Vec<EccPoint>,
    window_size: usize,
}

impl NafLut {
    /// Inclusive bounds of the LUT.
    /// Manually the bounds can be computed as an "all-one" NAF value, e.g.,
    /// "1 0 1 0 1" for `window_size == 5` (recall that in NAF there can be no adjacent non-zero values)
    const BOUND: [usize; 8] = [0, 1, 2, 5, 10, 21, 42, 85];
    pub const MIN_WINDOW_SIZE: usize = 3;
    pub const MAX_WINDOW_SIZE: usize = 7;
    /// Benchmarks show that the window size 5 is the best tradeoff between the efficient
    /// online phase and acceptable overhead for the precomputation, and it results in the best
    /// total run time.
    pub const DEFAULT_WINDOW_SIZE: usize = 5;

    /// Generates a LUT with the values `BOUND[window_size - 1] + 1..=BOUND[window_size]` and their negations.
    /// The values are stored in the ascending order, e.g., for `window_size == 5` it stores
    /// "-1 0 -1 0 -1"..="-1 0 1 0 1","1 0 -1 0 -1"..="1 0 1 0 1" or as integers -21..=-11,11..=21
    ///
    /// # Errors
    /// * CanisterThresholdError::InvalidArguments if `window_size` is out of bounds.
    fn new(point: &EccPoint, window_size: usize) -> CanisterThresholdResult<Self> {
        if !(Self::MIN_WINDOW_SIZE..=Self::MAX_WINDOW_SIZE).contains(&window_size) {
            return Err(CanisterThresholdError::InvalidArguments(format!(
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
    fn is_in_bounds(window_size: usize, i: i8) -> bool {
        (i.unsigned_abs() as usize) > Self::BOUND[window_size - 1]
            && (i.unsigned_abs() as usize) < (Self::BOUND[window_size] + 1)
    }

    /// Computes the LUT for NAF values of length of exactly `window_size`.
    ///
    /// # Errors
    /// * CurveMismatch in case of inconsistent points. However, this should generally not happen
    ///   because the curve type of all computed points is derived from `point`.
    fn compute_table(
        point: &EccPoint,
        window_size: usize,
    ) -> CanisterThresholdResult<Vec<EccPoint>> {
        let lower_bound = Self::BOUND[window_size - 1];
        let upper_bound = Self::BOUND[window_size] + 1;
        // Offset is equal to the number of negative values
        let num_negatives: usize = Self::BOUND[window_size] - Self::BOUND[window_size - 1];

        let id = EccPoint::identity(point.curve_type());
        let mut result = vec![id; 2 * num_negatives];

        let mut point_in_bounds = point.clone();
        let mut index_in_bounds: i8 = 1;
        while index_in_bounds as usize <= lower_bound {
            point_in_bounds = point_in_bounds.double();
            index_in_bounds *= 2;
        }

        let to_array_index = |real_index: i8| -> usize {
            if real_index.is_negative() {
                num_negatives - (real_index.unsigned_abs() as usize - lower_bound)
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
    fn get(&self, i: i8) -> &EccPoint {
        assert!(Self::is_in_bounds(self.window_size, i));
        let lower_bound = Self::BOUND[self.window_size - 1];
        let num_negatives = self.multiplications.len() / 2;
        let array_index: usize = if i.is_negative() {
            num_negatives - (i + (lower_bound as i8)).unsigned_abs() as usize
        } else {
            num_negatives + (i.unsigned_abs() as usize) - lower_bound - 1
        };
        &self.multiplications[array_index]
    }
}
