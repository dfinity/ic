use crate::{EccCurveType, ThresholdEcdsaError, ThresholdEcdsaResult};
use std::convert::TryInto;
use std::fmt;
use zeroize::Zeroize;

// The secp256k1 parameters are defined in FIPS 186-4, section D.1.2
// [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf]
//
// The SSWU parameters are defined in
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-nist-p-256
fe_derive::derive_field_element!(
    Secp256r1FieldElement,
    Modulus = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    A = "-3",
    B = "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    SSWU_A = "A",
    SSWU_B = "B",
    SSWU_Z = "-10",
);

// The secp256k1 parameters are defined in SEC2
// [https://www.secg.org/sec2-v2.pdf] section 2.4.1
//
// The SSWU parameters are defined in
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-secp256k1
fe_derive::derive_field_element!(
    Secp256k1FieldElement,
    Modulus = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    A = "0",
    B = "7",
    SSWU_A = "0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533",
    SSWU_B = "1771",
    SSWU_Z = "-11",
);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EccFieldElement {
    K256(Secp256k1FieldElement),
    P256(Secp256r1FieldElement),
}

impl fmt::Display for EccFieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FieldElem({}, 0x{})",
            self.curve_type(),
            hex::encode(self.as_bytes())
        )
    }
}

impl EccFieldElement {
    /// Return the curve this field element is from
    pub fn curve_type(&self) -> EccCurveType {
        match self {
            Self::K256(_) => EccCurveType::K256,
            Self::P256(_) => EccCurveType::P256,
        }
    }

    /// Return the zero field element
    pub fn zero(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::zero()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::zero()),
        }
    }

    /// Return the one field element
    pub fn one(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::one()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::one()),
        }
    }

    /// Return the field element "A" cooresponding to the curve equation
    pub fn a(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::a()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::a()),
        }
    }

    /// Return the field element "B" cooresponding to the curve equation
    pub fn b(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::b()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::b()),
        }
    }

    /// Return the field element "A" cooresponding to the curve equation
    /// for the curve used with SSWU hash2curve technique. This may or
    /// may not match the normal "A"
    pub fn sswu_a(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::sswu_a()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::sswu_a()),
        }
    }

    /// Return the field element "B" cooresponding to the curve equation
    /// for the curve used with SSWU hash2curve technique. This may or
    /// may not match the normal "B"
    pub fn sswu_b(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::sswu_b()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::sswu_b()),
        }
    }

    /// Return the field element "Z" as specified for the simplified
    /// SWU map in draft-irtf-cfrg-hash-to-curve-12
    pub fn sswu_z(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::sswu_z()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::sswu_z()),
        }
    }

    /// Return the field element "C2" as specified for the simplified
    /// SWU map in draft-irtf-cfrg-hash-to-curve-12
    /// See section F.2.1.2
    pub fn sswu_c2(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(Secp256k1FieldElement::sswu_c2()),
            EccCurveType::P256 => Self::P256(Secp256r1FieldElement::sswu_c2()),
        }
    }

    /// Decode a field element from encoded big-endian bytes
    ///
    /// The byte string must be the exact length of the field (32 bytes for
    /// P-256 and secp256k1), and must in big-endian convention encode an
    /// integer that is less than the prime.
    pub fn from_bytes(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let x = Secp256k1FieldElement::from_bytes(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidFieldElement)?;
                Ok(Self::K256(x))
            }
            EccCurveType::P256 => {
                let x = Secp256r1FieldElement::from_bytes(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidFieldElement)?;
                Ok(Self::P256(x))
            }
        }
    }

    /// Decode a field element from encoded big-endian bytes
    ///
    /// The byte string may be any length up to twice the length of the
    /// field. The bytes are taken to form an big-endian integer, which
    /// is then reduced modulo the prime to form a field element.
    pub fn from_bytes_wide(curve: EccCurveType, bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        match curve {
            EccCurveType::K256 => {
                let x = Secp256k1FieldElement::from_bytes_wide(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidFieldElement)?;
                Ok(Self::K256(x))
            }
            EccCurveType::P256 => {
                let x = Secp256r1FieldElement::from_bytes_wide(bytes)
                    .ok_or(ThresholdEcdsaError::InvalidFieldElement)?;
                Ok(Self::P256(x))
            }
        }
    }

    /// Return true if and only if self is equal to zero
    pub fn is_zero(&self) -> subtle::Choice {
        match self {
            Self::K256(x) => x.is_zero(),
            Self::P256(x) => x.is_zero(),
        }
    }

    /// Return the encoding of this field element
    ///
    /// The integer in range [0,p) is encoded as a big-endian byte string
    /// with leading zero padding as required.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::K256(x) => x.as_bytes().to_vec(),
            Self::P256(x) => x.as_bytes().to_vec(),
        }
    }

    /// Add two field elements
    ///
    /// It is an error to attempt to add two field elements which come
    /// from different curves.
    pub fn add(&self, other: &Self) -> Result<Self, ThresholdEcdsaError> {
        match (self, other) {
            (Self::K256(x), Self::K256(y)) => Ok(Self::K256(x.add(y))),
            (Self::P256(x), Self::P256(y)) => Ok(Self::P256(x.add(y))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Subtract two field elements
    ///
    /// It is an error to attempt to subtract two field elements which come
    /// from different curves.
    pub fn sub(&self, other: &Self) -> Result<Self, ThresholdEcdsaError> {
        match (self, other) {
            (Self::K256(x), Self::K256(y)) => Ok(Self::K256(x.subtract(y))),
            (Self::P256(x), Self::P256(y)) => Ok(Self::P256(x.subtract(y))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Multiply two field elements
    ///
    /// It is an error to attempt to multiply two field elements which come
    /// from different curves.
    pub fn mul(&self, other: &Self) -> Result<Self, ThresholdEcdsaError> {
        match (self, other) {
            (Self::K256(x), Self::K256(y)) => Ok(Self::K256(x.mul(y))),
            (Self::P256(x), Self::P256(y)) => Ok(Self::P256(x.mul(y))),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Square a field element
    pub fn square(&self) -> Result<Self, ThresholdEcdsaError> {
        self.mul(self)
    }

    /// Const time equality
    ///
    /// Same as == except returns subtle::Choice instead of a bool
    pub fn ct_eq(&self, other: &Self) -> ThresholdEcdsaResult<subtle::Choice> {
        match (self, other) {
            (Self::K256(x), Self::K256(y)) => Ok(x.ct_eq(y)),
            (Self::P256(x), Self::P256(y)) => Ok(x.ct_eq(y)),
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Conditional assignment
    ///
    /// If assign is true then set self to other. Otherwise self is left
    /// unmodified.
    pub fn ct_assign(&mut self, other: &Self, assign: subtle::Choice) -> ThresholdEcdsaResult<()> {
        match (self, other) {
            (Self::K256(x), Self::K256(y)) => {
                x.ct_assign(y, assign);
                Ok(())
            }
            (Self::P256(x), Self::P256(y)) => {
                x.ct_assign(y, assign);
                Ok(())
            }
            (_, _) => Err(ThresholdEcdsaError::CurveMismatch),
        }
    }

    /// Return the multiplicative inverse of self
    ///
    /// Returns zero if self is zero
    pub fn invert(&self) -> Self {
        match self {
            Self::K256(x) => Self::K256(x.invert()),
            Self::P256(x) => Self::P256(x.invert()),
        }
    }

    /// Return the additive inverse of self
    ///
    /// Returns zero if self is zero
    pub fn negate(&self) -> ThresholdEcdsaResult<Self> {
        Self::zero(self.curve_type()).sub(self)
    }

    /// Return the modular square root of self
    ///
    /// Returns zero if self is zero or if no square root exists
    ///
    /// The validity of the result is decided by the returned Choice
    pub fn sqrt(&self) -> (subtle::Choice, Self) {
        match self {
            Self::K256(x) => {
                let (valid, s) = x.sqrt();
                (valid, Self::K256(s))
            }
            Self::P256(x) => {
                let (valid, s) = x.sqrt();
                (valid, Self::P256(s))
            }
        }
    }

    /// Return the progenitor of self
    ///
    /// For curves with p == 3 (mod 4) this is equal to self**((p-3)/4)
    pub fn progenitor(&self) -> Self {
        match self {
            Self::K256(x) => Self::K256(x.progenitor()),
            Self::P256(x) => Self::P256(x.progenitor()),
        }
    }

    /// Return the "sign" of self
    ///
    /// See Section 4.1 of draft-irtf-cfrg-hash-to-curve-12 for details
    pub fn sign(&self) -> u8 {
        let bytes = match self {
            Self::K256(x) => x.as_bytes(),
            Self::P256(x) => x.as_bytes(),
        };

        // Return the low bit
        bytes[bytes.len() - 1] & 1
    }
}
