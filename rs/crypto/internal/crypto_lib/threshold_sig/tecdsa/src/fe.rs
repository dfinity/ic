use crate::{EccCurve, EccCurveType, ThresholdEcdsaError, ThresholdEcdsaResult};
use std::fmt;

mod secp256k1;
mod secp256r1;
mod utils;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EccFieldElement {
    K256(secp256k1::FieldElement),
    P256(secp256r1::FieldElement),
}

impl fmt::Display for EccFieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FieldElem({}, 0x{})",
            self.curve(),
            hex::encode(self.as_bytes())
        )
    }
}

impl EccFieldElement {
    /// Return the curve this field element is from
    pub fn curve(&self) -> EccCurve {
        match self {
            Self::K256(_) => EccCurve::new(EccCurveType::K256),
            Self::P256(_) => EccCurve::new(EccCurveType::P256),
        }
    }

    pub fn curve_type(&self) -> EccCurveType {
        self.curve().curve_type()
    }

    /// Return the zero field element
    pub fn zero(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::zero()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::zero()),
        }
    }

    /// Return the one field element
    pub fn one(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::one()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::one()),
        }
    }

    /// Return the field element "A" cooresponding to the curve equation
    pub fn a(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::a()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::a()),
        }
    }

    /// Return the field element "B" cooresponding to the curve equation
    pub fn b(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::b()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::b()),
        }
    }

    /// Return the field element "A" cooresponding to the curve equation
    /// for the curve used with SSWU hash2curve technique. This may or
    /// may not match the normal "A"
    pub fn sswu_a(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::sswu_a()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::sswu_a()),
        }
    }

    /// Return the field element "B" cooresponding to the curve equation
    /// for the curve used with SSWU hash2curve technique. This may or
    /// may not match the normal "B"
    pub fn sswu_b(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::sswu_b()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::sswu_b()),
        }
    }

    /// Return the field element "Z" as specified for the simplified
    /// SWU map in draft-irtf-cfrg-hash-to-curve-12
    pub fn sswu_z(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::sswu_z()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::sswu_z()),
        }
    }

    /// Return the field element "C2" as specified for the simplified
    /// SWU map in draft-irtf-cfrg-hash-to-curve-12
    /// See section F.2.1.2
    pub fn sswu_c2(curve: EccCurveType) -> Self {
        match curve {
            EccCurveType::K256 => Self::K256(secp256k1::FieldElement::sswu_c2()),
            EccCurveType::P256 => Self::P256(secp256r1::FieldElement::sswu_c2()),
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
                let x = secp256k1::FieldElement::from_bytes(bytes)?;
                Ok(Self::K256(x))
            }
            EccCurveType::P256 => {
                let x = secp256r1::FieldElement::from_bytes(bytes)?;
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
                let x = secp256k1::FieldElement::from_bytes_wide(bytes)?;
                Ok(Self::K256(x))
            }
            EccCurveType::P256 => {
                let x = secp256r1::FieldElement::from_bytes_wide(bytes)?;
                Ok(Self::P256(x))
            }
        }
    }

    /// Return true if and only if self is equal to zero
    pub fn is_zero(&self) -> bool {
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
            Self::K256(x) => x.as_bytes(),
            Self::P256(x) => x.as_bytes(),
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

    /// Conditional assignment
    ///
    /// If assign is true then set self to other. Otherwise self is left
    /// unmodified.
    pub fn ct_assign(&mut self, other: &Self, assign: bool) -> ThresholdEcdsaResult<()> {
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
    pub fn sqrt(&self) -> Self {
        match self {
            Self::K256(x) => Self::K256(x.sqrt()),
            Self::P256(x) => Self::P256(x.sqrt()),
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
