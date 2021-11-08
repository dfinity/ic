use crate::*;
//use k256::elliptic_curve::Field;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EccCurveType {
    K256,
    P256,
}

impl EccCurveType {
    pub fn scalar_len(&self) -> usize {
        match self {
            EccCurveType::K256 => 32,
            EccCurveType::P256 => 32,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EccCurve {
    curve: EccCurveType,
}

impl EccCurve {
    pub fn curve(&self) -> EccCurveType {
        self.curve
    }

    pub fn new(curve: EccCurveType) -> Self {
        Self { curve }
    }

    pub fn neutral_element(&self) -> EccPoint {
        match self.curve {
            EccCurveType::K256 => EccPoint::K256(k256::ProjectivePoint::identity()),
            EccCurveType::P256 => EccPoint::P256(p256::ProjectivePoint::identity()),
        }
    }

    pub fn generator_g(&self) -> EccPoint {
        match self.curve {
            EccCurveType::K256 => EccPoint::K256(k256::ProjectivePoint::generator()),
            EccCurveType::P256 => EccPoint::P256(p256::ProjectivePoint::generator()),
        }
    }

    pub fn generator_h(&self) -> EccPoint {
        // FIXME this should use hash2curve!!

        // It so happens that (in compressed form) this value is a valid point on both
        // K256 and P256 Nothing up my sleeve
        let magic = [0x02; 33];

        EccPoint::deserialize(self.curve, &magic).unwrap()
    }

    pub fn random_scalar<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> ThresholdSignatureResult<EccScalar> {
        EccScalar::random(self.curve, rng)
    }

    pub fn deserialize_scalar(&self, bits: &[u8]) -> ThresholdSignatureResult<EccScalar> {
        EccScalar::deserialize(self.curve, bits)
    }

    pub fn hash_to_scalar(&self, bits: &[u8]) -> ThresholdSignatureResult<EccScalar> {
        EccScalar::hash_to_scalar(self.curve, bits)
    }

    pub fn deserialize_point(&self, bits: &[u8]) -> ThresholdSignatureResult<EccPoint> {
        EccPoint::deserialize(self.curve, bits)
    }
}

#[derive(Clone, Debug)]
pub enum EccScalar {
    K256(k256::Scalar),
    P256(p256::Scalar),
}

impl EccScalar {
    pub fn curve(&self) -> EccCurve {
        match self {
            Self::K256(_) => EccCurve::new(EccCurveType::K256),
            Self::P256(_) => EccCurve::new(EccCurveType::P256),
        }
    }

    pub fn add(&self, other: &EccScalar) -> ThresholdSignatureResult<Self> {
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.add(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.add(s2))),
            (_, _) => Err(ThresholdSignatureError::CurveMismatch),
        }
    }

    pub fn sub(&self, other: &EccScalar) -> ThresholdSignatureResult<Self> {
        use std::ops::Sub;
        match (self, other) {
            (Self::K256(s1), Self::K256(s2)) => Ok(Self::K256(s1.sub(s2))),
            (Self::P256(s1), Self::P256(s2)) => Ok(Self::P256(s1.sub(s2))),
            (_, _) => Err(ThresholdSignatureError::CurveMismatch),
        }
    }

    pub fn invert(&self) -> ThresholdSignatureResult<Self> {
        match self {
            Self::K256(s) => {
                let inv = s.invert();
                if bool::from(inv.is_some()) {
                    Ok(EccScalar::K256(inv.unwrap()))
                } else {
                    Err(ThresholdSignatureError::InvalidScalar)
                }
            }
            Self::P256(s) => {
                let inv = s.invert();
                if bool::from(inv.is_some()) {
                    Ok(EccScalar::P256(inv.unwrap()))
                } else {
                    Err(ThresholdSignatureError::InvalidScalar)
                }
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::K256(s) => s.to_bytes().to_vec(),
            Self::P256(s) => s.to_bytes().to_vec(),
        }
    }

    pub fn hash_to_scalar(curve: EccCurveType, input: &[u8]) -> ThresholdSignatureResult<Self> {
        // This only works for P-256 and k256!
        let mut sha256 = Sha256::new();
        sha256.update(input);
        let digest: [u8; 32] = sha256.finalize().into();
        Self::deserialize(curve, &digest)
    }

    pub fn deserialize(curve: EccCurveType, bits: &[u8]) -> ThresholdSignatureResult<Self> {
        if curve.scalar_len() != bits.len() {
            return Err(ThresholdSignatureError::InvalidScalar);
        }

        match curve {
            EccCurveType::K256 => {
                let fb = k256::FieldBytes::from_slice(bits);
                Ok(Self::K256(k256::Scalar::from_bytes_reduced(fb)))
            }
            EccCurveType::P256 => {
                let fb = p256::FieldBytes::from_slice(bits);
                Ok(Self::P256(p256::Scalar::from_bytes_reduced(fb)))
            }
        }
    }

    pub fn random<R: CryptoRng + RngCore>(
        curve: EccCurveType,
        rng: &mut R,
    ) -> ThresholdSignatureResult<Self> {
        let mut buf = vec![0u8; curve.scalar_len()];
        rng.fill_bytes(&mut buf);
        Self::deserialize(curve, &buf)

        /*
        Ok(match curve {
            EccCurveType::K256 => Self::K256(k256::Scalar::generate_vartime(rng)),
            EccCurveType::P256 => Self::P256(p256::Scalar::random(rng)),
        })
         */
    }
}

#[derive(Clone, Debug)]
pub enum EccPoint {
    K256(k256::ProjectivePoint),
    P256(p256::ProjectivePoint),
}

impl EccPoint {
    pub fn curve(&self) -> EccCurve {
        match self {
            Self::K256(_) => EccCurve::new(EccCurveType::K256),
            Self::P256(_) => EccCurve::new(EccCurveType::P256),
        }
    }

    pub fn add_points(&self, other: &Self) -> ThresholdSignatureResult<Self> {
        match (self, other) {
            (Self::K256(pt1), Self::K256(pt2)) => Ok(Self::K256(pt1 + pt2)),
            (Self::P256(pt1), Self::P256(pt2)) => Ok(Self::P256(pt1 + pt2)),
            (_, _) => Err(ThresholdSignatureError::CurveMismatch),
        }
    }

    pub fn scalar_mul(&self, scalar: &EccScalar) -> ThresholdSignatureResult<Self> {
        match (self, scalar) {
            (Self::K256(pt), EccScalar::K256(s)) => Ok(Self::K256(pt * s)),
            (Self::P256(pt), EccScalar::P256(s)) => Ok(Self::P256(pt * s)),
            (_, _) => Err(ThresholdSignatureError::CurveMismatch),
        }
    }

    /// Return self * scalar1 + other * scalar2
    pub fn mul_points(
        &self,
        scalar1: &EccScalar,
        other: &Self,
        scalar2: &EccScalar,
    ) -> ThresholdSignatureResult<Self> {
        match (self, scalar1, other, scalar2) {
            (Self::K256(pt1), EccScalar::K256(s1), Self::K256(pt2), EccScalar::K256(s2)) => {
                Ok(Self::K256(k256::lincomb(pt1, s1, pt2, s2)))
            }

            (Self::P256(pt1), EccScalar::P256(s1), Self::P256(pt2), EccScalar::P256(s2)) => {
                // multi-scalar not available for p256?
                Ok(Self::P256(pt1 * s1 + pt2 * s2))
            }
            (_, _, _, _) => Err(ThresholdSignatureError::CurveMismatch),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::K256(pt) => {
                use k256::elliptic_curve::group::GroupEncoding;
                pt.to_affine().to_bytes().to_vec()
            }
            Self::P256(pt) => {
                use p256::elliptic_curve::group::GroupEncoding;
                pt.to_affine().to_bytes().to_vec()
            }
        }
    }

    pub fn affine_x(&self) -> Vec<u8> {
        let z = self.serialize();
        // assumes compressed serialization:
        z[1..].to_vec()
    }

    pub fn deserialize(curve: EccCurveType, bits: &[u8]) -> ThresholdSignatureResult<Self> {
        match curve {
            EccCurveType::K256 => {
                use k256::elliptic_curve::sec1::FromEncodedPoint;
                let ept = k256::EncodedPoint::from_bytes(bits)
                    .map_err(|_| ThresholdSignatureError::InvalidPoint)?;
                let apt = k256::AffinePoint::from_encoded_point(&ept);

                match apt {
                    Some(apt) => Ok(Self::K256(k256::ProjectivePoint::from(apt))),
                    None => Err(ThresholdSignatureError::InvalidPoint),
                }
            }
            EccCurveType::P256 => {
                use p256::elliptic_curve::sec1::FromEncodedPoint;
                let ept = p256::EncodedPoint::from_bytes(bits)
                    .map_err(|_| ThresholdSignatureError::InvalidPoint)?;
                let apt = p256::AffinePoint::from_encoded_point(&ept);

                match apt {
                    Some(apt) => Ok(Self::P256(p256::ProjectivePoint::from(apt))),
                    None => Err(ThresholdSignatureError::InvalidPoint),
                }
            }
        }
    }
}
