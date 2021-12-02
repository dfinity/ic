use crate::{ThresholdEcdsaError, ThresholdEcdsaResult};
use std::fmt;
use zeroize::Zeroize;

const LIMBS: usize = 256 / 64;

/// The secp256k1 modulus - see SEC2 [https://www.secg.org/sec2-v2.pdf] section 2.4.1
const MODULUS: FieldElement = FieldElement::from_u64x4(
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFC2F,
);

/// Constant `A'` in the curve `E': y'^2 = x'^3 + A' * x' + B'`
/// isogenous to curve Secp256k1 and specified in
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-secp256k1.
const ISO_CURVE_A: FieldElement = FieldElement::from_u64x4(
    0x3F8731ABDD661ADC,
    0xA08A5558F0F5D272,
    0xE953D363CB6F0E5D,
    0x405447C01A444533,
);

/// Constant `B'` in the curve `E': y'^2 = x'^3 + A' * x' + B'`
/// isogenous to curve Secp256k1 and specified in
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-secp256k1.
const ISO_CURVE_B: FieldElement = FieldElement::from_u64x4(
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x00000000000006eb,
);

/// The constant `Z=-11` in the simplified SWU map specified in
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-secp256k1
const SSWU_Z: FieldElement = FieldElement::from_u64x4(
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFC24,
);

/// The constant `C2` is the square root of `-Z` see
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#appendix-F.2.1.2
const SSWU_C2: FieldElement = FieldElement::from_u64x4(
    0x31FDF302724013E5,
    0x7AD13FB38F842AFE,
    0xEC184F00A74789DD,
    0x286729C8303C4A59,
);

const MODULUS_MINUS_2: [u64; LIMBS] = [
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFC2D,
];

const MODULUS_PLUS_1_OVER_4: [u64; LIMBS] = [
    0x3FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFBFFFFF0C,
];

const MODULUS_MINUS_3_OVER_4: [u64; LIMBS] = [
    0x3FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFBFFFFF0B,
];

/// Montgomery param (-p)^-1 mod 2^64
const P_DASH: u64 = 0xD838091DD2253531;

/// MONTY_R = 2^256 mod p
const MONTY_R: FieldElement = FieldElement::from_u64x4(
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x00000001000003d1,
);

/// MONTY_R^2 = 2^512 mod p
const MONTY_R2: FieldElement = FieldElement::from_u64x4(
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000001,
    0x000007a2000e90a1,
);

/// MONTY_R^3 = 2^768 mod p
const MONTY_R3: FieldElement = FieldElement::from_u64x4(
    0x0000000000000000,
    0x0000000000000000,
    0x0000000100000b73,
    0x002bb1e33795f671,
);

crate::fe::utils::define_field_element!(LIMBS);

impl FieldElement {
    /// Initialize from 4 u64 (private constructor)
    ///
    /// This function uses a reverse convention from the internal ordering,
    /// because it is used for creating the constants and it is nicer for
    /// those to read "in order".
    const fn from_u64x4(v0: u64, v1: u64, v2: u64, v3: u64) -> Self {
        Self::from_limbs([v3, v2, v1, v0])
    }

    /// Return one (in Montgomery form)
    pub fn one() -> Self {
        MONTY_R
    }

    /// Return A (in Montgomery form)
    pub fn a() -> Self {
        // secp256k1 A == 0
        Self::zero()
    }

    /// Return B (in Montgomery form)
    pub fn b() -> Self {
        // secp256k1 B == 7
        Self::from_u64x4(0, 0, 0, 7).mul(&MONTY_R2)
    }

    /// Return A' (in Montgomery form)
    pub fn sswu_a() -> Self {
        ISO_CURVE_A.mul(&MONTY_R2)
    }

    /// Return B' (in Montgomery form)
    pub fn sswu_b() -> Self {
        ISO_CURVE_B.mul(&MONTY_R2)
    }

    /// Return SSWU Z (in Montgomery form)
    pub fn sswu_z() -> Self {
        SSWU_Z.mul(&MONTY_R2)
    }

    /// Return SSWU C2 (in Montgomery form)
    pub fn sswu_c2() -> Self {
        SSWU_C2.mul(&MONTY_R2)
    }

    pub fn progenitor(&self) -> Self {
        self.pow_vartime(&MODULUS_MINUS_3_OVER_4)
    }

    /// Return the square root of self mod p, or zero if no square root exists.
    pub fn sqrt(&self) -> Self {
        // For p == 3 (mod 4) square root can be computed using x^(p+1)/4
        // See I.1 of draft-irtf-cfrg-hash-to-curve-12

        // This function could be much faster using an improved addition chain:
        // https://github.com/bitcoin-core/secp256k1/commit/f8ccd9befdb22824ef9a845a90e3db57c1307c11

        let sqrt = self.pow_vartime(&MODULUS_PLUS_1_OVER_4);

        // Check that the result is valid before returning
        if sqrt.square().ct_eq(self) {
            return sqrt;
        }

        Self::zero()
    }
}
