//! Arithmetic operations for BLS12-381 primitives

use group::CurveProjective;
use pairing::bls12_381::{Fr, FrRepr};

#[cfg(test)]
mod tests;

/// Multiply an element of a group by a scalar.
/// This can be applied to any group over Fr; in particular G1 and G2.
/// The factor can be &FrRepr or &Fr.  The difference is that FrRepr may be
/// larger than the modulus.
/// This is a pure wrapper around the impure function provided by the pairing
/// library.
pub fn scalar_multiply<G: CurveProjective<Scalar = Fr>, F: Into<FrRepr>>(
    mut base: G,
    factor: F,
) -> G {
    base.mul_assign(factor);
    base
}

/// Sum elements of a group.
/// This can be applied to elements of any group over Fr; in particular G1 and
/// G2.
pub fn sum<G: CurveProjective<Scalar = Fr>>(points: &[G]) -> G {
    points.iter().fold(G::zero(), |mut accumulator, point| {
        accumulator.add_assign(&point);
        accumulator
    })
}
