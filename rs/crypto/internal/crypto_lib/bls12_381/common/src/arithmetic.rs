//! Arithmetic operations for BLS12-381 primitives

use bls12_381::{G1Projective, G2Projective};

#[cfg(test)]
mod tests;

pub fn sum_g1(points: &[G1Projective]) -> G1Projective {
    points
        .iter()
        .fold(G1Projective::identity(), |mut accumulator, point| {
            accumulator += point;
            accumulator
        })
}

pub fn sum_g2(points: &[G2Projective]) -> G2Projective {
    points
        .iter()
        .fold(G2Projective::identity(), |mut accumulator, point| {
            accumulator += point;
            accumulator
        })
}
