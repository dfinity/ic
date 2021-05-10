use super::super::arbitrary::threshold_sig_public_key_bytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use proptest::prelude::*;

prop_compose! {
    /// Create public coefficients with length in the half-open interval `[min_size, max_size)`.
    pub fn public_coefficients_bytes(
        min_size: usize,
        max_size: usize,
    )
    (
        coefficients in prop::collection::vec(
            threshold_sig_public_key_bytes(), min_size..max_size
        ),
    ) -> PublicCoefficientsBytes {
        PublicCoefficientsBytes{ coefficients }
    }
}

pub fn arbitrary_public_coefficient_bytes(
    min_size: usize,
    max_size: usize,
) -> BoxedStrategy<PublicCoefficientsBytes> {
    public_coefficients_bytes(min_size, max_size).boxed()
}
