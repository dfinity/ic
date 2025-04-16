//! Data types for public coefficients.
//!
//! Note: Public coefficients are a generalised public key for threshold
//! signatures.
use crate::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use serde::{Deserialize, Serialize};
use strum_macros::IntoStaticStr;

/// Public coefficients for threshold signatures. This is a generalized public
/// key.
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, IntoStaticStr, Serialize,
)]
pub enum PublicCoefficients {
    Bls12_381(bls12_381::PublicCoefficientsBytes),
}

impl From<&CspNiDkgTranscript> for CspPublicCoefficients {
    fn from(csp_dkg_transcript: &CspNiDkgTranscript) -> Self {
        let CspNiDkgTranscript::Groth20_Bls12_381(transcript) = csp_dkg_transcript;
        CspPublicCoefficients::Bls12_381(transcript.clone().public_coefficients)
    }
}

/// A type alias for `PublicCoefficients`.
pub type CspPublicCoefficients = PublicCoefficients;

pub mod bls12_381 {
    //! Data types for BLS12-381 public coefficients.
    use crate::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
    use crate::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
    use serde::{Deserialize, Serialize};

    /// The public coefficients of a threshold public key.
    ///
    /// Any individual or combined signature can be verified by deriving the
    /// corresponding public key from the public coefficients and then verifying
    /// the signature against that public key.
    ///
    /// Given a polynomial with secret coefficients <a0, ..., ak> the public
    /// coefficients are the public keys <A0, ..., Ak> corresponding to those
    /// secret keys.
    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
    pub struct PublicCoefficientsBytes {
        pub coefficients: Vec<PublicKeyBytes>,
    }

    impl From<CspPublicCoefficients> for PublicCoefficientsBytes {
        fn from(coeffs: CspPublicCoefficients) -> PublicCoefficientsBytes {
            let CspPublicCoefficients::Bls12_381(bytes) = coeffs;
            bytes
        }
    }

    impl From<PublicCoefficientsBytes> for CspPublicCoefficients {
        fn from(coeffs: PublicCoefficientsBytes) -> Self {
            CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
                coefficients: coeffs.coefficients,
            })
        }
    }
}
