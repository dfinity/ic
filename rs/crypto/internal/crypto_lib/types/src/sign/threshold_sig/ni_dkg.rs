//! Data types for non-interactive distributed key generation (NI-DKG).
pub use crate::encrypt::forward_secure::{CspFsEncryptionPop, CspFsEncryptionPublicKey};
use crate::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use phantom_newtype::AmountOf;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use strum_macros::IntoStaticStr;

/// Input for threshold signature key material
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, IntoStaticStr, Serialize)]
#[allow(non_camel_case_types)]
pub enum CspNiDkgDealing {
    Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Dealing),
}
/// All the public data needed for threshold key derivation.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, IntoStaticStr, Serialize)]
#[allow(non_camel_case_types)]
pub enum CspNiDkgTranscript {
    Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript),
}
impl CspNiDkgTranscript {
    /// From a general transcript to general public coefficients.
    pub fn public_coefficients(&self) -> CspPublicCoefficients {
        match &self {
            Self::Groth20_Bls12_381(transcript) => {
                CspPublicCoefficients::Bls12_381(transcript.public_coefficients.clone())
            }
        }
    }
}

impl TryFrom<&InitialNiDkgTranscriptRecord> for CspNiDkgTranscript {
    type Error = String;

    fn try_from(
        initial_ni_dkg_transcript_record: &InitialNiDkgTranscriptRecord,
    ) -> Result<Self, Self::Error> {
        serde_cbor::from_slice(&initial_ni_dkg_transcript_record.internal_csp_transcript)
            .map_err(|e| format!("Error deserializing CspNiDkgTranscript: {e}"))
    }
}

/// A tag for defining the `Epoch` as `AmountOf`.
pub struct EpochTag;
/// A unit of DKG time.
pub type Epoch = AmountOf<EpochTag, u32>;

pub mod ni_dkg_groth20_bls12_381 {
    //! Data types for the Groth20 non-interactive distributed key generation
    //! scheme.

    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    // These are all the types used together with this scheme, made public in one
    // place for ease of use:
    pub use super::Epoch;
    pub use crate::NodeIndex;
    pub use crate::curves::bls12_381::{FrBytes, G1Bytes, G2Bytes};
    pub use crate::encrypt::forward_secure::groth20_bls12_381::{
        FsEncryptionCiphertextBytes, FsEncryptionPop, FsEncryptionPublicKey, NUM_CHUNKS,
    };
    pub use crate::sign::eddsa::ed25519::{PublicKey, Signature};
    pub use crate::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;

    /// Threshold signature key material with proofs of correctness.
    #[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
    pub struct Dealing {
        pub public_coefficients: PublicCoefficientsBytes,
        pub ciphertexts: EncryptedShares,
        pub zk_proof_decryptability: ZKProofDec,
        pub zk_proof_correct_sharing: ZKProofShare,
    }

    /// Threshold signature key material.
    pub use FsEncryptionCiphertextBytes as EncryptedShares;

    /// The number of repetitions for zero-knowledge proofs.
    pub const NUM_ZK_REPETITIONS: usize = 32;

    /// A zero knowledge proof that the encrypted shares can be decrypted by the
    /// corresponding receivers.
    #[derive(Clone, Hash, Eq, PartialEq, Debug, Deserialize, Serialize)]
    pub struct ZKProofDec {
        pub first_move_y0: G1Bytes,
        pub first_move_b: [G1Bytes; NUM_ZK_REPETITIONS],
        pub first_move_c: [G1Bytes; NUM_ZK_REPETITIONS],
        pub second_move_d: Vec<G1Bytes>, // Has length #receivers+1
        pub second_move_y: G1Bytes,
        pub response_z_r: Vec<FrBytes>,
        pub response_z_s: [FrBytes; NUM_ZK_REPETITIONS],
        pub response_z_b: FrBytes,
    }

    /// A zero knowledge proof that the shares are indeed valid points on the
    /// curve.
    #[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
    pub struct ZKProofShare {
        pub first_move_f: G1Bytes,
        pub first_move_a: G2Bytes,
        pub first_move_y: G1Bytes,
        pub response_z_r: FrBytes,
        pub response_z_a: FrBytes,
    }

    /// All the public data needed for threshold key derivation.
    #[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
    pub struct Transcript {
        pub public_coefficients: PublicCoefficientsBytes,
        /// NodeIndex is for the dealer who computed the encrypted shares
        pub receiver_data: BTreeMap<NodeIndex, EncryptedShares>,
    }
}
