//! Data types for non-interactive distributed key generation (NI-DKG).
pub use crate::encrypt::forward_secure::{CspFsEncryptionPop, CspFsEncryptionPublicKey};
use crate::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use phantom_newtype::AmountOf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::Hash;
use strum_macros::IntoStaticStr;

/// Input for threshold signature key material
#[derive(Clone, Debug, Eq, IntoStaticStr, PartialEq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CspNiDkgDealing {
    Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Dealing),
}
impl CspNiDkgDealing {
    /// Generates an instance of a dealing, for use in stub implementations.
    /// TODO (CRP-824): Delete when stub implementations are complete.
    pub fn placeholder_to_delete(seed: u8) -> Self {
        use ni_dkg_groth20_bls12_381 as scheme;
        fn fr(seed: u8) -> scheme::Fr {
            scheme::Fr([seed; scheme::Fr::SIZE])
        }
        fn g1(seed: u8) -> scheme::G1 {
            scheme::G1([seed; scheme::G1::SIZE])
        }
        fn g2(seed: u8) -> scheme::G2 {
            scheme::G2([seed; scheme::G2::SIZE])
        }
        const NUM_RECEIVERS: usize = 1;
        CspNiDkgDealing::Groth20_Bls12_381(scheme::Dealing {
            public_coefficients: scheme::PublicCoefficientsBytes {
                coefficients: Vec::new(),
            },
            ciphertexts: scheme::EncryptedShares {
                rand_r: [g1(seed); scheme::NUM_CHUNKS],
                rand_s: [g1(seed); scheme::NUM_CHUNKS],
                rand_z: [g2(seed); scheme::NUM_CHUNKS],
                ciphertext_chunks: (0..NUM_RECEIVERS)
                    .map(|i| [g1(seed ^ (i as u8)); scheme::NUM_CHUNKS])
                    .collect(),
            },
            zk_proof_decryptability: ni_dkg_groth20_bls12_381::ZKProofDec {
                // TODO(CRP-530): Populate this when it has been defined in the spec.
                first_move_y0: g1(seed),
                first_move_b: [g1(seed); scheme::NUM_ZK_REPETITIONS],
                first_move_c: [g1(seed); scheme::NUM_ZK_REPETITIONS],
                second_move_d: (0..NUM_RECEIVERS + 1)
                    .map(|i| g1(seed ^ (i as u8)))
                    .collect(),
                second_move_y: g1(seed),
                response_z_r: (0..NUM_RECEIVERS).map(|i| fr(seed | (i as u8))).collect(),
                response_z_s: [fr(seed); scheme::NUM_ZK_REPETITIONS],
                response_z_b: fr(seed),
            },
            zk_proof_correct_sharing: ni_dkg_groth20_bls12_381::ZKProofShare {
                first_move_f: g1(seed),
                first_move_a: g2(seed),
                first_move_y: g1(seed),
                response_z_r: fr(seed),
                response_z_a: fr(seed),
            },
        })
    }
}

/// All the public data needed for threshold key derivation.
#[derive(Clone, Debug, Eq, IntoStaticStr, PartialEq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CspNiDkgTranscript {
    Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript),
}
impl CspNiDkgTranscript {
    /// Generates an instance of a transcript, for use in stub implementations.
    /// TODO (CRP-824): Delete when stub implementations are complete.
    pub fn placeholder_to_delete() -> Self {
        use crate::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
        CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
            public_coefficients: ni_dkg_groth20_bls12_381::PublicCoefficientsBytes {
                coefficients: vec![PublicKeyBytes([0; PublicKeyBytes::SIZE])],
            },
            receiver_data: BTreeMap::new(),
        })
    }

    /// From a general transcript to general public coefficients.
    pub fn public_coefficients(&self) -> CspPublicCoefficients {
        match &self {
            Self::Groth20_Bls12_381(transcript) => {
                CspPublicCoefficients::Bls12_381(transcript.public_coefficients.clone())
            }
        }
    }
}

/// A tag for defining the `Epoch` as `AmountOf`.
pub struct EpochTag;
/// A unit of DKG time.
#[allow(unused)]
pub type Epoch = AmountOf<EpochTag, u32>;

pub mod ni_dkg_groth20_bls12_381 {
    //! Data types for the Groth20 non-interactive distributed key generation
    //! scheme.

    use arrayvec::ArrayVec;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::hash::{Hash, Hasher};

    // These are all the types used together with this scheme, made public in one
    // place for ease of use:
    pub use super::Epoch;
    pub use crate::curves::bls12_381::{Fr, G1, G2};
    pub use crate::encrypt::forward_secure::groth20_bls12_381::{
        Chunk, FsEncryptionCiphertext, FsEncryptionPlaintext, FsEncryptionPop,
        FsEncryptionPublicKey, NUM_CHUNKS,
    };
    pub use crate::sign::eddsa::ed25519::{PublicKey, Signature};
    pub use crate::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
    pub use crate::NodeIndex;

    /// Threshold signature key material with proofs of correctness.
    #[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct Dealing {
        pub public_coefficients: PublicCoefficientsBytes,
        pub ciphertexts: EncryptedShares,
        pub zk_proof_decryptability: ZKProofDec,
        pub zk_proof_correct_sharing: ZKProofShare,
    }

    /// Threshold signature key material.
    pub use FsEncryptionCiphertext as EncryptedShares;

    /// The number of repetitions for zero-knowledge proofs.
    pub const NUM_ZK_REPETITIONS: usize = 32;

    /// A zero knowledge proof that the encrypted shares can be decrypted by the
    /// corresponding receivers.
    #[derive(Clone)]
    pub struct ZKProofDec {
        pub first_move_y0: G1,
        pub first_move_b: [G1; NUM_ZK_REPETITIONS],
        pub first_move_c: [G1; NUM_ZK_REPETITIONS],
        pub second_move_d: Vec<G1>, // Has length #receivers+1
        pub second_move_y: G1,
        pub response_z_r: Vec<Fr>,
        pub response_z_s: [Fr; NUM_ZK_REPETITIONS],
        pub response_z_b: Fr,
    }

    /// Private structure to help implement ZKProofDec traits.
    ///
    /// Many #derive traits fail for arrays of over 32 elements so we need to
    /// implement those traits on ZKProofDec manually.  We can make this fairly
    /// simple by changing the arrays to vectors, for which the #derived
    /// definitions ARE defined, and calling those derived definitions.  Note
    /// that the helper can be deleted when we update our version of Rust to one
    /// that supports const generics, which should happen fairly soon.  There is
    /// little point in optimising this code given that it will be deleted
    /// shortly.
    #[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    #[serde(rename(serialize = "ZKProofDec"))]
    struct ZKProofDecHelper {
        pub first_move_y0: G1,
        pub first_move_b: Vec<G1>,
        pub first_move_c: Vec<G1>,
        pub second_move_d: Vec<G1>, // Has length #receivers+1
        pub second_move_y: G1,
        pub response_z_r: Vec<Fr>,
        pub response_z_s: Vec<Fr>,
        pub response_z_b: Fr,
    }

    impl From<&ZKProofDec> for ZKProofDecHelper {
        fn from(item: &ZKProofDec) -> ZKProofDecHelper {
            ZKProofDecHelper {
                first_move_y0: item.first_move_y0,
                first_move_b: item.first_move_b.to_vec(),
                first_move_c: item.first_move_c.to_vec(),
                second_move_d: item.second_move_d.clone(),
                second_move_y: item.second_move_y,
                response_z_r: item.response_z_r.clone(),
                response_z_s: item.response_z_s.to_vec(),
                response_z_b: item.response_z_b,
            }
        }
    }

    impl TryFrom<ZKProofDecHelper> for ZKProofDec {
        type Error = ();

        fn try_from(item: ZKProofDecHelper) -> Result<Self, Self::Error> {
            let first_move_b: ArrayVec<[G1; NUM_ZK_REPETITIONS]> =
                item.first_move_b.into_iter().collect();
            let first_move_c: ArrayVec<[G1; NUM_ZK_REPETITIONS]> =
                item.first_move_c.into_iter().collect();
            let response_z_s: ArrayVec<[Fr; NUM_ZK_REPETITIONS]> =
                item.response_z_s.into_iter().collect();
            Ok(ZKProofDec {
                first_move_y0: item.first_move_y0,
                first_move_b: first_move_b.into_inner().map_err(|_| ())?,
                first_move_c: first_move_c.into_inner().map_err(|_| ())?,
                second_move_d: item.second_move_d.clone(),
                second_move_y: item.second_move_y,
                response_z_r: item.response_z_r.clone(),
                response_z_s: response_z_s.into_inner().map_err(|_| ())?,
                response_z_b: item.response_z_b,
            })
        }
    }

    impl Serialize for ZKProofDec {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let serde_friendly = ZKProofDecHelper::from(self);
            serde_friendly.serialize(serializer)
        }
    }

    impl PartialEq for ZKProofDec {
        fn eq(&self, other: &Self) -> bool {
            let left = ZKProofDecHelper::from(self);
            let right = ZKProofDecHelper::from(other);
            left == right
        }
    }
    impl Eq for ZKProofDec {}

    impl<'de> Deserialize<'de> for ZKProofDec {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let parsed = ZKProofDecHelper::deserialize(deserializer)?;
            Ok(ZKProofDec::try_from(parsed).expect("Uh"))
        }
    }

    impl std::fmt::Debug for ZKProofDec {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Note: This will print the struct name as ZKProofDecHelper rather than
            // ZKProofDec but I think this is fine.
            ZKProofDecHelper::from(self).fmt(formatter)
        }
    }

    impl Hash for ZKProofDec {
        fn hash<H: Hasher>(&self, state: &mut H) {
            let repackaged = ZKProofDecHelper::from(self);
            repackaged.hash(state);
        }
    }

    /// A zero knowledge proof that the shares are indeed valid points on the
    /// curve.
    #[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct ZKProofShare {
        pub first_move_f: G1,
        pub first_move_a: G2,
        pub first_move_y: G1,
        pub response_z_r: Fr,
        pub response_z_a: Fr,
    }

    /// All the public data needed for threshold key derivation.
    #[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct Transcript {
        pub public_coefficients: PublicCoefficientsBytes,
        /// NodeIndex is for the dealer who computed the encrypted shares
        pub receiver_data: BTreeMap<NodeIndex, EncryptedShares>,
    }
}
