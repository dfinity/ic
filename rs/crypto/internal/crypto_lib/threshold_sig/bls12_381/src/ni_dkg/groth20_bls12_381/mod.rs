//! Non-interactive Distributed Key Generation using Groth20 with BLS12-381.
mod dealing;
mod encryption;
mod transcript;

pub mod types;

pub use dealing::{
    create_dealing, create_resharing_dealing, verify_dealing, verify_resharing_dealing,
};
pub use encryption::{SecretKey, create_forward_secure_key_pair, update_key_inplace_to_epoch};
pub use transcript::{
    compute_threshold_signing_key, create_resharing_transcript, create_transcript,
};

use ic_types::crypto::AlgorithmId;
const ALGORITHM_ID: AlgorithmId = AlgorithmId::NiDkg_Groth20_Bls12_381;
