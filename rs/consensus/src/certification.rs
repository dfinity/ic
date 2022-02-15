//! This module defines the certification component, which is responsible for
//! reaching consensus on parts of the replicated state produced by the upper
//! layers by signing state hashes.
use crate::consensus::crypto::{Aggregate, SignVerify};
use ic_interfaces::crypto::{Crypto, ThresholdSigner};
use ic_types::signature::*;
use ic_types::{
    consensus::certification::CertificationContent, crypto::threshold_sig::ni_dkg::NiDkgId,
};

mod certifier;
mod verifier;

pub use certifier::{setup, CertifierImpl};
pub use verifier::VerifierImpl;

/// A trait that encompasses all crypto signing/verification interface required
/// by the certifier.
pub trait CertificationCrypto:
    Aggregate<
        CertificationContent,
        ThresholdSignatureShare<CertificationContent>,
        NiDkgId,
        ThresholdSignature<CertificationContent>,
    > + ThresholdSigner<CertificationContent>
    + SignVerify<CertificationContent, ThresholdSignatureShare<CertificationContent>, NiDkgId>
    + Crypto
    + Send
    + Sync
{
}

impl<C: Crypto + Send + Sync> CertificationCrypto for C {}
