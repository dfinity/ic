//! The crypto public interface.
mod keygen;

pub use keygen::KeyManager;

mod hash;

pub use hash::CryptoHashDomain;
pub use hash::CryptoHashable;
pub use hash::CryptoHashableTestDummy;
pub use hash::DOMAIN_IC_REQUEST;

mod errors;

mod dkg;

pub use dkg::DkgAlgorithm;
pub use sign::threshold_sig::ni_dkg::{LoadTranscriptResult, NiDkgAlgorithm};

mod sign;

pub use sign::BasicSigVerifier;
pub use sign::BasicSigVerifierByPublicKey;
pub use sign::BasicSigner;
pub use sign::CanisterSigVerifier;
pub use sign::IngressSigVerifier;
pub use sign::MultiSigVerifier;
pub use sign::MultiSigner;
pub use sign::ThresholdSigVerifier;
pub use sign::ThresholdSigVerifierByPublicKey;
pub use sign::ThresholdSigner;
pub use sign::{Signable, SignableMock};

use ic_types::consensus::certification::CertificationContent;
use ic_types::consensus::dkg as consensus_dkg;
use ic_types::consensus::{
    Block, CatchUpContent, CatchUpContentProtobufBytes, FinalizationContent, NotarizationContent,
    RandomBeaconContent, RandomTapeContent,
};
use ic_types::messages::{MessageId, WebAuthnEnvelope};

/// The functionality offered by the crypto component
pub trait Crypto:
    KeyManager
    // Block
    + BasicSigner<Block>
    + BasicSigVerifier<Block>
    // Dealing
    + BasicSigner<consensus_dkg::DealingContent>
    + BasicSigVerifier<consensus_dkg::DealingContent>
    // DKG
    + DkgAlgorithm
    + NiDkgAlgorithm
    // CertificationContent
    + MultiSigner<CertificationContent>
    + MultiSigVerifier<CertificationContent>
    + ThresholdSigner<CertificationContent>
    + ThresholdSigVerifier<CertificationContent>
    + ThresholdSigVerifierByPublicKey<CertificationContent>
    // FinalizationContent
    + MultiSigner<FinalizationContent>
    + MultiSigVerifier<FinalizationContent>
    // NotarizationContent
    + MultiSigner<NotarizationContent>
    + MultiSigVerifier<NotarizationContent>
    // RequestId/WebAuthn
    + BasicSigVerifierByPublicKey<MessageId>
    + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
    // CatchUpPackage
    + ThresholdSigner<CatchUpContent>
    + ThresholdSigVerifier<CatchUpContent>
    + ThresholdSigVerifierByPublicKey<CatchUpContent>
    + ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes>
    // RandomBeacon
    + ThresholdSigner<RandomBeaconContent>
    + ThresholdSigVerifier<RandomBeaconContent>
    // RandomTape
    + ThresholdSigner<RandomTapeContent>
    + ThresholdSigVerifier<RandomTapeContent>
    // Traits for signing/verifying a MerkleRoot
    // (both Multi- and ThresholdSig) will be added at a later stage.
    //
    // Also, further traits concerning other functionality of the crypto
    // component (such as key generation) will be added at a later stage.
{
}

/// A classifier for errors returned by the crypto component. Indicates whether
/// a given error is permanent and guaranteed to occur in all replicas.
pub trait ErrorReplication {
    // If true is returned, retrying the failing call will return the same error,
    // and the same error will be encountered by other replicas.
    fn is_replicated(&self) -> bool;
}

// Blanket implementation of Crypto for all types that fulfill requirements
impl<T> Crypto for T where
    T: KeyManager
        + BasicSigner<Block>
        + BasicSigVerifier<Block>
        + BasicSigner<consensus_dkg::DealingContent>
        + BasicSigVerifier<consensus_dkg::DealingContent>
        + DkgAlgorithm
        + NiDkgAlgorithm
        + MultiSigner<CertificationContent>
        + MultiSigVerifier<CertificationContent>
        + ThresholdSigner<CertificationContent>
        + ThresholdSigVerifier<CertificationContent>
        + ThresholdSigVerifierByPublicKey<CertificationContent>
        + MultiSigner<FinalizationContent>
        + MultiSigVerifier<FinalizationContent>
        + MultiSigner<NotarizationContent>
        + MultiSigVerifier<NotarizationContent>
        + BasicSigVerifierByPublicKey<MessageId>
        + BasicSigVerifierByPublicKey<WebAuthnEnvelope>
        + ThresholdSigner<CatchUpContent>
        + ThresholdSigVerifier<CatchUpContent>
        + ThresholdSigVerifierByPublicKey<CatchUpContent>
        + ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes>
        + ThresholdSigner<RandomBeaconContent>
        + ThresholdSigVerifier<RandomBeaconContent>
        + ThresholdSigner<RandomTapeContent>
        + ThresholdSigVerifier<RandomTapeContent>
{
}
