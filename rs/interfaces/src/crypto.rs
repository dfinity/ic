//! The crypto public interface.
mod keygen;

use ic_types::canister_http::CanisterHttpResponseMetadata;
pub use keygen::*;

mod errors;

pub use sign::threshold_sig::ni_dkg::{LoadTranscriptResult, NiDkgAlgorithm};

mod sign;

pub use sign::BasicSigVerifier;
pub use sign::BasicSigner;
pub use sign::MultiSigVerifier;
pub use sign::MultiSigner;
pub use sign::ThresholdSigVerifier;
pub use sign::ThresholdSigVerifierByPublicKey;
pub use sign::ThresholdSigner;

pub use sign::canister_threshold_sig::*;

mod vetkd;
pub use vetkd::*;

use ic_crypto_interfaces_sig_verification::BasicSigVerifierByPublicKey;
use ic_types::consensus::{
    BlockMetadata, CatchUpContent, CatchUpContentProtobufBytes, FinalizationContent,
    NotarizationContent, RandomBeaconContent, RandomTapeContent,
    certification::CertificationContent,
    dkg as consensus_dkg,
    idkg::{IDkgComplaintContent, IDkgOpeningContent},
};
use ic_types::{
    crypto::canister_threshold_sig::idkg::{IDkgDealing, SignedIDkgDealing},
    messages::{MessageId, QueryResponseHash, WebAuthnEnvelope},
};

/// The functionality offered by the crypto component
pub trait Crypto:
    Send
    + Sync
    + KeyManager
    // Block
    + BasicSigner<BlockMetadata>
    + BasicSigVerifier<BlockMetadata>
    // MessageId
    + BasicSigner<MessageId>
    // Dealing
    + BasicSigner<consensus_dkg::DealingContent>
    + BasicSigVerifier<consensus_dkg::DealingContent>
    // DKG
    + NiDkgAlgorithm
    // CertificationContent
    + ThresholdSigner<CertificationContent>
    + ThresholdSigVerifier<CertificationContent>
    + ThresholdSigVerifierByPublicKey<CertificationContent>
    // FinalizationContent
    + MultiSigner<FinalizationContent>
    + MultiSigVerifier<FinalizationContent>
    // NotarizationContent
    + MultiSigner<NotarizationContent>
    + MultiSigVerifier<NotarizationContent>
    // SignedIDkgDealing
    + BasicSigner<SignedIDkgDealing>
    + BasicSigVerifier<SignedIDkgDealing>
    // IDkgDealing
    + BasicSigner<IDkgDealing>
    + BasicSigVerifier<IDkgDealing>
    // IDkgComplaintContent
    + BasicSigner<IDkgComplaintContent>
    + BasicSigVerifier<IDkgComplaintContent>
    // IDkgOpeningContent
    + BasicSigner<IDkgOpeningContent>
    + BasicSigVerifier<IDkgOpeningContent>
    + IDkgProtocol
    + ThresholdEcdsaSigner
    + ThresholdEcdsaSigVerifier
    + ThresholdSchnorrSigner
    + ThresholdSchnorrSigVerifier
    + VetKdProtocol
    // CanisterHttpResponse
    + BasicSigner<CanisterHttpResponseMetadata>
    + BasicSigVerifier<CanisterHttpResponseMetadata>
    // Signed Queries
    + BasicSigner<QueryResponseHash>
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

pub trait ErrorReproducibility {
    /// Indicates whether a given error is reproducible.
    ///
    /// If true, retrying the failing operation will not help
    /// since the same error would be encountered again by the replica.
    ///
    /// If false, retrying the failing operation may succeed or fail again (possibly for a different
    /// reason).
    fn is_reproducible(&self) -> bool;
}

// Blanket implementation of Crypto for all types that fulfill requirements
impl<T> Crypto for T where
    T: KeyManager
        + BasicSigner<BlockMetadata>
        + BasicSigVerifier<BlockMetadata>
        + BasicSigner<MessageId>
        + BasicSigner<consensus_dkg::DealingContent>
        + BasicSigVerifier<consensus_dkg::DealingContent>
        + NiDkgAlgorithm
        + ThresholdSigner<CertificationContent>
        + ThresholdSigVerifier<CertificationContent>
        + ThresholdSigVerifierByPublicKey<CertificationContent>
        + MultiSigner<FinalizationContent>
        + MultiSigVerifier<FinalizationContent>
        + MultiSigner<NotarizationContent>
        + MultiSigVerifier<NotarizationContent>
        + BasicSigner<SignedIDkgDealing>
        + BasicSigVerifier<SignedIDkgDealing>
        + BasicSigner<IDkgDealing>
        + BasicSigVerifier<IDkgDealing>
        + BasicSigner<IDkgComplaintContent>
        + BasicSigVerifier<IDkgComplaintContent>
        + BasicSigner<IDkgOpeningContent>
        + BasicSigVerifier<IDkgOpeningContent>
        + BasicSigner<CanisterHttpResponseMetadata>
        + BasicSigVerifier<CanisterHttpResponseMetadata>
        + BasicSigner<QueryResponseHash>
        + IDkgProtocol
        + ThresholdEcdsaSigner
        + ThresholdEcdsaSigVerifier
        + ThresholdSchnorrSigner
        + ThresholdSchnorrSigVerifier
        + VetKdProtocol
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
