//! Crypto mock for testing.
//!
//! [`MockCrypto`] is a `mockall`-based mock of every sub-trait required by
//! the [`Crypto`](ic_interfaces::crypto::Crypto) trait.
//!
//! Most methods are mockable via `expect_*`. Generic traits instantiated for
//! multiple type parameters use uniquely named inherent methods (e.g.
//! `expect_sign_basic_block()` for `BasicSigner<BlockMetadata>`). Traits with
//! conflicting method names use prefixed inherent methods (e.g.
//! `expect_ni_dkg_create_dealing()` vs `expect_idkg_create_dealing()`).
//!
//! Traits whose method signatures contain types parameterized by a lifetime
//! (`ThresholdEcdsaSigner`, `ThresholdEcdsaSigVerifier`,
//! `ThresholdSchnorrSigner`, `ThresholdSchnorrSigVerifier`, `VetKdProtocol`)
//! are stubbed with `unimplemented!()` because `mockall::mock!` cannot express
//! lifetime-parameterized types like `ThresholdEcdsaSigInputs<'a>` or
//! `VetKdArgs<'a>` (`'_` is forbidden, named lifetimes cannot be declared, and
//! elision does not work inside the macro).

use ic_crypto_interfaces_sig_verification::BasicSigVerifierByPublicKey;
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigner, CheckKeysWithRegistryError, CurrentNodePublicKeysError,
    IDkgDealingEncryptionKeyRotationError, IDkgKeyRotationResult, IDkgProtocol, KeyManager,
    LoadTranscriptResult, MultiSigVerifier, MultiSigner, NiDkgAlgorithm, ThresholdEcdsaSigVerifier,
    ThresholdEcdsaSigner, ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner,
    ThresholdSigVerifier, ThresholdSigVerifierByPublicKey, ThresholdSigner, VetKdProtocol,
};
use ic_types::canister_http::CanisterHttpResponseMetadata;
use ic_types::consensus::{
    BlockMetadata, CatchUpContent, CatchUpContentProtobufBytes, FinalizationContent,
    NotarizationContent, RandomBeaconContent, RandomTapeContent,
    certification::CertificationContent,
    dkg as consensus_dkg,
    idkg::{IDkgComplaintContent, IDkgOpeningContent},
};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError,
    ThresholdEcdsaCreateSigShareError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError, ThresholdSchnorrCombineSigSharesError,
    ThresholdSchnorrCreateSigShareError, ThresholdSchnorrVerifyCombinedSigError,
    ThresholdSchnorrVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealings, IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript,
    IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
    ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
};
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::errors::{
    create_dealing_error::DkgCreateDealingError, create_transcript_error::DkgCreateTranscriptError,
    key_removal_error::DkgKeyRemovalError, load_transcript_error::DkgLoadTranscriptError,
    verify_dealing_error::DkgVerifyDealingError,
};
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTranscript};
use ic_types::crypto::vetkd::{
    VetKdArgs, VetKdEncryptedKey, VetKdEncryptedKeyShare, VetKdKeyShareCombinationError,
    VetKdKeyShareCreationError, VetKdKeyShareVerificationError, VetKdKeyVerificationError,
};
use ic_types::crypto::{
    BasicSigOf, CombinedMultiSigOf, CombinedThresholdSigOf, CryptoResult, CurrentNodePublicKeys,
    IndividualMultiSigOf, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::messages::{MessageId, QueryResponseHash, WebAuthnEnvelope};
use ic_types::signature::BasicSignatureBatch;
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::collections::{BTreeMap, BTreeSet, HashSet};

// ── Delegation macros ───────────────────────────────────────────────────────

macro_rules! impl_basic_signer {
    ($t:ty, $method:ident) => {
        impl BasicSigner<$t> for MockCrypto {
            fn sign_basic(&self, message: &$t) -> CryptoResult<BasicSigOf<$t>> {
                self.$method(message)
            }
        }
    };
}

macro_rules! impl_basic_sig_verifier {
    ($t:ty, $verify:ident, $combine:ident, $verify_batch:ident) => {
        impl BasicSigVerifier<$t> for MockCrypto {
            fn verify_basic_sig(
                &self,
                signature: &BasicSigOf<$t>,
                message: &$t,
                signer: NodeId,
                registry_version: RegistryVersion,
            ) -> CryptoResult<()> {
                self.$verify(signature, message, signer, registry_version)
            }

            fn combine_basic_sig(
                &self,
                signatures: BTreeMap<NodeId, &BasicSigOf<$t>>,
                registry_version: RegistryVersion,
            ) -> CryptoResult<BasicSignatureBatch<$t>> {
                let owned = signatures
                    .into_iter()
                    .map(|(k, v)| (k, v.clone()))
                    .collect();
                self.$combine(owned, registry_version)
            }

            fn verify_basic_sig_batch(
                &self,
                signature_batch: &BasicSignatureBatch<$t>,
                message: &$t,
                registry_version: RegistryVersion,
            ) -> CryptoResult<()> {
                self.$verify_batch(signature_batch, message, registry_version)
            }
        }
    };
}

macro_rules! impl_threshold_signer {
    ($t:ty, $method:ident) => {
        impl ThresholdSigner<$t> for MockCrypto {
            fn sign_threshold(
                &self,
                message: &$t,
                dkg_id: &NiDkgId,
            ) -> CryptoResult<ThresholdSigShareOf<$t>> {
                self.$method(message, dkg_id)
            }
        }
    };
}

macro_rules! impl_threshold_sig_verifier {
    ($t:ty, $verify_share:ident, $combine:ident, $verify_combined:ident) => {
        impl ThresholdSigVerifier<$t> for MockCrypto {
            fn verify_threshold_sig_share(
                &self,
                signature: &ThresholdSigShareOf<$t>,
                message: &$t,
                dkg_id: &NiDkgId,
                signer: NodeId,
            ) -> CryptoResult<()> {
                self.$verify_share(signature, message, dkg_id, signer)
            }

            fn combine_threshold_sig_shares(
                &self,
                shares: BTreeMap<NodeId, ThresholdSigShareOf<$t>>,
                dkg_id: &NiDkgId,
            ) -> CryptoResult<CombinedThresholdSigOf<$t>> {
                self.$combine(shares, dkg_id)
            }

            fn verify_threshold_sig_combined(
                &self,
                signature: &CombinedThresholdSigOf<$t>,
                message: &$t,
                dkg_id: &NiDkgId,
            ) -> CryptoResult<()> {
                self.$verify_combined(signature, message, dkg_id)
            }
        }
    };
}

macro_rules! impl_threshold_sig_verifier_by_public_key {
    ($t:ty, $method:ident) => {
        impl ThresholdSigVerifierByPublicKey<$t> for MockCrypto {
            fn verify_combined_threshold_sig_by_public_key(
                &self,
                signature: &CombinedThresholdSigOf<$t>,
                message: &$t,
                subnet_id: SubnetId,
                registry_version: RegistryVersion,
            ) -> CryptoResult<()> {
                self.$method(signature, message, subnet_id, registry_version)
            }
        }
    };
}

macro_rules! impl_multi_signer {
    ($t:ty, $method:ident) => {
        impl MultiSigner<$t> for MockCrypto {
            fn sign_multi(
                &self,
                message: &$t,
                signer: NodeId,
                registry_version: RegistryVersion,
            ) -> CryptoResult<IndividualMultiSigOf<$t>> {
                self.$method(message, signer, registry_version)
            }
        }
    };
}

macro_rules! impl_multi_sig_verifier {
    ($t:ty, $verify:ident, $combine:ident, $verify_combined:ident) => {
        impl MultiSigVerifier<$t> for MockCrypto {
            fn verify_multi_sig_individual(
                &self,
                signature: &IndividualMultiSigOf<$t>,
                message: &$t,
                signer: NodeId,
                registry_version: RegistryVersion,
            ) -> CryptoResult<()> {
                self.$verify(signature, message, signer, registry_version)
            }

            fn combine_multi_sig_individuals(
                &self,
                signatures: BTreeMap<NodeId, IndividualMultiSigOf<$t>>,
                registry_version: RegistryVersion,
            ) -> CryptoResult<CombinedMultiSigOf<$t>> {
                self.$combine(signatures, registry_version)
            }

            fn verify_multi_sig_combined(
                &self,
                signature: &CombinedMultiSigOf<$t>,
                message: &$t,
                signers: BTreeSet<NodeId>,
                registry_version: RegistryVersion,
            ) -> CryptoResult<()> {
                self.$verify_combined(signature, message, signers, registry_version)
            }
        }
    };
}

macro_rules! impl_basic_sig_verifier_by_public_key {
    ($t:ty, $method:ident) => {
        impl BasicSigVerifierByPublicKey<$t> for MockCrypto {
            fn verify_basic_sig_by_public_key(
                &self,
                signature: &BasicSigOf<$t>,
                signed_bytes: &$t,
                public_key: &UserPublicKey,
            ) -> CryptoResult<()> {
                self.$method(signature, signed_bytes, public_key)
            }
        }
    };
}

// ── mockall mock definition ─────────────────────────────────────────────────
//
// Only traits whose method signatures are fully compatible with mockall live
// here.  Traits with lifetime-bearing types or method-name collisions are
// implemented manually below (either as additional inherent→delegation pairs
// or as `unimplemented!()` stubs).

mockall::mock! {
    pub Crypto {
        // ── BasicSigner<T> ──────────────────────────────────────────────

        pub fn sign_basic_block(
            &self, message: &BlockMetadata,
        ) -> CryptoResult<BasicSigOf<BlockMetadata>>;

        pub fn sign_basic_msg_id(
            &self, message: &MessageId,
        ) -> CryptoResult<BasicSigOf<MessageId>>;

        pub fn sign_basic_dkg_dealing_content(
            &self, message: &consensus_dkg::DealingContent,
        ) -> CryptoResult<BasicSigOf<consensus_dkg::DealingContent>>;

        pub fn sign_basic_signed_idkg_dealing(
            &self, message: &SignedIDkgDealing,
        ) -> CryptoResult<BasicSigOf<SignedIDkgDealing>>;

        pub fn sign_basic_idkg_dealing(
            &self, message: &IDkgDealing,
        ) -> CryptoResult<BasicSigOf<IDkgDealing>>;

        pub fn sign_basic_idkg_complaint(
            &self, message: &IDkgComplaintContent,
        ) -> CryptoResult<BasicSigOf<IDkgComplaintContent>>;

        pub fn sign_basic_idkg_opening(
            &self, message: &IDkgOpeningContent,
        ) -> CryptoResult<BasicSigOf<IDkgOpeningContent>>;

        pub fn sign_basic_http(
            &self, message: &CanisterHttpResponseMetadata,
        ) -> CryptoResult<BasicSigOf<CanisterHttpResponseMetadata>>;

        pub fn sign_basic_query(
            &self, message: &QueryResponseHash,
        ) -> CryptoResult<BasicSigOf<QueryResponseHash>>;

        // ── BasicSigVerifier<T> ─────────────────────────────────────────
        // combine_basic_sig uses owned values because mockall cannot
        // express the bare `&` inside BTreeMap<NodeId, &BasicSigOf<T>>.

        // BlockMetadata
        pub fn verify_basic_sig_block(
            &self, signature: &BasicSigOf<BlockMetadata>,
            message: &BlockMetadata, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_block(
            &self, signatures: BTreeMap<NodeId, BasicSigOf<BlockMetadata>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<BlockMetadata>>;

        pub fn verify_basic_sig_batch_block(
            &self, signature_batch: &BasicSignatureBatch<BlockMetadata>,
            message: &BlockMetadata, registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // consensus_dkg::DealingContent
        pub fn verify_basic_sig_dkg_dealing_content(
            &self, signature: &BasicSigOf<consensus_dkg::DealingContent>,
            message: &consensus_dkg::DealingContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_dkg_dealing_content(
            &self,
            signatures: BTreeMap<NodeId, BasicSigOf<consensus_dkg::DealingContent>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<consensus_dkg::DealingContent>>;

        pub fn verify_basic_sig_batch_dkg_dealing_content(
            &self,
            signature_batch: &BasicSignatureBatch<consensus_dkg::DealingContent>,
            message: &consensus_dkg::DealingContent,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // SignedIDkgDealing
        pub fn verify_basic_sig_signed_idkg_dealing(
            &self, signature: &BasicSigOf<SignedIDkgDealing>,
            message: &SignedIDkgDealing, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_signed_idkg_dealing(
            &self,
            signatures: BTreeMap<NodeId, BasicSigOf<SignedIDkgDealing>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<SignedIDkgDealing>>;

        pub fn verify_basic_sig_batch_signed_idkg_dealing(
            &self,
            signature_batch: &BasicSignatureBatch<SignedIDkgDealing>,
            message: &SignedIDkgDealing, registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // IDkgDealing
        pub fn verify_basic_sig_idkg_dealing(
            &self, signature: &BasicSigOf<IDkgDealing>,
            message: &IDkgDealing, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_idkg_dealing(
            &self, signatures: BTreeMap<NodeId, BasicSigOf<IDkgDealing>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<IDkgDealing>>;

        pub fn verify_basic_sig_batch_idkg(
            &self, signature_batch: &BasicSignatureBatch<IDkgDealing>,
            message: &IDkgDealing, registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // IDkgComplaintContent
        pub fn verify_basic_sig_idkg_complaint(
            &self, signature: &BasicSigOf<IDkgComplaintContent>,
            message: &IDkgComplaintContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_idkg_complaint(
            &self,
            signatures: BTreeMap<NodeId, BasicSigOf<IDkgComplaintContent>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<IDkgComplaintContent>>;

        pub fn verify_basic_sig_batch_idkg_complaint(
            &self,
            signature_batch: &BasicSignatureBatch<IDkgComplaintContent>,
            message: &IDkgComplaintContent, registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // IDkgOpeningContent
        pub fn verify_basic_sig_idkg_opening(
            &self, signature: &BasicSigOf<IDkgOpeningContent>,
            message: &IDkgOpeningContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_idkg_opening(
            &self,
            signatures: BTreeMap<NodeId, BasicSigOf<IDkgOpeningContent>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<IDkgOpeningContent>>;

        pub fn verify_basic_sig_batch_idkg_opening(
            &self,
            signature_batch: &BasicSignatureBatch<IDkgOpeningContent>,
            message: &IDkgOpeningContent, registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // CanisterHttpResponseMetadata
        pub fn verify_basic_sig_http(
            &self,
            signature: &BasicSigOf<CanisterHttpResponseMetadata>,
            message: &CanisterHttpResponseMetadata, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_basic_sig_http(
            &self,
            signatures: BTreeMap<NodeId, BasicSigOf<CanisterHttpResponseMetadata>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<CanisterHttpResponseMetadata>>;

        pub fn verify_basic_sig_batch_http(
            &self,
            signature_batch: &BasicSignatureBatch<CanisterHttpResponseMetadata>,
            message: &CanisterHttpResponseMetadata,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // ── ThresholdSigner<T> ──────────────────────────────────────────

        pub fn sign_threshold_certification(
            &self, message: &CertificationContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<ThresholdSigShareOf<CertificationContent>>;

        pub fn sign_threshold_cup(
            &self, message: &CatchUpContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<ThresholdSigShareOf<CatchUpContent>>;

        pub fn sign_threshold_beacon(
            &self, message: &RandomBeaconContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<ThresholdSigShareOf<RandomBeaconContent>>;

        pub fn sign_threshold_tape(
            &self, message: &RandomTapeContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<ThresholdSigShareOf<RandomTapeContent>>;

        // ── ThresholdSigVerifier<T> ─────────────────────────────────────

        // CertificationContent
        pub fn verify_threshold_sig_share_certification(
            &self,
            signature: &ThresholdSigShareOf<CertificationContent>,
            message: &CertificationContent, dkg_id: &NiDkgId,
            signer: NodeId,
        ) -> CryptoResult<()>;

        pub fn combine_threshold_sig_shares_certification(
            &self,
            shares: BTreeMap<NodeId, ThresholdSigShareOf<CertificationContent>>,
            dkg_id: &NiDkgId,
        ) -> CryptoResult<CombinedThresholdSigOf<CertificationContent>>;

        pub fn verify_threshold_sig_combined_certification(
            &self,
            signature: &CombinedThresholdSigOf<CertificationContent>,
            message: &CertificationContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<()>;

        // CatchUpContent
        pub fn verify_threshold_sig_share_cup(
            &self, signature: &ThresholdSigShareOf<CatchUpContent>,
            message: &CatchUpContent, dkg_id: &NiDkgId, signer: NodeId,
        ) -> CryptoResult<()>;

        pub fn combine_threshold_sig_shares_cup(
            &self,
            shares: BTreeMap<NodeId, ThresholdSigShareOf<CatchUpContent>>,
            dkg_id: &NiDkgId,
        ) -> CryptoResult<CombinedThresholdSigOf<CatchUpContent>>;

        pub fn verify_threshold_sig_combined_cup(
            &self, signature: &CombinedThresholdSigOf<CatchUpContent>,
            message: &CatchUpContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<()>;

        // RandomBeaconContent
        pub fn verify_threshold_sig_share_beacon(
            &self,
            signature: &ThresholdSigShareOf<RandomBeaconContent>,
            message: &RandomBeaconContent, dkg_id: &NiDkgId,
            signer: NodeId,
        ) -> CryptoResult<()>;

        pub fn combine_threshold_sig_shares_beacon(
            &self,
            shares: BTreeMap<NodeId, ThresholdSigShareOf<RandomBeaconContent>>,
            dkg_id: &NiDkgId,
        ) -> CryptoResult<CombinedThresholdSigOf<RandomBeaconContent>>;

        pub fn verify_threshold_sig_combined_beacon(
            &self,
            signature: &CombinedThresholdSigOf<RandomBeaconContent>,
            message: &RandomBeaconContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<()>;

        // RandomTapeContent
        pub fn verify_threshold_sig_share_tape(
            &self, signature: &ThresholdSigShareOf<RandomTapeContent>,
            message: &RandomTapeContent, dkg_id: &NiDkgId, signer: NodeId,
        ) -> CryptoResult<()>;

        pub fn combine_threshold_sig_shares_tape(
            &self,
            shares: BTreeMap<NodeId, ThresholdSigShareOf<RandomTapeContent>>,
            dkg_id: &NiDkgId,
        ) -> CryptoResult<CombinedThresholdSigOf<RandomTapeContent>>;

        pub fn verify_threshold_sig_combined_tape(
            &self, signature: &CombinedThresholdSigOf<RandomTapeContent>,
            message: &RandomTapeContent, dkg_id: &NiDkgId,
        ) -> CryptoResult<()>;

        // ── ThresholdSigVerifierByPublicKey<T> ──────────────────────────

        pub fn verify_threshold_by_pk_certification(
            &self,
            signature: &CombinedThresholdSigOf<CertificationContent>,
            message: &CertificationContent, subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn verify_threshold_by_pk_cup(
            &self, signature: &CombinedThresholdSigOf<CatchUpContent>,
            message: &CatchUpContent, subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn verify_threshold_by_pk_cup_proto(
            &self,
            signature: &CombinedThresholdSigOf<CatchUpContentProtobufBytes>,
            message: &CatchUpContentProtobufBytes, subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // ── MultiSigner<T> ──────────────────────────────────────────────

        pub fn sign_multi_finalization(
            &self, message: &FinalizationContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<IndividualMultiSigOf<FinalizationContent>>;

        pub fn sign_multi_notarization(
            &self, message: &NotarizationContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<IndividualMultiSigOf<NotarizationContent>>;

        // ── MultiSigVerifier<T> ─────────────────────────────────────────

        // FinalizationContent
        pub fn verify_multi_sig_individual_finalization(
            &self,
            signature: &IndividualMultiSigOf<FinalizationContent>,
            message: &FinalizationContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_multi_sig_individuals_finalization(
            &self,
            signatures: BTreeMap<NodeId, IndividualMultiSigOf<FinalizationContent>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<CombinedMultiSigOf<FinalizationContent>>;

        pub fn verify_multi_sig_combined_finalization(
            &self, signature: &CombinedMultiSigOf<FinalizationContent>,
            message: &FinalizationContent, signers: BTreeSet<NodeId>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // NotarizationContent
        pub fn verify_multi_sig_individual_notarization(
            &self,
            signature: &IndividualMultiSigOf<NotarizationContent>,
            message: &NotarizationContent, signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        pub fn combine_multi_sig_individuals_notarization(
            &self,
            signatures: BTreeMap<NodeId, IndividualMultiSigOf<NotarizationContent>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<CombinedMultiSigOf<NotarizationContent>>;

        pub fn verify_multi_sig_combined_notarization(
            &self, signature: &CombinedMultiSigOf<NotarizationContent>,
            message: &NotarizationContent, signers: BTreeSet<NodeId>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()>;

        // ── BasicSigVerifierByPublicKey<T> ──────────────────────────────

        pub fn verify_basic_sig_by_pk_msg_id(
            &self, signature: &BasicSigOf<MessageId>,
            signed_bytes: &MessageId, public_key: &UserPublicKey,
        ) -> CryptoResult<()>;

        pub fn verify_basic_sig_by_pk_webauthn(
            &self, signature: &BasicSigOf<WebAuthnEnvelope>,
            signed_bytes: &WebAuthnEnvelope, public_key: &UserPublicKey,
        ) -> CryptoResult<()>;

        // ── NiDkgAlgorithm (prefixed to avoid IDkgProtocol collision) ───

        pub fn ni_dkg_create_dealing(
            &self, config: &NiDkgConfig,
        ) -> Result<NiDkgDealing, DkgCreateDealingError>;

        pub fn ni_dkg_verify_dealing(
            &self, config: &NiDkgConfig, dealer: NodeId,
            dealing: &NiDkgDealing,
        ) -> Result<(), DkgVerifyDealingError>;

        pub fn ni_dkg_create_transcript(
            &self, config: &NiDkgConfig,
            verified_dealings: BTreeMap<NodeId, NiDkgDealing>,
        ) -> Result<NiDkgTranscript, DkgCreateTranscriptError>;

        pub fn ni_dkg_load_transcript(
            &self, transcript: &NiDkgTranscript,
        ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError>;

        pub fn ni_dkg_retain_only_active_keys(
            &self, transcripts: HashSet<NiDkgTranscript>,
        ) -> Result<(), DkgKeyRemovalError>;

        // ── IDkgProtocol (prefixed to avoid NiDkgAlgorithm collision) ───

        pub fn idkg_create_dealing(
            &self, params: &IDkgTranscriptParams,
        ) -> Result<SignedIDkgDealing, IDkgCreateDealingError>;

        pub fn idkg_verify_dealing_public(
            &self, params: &IDkgTranscriptParams,
            signed_dealing: &SignedIDkgDealing,
        ) -> Result<(), IDkgVerifyDealingPublicError>;

        pub fn idkg_verify_dealing_private(
            &self, params: &IDkgTranscriptParams,
            signed_dealing: &SignedIDkgDealing,
        ) -> Result<(), IDkgVerifyDealingPrivateError>;

        pub fn idkg_verify_initial_dealings(
            &self, params: &IDkgTranscriptParams,
            initial_dealings: &InitialIDkgDealings,
        ) -> Result<(), IDkgVerifyInitialDealingsError>;

        pub fn idkg_create_transcript(
            &self, params: &IDkgTranscriptParams,
            dealings: BatchSignedIDkgDealings,
        ) -> Result<IDkgTranscript, IDkgCreateTranscriptError>;

        pub fn idkg_verify_transcript(
            &self, params: &IDkgTranscriptParams,
            transcript: &IDkgTranscript,
        ) -> Result<(), IDkgVerifyTranscriptError>;

        pub fn idkg_load_transcript(
            &self, transcript: &IDkgTranscript,
        ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError>;

        pub fn idkg_verify_complaint(
            &self, transcript: &IDkgTranscript, complainer_id: NodeId,
            complaint: &IDkgComplaint,
        ) -> Result<(), IDkgVerifyComplaintError>;

        pub fn idkg_open_transcript(
            &self, transcript: &IDkgTranscript, complainer_id: NodeId,
            complaint: &IDkgComplaint,
        ) -> Result<IDkgOpening, IDkgOpenTranscriptError>;

        pub fn idkg_verify_opening(
            &self, transcript: &IDkgTranscript, opener: NodeId,
            opening: &IDkgOpening, complaint: &IDkgComplaint,
        ) -> Result<(), IDkgVerifyOpeningError>;

        pub fn idkg_load_transcript_with_openings(
            &self, transcript: &IDkgTranscript,
            openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
        ) -> Result<(), IDkgLoadTranscriptError>;

        pub fn idkg_retain_active_transcripts(
            &self, active_transcripts: &HashSet<IDkgTranscript>,
        ) -> Result<(), IDkgRetainKeysError>;
    }

    // ── KeyManager ──────────────────────────────────────────────────────

    impl KeyManager for Crypto {
        fn check_keys_with_registry(
            &self, registry_version: RegistryVersion,
        ) -> Result<(), CheckKeysWithRegistryError>;

        fn current_node_public_keys(
            &self,
        ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError>;

        fn rotate_idkg_dealing_encryption_keys(
            &self, registry_version: RegistryVersion,
        ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError>;
    }
}

// ── Delegation impls: bridge inherent methods → real generic traits ─────────

impl_basic_signer!(BlockMetadata, sign_basic_block);
impl_basic_signer!(MessageId, sign_basic_msg_id);
impl_basic_signer!(
    consensus_dkg::DealingContent,
    sign_basic_dkg_dealing_content
);
impl_basic_signer!(SignedIDkgDealing, sign_basic_signed_idkg_dealing);
impl_basic_signer!(IDkgDealing, sign_basic_idkg_dealing);
impl_basic_signer!(IDkgComplaintContent, sign_basic_idkg_complaint);
impl_basic_signer!(IDkgOpeningContent, sign_basic_idkg_opening);
impl_basic_signer!(CanisterHttpResponseMetadata, sign_basic_http);
impl_basic_signer!(QueryResponseHash, sign_basic_query);

impl_basic_sig_verifier!(
    BlockMetadata,
    verify_basic_sig_block,
    combine_basic_sig_block,
    verify_basic_sig_batch_block
);
impl_basic_sig_verifier!(
    consensus_dkg::DealingContent,
    verify_basic_sig_dkg_dealing_content,
    combine_basic_sig_dkg_dealing_content,
    verify_basic_sig_batch_dkg_dealing_content
);
impl_basic_sig_verifier!(
    SignedIDkgDealing,
    verify_basic_sig_signed_idkg_dealing,
    combine_basic_sig_signed_idkg_dealing,
    verify_basic_sig_batch_signed_idkg_dealing
);
impl_basic_sig_verifier!(
    IDkgDealing,
    verify_basic_sig_idkg_dealing,
    combine_basic_sig_idkg_dealing,
    verify_basic_sig_batch_idkg
);
impl_basic_sig_verifier!(
    IDkgComplaintContent,
    verify_basic_sig_idkg_complaint,
    combine_basic_sig_idkg_complaint,
    verify_basic_sig_batch_idkg_complaint
);
impl_basic_sig_verifier!(
    IDkgOpeningContent,
    verify_basic_sig_idkg_opening,
    combine_basic_sig_idkg_opening,
    verify_basic_sig_batch_idkg_opening
);
impl_basic_sig_verifier!(
    CanisterHttpResponseMetadata,
    verify_basic_sig_http,
    combine_basic_sig_http,
    verify_basic_sig_batch_http
);

impl_threshold_signer!(CertificationContent, sign_threshold_certification);
impl_threshold_signer!(CatchUpContent, sign_threshold_cup);
impl_threshold_signer!(RandomBeaconContent, sign_threshold_beacon);
impl_threshold_signer!(RandomTapeContent, sign_threshold_tape);

impl_threshold_sig_verifier!(
    CertificationContent,
    verify_threshold_sig_share_certification,
    combine_threshold_sig_shares_certification,
    verify_threshold_sig_combined_certification
);
impl_threshold_sig_verifier!(
    CatchUpContent,
    verify_threshold_sig_share_cup,
    combine_threshold_sig_shares_cup,
    verify_threshold_sig_combined_cup
);
impl_threshold_sig_verifier!(
    RandomBeaconContent,
    verify_threshold_sig_share_beacon,
    combine_threshold_sig_shares_beacon,
    verify_threshold_sig_combined_beacon
);
impl_threshold_sig_verifier!(
    RandomTapeContent,
    verify_threshold_sig_share_tape,
    combine_threshold_sig_shares_tape,
    verify_threshold_sig_combined_tape
);

impl_threshold_sig_verifier_by_public_key!(
    CertificationContent,
    verify_threshold_by_pk_certification
);
impl_threshold_sig_verifier_by_public_key!(CatchUpContent, verify_threshold_by_pk_cup);
impl_threshold_sig_verifier_by_public_key!(
    CatchUpContentProtobufBytes,
    verify_threshold_by_pk_cup_proto
);

impl_multi_signer!(FinalizationContent, sign_multi_finalization);
impl_multi_signer!(NotarizationContent, sign_multi_notarization);

impl_multi_sig_verifier!(
    FinalizationContent,
    verify_multi_sig_individual_finalization,
    combine_multi_sig_individuals_finalization,
    verify_multi_sig_combined_finalization
);
impl_multi_sig_verifier!(
    NotarizationContent,
    verify_multi_sig_individual_notarization,
    combine_multi_sig_individuals_notarization,
    verify_multi_sig_combined_notarization
);

impl_basic_sig_verifier_by_public_key!(MessageId, verify_basic_sig_by_pk_msg_id);
impl_basic_sig_verifier_by_public_key!(WebAuthnEnvelope, verify_basic_sig_by_pk_webauthn);

// ── NiDkgAlgorithm delegation ──────────────────────────────────────────────

impl NiDkgAlgorithm for MockCrypto {
    fn create_dealing(&self, config: &NiDkgConfig) -> Result<NiDkgDealing, DkgCreateDealingError> {
        self.ni_dkg_create_dealing(config)
    }
    fn verify_dealing(
        &self,
        config: &NiDkgConfig,
        dealer: NodeId,
        dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        self.ni_dkg_verify_dealing(config, dealer, dealing)
    }
    fn create_transcript(
        &self,
        config: &NiDkgConfig,
        verified_dealings: BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
        self.ni_dkg_create_transcript(config, verified_dealings)
    }
    fn load_transcript(
        &self,
        transcript: &NiDkgTranscript,
    ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
        self.ni_dkg_load_transcript(transcript)
    }
    fn retain_only_active_keys(
        &self,
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError> {
        self.ni_dkg_retain_only_active_keys(transcripts)
    }
}

// ── IDkgProtocol delegation ────────────────────────────────────────────────

impl IDkgProtocol for MockCrypto {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
        self.idkg_create_dealing(params)
    }
    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        self.idkg_verify_dealing_public(params, signed_dealing)
    }
    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        self.idkg_verify_dealing_private(params, signed_dealing)
    }
    fn verify_initial_dealings(
        &self,
        params: &IDkgTranscriptParams,
        initial_dealings: &InitialIDkgDealings,
    ) -> Result<(), IDkgVerifyInitialDealingsError> {
        self.idkg_verify_initial_dealings(params, initial_dealings)
    }
    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: BatchSignedIDkgDealings,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        self.idkg_create_transcript(params, dealings)
    }
    fn verify_transcript(
        &self,
        params: &IDkgTranscriptParams,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        self.idkg_verify_transcript(params, transcript)
    }
    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
        self.idkg_load_transcript(transcript)
    }
    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        self.idkg_verify_complaint(transcript, complainer_id, complaint)
    }
    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        self.idkg_open_transcript(transcript, complainer_id, complaint)
    }
    fn verify_opening(
        &self,
        transcript: &IDkgTranscript,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError> {
        self.idkg_verify_opening(transcript, opener, opening, complaint)
    }
    fn load_transcript_with_openings(
        &self,
        transcript: &IDkgTranscript,
        openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError> {
        self.idkg_load_transcript_with_openings(transcript, openings)
    }
    fn retain_active_transcripts(
        &self,
        active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainKeysError> {
        self.idkg_retain_active_transcripts(active_transcripts)
    }
}

// ── Traits with lifetime-parameterized types ───────────────────────────────
//
// mockall::mock! cannot express types like ThresholdEcdsaSigInputs<'a> or
// VetKdArgs<'a>: '_ is forbidden, named lifetimes can't be declared, and
// elision doesn't work inside the macro.  These traits also have method-name
// collisions (Ecdsa vs Schnorr).  Stubbed with unimplemented!(); extend
// with manual closure fields if tests need them.

impl ThresholdEcdsaSigner for MockCrypto {
    fn create_sig_share(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError> {
        unimplemented!("MockCrypto::ThresholdEcdsaSigner::create_sig_share")
    }
}

impl ThresholdEcdsaSigVerifier for MockCrypto {
    fn verify_sig_share(
        &self,
        _signer: NodeId,
        _inputs: &ThresholdEcdsaSigInputs,
        _share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
        unimplemented!("MockCrypto::ThresholdEcdsaSigVerifier::verify_sig_share")
    }
    fn combine_sig_shares(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
        _shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
        unimplemented!("MockCrypto::ThresholdEcdsaSigVerifier::combine_sig_shares")
    }
    fn verify_combined_sig(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
        _signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
        unimplemented!("MockCrypto::ThresholdEcdsaSigVerifier::verify_combined_sig")
    }
}

impl ThresholdSchnorrSigner for MockCrypto {
    fn create_sig_share(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
    ) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError> {
        unimplemented!("MockCrypto::ThresholdSchnorrSigner::create_sig_share")
    }
}

impl ThresholdSchnorrSigVerifier for MockCrypto {
    fn verify_sig_share(
        &self,
        _signer: NodeId,
        _inputs: &ThresholdSchnorrSigInputs,
        _share: &ThresholdSchnorrSigShare,
    ) -> Result<(), ThresholdSchnorrVerifySigShareError> {
        unimplemented!("MockCrypto::ThresholdSchnorrSigVerifier::verify_sig_share")
    }
    fn combine_sig_shares(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
        _shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    ) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError> {
        unimplemented!("MockCrypto::ThresholdSchnorrSigVerifier::combine_sig_shares")
    }
    fn verify_combined_sig(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
        _signature: &ThresholdSchnorrCombinedSignature,
    ) -> Result<(), ThresholdSchnorrVerifyCombinedSigError> {
        unimplemented!("MockCrypto::ThresholdSchnorrSigVerifier::verify_combined_sig")
    }
}

impl VetKdProtocol for MockCrypto {
    fn create_encrypted_key_share(
        &self,
        _args: VetKdArgs,
    ) -> Result<VetKdEncryptedKeyShare, VetKdKeyShareCreationError> {
        unimplemented!("MockCrypto::VetKdProtocol::create_encrypted_key_share")
    }
    fn verify_encrypted_key_share(
        &self,
        _signer: NodeId,
        _key_share: &VetKdEncryptedKeyShare,
        _args: &VetKdArgs,
    ) -> Result<(), VetKdKeyShareVerificationError> {
        unimplemented!("MockCrypto::VetKdProtocol::verify_encrypted_key_share")
    }
    fn combine_encrypted_key_shares(
        &self,
        _shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        _args: &VetKdArgs,
    ) -> Result<VetKdEncryptedKey, VetKdKeyShareCombinationError> {
        unimplemented!("MockCrypto::VetKdProtocol::combine_encrypted_key_shares")
    }
    fn verify_encrypted_key(
        &self,
        _key: &VetKdEncryptedKey,
        _args: &VetKdArgs,
    ) -> Result<(), VetKdKeyVerificationError> {
        unimplemented!("MockCrypto::VetKdProtocol::verify_encrypted_key")
    }
}
