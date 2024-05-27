#![allow(clippy::try_err)]
//! This module encapsulates functions required for validating consensus
//! artifacts.

use crate::{
    consensus::{
        check_protocol_version,
        metrics::ValidatorMetrics,
        status::{self, Status},
        ConsensusMessageId,
    },
    dkg, ecdsa,
};
use ic_consensus_utils::{
    active_high_threshold_transcript, active_low_threshold_transcript,
    crypto::ConsensusCrypto,
    find_lowest_ranked_proposals, get_oldest_ecdsa_state_registry_version, is_time_to_make_block,
    membership::{Membership, MembershipError},
    pool_reader::PoolReader,
    RoundRobin,
};
use ic_interfaces::{
    batch_payload::ProposalContext,
    consensus::{InvalidPayloadReason, PayloadBuilder, PayloadValidationFailure},
    consensus_pool::*,
    dkg::DkgPool,
    ingress_manager::IngressSelector,
    messaging::MessageRouting,
    time_source::TimeSource,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{StateHashError, StateManager, StateManagerError};
use ic_logger::{trace, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::ValidationContext,
    consensus::{
        Block, BlockMetadata, BlockPayload, BlockProposal, CatchUpContent, CatchUpPackage,
        CatchUpShareContent, Committee, ConsensusMessage, ConsensusMessageHashable,
        FinalizationContent, HasCommittee, HasHeight, HasRank, HasVersion, Notarization,
        NotarizationContent, RandomBeacon, RandomBeaconShare, RandomTape, RandomTapeShare, Rank,
    },
    crypto::{threshold_sig::ni_dkg::NiDkgId, CryptoError, CryptoHashOf, Signed},
    registry::RegistryClientError,
    replica_config::ReplicaConfig,
    signature::{MultiSignature, MultiSignatureShare, ThresholdSignatureShare},
    Height, NodeId, RegistryVersion,
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

/// The number of seconds spent in unvalidated pool, after which we start
/// logging why we cannot validate an artifact.
const SECONDS_TO_LOG_UNVALIDATED: u64 = 300;

/// How often we log an old unvalidated artifact.
const LOG_EVERY_N_SECONDS: i32 = 60;

/// The time, after which we will load a CUP even if we
/// where holding it back before, to give recomputation a chance during catch up.
const CATCH_UP_HOLD_OF_TIME: Duration = Duration::from_secs(150);

/// Possible transient validation failures.
#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
enum ValidationFailure {
    CryptoError(CryptoError),
    RegistryClientError(RegistryClientError),
    PayloadValidationFailed(PayloadValidationFailure),
    DkgPayloadValidationFailed(dkg::DkgPayloadValidationFailure),
    EcdsaPayloadValidationFailed(ecdsa::EcdsaPayloadValidationFailure),
    DkgSummaryNotFound(Height),
    RandomBeaconNotFound(Height),
    StateHashError(StateHashError),
    StateManagerError(StateManagerError),
    BlockNotFound(CryptoHashOf<Block>, Height),
    FinalizedBlockNotFound(Height),
    FailedToGetRegistryVersion,
    ValidationContextNotReached(ValidationContext, ValidationContext),
    CatchUpHeightNegligible,
}

/// Possible reasons for invalid artifacts.
#[derive(Debug)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
#[allow(dead_code)]
enum InvalidArtifactReason {
    CryptoError(CryptoError),
    MismatchedRank(Rank, Option<Rank>),
    MembershipError(MembershipError),
    InappropriateDkgId(NiDkgId),
    SignerNotInThresholdCommittee(NodeId),
    SignerNotInMultiSigCommittee(NodeId),
    InvalidPayload(InvalidPayloadReason),
    InvalidDkgPayload(dkg::InvalidDkgPayloadReason),
    InvalidEcdsaPayload(ecdsa::InvalidEcdsaPayloadReason),
    InsufficientSignatures,
    CannotVerifyBlockHeightZero,
    NonEmptyPayloadPastUpgradePoint,
    NonStrictlyIncreasingValidationContext,
    MismatchedBlockInCatchUpPackageShare,
    DataPayloadBlockInCatchUpPackageShare,
    MismatchedOldestRegistryVersionInCatchUpPackageShare,
    MismatchedStateHashInCatchUpPackageShare,
    MismatchedRandomBeaconInCatchUpPackageShare,
    RepeatedSigner,
    ReplicaVersionMismatch,
}

impl From<CryptoError> for ValidationFailure {
    fn from(err: CryptoError) -> ValidationFailure {
        ValidationFailure::CryptoError(err)
    }
}

impl From<CryptoError> for InvalidArtifactReason {
    fn from(err: CryptoError) -> InvalidArtifactReason {
        InvalidArtifactReason::CryptoError(err)
    }
}

impl<T> From<InvalidArtifactReason> for ValidationError<InvalidArtifactReason, T> {
    fn from(err: InvalidArtifactReason) -> ValidationError<InvalidArtifactReason, T> {
        ValidationError::InvalidArtifact(err)
    }
}

impl<P> From<ValidationFailure> for ValidationError<P, ValidationFailure> {
    fn from(err: ValidationFailure) -> ValidationError<P, ValidationFailure> {
        ValidationError::ValidationFailed(err)
    }
}

type ValidatorError = ValidationError<InvalidArtifactReason, ValidationFailure>;

fn membership_error_to_validation_error(err: MembershipError) -> ValidatorError {
    match err {
        MembershipError::NodeNotFound(_) => InvalidArtifactReason::MembershipError(err).into(),
        MembershipError::UnableToRetrieveDkgSummary(h) => {
            ValidationFailure::DkgSummaryNotFound(h).into()
        }
        MembershipError::RegistryClientError(err) => {
            ValidationFailure::RegistryClientError(err).into()
        }
    }
}

/// `SignatureVerify` provides a uniform interface to the verification of things
/// directly related to the signature on a Consensus artifact.
trait SignatureVerify: HasHeight {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError>;
}

impl SignatureVerify for BlockProposal {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let previous_beacon = get_previous_beacon(pool, height)?;
        let rank = membership
            .get_block_maker_rank(height, &previous_beacon, self.signature.signer)
            .map_err(membership_error_to_validation_error)?;
        if rank != Some(self.rank()) {
            return Err(ValidationError::from(
                InvalidArtifactReason::MismatchedRank(self.rank(), rank),
            ));
        }
        let registry_version = get_registry_version(pool, height)?;
        let signed_metadata = BlockMetadata::signed_from_proposal(self, cfg);
        crypto.verify(&signed_metadata, registry_version)?;
        Ok(())
    }
}

impl SignatureVerify for RandomTape {
    fn verify_signature(
        &self,
        _membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let transcript = active_low_threshold_transcript(pool.as_cache(), self.height())
            .ok_or_else(|| ValidationFailure::DkgSummaryNotFound(self.height()))?;
        if self.signature.signer == transcript.dkg_id {
            crypto.verify_aggregate(self, self.signature.signer)?;
            Ok(())
        } else {
            Err(InvalidArtifactReason::InappropriateDkgId(self.signature.signer).into())
        }
    }
}

impl SignatureVerify for RandomTapeShare {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_low_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| ValidationFailure::DkgSummaryNotFound(self.height()))?;
        verify_threshold_committee(
            membership,
            self.signature.signer,
            height,
            RandomTape::committee(),
        )?;
        crypto.verify(self, transcript.dkg_id)?;
        Ok(())
    }
}

impl SignatureVerify for RandomBeacon {
    fn verify_signature(
        &self,
        _membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let transcript = active_low_threshold_transcript(pool.as_cache(), self.height())
            .ok_or_else(|| ValidationFailure::DkgSummaryNotFound(self.height()))?;
        if self.signature.signer == transcript.dkg_id {
            crypto.verify_aggregate(self, self.signature.signer)?;
            Ok(())
        } else {
            Err(InvalidArtifactReason::InappropriateDkgId(self.signature.signer).into())
        }
    }
}

impl SignatureVerify for RandomBeaconShare {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_low_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| ValidationFailure::DkgSummaryNotFound(self.height()))?;
        verify_threshold_committee(
            membership,
            self.signature.signer,
            height,
            RandomBeacon::committee(),
        )?;

        crypto.verify(self, transcript.dkg_id)?;
        Ok(())
    }
}

impl SignatureVerify for Signed<CatchUpContent, ThresholdSignatureShare<CatchUpContent>> {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_high_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| ValidationFailure::DkgSummaryNotFound(self.height()))?;
        verify_threshold_committee(
            membership,
            self.signature.signer,
            height,
            CatchUpPackage::committee(),
        )?;
        crypto.verify(self, transcript.dkg_id)?;
        Ok(())
    }
}

impl SignatureVerify for CatchUpPackage {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        _pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        crypto
            .verify_combined_threshold_sig_by_public_key(
                &self.signature.signature,
                &self.content,
                membership.subnet_id,
                // Using any registry version here is fine because we assume that the
                // public key of the subnet will not change. The alternative of trying
                // to use the registry version obtained from the pool is not an option
                // here because we may not be able to get a proper value if we do not
                // have the relevant portion of the chain.
                membership.registry_client.get_latest_version(),
            )
            .map_err(ValidatorError::from)
    }
}

/// `NotaryIssued` is a trait that exists to deduplicate the validation code of
/// Notarization, Finalization and the corresponding shares.
trait NotaryIssued: Sized + HasHeight + std::fmt::Debug {
    fn block(&self) -> &CryptoHashOf<Block>;
    fn verify_multi_sig_combined(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignature<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError>;
    fn verify_multi_sig_individual(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignatureShare<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError>;
    fn is_duplicate(&self, pool: &PoolReader) -> bool;
    fn dependencies_validated(&self, pool: &PoolReader) -> Result<(), &str>;
}

impl NotaryIssued for NotarizationContent {
    fn block(&self) -> &CryptoHashOf<Block> {
        &self.block
    }

    fn verify_multi_sig_combined(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignature<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        crypto.verify_aggregate(signed_message, registry_version)
    }

    fn verify_multi_sig_individual(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignatureShare<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        crypto.verify(signed_message, registry_version)
    }

    fn is_duplicate(&self, pool: &PoolReader) -> bool {
        pool.pool()
            .validated()
            .notarization()
            .get_by_height(self.height)
            .any(|n| &n.content == self)
    }

    /// Checks that there is a validated block with the given hash and the
    /// previous beacon is available to compute the notarization committee.
    fn dependencies_validated(&self, pool: &PoolReader) -> Result<(), &str> {
        if self.height == Height::from(0) {
            return Err("Cannot validate height 0 notarization: ");
        }
        if pool.get_block(&self.block, self.height).is_err() {
            return Err("Cannot validate notarization without valid proposal: ");
        }
        if get_previous_beacon(pool, self.height).is_err() {
            return Err("Cannot validate notarization without previous beacon: ");
        }
        Ok(())
    }
}

impl NotaryIssued for FinalizationContent {
    fn block(&self) -> &CryptoHashOf<Block> {
        &self.block
    }

    fn verify_multi_sig_combined(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignature<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        crypto.verify_aggregate(signed_message, registry_version)
    }

    fn verify_multi_sig_individual(
        crypto: &dyn ConsensusCrypto,
        signed_message: &Signed<Self, MultiSignatureShare<Self>>,
        registry_version: RegistryVersion,
    ) -> ValidationResult<CryptoError> {
        crypto.verify(signed_message, registry_version)
    }

    fn is_duplicate(&self, pool: &PoolReader) -> bool {
        pool.pool()
            .validated()
            .finalization()
            .get_by_height(self.height)
            .any(|f| &f.content == self)
    }

    /// Checks that there is a *notarized* block with the given hash and the
    /// previous beacon is available to compute the notarization committee.
    fn dependencies_validated(&self, pool: &PoolReader) -> Result<(), &str> {
        if self.height == Height::from(0) {
            return Err("Cannot validate height 0 finalization: ");
        }
        if pool.get_notarized_block(&self.block, self.height).is_err() {
            return Err("Cannot validate finalization without valid notarization: ");
        }
        if get_previous_beacon(pool, self.height).is_err() {
            return Err("Cannot validate finalization without previous beacon: ");
        }
        Ok(())
    }
}

/// This `SignatureVerify` implementation is used for both `Notarization` and
/// `Finalization` artifacts. It checks:
/// * the signers are unique,
/// * the number of signers is not less than the required threshold,
/// * the signers are in the notary committee,
/// * the signature is valid.
impl<T: NotaryIssued> SignatureVerify for Signed<T, MultiSignature<T>> {
    fn verify_signature<'a>(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let previous_beacon = get_previous_beacon(pool, height)?;
        verify_notaries(
            membership,
            height,
            &previous_beacon,
            &self.signature.signers,
        )?;
        let registry_version = get_registry_version(pool, height)?;
        T::verify_multi_sig_combined(crypto, self, registry_version)?;
        Ok(())
    }
}

/// This `SignatureVerify` implementation is used for both `NotarizationShare`
/// and `FinalizationShare` artifacts. It checks:
/// * the signer is in the notary committee,
/// * the signature is valid.
impl<T: NotaryIssued> SignatureVerify for Signed<T, MultiSignatureShare<T>> {
    fn verify_signature<'a>(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
        _cfg: &ReplicaConfig,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let previous_beacon = get_previous_beacon(pool, height)?;
        verify_notary(membership, height, &previous_beacon, self.signature.signer)?;
        let registry_version = get_registry_version(pool, height)?;
        T::verify_multi_sig_individual(crypto, self, registry_version)?;
        Ok(())
    }
}

fn get_previous_beacon(
    pool: &PoolReader<'_>,
    height: Height,
) -> Result<RandomBeacon, ValidatorError> {
    let previous_height = height.decrement();
    match pool.get_random_beacon(previous_height) {
        Some(beacon) => Ok(beacon),
        None => Err(ValidationError::from(
            ValidationFailure::RandomBeaconNotFound(previous_height),
        )),
    }
}

fn get_registry_version(
    pool: &PoolReader<'_>,
    height: Height,
) -> Result<RegistryVersion, ValidatorError> {
    match pool.registry_version(height) {
        Some(version) => Ok(version),
        None => Err(ValidationError::from(
            ValidationFailure::FailedToGetRegistryVersion,
        )),
    }
}

fn verify_notaries(
    membership: &Membership,
    height: Height,
    previous_beacon: &RandomBeacon,
    signers: &[NodeId],
) -> ValidationResult<ValidatorError> {
    let threshold = membership
        .get_committee_threshold(height, Notarization::committee())
        .map_err(membership_error_to_validation_error)?;
    let unique_signers: HashSet<_> = signers.iter().collect();
    if unique_signers.len() < signers.len() {
        return Err(InvalidArtifactReason::RepeatedSigner.into());
    }
    if signers.len() < threshold {
        return Err(InvalidArtifactReason::InsufficientSignatures.into());
    }
    for node_id in signers.iter() {
        verify_notary(membership, height, previous_beacon, *node_id)?;
    }
    Ok(())
}

fn verify_notary(
    membership: &Membership,
    height: Height,
    previous_beacon: &RandomBeacon,
    node_id: NodeId,
) -> ValidationResult<ValidatorError> {
    if !membership
        .node_belongs_to_notarization_committee(height, previous_beacon, node_id)
        .map_err(membership_error_to_validation_error)?
    {
        Err(InvalidArtifactReason::SignerNotInMultiSigCommittee(node_id).into())
    } else {
        Ok(())
    }
}

fn verify_threshold_committee(
    membership: &Membership,
    node_id: NodeId,
    height: Height,
    committee: Committee,
) -> ValidationResult<ValidatorError> {
    if !membership
        .node_belongs_to_threshold_committee(node_id, height, committee)
        .map_err(membership_error_to_validation_error)?
    {
        Err(InvalidArtifactReason::SignerNotInThresholdCommittee(node_id).into())
    } else {
        Ok(())
    }
}

fn get_notarized_parent(
    pool: &PoolReader<'_>,
    proposal: &BlockProposal,
) -> Result<Block, ValidatorError> {
    let parent = &proposal.as_ref().parent;
    let height = proposal.height().decrement();
    pool.get_notarized_block(parent, height)
        .map(|block| block.into_inner())
        .map_err(|_| ValidationFailure::BlockNotFound(parent.clone(), height).into())
}

/// Collect the min of validated block proposal ranks in the range.
fn get_min_validated_ranks(
    pool: &PoolReader<'_>,
    range: &HeightRange,
) -> BTreeMap<Height, Option<Rank>> {
    (range.min.get()..=range.max.get())
        .map(|h| {
            let height = Height::from(h);
            (
                height,
                find_lowest_ranked_proposals(pool, height)
                    .first()
                    .map(|block| block.rank()),
            )
        })
        .collect()
}

/// Validator holds references to components required for artifact validation.
/// It implements validation functions for all consensus artifacts which are
/// called by `on_state_change` in round-robin manner.
pub struct Validator {
    replica_config: ReplicaConfig,
    membership: Arc<Membership>,
    crypto: Arc<dyn ConsensusCrypto>,
    registry_client: Arc<dyn RegistryClient>,
    payload_builder: Arc<dyn PayloadBuilder>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    message_routing: Arc<dyn MessageRouting>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
    log: ReplicaLogger,
    metrics: ValidatorMetrics,
    schedule: RoundRobin,
    time_source: Arc<dyn TimeSource>,
    ingress_selector: Option<Arc<dyn IngressSelector>>,
}

impl Validator {
    #[allow(clippy::too_many_arguments)]
    /// The constructor creates a new [`Validator`] instance.
    pub fn new(
        replica_config: ReplicaConfig,
        membership: Arc<Membership>,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn ConsensusCrypto>,
        payload_builder: Arc<dyn PayloadBuilder>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        message_routing: Arc<dyn MessageRouting>,
        dkg_pool: Arc<RwLock<dyn DkgPool>>,
        log: ReplicaLogger,
        metrics: ValidatorMetrics,
        time_source: Arc<dyn TimeSource>,
        ingress_selector: Option<Arc<dyn IngressSelector>>,
    ) -> Validator {
        Validator {
            replica_config,
            membership,
            registry_client,
            crypto,
            payload_builder,
            state_manager,
            message_routing,
            dkg_pool,
            log,
            metrics,
            schedule: RoundRobin::default(),
            time_source,
            ingress_selector,
        }
    }

    /// Invoke each artifact validation function in order.
    /// Return the first non-empty [ChangeSet] as returned by a function.
    /// Otherwise return an empty [ChangeSet] if all functions return
    /// empty.
    pub fn on_state_change(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        trace!(self.log, "on_state_change");
        let validate_finalization = || self.validate_finalizations(pool_reader);
        let validate_notarization = || self.validate_notarizations(pool_reader);
        let validate_blocks = || self.validate_blocks(pool_reader);
        let validate_beacons = || self.validate_beacons(pool_reader);
        let validate_tapes = || self.validate_tapes(pool_reader);
        let validate_catch_up_packages = || self.validate_catch_up_packages(pool_reader);
        let validate_finalization_shares = || self.validate_finalization_shares(pool_reader);
        let validate_notarization_shares = || self.validate_notarization_shares(pool_reader);
        let validate_beacon_shares = || self.validate_beacon_shares(pool_reader);
        let validate_tape_shares = || self.validate_tape_shares(pool_reader);
        let validate_catch_up_package_shares =
            || self.validate_catch_up_package_shares(pool_reader);
        let calls: [&'_ dyn Fn() -> ChangeSet; 11] = [
            &|| self.call_with_metrics("Finalization", validate_finalization),
            &|| self.call_with_metrics("Notarization", validate_notarization),
            &|| self.call_with_metrics("BlockProposal", validate_blocks),
            &|| self.call_with_metrics("RandomBeacon", validate_beacons),
            &|| self.call_with_metrics("RandomTape", validate_tapes),
            &|| self.call_with_metrics("CUP", validate_catch_up_packages),
            &|| self.call_with_metrics("FinalizationShare", validate_finalization_shares),
            &|| self.call_with_metrics("NotarizationShare", validate_notarization_shares),
            &|| self.call_with_metrics("RandomBeaconShare", validate_beacon_shares),
            &|| self.call_with_metrics("RandomTapeShare", validate_tape_shares),
            &|| self.call_with_metrics("CUPShare", validate_catch_up_package_shares),
        ];
        self.schedule.call_next(&calls)
    }

    fn call_with_metrics<F>(&self, sub_component: &str, validator_fn: F) -> ChangeSet
    where
        F: FnOnce() -> ChangeSet,
    {
        let _timer = self
            .metrics
            .validation_duration
            .with_label_values(&[sub_component])
            .start_timer();
        (validator_fn)()
    }

    /// Verify the version and signature of some artifact that is verifiable with the
    /// `SignatureVerify` and `HasVersion` traits.
    fn verify_artifact<S: SignatureVerify + HasVersion>(
        &self,
        pool_reader: &PoolReader<'_>,
        artifact: &S,
    ) -> ValidationResult<ValidatorError> {
        check_protocol_version(artifact.version())
            .map_err(|_| InvalidArtifactReason::ReplicaVersionMismatch)?;
        artifact.verify_signature(
            self.membership.as_ref(),
            self.crypto.as_ref(),
            pool_reader,
            &self.replica_config,
        )
    }

    /// Return a `ChangeSet` of `Finalization`s. See `validate_notary_issued`
    /// for details about exactly what is checked.
    fn validate_finalizations(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader.pool().unvalidated().finalization().max_height() {
            Some(height) => height,
            None => return ChangeSet::new(),
        };

        let range = HeightRange::new(pool_reader.get_finalized_height().increment(), max_height);
        let finalizations = pool_reader
            .pool()
            .unvalidated()
            .finalization()
            .get_by_height_range(range);

        let change_set: ChangeSet = finalizations
            .filter_map(|finalization| self.validate_notary_issued(pool_reader, finalization))
            .collect();
        self.dedup_change_actions("finalization", change_set)
    }

    /// Return a `ChangeSet` of `FinalizationShare`s. See
    /// `validate_notary_issued` for details about exactly what is checked.
    fn validate_finalization_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader
            .pool()
            .unvalidated()
            .finalization_share()
            .max_height()
        {
            Some(height) => height,
            None => return ChangeSet::new(),
        };

        let range = HeightRange::new(pool_reader.get_finalized_height().increment(), max_height);
        let finalization_shares = pool_reader
            .pool()
            .unvalidated()
            .finalization_share()
            .get_by_height_range(range);

        finalization_shares
            .filter_map(|share| self.validate_notary_issued(pool_reader, share))
            .collect()
    }

    /// Return a `ChangeSet` of `Notarization`s. See
    /// `validate_notary_issued` for details about exactly what is checked.
    fn validate_notarizations(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader.pool().unvalidated().notarization().max_height() {
            Some(height) => height,
            None => return ChangeSet::new(),
        };

        let range = HeightRange::new(pool_reader.get_finalized_height().increment(), max_height);
        let notarizations = pool_reader
            .pool()
            .unvalidated()
            .notarization()
            .get_by_height_range(range);

        let change_set: ChangeSet = notarizations
            .filter_map(|notarization| self.validate_notary_issued(pool_reader, notarization))
            .collect();
        self.dedup_change_actions("notarization", change_set)
    }

    /// Return a `ChangeSet` of `NotarizationShare`s. See
    /// `validate_notary_issued` for details about exactly what is checked.
    fn validate_notarization_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader
            .pool()
            .unvalidated()
            .notarization_share()
            .max_height()
        {
            Some(height) => height,
            None => return ChangeSet::new(),
        };

        let range = HeightRange::new(pool_reader.get_finalized_height().increment(), max_height);
        let notarization_shares = pool_reader
            .pool()
            .unvalidated()
            .notarization_share()
            .get_by_height_range(range);

        notarization_shares
            .filter_map(|share| self.validate_notary_issued(pool_reader, share))
            .collect()
    }

    /// Validate a single `Signed`, `NotaryIssued` value. This involves checking
    /// that the associated block and beacon both exist and that the signer(s)
    /// is(are) in the notary group. The details of signature verification
    /// including any calls to crypto happen within the `SignatureVerify`
    /// interface. Note that whether the ancestor block of the given block is
    /// notarized is checked while validating the corresponding BlockProposal in
    /// check_block_validity.
    fn validate_notary_issued<T, S>(
        &self,
        pool_reader: &PoolReader<'_>,
        notary_issued: Signed<T, S>,
    ) -> Option<ChangeAction>
    where
        Signed<T, S>: SignatureVerify + ConsensusMessageHashable + Clone,
        T: NotaryIssued + HasVersion,
    {
        if check_protocol_version(notary_issued.content.version()).is_err() {
            return Some(ChangeAction::RemoveFromUnvalidated(
                notary_issued.into_message(),
            ));
        }
        // This is checked before entering this function.
        debug_assert!(notary_issued.height() > pool_reader.get_finalized_height());
        if notary_issued.content.is_duplicate(pool_reader) {
            return Some(ChangeAction::RemoveFromUnvalidated(
                notary_issued.into_message(),
            ));
        }
        match notary_issued.content.dependencies_validated(pool_reader) {
            Ok(()) => {
                let verification = self.verify_artifact(pool_reader, &notary_issued);
                self.compute_action_from_artifact_verification(
                    pool_reader,
                    verification,
                    notary_issued.into_message(),
                )
            }
            Err(err) => {
                if self.unvalidated_for_too_long(pool_reader, &notary_issued.get_id()) {
                    warn!(every_n_seconds => LOG_EVERY_N_SECONDS,
                          self.log,
                          "{} {:?}", err, notary_issued.content
                    );
                }
                None
            }
        }
    }

    /// Return a `ChangeSet` containing status updates concerning any currently
    /// unvalidated blocks that can now be marked valid or invalid. See
    /// `check_block_validity`.
    fn validate_blocks(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let mut change_set = Vec::new();

        let notarization_height = pool_reader.get_notarized_height();
        let finalized_height = pool_reader.get_finalized_height();
        let max_height = notarization_height.increment();
        let range = HeightRange::new(finalized_height.increment(), max_height);
        // Collect the min of validated block proposal ranks in the range.
        let mut known_ranks: BTreeMap<Height, Option<Rank>> =
            get_min_validated_ranks(pool_reader, &range);

        // It is necessary to traverse all the proposals and not only the ones with min
        // rank per height; because proposals for which there is an unvalidated
        // notarization are considered even if there is a lower rank proposal.
        for proposal in pool_reader
            .pool()
            .unvalidated()
            .block_proposal()
            .get_by_height_range(range)
        {
            if proposal.check_integrity() {
                // Attempt to validate the proposal through a notarization
                if let Some(notarization) = pool_reader
                    .pool()
                    .unvalidated()
                    .notarization()
                    .get_by_height(proposal.height())
                    .find(|notarization| &notarization.content.block == proposal.content.get_hash())
                {
                    // Verify notarization signature before checking block validity.
                    let verification = self.verify_artifact(pool_reader, &notarization);
                    if let Err(ValidationError::InvalidArtifact(e)) = verification {
                        change_set.push(ChangeAction::HandleInvalid(
                            notarization.into_message(),
                            format!("{:?}", e),
                        ));
                    } else if verification.is_ok() {
                        if get_notarized_parent(pool_reader, &proposal).is_ok() {
                            self.metrics
                                .observe_data_payload(&proposal, self.ingress_selector.as_deref());
                            self.metrics.observe_block(pool_reader, &proposal);
                            known_ranks.insert(proposal.height(), Some(proposal.rank()));
                            change_set.push(ChangeAction::MoveToValidated(proposal.into_message()));
                            change_set
                                .push(ChangeAction::MoveToValidated(notarization.into_message()));
                        }
                        // If the parent is notarized, this block and its notarization are
                        // validated. If not, this block currently cannot be
                        // validated through parent either.
                        continue;
                    }
                    // Note that transient errors on notarization signature
                    // verification should cause fall through, and the block
                    // proposals proceed to be checked normally.
                }

                // Skip validation and drop the block if it has a higher rank than a known valid
                // block. Note that this must happen after we first allow "block with
                // notarization" validation (see above). Otherwise we may get stuck when a block
                // maker equivocates.
                if let Some(Some(min_rank)) = known_ranks.get(&proposal.height()) {
                    if proposal.rank() > *min_rank {
                        // Skip them instead of removal because we don't want to end up
                        // requesting these artifacts again.
                        let id = proposal.get_id();
                        if self.unvalidated_for_too_long(pool_reader, &id) {
                            warn!(every_n_seconds => LOG_EVERY_N_SECONDS,
                                  self.log,
                                  "Due a valid proposal with a lower rank {}, /
                                  skipping validating the proposal: {:?} with rank {}",
                                  min_rank.0, id, proposal.rank().0
                            );
                        }
                        continue;
                    }
                }

                // We only validate blocks from a block maker of a certain rank after a
                // rank-based delay. If this time has not elapsed yet, we ignore the block for
                // now.
                if !is_time_to_make_block(
                    &self.log,
                    self.registry_client.as_ref(),
                    self.replica_config.subnet_id,
                    pool_reader,
                    proposal.height(),
                    proposal.rank(),
                    self.time_source.as_ref(),
                ) {
                    continue;
                }

                match self.check_block_validity(pool_reader, &proposal) {
                    Ok(()) => {
                        self.metrics
                            .observe_data_payload(&proposal, self.ingress_selector.as_deref());
                        self.metrics.observe_block(pool_reader, &proposal);
                        known_ranks.insert(proposal.height(), Some(proposal.rank()));
                        change_set.push(ChangeAction::MoveToValidated(proposal.into_message()))
                    }
                    Err(ValidationError::InvalidArtifact(
                        InvalidArtifactReason::ReplicaVersionMismatch,
                    )) => change_set
                        .push(ChangeAction::RemoveFromUnvalidated(proposal.into_message())),
                    Err(ValidationError::InvalidArtifact(err)) => change_set.push(
                        ChangeAction::HandleInvalid(proposal.into_message(), format!("{:?}", err)),
                    ),
                    Err(ValidationError::ValidationFailed(err)) => {
                        if self.unvalidated_for_too_long(pool_reader, &proposal.get_id()) {
                            warn!(every_n_seconds => LOG_EVERY_N_SECONDS,
                                  self.log,
                                  "Couldn't check the block validity: {:?}", err
                            );
                        }
                    }
                }
            } else {
                warn!(
                    self.log,
                    "Invalid block (compromised payload integrity): {:?}", proposal
                );
                change_set.push(ChangeAction::HandleInvalid(
                    proposal.clone().into_message(),
                    format!(
                        "Proposal integrity check failed: {:?} {:?} {:?}",
                        proposal.content.get_hash(),
                        proposal.as_ref().payload.get_hash(),
                        proposal.as_ref().payload.as_ref()
                    ),
                ))
            }
        }
        self.metrics.observe_and_reset_dkg_time_per_validator_run();
        change_set
    }

    /// Check whether or not the provided `BlockProposal` can be moved into the
    /// validated pool. A `ValidatiorError::ValidationFailure` value is returned
    /// when any of the following conditions are met:
    ///
    /// - the `Block`'s validation context is not available locally.
    /// - The `Block`'s parent is not in the validated pool
    /// - The `Block`'s parent is not notarized
    /// - The payload_builder returns an `Err` result of any kind
    ///
    /// A `ValidatorError::InvalidArtifact` is returned when any of the following
    /// conditions are met:
    ///
    /// - The signer of the `BlockProposal` does not have the rank claimed on
    ///   the `Block`
    /// - The signature on the `BlockProposal` is invalid.
    /// - Any messages included in the payload are present in some ancestor of
    ///   the block
    /// - Any of the values in the `ValidationContext` on the `Block` are less
    ///   than the corresponding value on the parent `Block`'s
    ///   `ValidationContext`. Additionally for timestamps, we require a strict
    ///   monotonic increase between blocks.
    fn check_block_validity(
        &self,
        pool_reader: &PoolReader<'_>,
        proposal: &BlockProposal,
    ) -> ValidationResult<ValidatorError> {
        if proposal.height() == Height::from(0) {
            return Err(InvalidArtifactReason::CannotVerifyBlockHeightZero.into());
        }

        let Some(status) = status::get_status(
            proposal.height(),
            self.registry_client.as_ref(),
            self.replica_config.subnet_id,
            pool_reader,
            &self.log,
        ) else {
            return Err(ValidationFailure::FailedToGetRegistryVersion.into());
        };

        // If the replica is halted, block payload should be empty.
        if status == Status::Halting || status == Status::Halted {
            let payload = proposal.as_ref().payload.as_ref();
            if !payload.is_summary() && !payload.is_empty() {
                return Err(InvalidArtifactReason::NonEmptyPayloadPastUpgradePoint.into());
            }
        }

        let proposer = proposal.signature.signer;
        let parent = get_notarized_parent(pool_reader, proposal)?;
        self.verify_artifact(pool_reader, proposal)?;

        // Ensure registry_version, certified_height increase monotonically and that
        // time increases *strictly* monotonically.
        let proposal = proposal.as_ref();
        if !proposal.context.greater(&parent.context) {
            return Err(InvalidArtifactReason::NonStrictlyIncreasingValidationContext.into());
        }

        let local_context = ValidationContext {
            certified_height: self.state_manager.latest_certified_height(),
            registry_version: self.registry_client.get_latest_version(),
            time: self.time_source.get_relative_time(),
        };

        // If we don't find an instant for the parent block, we fall back to the origin
        // instant which we recorded at validator initialization.
        // The only scenario in which we may have a notarized parent but no instant for
        // the block are replica restarts due to updates or crashes, or while the replica
        // is catching up via CUP. This is not a big problem in practice, because we will
        // always wait at most `proposal.time - parent.time` before validating the
        // proposal. Any heights after that point will have instants, so there will be no
        // further slowdown for other rounds.
        let parent_block_instant = pool_reader
            .get_block_instant(&proposal.parent)
            .unwrap_or(self.time_source.get_origin_instant());
        let duration_since_received_parent = self
            .time_source
            .get_instant()
            .saturating_duration_since(parent_block_instant);

        // Check that our locally available validation context is sufficient for
        // validating the proposal. We require all fields of our local context - with
        // the exception of time - to be greater or equal to the proposal's context.
        //
        // We allow out-of-sync validation, assuming the block proposal's timestamp is
        // not further than the time since we received the parent block.
        // We do this to shield against clock issues, to prevent nodes with lagging
        // clocks to stall a subnet with f malicious replicas.
        let sufficient_local_ctx = local_context.registry_version
            >= proposal.context.registry_version
            && local_context.certified_height >= proposal.context.certified_height
            && std::cmp::max(
                local_context.time,
                parent.context.time + duration_since_received_parent,
            ) >= proposal.context.time;

        if !sufficient_local_ctx {
            return Err(ValidationFailure::ValidationContextNotReached(
                proposal.context.clone(),
                local_context,
            )
            .into());
        }

        // If the replica is halted, the block payload is empty so we can skip the rest of the
        // validation.
        if status == Status::Halting || status == Status::Halted {
            return Ok(());
        }

        // Below are all the payload validations
        let payloads = pool_reader.get_payloads_from_height(
            proposal.context.certified_height.increment(),
            parent.clone(),
        );

        self.payload_builder
            .validate_payload(
                proposal.height,
                &ProposalContext {
                    proposer,
                    validation_context: &proposal.context,
                },
                &proposal.payload,
                &payloads,
            )
            .map_err(|err| {
                err.map(
                    InvalidArtifactReason::InvalidPayload,
                    ValidationFailure::PayloadValidationFailed,
                )
            })?;

        ecdsa::validate_payload(
            self.replica_config.subnet_id,
            self.registry_client.as_ref(),
            self.crypto.as_ref(),
            pool_reader,
            self.state_manager.as_ref(),
            &proposal.context,
            &parent,
            proposal.payload.as_ref(),
            self.metrics.ecdsa_validation_duration.clone(),
        )
        .map_err(|err| {
            err.map(
                InvalidArtifactReason::InvalidEcdsaPayload,
                ValidationFailure::EcdsaPayloadValidationFailed,
            )
        })?;

        let timer = self
            .metrics
            .validation_duration
            .with_label_values(&["Dkg"])
            .start_timer();
        let dkg_pool = &*self.dkg_pool.read().unwrap();
        let ret = dkg::payload_validator::validate_payload(
            self.replica_config.subnet_id,
            self.registry_client.as_ref(),
            self.crypto.as_ref(),
            pool_reader,
            dkg_pool,
            parent,
            proposal.payload.as_ref(),
            self.state_manager.as_ref(),
            &proposal.context,
            &self.metrics.dkg_validator,
        )
        .map_err(|err| {
            err.map(
                InvalidArtifactReason::InvalidDkgPayload,
                ValidationFailure::DkgPayloadValidationFailed,
            )
        });
        let elapsed = timer.stop_and_record();
        self.metrics.add_to_dkg_time_per_validator_run(elapsed);
        ret
    }

    /// Return a `ChangeSet` of `RandomBeacon` artifacts. Check the validity of RandomBeacons of
    /// the next height against the random beacon tip. This consists of checking whether each beacon:
    /// * points to the random beacon tip as its parent,
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    fn validate_beacons(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let last_beacon = pool_reader.get_random_beacon_tip();
        let last_hash: CryptoHashOf<RandomBeacon> = ic_types::crypto::crypto_hash(&last_beacon);
        // Only a single height is validated, per round.
        pool_reader
            .pool()
            .unvalidated()
            .random_beacon()
            .get_by_height(last_beacon.content.height().increment())
            .filter_map(|beacon| {
                if last_hash != beacon.content.parent {
                    Some(ChangeAction::HandleInvalid(
                        beacon.into_message(),
                        "The parent hash of the beacon is not correct".to_string(),
                    ))
                } else {
                    let verification = self.verify_artifact(pool_reader, &beacon);
                    self.compute_action_from_artifact_verification(
                        pool_reader,
                        verification,
                        beacon.into_message(),
                    )
                }
            })
            .collect()
    }

    /// Return a `ChangeSet` of `RandomBeaconShare` artifacts. Check the validity of RandomBeaconShares of
    /// the next height against the random beacon tip. This consists of checking whether each share:
    /// * points to the random beacon tip as its parent,
    /// * not more than threshold shares have already been validated for each height
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    fn validate_beacon_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let last_beacon = pool_reader.get_random_beacon_tip();
        let last_hash: CryptoHashOf<RandomBeacon> = ic_types::crypto::crypto_hash(&last_beacon);
        let next_height = last_beacon.content.height().increment();

        // Since the parent beacon is required to be already validated, only a single
        // height is checked.
        let change_set: ChangeSet = pool_reader
            .pool()
            .unvalidated()
            .random_beacon_share()
            .get_by_height(next_height)
            .filter_map(|beacon| {
                if last_hash != beacon.content.parent {
                    Some(ChangeAction::HandleInvalid(
                        beacon.into_message(),
                        "The parent hash of the beacon was not correct".to_string(),
                    ))
                } else {
                    self.metrics.validation_random_beacon_shares_count.add(1);
                    let verification = self.verify_artifact(pool_reader, &beacon);
                    self.compute_action_from_artifact_verification(
                        pool_reader,
                        verification,
                        beacon.into_message(),
                    )
                }
            })
            .collect();

        self.metrics
            .validation_share_batch_size
            .with_label_values(&["beacon"])
            .observe(change_set.len() as f64);
        change_set
    }

    /// Return a `ChangeSet` of `RandomTape` artifacts. Check the validity of RandomTape
    /// artifacts. This function checks whether each RandomTapeContent
    /// * has non-zero height,
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    fn validate_tapes(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader.pool().unvalidated().random_tape().max_height() {
            Some(height) => height,
            None => return ChangeSet::new(),
        };
        // Since we only need tape values when a height is also finalized, we don't
        // need to look beyond finalized height.
        let finalized_height = pool_reader.get_finalized_height();
        let expected_height = self.message_routing.expected_batch_height();
        let range = HeightRange::new(
            expected_height,
            max_height.min(finalized_height.increment()),
        );
        pool_reader
            .pool()
            .unvalidated()
            .random_tape()
            .get_by_height_range(range)
            .filter_map(|tape| {
                let height = tape.height();
                if height == Height::from(0) {
                    // tape of height 0 is considered invalid
                    Some(ChangeAction::HandleInvalid(
                        tape.into_message(),
                        "Tape at height 0".to_string(),
                    ))
                } else if pool_reader.get_random_tape(height).is_some() {
                    // Remove if we already have a validated tape at this height
                    Some(ChangeAction::RemoveFromUnvalidated(tape.into_message()))
                } else {
                    let verification = self.verify_artifact(pool_reader, &tape);
                    self.compute_action_from_artifact_verification(
                        pool_reader,
                        verification,
                        tape.into_message(),
                    )
                }
            })
            .collect()
    }

    /// Return a `ChangeSet` of `RandomTapeShare` artifacts. Check the validity of RandomTapeShare
    /// artifacts. This function checks whether each RandomTapeContent
    /// * has non-zero height,
    /// * not more than threshold shares have already been validated for each height
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    fn validate_tape_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let max_height = match pool_reader
            .pool()
            .unvalidated()
            .random_tape_share()
            .max_height()
        {
            Some(height) => height,
            None => return ChangeSet::new(),
        };
        // Since we only need tape values when a height is also finalized, we don't
        // need to look beyond finalized height.
        let finalized_height = pool_reader.get_finalized_height();
        let expected_height = self.message_routing.expected_batch_height();
        let range = HeightRange::new(
            expected_height,
            max_height.min(finalized_height.increment()),
        );

        let change_set: ChangeSet = pool_reader
            .pool()
            .unvalidated()
            .random_tape_share()
            .get_by_height_range(range)
            .filter_map(|tape| {
                let height = tape.height();
                if height == Height::from(0) {
                    // tape of height 0 is considered invalid
                    Some(ChangeAction::HandleInvalid(
                        tape.into_message(),
                        "Tape at height 0".to_string(),
                    ))
                } else if pool_reader.get_random_tape(height).is_some() {
                    // Remove if we already have a validated tape at this height
                    Some(ChangeAction::RemoveFromUnvalidated(tape.into_message()))
                } else {
                    self.metrics.validation_random_tape_shares_count.add(1);
                    let verification = self.verify_artifact(pool_reader, &tape);
                    self.compute_action_from_artifact_verification(
                        pool_reader,
                        verification,
                        tape.into_message(),
                    )
                }
            })
            .collect();

        self.metrics
            .validation_share_batch_size
            .with_label_values(&["tape"])
            .observe(change_set.len() as f64);
        change_set
    }

    /// Return a `ChangeSet` of `CatchUpPackage` artifacts.
    /// The validity of a CatchUpPackage only depends on its signature
    /// and signer, which must match a known threshold key.
    fn validate_catch_up_packages(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let catch_up_height = pool_reader.get_catch_up_height();
        let max_height = match pool_reader
            .pool()
            .unvalidated()
            .catch_up_package()
            .max_height()
        {
            Some(height) => height,
            None => return ChangeSet::new(),
        };
        let range = HeightRange::new(catch_up_height.increment(), max_height);

        let catch_up_packages = pool_reader
            .pool()
            .unvalidated()
            .catch_up_package()
            .get_by_height_range(range);

        catch_up_packages
            .filter_map(|catch_up_package| {
                // Such heights should not make it into this loop.
                debug_assert!(catch_up_package.height() > catch_up_height);
                if !catch_up_package.check_integrity() {
                    return Some(ChangeAction::HandleInvalid(
                        catch_up_package.into_message(),
                        "CatchUpPackage integrity check failed".to_string(),
                    ));
                }
                let verification = self
                    .verify_artifact(pool_reader, &catch_up_package)
                    .and_then(|_| self.maybe_hold_back_cup(&catch_up_package, pool_reader));

                self.compute_action_from_artifact_verification(
                    pool_reader,
                    verification,
                    catch_up_package.into_message(),
                )
            })
            .collect()
    }

    /// Return a `ChangeSet` of `CatchUpPackageShare` artifacts.  This consists
    /// of checking whether each share is signed by member(s) of the threshold
    /// group, and has a valid signature.
    fn validate_catch_up_package_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let catch_up_height = pool_reader.get_catch_up_height();
        let max_height = match pool_reader
            .pool()
            .unvalidated()
            .catch_up_package_share()
            .max_height()
        {
            Some(height) => height,
            None => return ChangeSet::new(),
        };
        let range = HeightRange::new(catch_up_height.increment(), max_height);

        let shares = pool_reader
            .pool()
            .unvalidated()
            .catch_up_package_share()
            .get_by_height_range(range);

        shares
            .filter_map(|share| {
                debug_assert!(share.height() > catch_up_height);
                if !share.check_integrity() {
                    return Some(ChangeAction::HandleInvalid(
                        share.into_message(),
                        "CatchUpPackageShare integrity check failed".to_string(),
                    ));
                }
                match self.validate_catch_up_share_content(pool_reader, &share.content) {
                    Ok(block) => {
                        let verification = self.verify_artifact(
                            pool_reader,
                            &Signed {
                                content: CatchUpContent::from_share_content(
                                    share.content.clone(),
                                    block,
                                ),
                                signature: share.signature.clone(),
                            },
                        );
                        self.compute_action_from_artifact_verification(
                            pool_reader,
                            verification,
                            share.into_message(),
                        )
                    }
                    Err(ValidationError::InvalidArtifact(err)) => Some(
                        ChangeAction::HandleInvalid(share.into_message(), format!("{:?}", err)),
                    ),
                    Err(ValidationError::ValidationFailed(err)) => {
                        if self.unvalidated_for_too_long(pool_reader, &share.get_id()) {
                            warn!(
                                every_n_seconds => LOG_EVERY_N_SECONDS,
                                self.log,
                                "Couldn't validate the catch-up package share: {:?}", err
                            );
                        }
                        None
                    }
                }
            })
            .collect()
    }

    /// Return the finalized block at height if the given `CatchUpContent` is
    /// consistent, InvalidArtifact if it is inconsistent, and ValidationFailure
    /// if there is insufficient data to verify consistency (see CON-330).
    ///
    /// A CatchUpContent is inconsistent if things in it do not match up, e.g.
    /// block height != random beacon height. Or it does not match
    /// known valid artifacts already in the validated pool. Note that this
    /// validation is only performed for the content of catch-up package
    /// shares. The content of full CUPs has to be trusted if it is signed
    /// by the subnet.
    fn validate_catch_up_share_content(
        &self,
        pool_reader: &PoolReader<'_>,
        share_content: &CatchUpShareContent,
    ) -> Result<Block, ValidatorError> {
        let height = share_content.height();
        let block = pool_reader
            .get_finalized_block(height)
            .ok_or(ValidationFailure::FinalizedBlockNotFound(height))?;
        if ic_types::crypto::crypto_hash(&block) != share_content.block {
            warn!(self.log, "Block from received CatchUpShareContent does not match finalized block in the pool: {:?} {:?}", share_content, block);
            return Err(InvalidArtifactReason::MismatchedBlockInCatchUpPackageShare.into());
        }
        if !block.payload.is_summary() {
            warn!(
                self.log,
                "Block from received CatchUpShareContent is not a summary block: {:?} {:?}",
                share_content,
                block
            );
            return Err(InvalidArtifactReason::DataPayloadBlockInCatchUpPackageShare.into());
        }

        let beacon = pool_reader
            .get_random_beacon(height)
            .ok_or(ValidationFailure::RandomBeaconNotFound(height))?;
        if &beacon != share_content.random_beacon.get_value() {
            warn!(self.log, "RandomBeacon from received CatchUpContent does not match RandomBeacon in the pool: {:?} {:?}", share_content, beacon);
            return Err(InvalidArtifactReason::MismatchedRandomBeaconInCatchUpPackageShare.into());
        }

        let hash = self
            .state_manager
            .get_state_hash_at(height)
            .map_err(ValidationFailure::StateHashError)?;
        if hash != share_content.state_hash {
            warn!(self.log, "State hash from received CatchUpContent does not match local state hash: {:?} {:?}", share_content, hash);
            return Err(InvalidArtifactReason::MismatchedStateHashInCatchUpPackageShare.into());
        }

        let summary = block.payload.as_ref().as_summary();
        let registry_version = if let Some(ecdsa) = summary.ecdsa.as_ref() {
            // Should succeed as we already got the hash above
            let state = self
                .state_manager
                .get_state_at(height)
                .map_err(ValidationFailure::StateManagerError)?;
            get_oldest_ecdsa_state_registry_version(ecdsa, state.get_ref())
        } else {
            None
        };
        if registry_version != share_content.oldest_registry_version_in_use_by_replicated_state {
            warn!(self.log, "Oldest registry version from received CatchUpContent does not match local one: {:?} {:?}", share_content, registry_version);
            return Err(
                InvalidArtifactReason::MismatchedOldestRegistryVersionInCatchUpPackageShare.into(),
            );
        }

        Ok(block)
    }

    fn dedup_change_actions(&self, name: &str, actions: ChangeSet) -> ChangeSet {
        let mut change_set = ChangeSet::new();
        for action in actions {
            change_set.dedup_push(action).unwrap_or_else(|action| {
                self.metrics
                    .duplicate_artifact
                    .with_label_values(&[name])
                    .inc();
                trace!(
                    self.log,
                    "Duplicated {} detected in changeset {:?}",
                    name,
                    action
                )
            })
        }
        change_set
    }

    fn compute_action_from_artifact_verification(
        &self,
        pool_reader: &PoolReader<'_>,
        result: ValidationResult<ValidatorError>,
        message: ConsensusMessage,
    ) -> Option<ChangeAction> {
        match result {
            Ok(()) => Some(ChangeAction::MoveToValidated(message)),
            Err(ValidationError::InvalidArtifact(
                InvalidArtifactReason::ReplicaVersionMismatch,
            )) => Some(ChangeAction::RemoveFromUnvalidated(message)),
            Err(ValidationError::InvalidArtifact(s)) => {
                Some(ChangeAction::HandleInvalid(message, format!("{:?}", s)))
            }
            Err(ValidationError::ValidationFailed(err)) => {
                if self.unvalidated_for_too_long(pool_reader, &message.get_id()) {
                    warn!(every_n_seconds => LOG_EVERY_N_SECONDS,
                          self.log,
                          "Could not verify signature: {:?}", err
                    );
                }
                None
            }
        }
    }

    fn unvalidated_for_too_long(
        &self,
        pool_reader: &PoolReader<'_>,
        id: &ConsensusMessageId,
    ) -> bool {
        match pool_reader.pool().unvalidated().get_timestamp(id) {
            Some(timestamp) => {
                let now = self.time_source.get_relative_time();
                now >= timestamp + Duration::from_secs(SECONDS_TO_LOG_UNVALIDATED)
            }
            None => false, // should never happen.
        }
    }

    /// Under certain conditions, it makes sense to delay validating (and loading) a CUP
    /// If we are already close to caught up and have all necessary artifacts in the pool
    /// we might want to hold off loading the cup and try to get there by computation first.
    /// After a while, if we did not catch up via computing, we will still load the CUP.
    fn maybe_hold_back_cup(
        &self,
        catch_up_package: &CatchUpPackage,
        pool_reader: &PoolReader<'_>,
    ) -> Result<(), ValidationError<InvalidArtifactReason, ValidationFailure>> {
        let cup_height = catch_up_package.height();

        // Check that this is a CUP that is close to the current state we have
        // in the state manager, i.e. there is a chance to catch up via recomputing
        if cup_height
            .get()
            .saturating_sub(self.state_manager.latest_state_height().get())
            < Self::get_next_interval_length(catch_up_package).get() / 4
            // Check that the finalized height is higher than this cup
            // In order to validate the finalization of height `h` we need to have
            // a valid random beacon of height `h-1` and a valid block of height `h`.
            // In order to have a valid block of height `h` you need to have
            // a valid block of height `h-1`.
            // The same is true for the random beacon.
            // Thus, if this condition is true, we know that we have all blocks and random beacons
            // between the latest CUP height and finalized height and are therefore
            // able to recompute.
            && pool_reader.get_finalized_height() >= cup_height
            // If the state height exceeded the cup height, we can validate the cup, as it won't
            // trigger the state sync.
            && self.state_manager.latest_state_height() < cup_height
        {
            // Check that this CUP has not been in the pool for too long
            // If it has, we validate the CUP nonetheless
            // This is a safety measure
            let now = self.time_source.get_relative_time();
            match pool_reader
                .pool()
                .unvalidated()
                .get_timestamp(&catch_up_package.get_id())
            {
                Some(timestamp) if now > timestamp + CATCH_UP_HOLD_OF_TIME => {
                    warn!(
                        self.log,
                        "Validating CUP at height {} after holding it back for {} seconds",
                        cup_height,
                        CATCH_UP_HOLD_OF_TIME.as_secs()
                    );
                    Ok(())
                }
                Some(_) => Err(ValidationError::ValidationFailed(
                    ValidationFailure::CatchUpHeightNegligible,
                )),
                None => Ok(()),
            }
        } else {
            Ok(())
        }
    }

    fn get_next_interval_length(cup: &CatchUpPackage) -> Height {
        let a = cup.content.block.as_ref().payload.as_ref();
        match a {
            BlockPayload::Summary(summary) => summary.dkg.next_interval_length,
            _ => unreachable!("CatchUpPackage always contains a SummaryBlock"),
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::ecdsa::test_utils::{
        add_available_quadruple_to_payload, empty_ecdsa_payload, fake_ecdsa_key_id,
        fake_sign_with_ecdsa_context_with_quadruple, fake_state_with_ecdsa_contexts,
    };

    use super::*;
    use assert_matches::assert_matches;
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_consensus_mocks::{
        dependencies_with_subnet_params, dependencies_with_subnet_records_with_raw_state_manager,
        Dependencies, RefMockPayloadBuilder,
    };
    use ic_consensus_utils::get_block_maker_delay;
    use ic_interfaces::{
        messaging::XNetPayloadValidationFailure, p2p::consensus::MutablePool,
        time_source::TimeSource,
    };
    use ic_interfaces_mocks::messaging::RefMockMessageRouting;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::subnet::SubnetRegistry;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{crypto::CryptoReturningOk, state_manager::RefMockStateManager};
    use ic_test_utilities_consensus::{assert_changeset_matches_pattern, fake::*, matches_pattern};
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        consensus::{
            idkg::PreSigId, BlockPayload, CatchUpPackageShare, Finalization, FinalizationShare,
            HashedBlock, HashedRandomBeacon, NotarizationShare, Payload, RandomBeaconContent,
            RandomTapeContent, SummaryPayload,
        },
        crypto::{CombinedMultiSig, CombinedMultiSigOf, CryptoHash},
        replica_config::ReplicaConfig,
        signature::ThresholdSignature,
        CryptoHashOfState, ReplicaVersion,
    };
    use std::{
        borrow::Borrow,
        sync::{Arc, RwLock},
    };

    pub fn assert_block_valid(results: &[ChangeAction], block: &BlockProposal) {
        match results.first() {
            Some(ChangeAction::MoveToValidated(ConsensusMessage::BlockProposal(b))) => {
                assert_eq!(block, b);
            }
            item => panic!("Unexpected change action set: {:?}", item),
        };
    }

    fn assert_block_invalid(results: &[ChangeAction], block: &BlockProposal) {
        match results.first() {
            Some(ChangeAction::HandleInvalid(ConsensusMessage::BlockProposal(b), _)) => {
                assert_eq!(block, b);
            }
            item => panic!("Unexpected change action set: {:?}", item),
        };
    }

    pub struct ValidatorAndDependencies {
        pub validator: Validator,
        pub payload_builder: Arc<RefMockPayloadBuilder>,
        pub membership: Arc<Membership>,
        pub state_manager: Arc<RefMockStateManager>,
        pub message_routing: Arc<RefMockMessageRouting>,
        pub crypto: Arc<CryptoReturningOk>,
        pub data_provider: Arc<ProtoRegistryDataProvider>,
        pub registry_client: Arc<FakeRegistryClient>,
        pub pool: TestConsensusPool,
        pub dkg_pool: Arc<RwLock<DkgPoolImpl>>,
        pub time_source: Arc<FastForwardTimeSource>,
        pub replica_config: ReplicaConfig,
    }

    impl ValidatorAndDependencies {
        fn new(dependencies: Dependencies) -> Self {
            let payload_builder = Arc::new(RefMockPayloadBuilder::default());
            let message_routing = Arc::new(RefMockMessageRouting::default());
            let validator = Validator::new(
                dependencies.replica_config.clone(),
                dependencies.membership.clone(),
                dependencies.registry.clone(),
                dependencies.crypto.clone(),
                payload_builder.clone(),
                dependencies.state_manager.clone(),
                message_routing.clone(),
                dependencies.dkg_pool.clone(),
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&dependencies.time_source) as Arc<_>,
                /*ingress_selector=*/ None,
            );
            Self {
                validator,
                payload_builder,
                membership: dependencies.membership,
                state_manager: dependencies.state_manager,
                message_routing,
                crypto: dependencies.crypto,
                data_provider: dependencies.registry_data_provider,
                registry_client: dependencies.registry,
                pool: dependencies.pool,
                dkg_pool: dependencies.dkg_pool,
                time_source: dependencies.time_source,
                replica_config: dependencies.replica_config,
            }
        }
    }

    fn setup_dependencies(
        pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
        node_ids: &[NodeId],
    ) -> ValidatorAndDependencies {
        ValidatorAndDependencies::new(dependencies_with_subnet_params(
            pool_config,
            subnet_test_id(0),
            vec![(
                1,
                SubnetRecordBuilder::from(node_ids)
                    .with_dkg_interval_length(9)
                    .build(),
            )],
        ))
    }

    fn setup_dependencies_with_raw_state_manager(
        pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
        node_ids: &[NodeId],
    ) -> ValidatorAndDependencies {
        ValidatorAndDependencies::new(dependencies_with_subnet_records_with_raw_state_manager(
            pool_config,
            subnet_test_id(0),
            vec![(
                1,
                SubnetRecordBuilder::from(node_ids)
                    .with_dkg_interval_length(9)
                    .build(),
            )],
        ))
    }

    #[test]
    fn test_validate_catch_up_package_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                state_manager,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            // The state manager is mocked and the `StateHash` is completely arbitrary. It
            // must just be the same as in the `CatchUpPackageShare`.
            let state_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(state_hash.clone()));

            // Manually construct a cup share
            let make_next_cup_share = |pool: &TestConsensusPool| -> CatchUpPackageShare {
                let random_beacon = pool.make_next_beacon();
                let random_beacon_hash =
                    HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon);
                let block = Block::from(pool.make_next_block());
                let block_hash = HashedBlock::new(ic_types::crypto::crypto_hash, block);

                Signed {
                    content: CatchUpShareContent::from(&CatchUpContent::new(
                        block_hash,
                        random_beacon_hash,
                        state_hash.clone(),
                        None,
                    )),
                    signature: ThresholdSignatureShare::fake(node_test_id(0)),
                }
            };

            // Skip to two heights before Summary height
            pool.advance_round_normal_operation_no_cup_n(8);

            let cup_share_data_height = make_next_cup_share(&pool);
            pool.advance_round_normal_operation_no_cup_n(1);
            let cup_share_summary_height = make_next_cup_share(&pool);

            // Advance by two rounds so we have a finalized block at the heights
            // This is necessary for the validate function to succeed
            pool.advance_round_normal_operation_no_cup_n(1);
            pool.insert_unvalidated(cup_share_data_height.clone());
            pool.insert_unvalidated(cup_share_summary_height.clone());
            let mut cup_from_old_replica_version = cup_share_summary_height.clone();
            cup_from_old_replica_version.content.version =
                ReplicaVersion::try_from("old_version").unwrap();
            pool.insert_unvalidated(cup_from_old_replica_version.clone());
            let mut cup_with_registry_version = cup_share_summary_height.clone();
            cup_with_registry_version
                .content
                .oldest_registry_version_in_use_by_replicated_state =
                Some(RegistryVersion::from(1));
            pool.insert_unvalidated(cup_with_registry_version.clone());

            let pool_reader = PoolReader::new(&pool);
            let change_set = validator.validate_catch_up_package_shares(&pool_reader);

            // Check that the change set contains exactly the one `CatchUpPackageShare` we
            // expect it to.
            assert_eq!(change_set.len(), 4);
            assert_matches!(&change_set[0], ChangeAction::HandleInvalid(ConsensusMessage::CatchUpPackageShare(s), m)
                if s == &cup_share_data_height && m.contains("DataPayloadBlockInCatchUpPackageShare")
            );
            assert_matches!(&change_set[1], ChangeAction::MoveToValidated(ConsensusMessage::CatchUpPackageShare(s))
                if s == &cup_share_summary_height
            );
            assert_matches!(&change_set[2], ChangeAction::RemoveFromUnvalidated(ConsensusMessage::CatchUpPackageShare(s))
                if s == &cup_from_old_replica_version
            );
            assert_matches!(&change_set[3], ChangeAction::HandleInvalid(ConsensusMessage::CatchUpPackageShare(s), m)
                if s == &cup_with_registry_version && m.contains("MismatchedOldestRegistryVersion")
            );
        })
    }

    #[test]
    fn test_validate_catch_up_package_shares_with_registry_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                state_manager,
                mut pool,
                ..
            } = setup_dependencies_with_raw_state_manager(
                pool_config,
                &(0..4).map(node_test_id).collect::<Vec<_>>(),
            );

            // The state manager is mocked and the `StateHash` is completely arbitrary. It
            // must just be the same as in the `CatchUpPackageShare`.
            let state_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(state_hash.clone()));

            let key_id = fake_ecdsa_key_id();
            // Create three quadruple Ids and contexts, quadruple "2" will remain unmatched.
            let pre_sig_id1 = PreSigId(1);
            let pre_sig_id2 = PreSigId(2);
            let pre_sig_id3 = PreSigId(3);

            let contexts = vec![
                fake_sign_with_ecdsa_context_with_quadruple(1, key_id.clone(), Some(pre_sig_id1)),
                fake_sign_with_ecdsa_context_with_quadruple(2, key_id.clone(), None),
                fake_sign_with_ecdsa_context_with_quadruple(3, key_id.clone(), Some(pre_sig_id3)),
            ];

            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(fake_state_with_ecdsa_contexts(
                    Height::from(0),
                    contexts.clone(),
                )
                .get_labeled_state()));

            // Manually construct a cup share
            let make_next_cup_share = |proposal: BlockProposal,
                                       beacon: RandomBeacon,
                                       oldest_registry_version: Option<RegistryVersion>|
             -> CatchUpPackageShare {
                let random_beacon_hash =
                    HashedRandomBeacon::new(ic_types::crypto::crypto_hash, beacon);
                let block = Block::from(proposal);
                let block_hash = HashedBlock::new(ic_types::crypto::crypto_hash, block);

                Signed {
                    content: CatchUpShareContent::from(&CatchUpContent::new(
                        block_hash,
                        random_beacon_hash,
                        state_hash.clone(),
                        oldest_registry_version,
                    )),
                    signature: ThresholdSignatureShare::fake(node_test_id(0)),
                }
            };

            // Skip to Summary height
            pool.advance_round_normal_operation_no_cup_n(9);

            let mut proposal = pool.make_next_block();
            let block = proposal.content.as_mut();
            block.context.certified_height = block.height();

            let mut ecdsa = empty_ecdsa_payload(subnet_test_id(0));
            // Add the three quadruples using registry version 3, 1 and 2 in order
            add_available_quadruple_to_payload(&mut ecdsa, pre_sig_id1, RegistryVersion::from(3));
            add_available_quadruple_to_payload(&mut ecdsa, pre_sig_id2, RegistryVersion::from(1));
            add_available_quadruple_to_payload(&mut ecdsa, pre_sig_id3, RegistryVersion::from(2));

            let dkg = block.payload.as_ref().as_summary().dkg.clone();
            block.payload = Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload {
                    dkg,
                    ecdsa: Some(ecdsa),
                }),
            );
            proposal.content = HashedBlock::new(ic_types::crypto::crypto_hash, block.clone());

            let beacon = pool.make_next_beacon();
            pool.advance_round_with_block(&proposal);

            let cup_share_no_registry_version =
                make_next_cup_share(proposal.clone(), beacon.clone(), None);
            pool.insert_unvalidated(cup_share_no_registry_version.clone());

            let cup_share_wrong_registry_version = make_next_cup_share(
                proposal.clone(),
                beacon.clone(),
                Some(RegistryVersion::from(1)),
            );
            pool.insert_unvalidated(cup_share_wrong_registry_version.clone());

            // Since the quadruple using registry version 1 wasn't matched, the oldest one in use
            // by the replicated state should be the registry version of quadruple 3, which is 2.
            let cup_share_valid =
                make_next_cup_share(proposal, beacon, Some(RegistryVersion::from(2)));
            pool.insert_unvalidated(cup_share_valid.clone());

            let pool_reader = PoolReader::new(&pool);
            let change_set = validator.validate_catch_up_package_shares(&pool_reader);

            // Check that the change set contains exactly the one `CatchUpPackageShare` we
            // expect it to.
            assert_eq!(change_set.len(), 3);
            assert_matches!(&change_set[0], ChangeAction::HandleInvalid(ConsensusMessage::CatchUpPackageShare(s), m)
                if s == &cup_share_no_registry_version && m.contains("MismatchedOldestRegistryVersion")
            );
            assert_matches!(&change_set[1], ChangeAction::HandleInvalid(ConsensusMessage::CatchUpPackageShare(s), m)
                if s == &cup_share_wrong_registry_version && m.contains("MismatchedOldestRegistryVersion")
            );
            assert_matches!(&change_set[2], ChangeAction::MoveToValidated(ConsensusMessage::CatchUpPackageShare(s))
                if s == &cup_share_valid
            );
        })
    }

    /// Test that Finalizations are not moved from `unvalidated` to `validated`
    /// unless a Notarization exists in `validated` for the associated block
    #[test]
    fn test_finalization_requires_notarization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            // Insert a Finalization for `block` in the unvalidated pool
            let share = FinalizationShare::fake(block.as_ref(), block.signature.signer);
            pool.insert_unvalidated(Finalization::fake(share.content));

            // With no existing Notarization for `block`, the Finalization in the
            // unvalidated pool should not be added to validated
            assert!(validator
                .on_state_change(&PoolReader::new(&pool))
                .is_empty());

            // Add a Notarization for `block` and assert it causes the Finalization
            // to be added to validated
            pool.notarize(&block);
            assert_eq!(validator.on_state_change(&PoolReader::new(&pool)).len(), 1);
        })
    }

    #[test]
    fn test_validation_context_ordering() {
        assert!(!ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_types::time::UNIX_EPOCH,
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(4),
            time: ic_types::time::UNIX_EPOCH,
        }),);
        assert!(ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_types::time::UNIX_EPOCH,
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_types::time::UNIX_EPOCH,
        }),);
        assert!(ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(5),
            time: ic_types::time::UNIX_EPOCH,
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(4),
            time: ic_types::time::UNIX_EPOCH,
        }),);
        assert!(!ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_types::time::UNIX_EPOCH,
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(6),
            time: ic_types::time::UNIX_EPOCH,
        }),);
    }

    #[test]
    fn test_random_beacon_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                mut pool,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            pool.advance_round_normal_operation();

            // Put a random tape share in the unvalidated pool
            let pool_reader = PoolReader::new(&pool);
            let beacon_1 = pool_reader.get_random_beacon(Height::from(1)).unwrap();
            let beacon_2 = RandomBeacon::from_parent(&beacon_1);
            let share_3 = RandomBeaconShare::fake(&beacon_2, replica_config.node_id);
            pool.insert_unvalidated(share_3.clone());
            let mut share_with_old_version = share_3.clone();
            share_with_old_version.content = RandomBeaconContent {
                version: ReplicaVersion::try_from("old_version").unwrap(),
                height: share_3.content.height,
                parent: share_3.content.parent.clone(),
            };
            pool.insert_unvalidated(share_with_old_version.clone());

            // share_3 cannot validate due to missing parent
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 0);

            // beacon_2 validates
            pool.insert_unvalidated(beacon_2.clone());
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomBeacon(beacon_2))
            );
            pool.apply_changes(changeset);

            // share_3 now validates
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 2);
            assert_eq!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomBeaconShare(share_3))
            );
            assert_eq!(
                changeset[1],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::RandomBeaconShare(
                    share_with_old_version
                ))
            )
        })
    }

    #[test]
    fn test_random_tape_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                state_manager,
                message_routing,
                mut pool,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            let mut round = pool.prepare_round().dont_finalize().dont_add_random_tape();
            round.advance();
            pool.prepare_round()
                .dont_add_catch_up_package()
                .dont_add_random_tape()
                .advance();
            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
            let expected_batch_height = Arc::new(RwLock::new(Height::from(1)));
            let expected_batch_height_clone = expected_batch_height.clone();
            message_routing
                .get_mut()
                .expect_expected_batch_height()
                .returning(move || *expected_batch_height_clone.read().unwrap());

            // Put a random tape share in the unvalidated pool
            let share_1 = RandomTapeShare::fake(Height::from(1), replica_config.node_id);
            pool.insert_unvalidated(share_1.clone());

            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomTapeShare(share_1.clone()))
            );

            // Put another random tape share in the unvalidated pool
            let share_2 = RandomTapeShare::fake(Height::from(2), replica_config.node_id);
            pool.insert_unvalidated(share_2.clone());
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 2);
            assert!(changeset.iter().all(|action| matches!(
                action,
                ChangeAction::MoveToValidated(ConsensusMessage::RandomTapeShare(_))
            )));

            // Insert a random tape of height 1 in validated pool, check if only share_2 is
            // validated
            let tape_1 = RandomTape::fake(RandomTapeContent::new(Height::from(1)));
            pool.insert_validated(tape_1);

            let mut old_replica_version_share = share_2.clone();
            old_replica_version_share.content.version =
                ReplicaVersion::try_from("old_version").unwrap();
            pool.insert_unvalidated(old_replica_version_share.clone());

            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 3);
            assert_eq!(
                changeset[1],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomTapeShare(share_2))
            );
            assert_eq!(
                changeset[0],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::RandomTapeShare(share_1))
            );
            assert_eq!(
                changeset[2],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::RandomTapeShare(
                    old_replica_version_share
                ))
            );

            // Accept changes
            pool.apply_changes(changeset);

            // Insert random tape at height 4, check if it is ignored
            let content = RandomTapeContent::new(Height::from(4));
            let signature = ThresholdSignature::fake();
            let tape_4 = RandomTape { content, signature };
            pool.insert_unvalidated(tape_4.clone());
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 0);

            // Make finalized block at height 4, check if tape_4 is now accepted
            pool.prepare_round()
                .dont_add_catch_up_package()
                .dont_add_random_tape()
                .advance();
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomTape(tape_4))
            );

            // Accept changes
            pool.apply_changes(changeset);

            // Set expected batch height to height 4, check if tape_3 is ignored
            let content = RandomTapeContent::new(Height::from(3));
            let signature = ThresholdSignature::fake();
            let tape_3 = RandomTape { content, signature };
            pool.insert_unvalidated(tape_3);
            *expected_batch_height.write().unwrap() = Height::from(4);
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 0);
        })
    }

    #[test]
    fn test_block_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let prior_height = Height::from(5);
            let certified_height = Height::from(1);
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                data_provider,
                registry_client,
                mut pool,
                time_source,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &committee);
            payload_builder
                .get_mut()
                .expect_validate_payload()
                .withf(move |_, _, _, payloads| {
                    // Assert that payloads are from blocks between:
                    // `certified_height` and the current height (`prior_height`)
                    payloads.len() as u64 == (prior_height - certified_height).get()
                })
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);

            add_subnet_record(
                &data_provider,
                11,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );
            registry_client.update_to_latest_version();

            // Create a block chain with some length that will not be finalized
            pool.insert_beacon_chain(&pool.make_next_beacon(), prior_height);
            let block_chain = pool.insert_block_chain(prior_height);

            // Create and insert the block whose validation we will be testing
            let parent: &Block = block_chain.last().unwrap().as_ref();
            let rank = Rank(1);
            let mut test_block: Block = pool.make_next_block_from_parent(parent, rank).into();

            let node_id = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &committee,
                rank,
            );

            test_block.context.registry_version = RegistryVersion::from(11);
            test_block.context.certified_height = Height::from(1);
            let block_proposal = BlockProposal::fake(test_block.clone(), node_id);
            pool.insert_unvalidated(block_proposal.clone());

            // Finalize some blocks to ensure that:
            // certified_height + 1 != finalized_height
            // We can then correctly assert that the payloads we pass to
            // `payload_builder.validate_payload()` are from blocks after
            // certified_height, and not finalized_height
            pool.finalize(&block_chain[0]);
            pool.finalize(&block_chain[1]);
            pool.finalize(&block_chain[2]);

            // Ensure that the validator initially does not validate anything, as it is not
            // time for rank 1 yet
            assert!(validator
                .on_state_change(&PoolReader::new(&pool))
                .is_empty(),);

            // Time between blocks increases by at least initial_notary_delay + 1ns
            let monotonic_block_increment = registry_client
                .get_notarization_delay_settings(
                    replica_config.subnet_id,
                    test_block.context.registry_version,
                )
                .unwrap()
                .expect("subnet record should be available")
                .initial_notary_delay
                + Duration::from_nanos(1);

            // After sufficiently advancing the time, ensure that the validator validates
            // the block
            let delay = monotonic_block_increment
                + get_block_maker_delay(
                    &no_op_logger(),
                    registry_client.as_ref(),
                    replica_config.subnet_id,
                    PoolReader::new(&pool)
                        .registry_version(test_block.height())
                        .unwrap(),
                    rank,
                )
                .unwrap();

            time_source.set_time(parent.context.time + delay).unwrap();
            let valid_results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_valid(&valid_results, &block_proposal);
        });
    }

    #[test]
    fn test_block_validation_with_old_replica_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let prior_height = Height::from(5);
            let certified_height = Height::from(1);
            let committee: Vec<_> = (0..4).map(node_test_id).collect();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                data_provider,
                registry_client,
                mut pool,
                time_source,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &committee);
            payload_builder
                .get_mut()
                .expect_validate_payload()
                .withf(move |_, _, _, payloads| {
                    // Assert that payloads are from blocks between:
                    // `certified_height` and the current height (`prior_height`)
                    payloads.len() as u64 == (prior_height - certified_height).get()
                })
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);

            add_subnet_record(
                &data_provider,
                11,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );
            registry_client.update_to_latest_version();

            // Create a block chain with some length that will not be finalized
            pool.insert_beacon_chain(&pool.make_next_beacon(), prior_height);
            let block_chain = pool.insert_block_chain(prior_height);

            // Create and insert the block whose validation we will be testing
            let parent: &Block = block_chain.last().unwrap().as_ref();
            let rank = Rank(1);
            let mut test_block: Block = pool.make_next_block_from_parent(parent, rank).into();
            let node_id = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &committee,
                rank,
            );

            test_block.context.registry_version = RegistryVersion::from(11);
            test_block.context.certified_height = Height::from(1);
            test_block.version = ReplicaVersion::try_from("old_version").unwrap();

            let block_proposal = BlockProposal::fake(test_block.clone(), node_id);
            pool.insert_unvalidated(block_proposal.clone());

            // Finalize some blocks to ensure that:
            // certified_height + 1 != finalized_height
            // We can then correctly assert that the payloads we pass to
            // `payload_builder.validate_payload()` are from blocks after
            // certified_height, and not finalized_height
            pool.finalize(&block_chain[0]);
            pool.finalize(&block_chain[1]);
            pool.finalize(&block_chain[2]);

            // ensure that the validator initially does not validate anything, as it is not
            // time for rank 1 yet
            assert!(validator
                .on_state_change(&PoolReader::new(&pool))
                .is_empty(),);

            // Time between blocks increases by at least initial_notary_delay + 1ns
            let monotonic_block_increment = registry_client
                .get_notarization_delay_settings(
                    replica_config.subnet_id,
                    test_block.context.registry_version,
                )
                .unwrap()
                .expect("subnet record should be available")
                .initial_notary_delay
                + Duration::from_nanos(1);

            // After sufficiently advancing the time, ensure that the validator validates
            // the block
            let delay = monotonic_block_increment
                + get_block_maker_delay(
                    &no_op_logger(),
                    registry_client.as_ref(),
                    replica_config.subnet_id,
                    PoolReader::new(&pool)
                        .registry_version(test_block.height())
                        .unwrap(),
                    rank,
                )
                .unwrap();

            time_source.set_time(parent.context.time + delay).unwrap();
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(results.len(), 1);
            assert_matches!(&results[0], ChangeAction::RemoveFromUnvalidated(ConsensusMessage::BlockProposal(b))
                if b == &block_proposal
            );
        })
    }

    #[test]
    // Construct a proposal block with a non-notarized parent and make sure we're
    // not validating this block until the parent gets notarized.
    fn test_block_validation_without_notarized_parent() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let certified_height = Height::from(1);
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                data_provider,
                registry_client,
                mut pool,
                time_source,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &committee);
            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);
            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(ic_test_utilities_state::get_initial_state(0, 0)),
                )));

            add_subnet_record(
                &data_provider,
                11,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );

            registry_client.update_to_latest_version();

            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(3));

            let mut test_block = pool.make_next_block();
            test_block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &committee,
                Rank(0),
            );
            test_block.content.as_mut().context.registry_version = RegistryVersion::from(11);
            test_block.content.as_mut().context.certified_height = Height::from(1);
            test_block.content.as_mut().rank = Rank(0);
            test_block.update_content();
            pool.insert_unvalidated(test_block.clone());
            // Forward time correctly
            time_source
                .set_time(test_block.content.as_mut().context.time)
                .unwrap();
            let valid_results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_valid(&valid_results, &test_block);
            pool.apply_changes(valid_results);

            let rank = Rank(0);
            let mut next_block = pool.make_next_block_from_parent(test_block.as_ref(), rank);
            next_block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                next_block.height(),
                &committee,
                rank,
            );
            next_block.content.as_mut().context.registry_version = RegistryVersion::from(11);
            next_block.content.as_mut().context.certified_height = Height::from(1);
            next_block.content.as_mut().rank = rank;
            next_block.update_content();
            pool.insert_unvalidated(next_block.clone());
            // Forward time correctly
            time_source
                .set_time(next_block.content.as_mut().context.time)
                .unwrap();
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert!(results.is_empty());
            pool.notarize(&test_block);
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_valid(&results, &next_block);
        });
    }

    #[test]
    fn test_block_validation_with_registry_versions() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let certified_height = Height::from(1);
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                data_provider,
                registry_client,
                mut pool,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &subnet_members);
            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(certified_height);

            add_subnet_record(
                &data_provider,
                11,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );

            add_subnet_record(
                &data_provider,
                12,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );

            registry_client.update_to_latest_version();

            let mut parent_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            parent_block.content.as_mut().context.registry_version = RegistryVersion::from(12);
            parent_block.content.as_mut().context.certified_height = Height::from(1);
            parent_block.update_content();
            pool.advance_round_with_block(&parent_block);

            // Construct a block with a higher registry version but lower certified height
            // (which will be considered invalid)
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            test_block.content.as_mut().context.registry_version = RegistryVersion::from(12);
            test_block.content.as_mut().context.certified_height = Height::from(0);
            test_block.update_content();

            pool.insert_unvalidated(test_block.clone());
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_invalid(&results, &test_block);
            pool.apply_changes(results);

            // Construct a block with a registry version that is higher than any we
            // currently recognize. This should yield an empty change set
            let mut test_block = make_next_block(&pool, membership.borrow(), &subnet_members);
            test_block.content.as_mut().context.registry_version = RegistryVersion::from(2000);
            test_block.update_content();
            pool.insert_unvalidated(test_block);
            assert_eq!(validator.on_state_change(&PoolReader::new(&pool)), vec![]);
        })
    }

    // utility function to determine the identity of the block maker with the
    // specified rank at a given height. Panics if this rank does not exist.
    fn get_block_maker_by_rank(
        membership: &Membership,
        pool_reader: &PoolReader,
        height: Height,
        subnet_members: &[NodeId],
        rank: Rank,
    ) -> NodeId {
        *subnet_members
            .iter()
            .find(|node| {
                let prev_beacon = pool_reader.get_random_beacon(height.decrement()).unwrap();
                membership.get_block_maker_rank(height, &prev_beacon, **node) == Ok(Some(rank))
            })
            .unwrap()
    }

    fn make_next_block(
        pool: &TestConsensusPool,
        membership: &Membership,
        subnet_members: &[NodeId],
    ) -> BlockProposal {
        let mut next_block = pool.make_next_block();
        next_block.signature.signer = get_block_maker_by_rank(
            membership,
            &PoolReader::new(pool),
            next_block.height(),
            subnet_members,
            Rank(0),
        );
        next_block.content.as_mut().rank = Rank(0);
        next_block.update_content();
        next_block
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_certified_height_change() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                mut pool,
                time_source,
                ..
            } = setup_dependencies(pool_config, &subnet_members);

            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .times(1)
                .return_const(Height::from(0)); // return 0 when called first time
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .times(1)
                .return_const(Height::from(1)); // return 1 when called second time

            // Construct a finalized chain of blocks
            let prior_height = Height::from(5);
            pool.insert_beacon_chain(&pool.make_next_beacon(), prior_height);
            let block_chain = pool.insert_block_chain(prior_height);
            pool.finalize(&block_chain[3]);
            pool.notarize(&block_chain[4]);

            // Construct a block with certified height 1 (which can't yet be verified
            // because state_manager will return certified height 0 the first time,
            // indicating that the replicated state at height 1 is not certified
            // yet).
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            test_block.content.as_mut().context.certified_height = Height::from(1);
            test_block.update_content();
            pool.insert_unvalidated(test_block.clone());
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(results, ChangeSet::new());

            // Try validate again, it should succeed, because certified_height has caught up
            // Make sure to set the correct time for validation
            time_source
                .set_time(test_block.content.as_mut().context.time)
                .unwrap();
            let results = validator.on_state_change(&PoolReader::new(&pool));
            match results.first() {
                Some(ChangeAction::MoveToValidated(ConsensusMessage::BlockProposal(proposal))) => {
                    assert_eq!(proposal, &test_block);
                }
                other => panic!("unexpected action: {other:?}"),
            }
        })
    }

    #[test]
    fn test_block_context_time() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                mut pool,
                time_source,
                ..
            } = setup_dependencies(pool_config, &subnet_members);

            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::from(0));

            // Construct a finalized chain of blocks
            let prior_height = Height::from(5);
            pool.insert_beacon_chain(&pool.make_next_beacon(), prior_height);
            let block_chain = pool.insert_block_chain(prior_height);
            pool.finalize(&block_chain[3]);
            pool.notarize(&block_chain[4]);

            // We construct a block with a time greater than the current consensus time.
            // It should not be validated yet.
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            let block_time = test_block.content.as_mut().context.time;
            test_block.update_content();
            pool.insert_unvalidated(test_block.clone());
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(results, ChangeSet::new());

            // when we advance the time, it should be validated
            time_source.set_time(block_time).unwrap();
            let results = validator.on_state_change(&PoolReader::new(&pool));
            match results.first() {
                Some(ChangeAction::MoveToValidated(ConsensusMessage::BlockProposal(proposal))) => {
                    assert_eq!(proposal, &test_block);
                }
                _ => panic!(),
            }

            // after we finalize a block with time `block_time`, the validator should reject
            // a child block with a smaller time
            pool.apply_changes(results);
            pool.notarize(&test_block);
            pool.finalize(&test_block);
            pool.insert_validated(pool.make_next_beacon());

            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            test_block.content.as_mut().context.time =
                block_time.checked_sub(Duration::from_nanos(1)).unwrap();
            test_block.update_content();
            pool.insert_unvalidated(test_block.clone());
            let results = validator.on_state_change(&PoolReader::new(&pool));
            match results.first() {
                Some(ChangeAction::HandleInvalid(ConsensusMessage::BlockProposal(proposal), _)) => {
                    assert_eq!(proposal, &test_block);
                }
                _ => panic!(),
            }
        })
    }

    #[test]
    fn test_notarization_requires_at_least_threshold_signatures() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let ValidatorAndDependencies {
                validator,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());

            let share = NotarizationShare::fake(block.as_ref(), block.signature.signer);
            let mut notarization = Notarization::fake(share.content);
            notarization.signature.signers = vec![];

            pool.insert_unvalidated(notarization.clone());

            // The notarization should be marked invalid
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_changeset_matches_pattern!(
                changeset,
                ChangeAction::HandleInvalid(ConsensusMessage::Notarization(_), _)
            );
            pool.remove_unvalidated(notarization.clone());

            // create a fake notarization that has one signer repeated, which should be
            // marked as invalid
            notarization.signature.signers =
                vec![node_test_id(1), node_test_id(1), node_test_id(1)];
            pool.insert_unvalidated(notarization.clone());
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_changeset_matches_pattern!(
                changeset,
                ChangeAction::HandleInvalid(ConsensusMessage::Notarization(_), _)
            );

            pool.remove_unvalidated(notarization.clone());

            notarization.signature.signers =
                vec![node_test_id(1), node_test_id(2), node_test_id(3)];
            pool.insert_unvalidated(notarization);

            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_changeset_matches_pattern!(
                changeset,
                ChangeAction::MoveToValidated(ConsensusMessage::Notarization(_))
            );
        })
    }

    #[test]
    fn test_notarization_deduped_by_content() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Setup validator dependencies.
            let ValidatorAndDependencies {
                validator,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            let block = pool.make_next_block();
            pool.insert_validated(block.clone());

            // Insert two Notarizations for `block` in the unvalidated pool.
            let share = NotarizationShare::fake(block.as_ref(), block.signature.signer);
            let mut notarization_0 = Notarization::fake(share.content);
            notarization_0.signature.signers =
                vec![node_test_id(1), node_test_id(2), node_test_id(3)];
            let notarization_1 = Signed {
                content: notarization_0.content.clone(),
                signature: MultiSignature {
                    signers: vec![node_test_id(1), node_test_id(2), node_test_id(0)],
                    signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
                },
            };
            assert!(notarization_0 != notarization_1);
            pool.insert_unvalidated(notarization_0);
            pool.insert_unvalidated(notarization_1);

            // Only one notarization is emitted in the ChangeSet.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_matches!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::Notarization(_))
            );
            pool.apply_changes(changeset);

            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_matches!(
                changeset[0],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::Notarization(_))
            );
            pool.apply_changes(changeset);

            // Finally, changeset should be empty.
            assert!(validator
                .on_state_change(&PoolReader::new(&pool))
                .is_empty());
        })
    }

    #[test]
    fn test_finalization_deduped_by_content() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Setup validator dependencies.
            let ValidatorAndDependencies {
                validator,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            pool.notarize(&block);

            // Insert two Finalization for `block` in the unvalidated pool.
            let share = FinalizationShare::fake(block.as_ref(), block.signature.signer);
            let mut finalization_0 = Finalization::fake(share.content);
            finalization_0.signature.signers =
                vec![node_test_id(1), node_test_id(2), node_test_id(3)];
            let finalization_1 = Signed {
                content: finalization_0.content.clone(),
                signature: MultiSignature {
                    signers: vec![node_test_id(1), node_test_id(2), node_test_id(0)],
                    signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
                },
            };
            assert!(finalization_0 != finalization_1);
            pool.insert_unvalidated(finalization_0);
            pool.insert_unvalidated(finalization_1);

            // Only one finalization is emitted in the ChangeSet.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_matches!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::Finalization(_))
            );
            assert_eq!(changeset.len(), 1);
            pool.apply_changes(changeset);

            // Next run does not consider the extra Finalization.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 0);
        })
    }

    #[test]
    fn test_should_validate_catch_up_package_state_behind_the_cup_height() {
        test_validate_catch_up_package(
            /*state_height=*/ Height::new(1),
            /*held_back_duration*/ Duration::from_secs(0),
            /*expected_to_validate*/ true,
        );
    }

    #[test]
    fn test_should_not_validate_catch_up_package_when_state_close_to_the_cup_height() {
        test_validate_catch_up_package(
            /*state_height=*/ Height::new(9),
            /*held_back_duration*/ Duration::from_secs(0),
            /*expected_to_validate*/ false,
        );
    }

    #[test]
    fn test_should_validate_catch_up_package_when_held_back_for_too_long() {
        test_validate_catch_up_package(
            /*state_height=*/ Height::new(9),
            /*held_back_duration*/ CATCH_UP_HOLD_OF_TIME + Duration::from_secs(1),
            /*expected_to_validate*/ true,
        );
    }

    #[test]
    fn test_should_validate_catch_up_package_when_state_exceeds_the_cup_height() {
        test_validate_catch_up_package(
            /*state_height=*/ Height::new(10),
            /*held_back_duration*/ Duration::from_secs(0),
            /*expected_to_validate=*/ true,
        );
    }

    /// Tests whether we can validate a CUP at height `10`.
    fn test_validate_catch_up_package(
        state_height: Height,
        // How long has the CUP been in the pool
        held_back_duration: Duration,
        expected_to_validate: bool,
    ) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Setup validator dependencies.
            let ValidatorAndDependencies {
                validator,
                state_manager,
                mut pool,
                time_source,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            pool.advance_round_normal_operation_n(9);
            // Create, notarize, and finalize a block at the CUP height, but don't create a CUP.
            pool.prepare_round().dont_add_catch_up_package().advance();

            let finalization = pool.validated().finalization().get_highest().unwrap();
            let catch_up_package = pool.make_catch_up_package(finalization.height());
            pool.insert_unvalidated(catch_up_package.clone());

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .return_const(state_height);

            time_source.advance_time(held_back_duration);

            let mut changeset = validator.on_state_change(&PoolReader::new(&pool));
            if expected_to_validate {
                assert_eq!(changeset.len(), 1);
                assert_eq!(
                    changeset.pop(),
                    Some(ChangeAction::MoveToValidated(
                        ConsensusMessage::CatchUpPackage(catch_up_package)
                    ))
                );
            } else {
                assert_eq!(changeset.len(), 0);
            }
        })
    }

    #[test]
    fn test_should_not_validate_catch_up_package_when_wrong_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Setup validator dependencies.
            let ValidatorAndDependencies {
                validator,
                state_manager,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            pool.advance_round_normal_operation_n(9);
            // Create, notarize, and finalize a block at the CUP height, but don't create a CUP.
            pool.prepare_round().dont_add_catch_up_package().advance();

            let finalization = pool.validated().finalization().get_highest().unwrap();
            let mut catch_up_package = pool.make_catch_up_package(finalization.height());
            catch_up_package.content.version = ReplicaVersion::try_from("old_version").unwrap();
            pool.insert_unvalidated(catch_up_package.clone());

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
            state_manager
                .get_mut()
                .expect_latest_state_height()
                .return_const(Height::new(1));

            let mut changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);

            assert_eq!(
                changeset.pop(),
                Some(ChangeAction::RemoveFromUnvalidated(
                    ConsensusMessage::CatchUpPackage(catch_up_package)
                ))
            );
        })
    }

    #[test]
    fn test_out_of_sync_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                registry_client,
                mut pool,
                time_source,
                replica_config,
                ..
            } = setup_dependencies(pool_config, &subnet_members);

            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| Ok(()));
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::from(0));

            // Insert a chain of blocks, and for each round set the time_source during
            // insertion equal to the block proposal's timestamp.
            let mut current = pool.make_next_block();
            let mut current_beacon = pool.make_next_beacon();
            for _ in 0..5 {
                // Set local time to the block proposal timestamp
                time_source
                    .set_time(current.content.get_value().context.time)
                    .unwrap();
                pool.insert_validated(current.clone());
                pool.insert_validated(current_beacon.clone());
                pool.notarize(&current);
                pool.finalize(&current);
                current = pool.make_next_block_from_parent(current.as_ref(), Rank(0));
                current_beacon = RandomBeacon::from_parent(&current_beacon);
            }

            // The current time is the time at which we inserted, notarized and finalized
            // the current tip of the chain (i.e. the parent of test_block).
            let parent_time = time_source.get_relative_time();
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            let rank = Rank(1);
            let delay = get_block_maker_delay(
                &no_op_logger(),
                registry_client.as_ref(),
                replica_config.subnet_id,
                PoolReader::new(&pool)
                    .registry_version(test_block.height())
                    .unwrap(),
                rank,
            )
            .unwrap();
            test_block.content.as_mut().rank = rank;
            test_block.content.as_mut().context.time += delay;
            test_block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &subnet_members,
                rank,
            );
            test_block.update_content();
            let proposal_time = test_block.content.get_value().context.time;
            pool.insert_unvalidated(test_block.clone());

            // Sanity check: monotonic increment
            assert!(proposal_time > parent_time);

            // Our local time has not changed. We can't validate.
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert!(results.is_empty());

            // Now, assume our node goes out of sync. The clock stalls. We can only
            // advance the monotonic time.
            // According to the rules of out-of-sync validation, we need to advance
            // the time by x, so that `parent + x >= proposal`. Then the proposal is
            // allowed to be validated.
            let diff = proposal_time.saturating_duration_since(parent_time);
            time_source.advance_only_monotonic(diff);

            // Sanity check: our local time is still unchanged.
            assert_eq!(parent_time, time_source.get_relative_time());

            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                results.first(),
                Some(&ChangeAction::MoveToValidated(
                    ConsensusMessage::BlockProposal(test_block.clone())
                )),
            );

            pool.apply_changes(results);
            pool.notarize(&test_block);
            pool.finalize(&test_block);
            pool.insert_validated(pool.make_next_beacon());

            // Continue stalling the clock, and validate a rank > 0 block.
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            let rank = Rank(1);
            let delay = get_block_maker_delay(
                &no_op_logger(),
                registry_client.as_ref(),
                replica_config.subnet_id,
                PoolReader::new(&pool)
                    .registry_version(test_block.height())
                    .unwrap(),
                rank,
            )
            .unwrap();
            test_block.content.as_mut().rank = rank;
            test_block.content.as_mut().context.time += delay;
            test_block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &subnet_members,
                rank,
            );
            test_block.update_content();
            let proposal_time = test_block.content.get_value().context.time;
            pool.insert_unvalidated(test_block.clone());

            let diff = proposal_time.saturating_duration_since(parent_time);
            time_source.advance_only_monotonic(diff);

            // Sanity check: our local time is still unchanged.
            assert_eq!(parent_time, time_source.get_relative_time());

            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(
                results.first(),
                Some(&ChangeAction::MoveToValidated(
                    ConsensusMessage::BlockProposal(test_block)
                )),
            );
        })
    }

    #[test]
    fn test_block_validated_through_notarization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let ValidatorAndDependencies {
                validator,
                payload_builder,
                membership,
                state_manager,
                mut pool,
                ..
            } = setup_dependencies(pool_config, &subnet_members);
            pool.advance_round_normal_operation();

            payload_builder
                .get_mut()
                .expect_validate_payload()
                .returning(|_, _, _, _| {
                    Err(ValidationError::ValidationFailed(
                        PayloadValidationFailure::XNetPayloadValidationFailed(
                            XNetPayloadValidationFailure::StateNotCommittedYet(Height::from(0)),
                        ),
                    ))
                });
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::from(0));

            // First ensure that we require the parent block
            pool.insert_validated(pool.make_next_beacon());
            let parent_block = pool.make_next_block();
            let rank = Rank(0);
            let mut block = pool.make_next_block_from_parent(parent_block.as_ref(), rank);
            block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                block.height(),
                &subnet_members,
                rank,
            );

            block.update_content();
            let content = NotarizationContent::new(
                block.height(),
                ic_types::crypto::crypto_hash(block.as_ref()),
            );
            let mut notarization = Notarization::fake(content);
            notarization.signature.signers =
                vec![node_test_id(1), node_test_id(2), node_test_id(3)];
            pool.insert_unvalidated(notarization.clone());
            pool.insert_unvalidated(block.clone());

            // This should be empty because the parent block is not yet validated
            assert_eq!(validator.on_state_change(&PoolReader::new(&pool)), vec![]);
            pool.insert_validated(parent_block.clone());

            // This should still be empty because the parent is not notarized
            assert_eq!(validator.on_state_change(&PoolReader::new(&pool)), vec![]);
            pool.notarize(&parent_block);

            let changeset = validator.on_state_change(&PoolReader::new(&pool));

            assert_eq!(
                changeset,
                vec![
                    ChangeAction::MoveToValidated(block.into_message()),
                    ChangeAction::MoveToValidated(notarization.into_message())
                ]
            );
            pool.apply_changes(changeset);
        })
    }
}
