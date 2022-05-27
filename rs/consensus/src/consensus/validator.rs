#![allow(clippy::try_err)]

use crate::{
    consensus::{
        membership::{Membership, MembershipError},
        metrics::ValidatorMetrics,
        payload_builder::PayloadBuilder,
        pool_reader::PoolReader,
        prelude::*,
        utils::{
            active_high_threshold_transcript, active_low_threshold_transcript,
            find_lowest_ranked_proposals, is_time_to_make_block, lookup_replica_version,
            RoundRobin,
        },
        ConsensusMessageId,
    },
    dkg, ecdsa,
};
use ic_interfaces::time_source::TimeSource;
use ic_interfaces::{
    consensus::{PayloadPermanentError, PayloadTransientError},
    consensus_pool::*,
    dkg::DkgPool,
    messaging::MessageRouting,
    registry::RegistryClient,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_state_manager::{StateHashError, StateManager};
use ic_logger::{trace, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    crypto::{threshold_sig::ni_dkg::NiDkgId, CryptoError},
    registry::RegistryClientError,
    replica_config::ReplicaConfig,
    ReplicaVersion,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// The number of seconds spent in unvalidated pool, after which we start
/// logging why we cannot validate an artifact.
const SECONDS_TO_LOG_UNVALIDATED: u64 = 300;

/// How often we log an old unvalidated artifact.
const LOG_EVERY_N_SECONDS: i32 = 60;

/// Possible validator transient errors.
#[derive(Debug)]
enum TransientError {
    CryptoError(CryptoError),
    RegistryClientError(RegistryClientError),
    PayloadValidationError(PayloadTransientError),
    DkgPayloadValidationError(crate::dkg::TransientError),
    EcdsaPayloadValidationError(crate::ecdsa::TransientError),
    DkgSummaryNotFound(Height),
    RandomBeaconNotFound(Height),
    StateHashError(StateHashError),
    BlockNotFound(CryptoHashOf<Block>, Height),
    FinalizedBlockNotFound(Height),
    FailedToGetRegistryVersion,
    ValidationContextNotReached(ValidationContext, ValidationContext),
}

/// Possible validator permanent errors.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum PermanentError {
    CryptoError(CryptoError),
    MismatchedRank(Rank, Option<Rank>),
    MembershipError(MembershipError),
    InappropriateDkgId(NiDkgId),
    SignerNotInThresholdCommittee(NodeId),
    SignerNotInMultiSigCommittee(NodeId),
    PayloadValidationError(PayloadPermanentError),
    DkgPayloadValidationError(crate::dkg::PermanentError),
    EcdsaPayloadValidationError(crate::ecdsa::PermanentError),
    InsufficientSignatures,
    CannotVerifyBlockHeightZero,
    NonEmptyPayloadPastUpgradePoint,
    DecreasingValidationContext,
    MismatchedBlockInCatchUpPackageShare,
    MismatchedStateHashInCatchUpPackageShare,
    MismatchedRandomBeaconInCatchUpPackageShare,
    RepeatedSigner,
}

impl From<CryptoError> for TransientError {
    fn from(err: CryptoError) -> TransientError {
        TransientError::CryptoError(err)
    }
}

impl From<CryptoError> for PermanentError {
    fn from(err: CryptoError) -> PermanentError {
        PermanentError::CryptoError(err)
    }
}

impl<T> From<PermanentError> for ValidationError<PermanentError, T> {
    fn from(err: PermanentError) -> ValidationError<PermanentError, T> {
        ValidationError::Permanent(err)
    }
}

impl<P> From<TransientError> for ValidationError<P, TransientError> {
    fn from(err: TransientError) -> ValidationError<P, TransientError> {
        ValidationError::Transient(err)
    }
}

type ValidatorError = ValidationError<PermanentError, TransientError>;

impl From<MembershipError> for ValidatorError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::NodeNotFound(_) => PermanentError::MembershipError(err).into(),
            MembershipError::UnableToRetrieveDkgSummary(h) => {
                TransientError::DkgSummaryNotFound(h).into()
            }
            MembershipError::RegistryClientError(err) => {
                TransientError::RegistryClientError(err).into()
            }
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
    ) -> ValidationResult<ValidatorError>;
}

impl SignatureVerify for BlockProposal {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let previous_beacon = get_previous_beacon(pool, height)?;
        let rank =
            membership.get_block_maker_rank(height, &previous_beacon, self.signature.signer)?;
        if rank != Some(self.rank()) {
            return Err(ValidationError::from(PermanentError::MismatchedRank(
                self.rank(),
                rank,
            )));
        }
        let registry_version = get_registry_version(pool, height)?;
        crypto.verify(self, registry_version)?;
        Ok(())
    }
}

impl SignatureVerify for RandomTape {
    fn verify_signature(
        &self,
        _membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
    ) -> ValidationResult<ValidatorError> {
        let transcript = active_low_threshold_transcript(pool.as_cache(), self.height())
            .ok_or_else(|| TransientError::DkgSummaryNotFound(self.height()))?;
        if self.signature.signer == transcript.dkg_id {
            crypto.verify_aggregate(self, self.signature.signer)?
        } else {
            Err(PermanentError::InappropriateDkgId(self.signature.signer))?
        }
        Ok(())
    }
}

impl SignatureVerify for RandomTapeShare {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_low_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| TransientError::DkgSummaryNotFound(self.height()))?;
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
    ) -> ValidationResult<ValidatorError> {
        let transcript = active_low_threshold_transcript(pool.as_cache(), self.height())
            .ok_or_else(|| TransientError::DkgSummaryNotFound(self.height()))?;
        if self.signature.signer == transcript.dkg_id {
            crypto.verify_aggregate(self, self.signature.signer)?
        } else {
            Err(PermanentError::InappropriateDkgId(self.signature.signer))?
        }
        Ok(())
    }
}

impl SignatureVerify for RandomBeaconShare {
    fn verify_signature(
        &self,
        membership: &Membership,
        crypto: &dyn ConsensusCrypto,
        pool: &PoolReader<'_>,
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_low_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| TransientError::DkgSummaryNotFound(self.height()))?;
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
    ) -> ValidationResult<ValidatorError> {
        let height = self.height();
        let transcript = active_high_threshold_transcript(pool.as_cache(), height)
            .ok_or_else(|| TransientError::DkgSummaryNotFound(self.height()))?;
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
        None => Err(ValidationError::from(TransientError::RandomBeaconNotFound(
            previous_height,
        ))),
    }
}

fn get_registry_version(
    pool: &PoolReader<'_>,
    height: Height,
) -> Result<RegistryVersion, ValidatorError> {
    match pool.registry_version(height) {
        Some(version) => Ok(version),
        None => Err(ValidationError::from(
            TransientError::FailedToGetRegistryVersion,
        )),
    }
}

fn verify_notaries(
    membership: &Membership,
    height: Height,
    previous_beacon: &RandomBeacon,
    signers: &[NodeId],
) -> ValidationResult<ValidatorError> {
    let threshold = membership.get_committee_threshold(height, Notarization::committee())?;
    let unique_signers: HashSet<_> = signers.iter().collect();
    if unique_signers.len() < signers.len() {
        Err(PermanentError::RepeatedSigner)?
    }
    if signers.len() < threshold {
        Err(PermanentError::InsufficientSignatures)?
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
    if !membership.node_belongs_to_notarization_committee(height, previous_beacon, node_id)? {
        Err(PermanentError::SignerNotInMultiSigCommittee(node_id))?
    };
    Ok(())
}

fn verify_threshold_committee(
    membership: &Membership,
    node_id: NodeId,
    height: Height,
    committee: Committee,
) -> ValidationResult<ValidatorError> {
    if !membership.node_belongs_to_threshold_committee(node_id, height, committee)? {
        Err(PermanentError::SignerNotInThresholdCommittee(node_id))?
    }
    Ok(())
}

fn get_notarized_parent(
    pool: &PoolReader<'_>,
    proposal: &BlockProposal,
) -> Result<Block, ValidatorError> {
    let parent = &proposal.as_ref().parent;
    let height = proposal.height().decrement();
    pool.get_notarized_block(parent, height)
        .map_err(|_| TransientError::BlockNotFound(parent.clone(), height).into())
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
}

impl Validator {
    #[allow(clippy::too_many_arguments)]
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
        }
    }

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
            &|| self.call_with_metrics("Finalization", &validate_finalization),
            &|| self.call_with_metrics("Notarization", &validate_notarization),
            &|| self.call_with_metrics("BlockProposal", &validate_blocks),
            &|| self.call_with_metrics("RandomBeacon", &validate_beacons),
            &|| self.call_with_metrics("RandomTape", &validate_tapes),
            &|| self.call_with_metrics("CUP", &validate_catch_up_packages),
            &|| self.call_with_metrics("FinalizationShare", &validate_finalization_shares),
            &|| self.call_with_metrics("NotarizationShare", &validate_notarization_shares),
            &|| self.call_with_metrics("RandomBeaconShare", &validate_beacon_shares),
            &|| self.call_with_metrics("RandomTapeShare", &validate_tape_shares),
            &|| self.call_with_metrics("CUPShare", &validate_catch_up_package_shares),
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

    /// Verify the signature of some artifact that is verifiable with the
    /// `SignatureVerify` trait.
    fn verify_signature<S: SignatureVerify>(
        &self,
        pool_reader: &PoolReader<'_>,
        artifact: &S,
    ) -> ValidationResult<ValidatorError> {
        artifact.verify_signature(self.membership.as_ref(), self.crypto.as_ref(), pool_reader)
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

    /// Return a `ChangeSet` of `FinalizationShares`s. See
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
        T: NotaryIssued,
    {
        // This is checked before entering this function.
        debug_assert!(notary_issued.height() > pool_reader.get_finalized_height());
        if notary_issued.content.is_duplicate(pool_reader) {
            return Some(ChangeAction::RemoveFromUnvalidated(
                notary_issued.into_message(),
            ));
        }
        match notary_issued.content.dependencies_validated(pool_reader) {
            Ok(()) => {
                let verification = self.verify_signature(pool_reader, &notary_issued);
                self.compute_action_from_sig_verification(
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
        let dkg_pool = &*self.dkg_pool.read().unwrap();

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
                    let verification = self.verify_signature(pool_reader, &notarization);
                    if let Err(ValidationError::Permanent(e)) = verification {
                        change_set.push(ChangeAction::HandleInvalid(
                            notarization.into_message(),
                            format!("{:?}", e),
                        ));
                    } else if verification.is_ok() {
                        if get_notarized_parent(pool_reader, &proposal).is_ok() {
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

                match self.check_block_validity(pool_reader, &proposal, dkg_pool) {
                    Ok(()) => {
                        self.metrics.observe_block(pool_reader, &proposal);
                        known_ranks.insert(proposal.height(), Some(proposal.rank()));
                        change_set.push(ChangeAction::MoveToValidated(proposal.into_message()))
                    }
                    Err(ValidationError::Permanent(err)) => change_set.push(
                        ChangeAction::HandleInvalid(proposal.into_message(), format!("{:?}", err)),
                    ),
                    Err(ValidationError::Transient(err)) => {
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
    /// validated pool. A `ValidatiorError::TransientError` value is returned
    /// when any of the following conditions are met:
    ///
    /// - the `Block`'s validation context is not available locally.
    /// - The `Block`'s parent is not in the validated pool
    /// - The `Block`'s parent is not notarized
    /// - The payload_builder returns an `Err` result of any kind
    ///
    /// A `ValidatorError::PermanentError` is returned when any of the following
    /// conditions are met:
    ///
    /// - The signer of the `BlockProposal` does not have the rank claimed on
    ///   the `Block`
    /// - The signature on the `BlockProposal` is invalid.
    /// - Any messages included in the payload are present in some ancestor of
    ///   the block
    /// - Any of the values in the `ValidationContext` on the `Block` are less
    ///   than the corresponding value on the parent `Block`'s
    ///   `ValidationContext`.
    fn check_block_validity(
        &self,
        pool_reader: &PoolReader<'_>,
        proposal: &BlockProposal,
        dkg_pool: &dyn DkgPool,
    ) -> ValidationResult<ValidatorError> {
        if proposal.height() == Height::from(0) {
            Err(PermanentError::CannotVerifyBlockHeightZero)?
        }

        // If the replica is upgrading, block payload should be empty.
        match pool_reader
            .registry_version(proposal.height())
            .and_then(|registry_version| {
                lookup_replica_version(
                    self.registry_client.as_ref(),
                    self.replica_config.subnet_id,
                    &self.log,
                    registry_version,
                )
            }) {
            Some(replica_version) => {
                if replica_version != ReplicaVersion::default() {
                    let payload = proposal.as_ref().payload.as_ref();
                    if !payload.is_summary() && !payload.is_empty() {
                        Err(PermanentError::NonEmptyPayloadPastUpgradePoint)?
                    }
                }
            }
            None => Err(TransientError::FailedToGetRegistryVersion)?,
        }

        let parent = get_notarized_parent(pool_reader, proposal)?;
        self.verify_signature(pool_reader, proposal)?;

        // Ensure registry_version, certified_height and time are non-decreasing.
        let proposal = proposal.as_ref();
        if !proposal.context.greater_or_equal(&parent.context) {
            Err(PermanentError::DecreasingValidationContext)?
        }

        let locally_available_context = ValidationContext {
            certified_height: self.state_manager.latest_certified_height(),
            registry_version: self.registry_client.get_latest_version(),
            time: self.time_source.get_relative_time(),
        };

        // If any part of our locally available validation context is less than the
        // proposal's validation context, we cannot validate it yet.
        if !locally_available_context.greater_or_equal(&proposal.context) {
            Err(TransientError::ValidationContextNotReached(
                proposal.context.clone(),
                locally_available_context,
            ))?
        }

        let payloads = pool_reader.get_payloads_from_height(
            proposal.context.certified_height.increment(),
            parent.clone(),
        );

        self.payload_builder
            .validate_payload(
                proposal.height,
                &proposal.payload,
                &payloads,
                &proposal.context,
            )
            .map_err(|err| {
                err.map(
                    PermanentError::PayloadValidationError,
                    TransientError::PayloadValidationError,
                )
            })?;

        let timer = self
            .metrics
            .validation_duration
            .with_label_values(&["ecdsa"])
            .start_timer();
        let ret = ecdsa::validate_payload(
            self.replica_config.subnet_id,
            self.registry_client.as_ref(),
            self.crypto.as_ref(),
            pool_reader,
            self.state_manager.as_ref(),
            &proposal.context,
            &parent,
            proposal.payload.as_ref(),
        )
        .map_err(|err| {
            err.map(
                PermanentError::EcdsaPayloadValidationError,
                TransientError::EcdsaPayloadValidationError,
            )
        });
        let elapsed = timer.stop_and_record();
        self.metrics.add_to_ecdsa_time_per_validator_run(elapsed);
        ret?;

        let timer = self
            .metrics
            .validation_duration
            .with_label_values(&["Dkg"])
            .start_timer();
        let ret = dkg::validate_payload(
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
                PermanentError::DkgPayloadValidationError,
                TransientError::DkgPayloadValidationError,
            )
        });
        let elapsed = timer.stop_and_record();
        self.metrics.add_to_dkg_time_per_validator_run(elapsed);
        ret
    }

    /// Return a `ChangeSet` of `RandomBeacon` artifacts. See
    /// `validate_beacon_artifacts` for details about exactly what is checked.
    fn validate_beacons(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let last_beacon = pool_reader.get_random_beacon_tip();
        // Only a single height is validated, per round.
        self.validate_beacon_artifacts(
            pool_reader,
            &last_beacon,
            pool_reader
                .pool()
                .unvalidated()
                .random_beacon()
                .get_by_height(last_beacon.height().increment()),
        )
    }

    /// Return a `ChangeSet` of `RandomBeaconShare` artifacts. See
    /// `validate_beacon_artifacts` for details about exactly what is checked.
    fn validate_beacon_shares(&self, pool_reader: &PoolReader<'_>) -> ChangeSet {
        let last_beacon = pool_reader.get_random_beacon_tip();
        // Since the parent beacon is required to be already validated, only a single
        // height is checked.
        self.validate_beacon_artifacts(
            pool_reader,
            &last_beacon,
            pool_reader
                .pool()
                .unvalidated()
                .random_beacon_share()
                .get_by_height(last_beacon.height().increment()),
        )
    }

    /// Check the validity of a collection of RandomBeacon(/Share)s against the
    /// random beacon tip. This consists of checking whether each beacon:
    /// * points to this parent,
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    /// Precondition: all elements in beacons must be at height last_beacon + 1
    fn validate_beacon_artifacts<S>(
        &self,
        pool_reader: &PoolReader<'_>,
        last_beacon: &RandomBeacon,
        beacons: Box<dyn Iterator<Item = Signed<RandomBeaconContent, S>>>,
    ) -> ChangeSet
    where
        Signed<RandomBeaconContent, S>: SignatureVerify + ConsensusMessageHashable + Clone,
    {
        let last_hash: CryptoHashOf<RandomBeacon> = ic_crypto::crypto_hash(last_beacon);
        let last_height = last_beacon.content.height();
        beacons
            .filter_map(|beacon| {
                // This function expects to handle only the following height.
                debug_assert_eq!(beacon.content.height, last_height.increment());
                if last_hash != beacon.content.parent {
                    Some(ChangeAction::HandleInvalid(
                        beacon.into_message(),
                        "The parent hash of the beacon was not correct".to_string(),
                    ))
                } else {
                    let verification = self.verify_signature(pool_reader, &beacon);
                    self.compute_action_from_sig_verification(
                        pool_reader,
                        verification,
                        beacon.into_message(),
                    )
                }
            })
            .collect()
    }

    /// Return a `ChangeSet` of `RandomTape` artifacts. See
    /// `validate_tape_artifacts` for details about exactly what is checked.
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
        self.validate_tape_artifacts(
            pool_reader,
            pool_reader
                .pool()
                .unvalidated()
                .random_tape()
                .get_by_height_range(range),
        )
    }

    /// Return a `ChangeSet` of `RandomTapeShare` artifacts. See
    /// `validate_tape_artifacts` for details about exactly what is checked.
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
        self.validate_tape_artifacts(
            pool_reader,
            pool_reader
                .pool()
                .unvalidated()
                .random_tape_share()
                .get_by_height_range(range),
        )
    }

    /// Check the validity of a Vec of RandomTape artifacts. This function
    /// assumes that the received artifacts are already filtered by their height
    /// and checks whether each RandomTapeContent
    /// * has non-zero height,
    /// * is signed by member(s) of the threshold group,
    /// * has a valid signature.
    fn validate_tape_artifacts<S>(
        &self,
        pool_reader: &PoolReader<'_>,
        tapes: Box<dyn Iterator<Item = Signed<RandomTapeContent, S>>>,
    ) -> ChangeSet
    where
        Signed<RandomTapeContent, S>: SignatureVerify + ConsensusMessageHashable + Clone,
    {
        tapes
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
                    let verification = self.verify_signature(pool_reader, &tape);
                    self.compute_action_from_sig_verification(
                        pool_reader,
                        verification,
                        tape.into_message(),
                    )
                }
            })
            .collect()
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
                    .crypto
                    .verify_combined_threshold_sig_by_public_key(
                        &catch_up_package.signature.signature,
                        &catch_up_package.content,
                        self.replica_config.subnet_id,
                        // Using any registry version here is fine because we assume that the
                        // public key of the subnet will not change. The alternative of trying
                        // to use the registry version obtained from the pool is not an option
                        // here because we may not be able to get a proper value if we do not
                        // have the relevant portion of the chain.
                        self.registry_client.get_latest_version(),
                    )
                    .map_err(ValidatorError::from);

                self.compute_action_from_sig_verification(
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
                        let verification = self.verify_signature(
                            pool_reader,
                            &Signed {
                                content: CatchUpContent::from_share_content(
                                    share.content.clone(),
                                    block,
                                ),
                                signature: share.signature.clone(),
                            },
                        );
                        self.compute_action_from_sig_verification(
                            pool_reader,
                            verification,
                            share.into_message(),
                        )
                    }
                    Err(ValidationError::Permanent(err)) => Some(ChangeAction::HandleInvalid(
                        share.into_message(),
                        format!("{:?}", err),
                    )),
                    Err(ValidationError::Transient(err)) => {
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
    /// consistent, PermanentError if it is inconsistent, and TransientError
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
            .ok_or(TransientError::FinalizedBlockNotFound(height))?;

        if ic_crypto::crypto_hash(&block) != share_content.block {
            warn!(self.log, "Block from received CatchUpShareContent does not match finalized block in the pool: {:?} {:?}", share_content, block);
            Err(PermanentError::MismatchedBlockInCatchUpPackageShare)?
        }
        let beacon = pool_reader
            .get_random_beacon(height)
            .ok_or(TransientError::RandomBeaconNotFound(height))?;

        if &beacon != share_content.random_beacon.get_value() {
            warn!(self.log, "RandomBeacon from received CatchUpContent does not match RandomBeacon in the pool: {:?} {:?}", share_content, beacon);
            Err(PermanentError::MismatchedRandomBeaconInCatchUpPackageShare)?
        }

        let hash = self
            .state_manager
            .get_state_hash_at(height)
            .map_err(TransientError::StateHashError)?;
        if hash != share_content.state_hash {
            warn!( self.log, "State hash from received CatchUpContent does not match local state hash: {:?} {:?}", share_content, hash);
            Err(PermanentError::MismatchedStateHashInCatchUpPackageShare)?
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

    fn compute_action_from_sig_verification(
        &self,
        pool_reader: &PoolReader<'_>,
        result: ValidationResult<ValidatorError>,
        message: ConsensusMessage,
    ) -> Option<ChangeAction> {
        match result {
            Ok(()) => Some(ChangeAction::MoveToValidated(message)),
            Err(ValidationError::Permanent(s)) => {
                Some(ChangeAction::HandleInvalid(message, format!("{:?}", s)))
            }
            Err(ValidationError::Transient(err)) => {
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
                now >= timestamp // otherwise subtraction can panic!
                    && now - timestamp >= Duration::from_secs(SECONDS_TO_LOG_UNVALIDATED)
            }
            None => false, // should never happen.
        }
    }
}

/// Return a `ChangeSet` that moves all block proposals in the range to the
/// validated pool.
#[cfg(feature = "malicious_code")]
pub(crate) fn maliciously_validate_all_blocks(
    pool_reader: &PoolReader,
    logger: &ReplicaLogger,
) -> ChangeSet {
    trace!(logger, "maliciously_validate_all_blocks");
    let mut change_set = Vec::new();

    let finalized_height = pool_reader.get_finalized_height();
    let beacon_height = pool_reader.get_random_beacon_height();
    let max_height = beacon_height.increment();
    let range = HeightRange::new(finalized_height.increment(), max_height);

    for proposal in pool_reader
        .pool()
        .unvalidated()
        .block_proposal()
        .get_by_height_range(range)
    {
        change_set.push(ChangeAction::MoveToValidated(proposal.into_message()))
    }

    if !change_set.is_empty() {
        ic_logger::debug!(
            logger,
            "[MALICIOUS] maliciously validating all {} proposals",
            change_set.len()
        );
    }

    change_set
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::consensus::mocks::{
        dependencies_with_subnet_params, Dependencies, MockPayloadBuilder,
    };
    use crate::consensus::utils::get_block_maker_delay;
    use ic_artifact_pool::dkg_pool::DkgPoolImpl;
    use ic_interfaces::messaging::XNetTransientValidationError;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{
        assert_changeset_matches_pattern,
        consensus::fake::*,
        crypto::CryptoReturningOk,
        matches_pattern,
        message_routing::MockMessageRouting,
        state_manager::RefMockStateManager,
        types::ids::{node_test_id, subnet_test_id},
        FastForwardTimeSource,
    };
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_types::replica_config::ReplicaConfig;
    use std::borrow::Borrow;
    use std::sync::{Arc, RwLock};

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

    #[allow(clippy::type_complexity)]
    fn setup_dependencies(
        pool_config: ic_config::artifact_pool::ArtifactPoolConfig,
        node_ids: &[NodeId],
    ) -> (
        Arc<MockPayloadBuilder>,
        Arc<Membership>,
        Arc<RefMockStateManager>,
        Arc<MockMessageRouting>,
        Arc<CryptoReturningOk>,
        Arc<ProtoRegistryDataProvider>,
        Arc<FakeRegistryClient>,
        TestConsensusPool,
        Arc<RwLock<DkgPoolImpl>>,
        Arc<FastForwardTimeSource>,
        ReplicaConfig,
    ) {
        let Dependencies {
            replica_config,
            time_source,
            pool,
            membership,
            registry_data_provider,
            registry,
            crypto,
            state_manager,
            ..
        } = dependencies_with_subnet_params(
            pool_config,
            subnet_test_id(0),
            vec![(
                1,
                SubnetRecordBuilder::from(node_ids)
                    .with_dkg_interval_length(9)
                    .build(),
            )],
        );
        let dkg_pool = Arc::new(RwLock::new(ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
            MetricsRegistry::new(),
        )));
        (
            Arc::new(MockPayloadBuilder::new()),
            membership,
            state_manager,
            Arc::new(MockMessageRouting::new()),
            crypto,
            registry_data_provider,
            registry,
            pool,
            dkg_pool,
            time_source,
            replica_config,
        )
    }

    #[test]
    fn test_validate_catch_up_package_shares() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            // Manually construct a cup share
            let random_beacon = pool.make_next_beacon();
            let random_beacon_hash = HashedRandomBeacon::new(ic_crypto::crypto_hash, random_beacon);
            let block = Block::from(pool.make_next_block());
            let block_hash = HashedBlock::new(ic_crypto::crypto_hash, block);

            // The state manager is mocked and the `StateHash` is completely arbitrary. It
            // must just be the same as in the `CatchUpPackageShare`.
            let state_hash = CryptoHashOfState::from(CryptoHash(vec![1u8; 32]));
            state_manager
                .mock
                .write()
                .unwrap()
                .expect_get_state_hash_at()
                .return_const(Ok(state_hash.clone()));

            let cup_share = Signed {
                content: CatchUpShareContent::from(&CatchUpContent::new(
                    block_hash,
                    random_beacon_hash,
                    state_hash,
                )),
                signature: ThresholdSignatureShare::fake(node_test_id(0)),
            };

            // Advance by one round so we have a finalized block at height 1
            // This is neccesary for the validate function to succeed
            pool.advance_round_normal_operation();
            pool.insert_unvalidated(cup_share);

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            let pool_reader = PoolReader::new(&pool);
            let change_set = validator.validate_catch_up_package_shares(&pool_reader);

            // Check that the change set contains exactly the one `CatchUpPackageShare` we
            // expect it to.
            assert_eq!(change_set.len(), 1);
            match change_set[0] {
                ChangeAction::MoveToValidated(ConsensusMessage::CatchUpPackageShare(_)) => (),
                _ => panic!("expected change set to contain signed content"),
            }
        })
    }

    /// Test that Finalizations are not moved from `unvalidated` to `validated`
    /// unless a Notarization exists in `validated` for the associated block
    #[test]
    fn test_finalization_requires_notarization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());
            // Insert a Finalization for `block` in the unvalidated pool
            let share = FinalizationShare::fake(block.as_ref(), block.signature.signer);
            pool.insert_unvalidated(Finalization::fake(share.content));

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            time: ic_test_utilities::mock_time(),
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(4),
            time: ic_test_utilities::mock_time(),
        }),);
        assert!(ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_test_utilities::mock_time(),
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_test_utilities::mock_time(),
        }),);
        assert!(ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(5),
            time: ic_test_utilities::mock_time(),
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(4),
            time: ic_test_utilities::mock_time(),
        }),);
        assert!(!ValidationContext {
            registry_version: RegistryVersion::from(10),
            certified_height: Height::from(5),
            time: ic_test_utilities::mock_time(),
        }
        .greater_or_equal(&ValidationContext {
            registry_version: RegistryVersion::from(11),
            certified_height: Height::from(6),
            time: ic_test_utilities::mock_time(),
        }),);
    }

    #[test]
    fn test_random_beacon_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            pool.advance_round_normal_operation();

            let validator = Validator::new(
                replica_config.clone(),
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            // Put a random tape share in the unvalidated pool
            let pool_reader = PoolReader::new(&pool);
            let beacon_1 = pool_reader.get_random_beacon(Height::from(1)).unwrap();
            let beacon_2 = RandomBeacon::from_parent(&beacon_1);
            let share_3 = RandomBeaconShare::fake(&beacon_2, replica_config.node_id);
            pool.insert_unvalidated(share_3.clone());

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
            pool.apply_changes(time_source.as_ref(), changeset);

            // share_3 now validates
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomBeaconShare(share_3))
            )
        })
    }

    #[test]
    fn test_random_tape_validation() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let (
                payload_builder,
                membership,
                state_manager,
                mut message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

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
            Arc::get_mut(&mut message_routing)
                .unwrap()
                .expect_expected_batch_height()
                .returning(move || *expected_batch_height_clone.read().unwrap());

            let validator = Validator::new(
                replica_config.clone(),
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 2);
            assert_eq!(
                changeset[1],
                ChangeAction::MoveToValidated(ConsensusMessage::RandomTapeShare(share_2))
            );
            assert_eq!(
                changeset[0],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::RandomTapeShare(share_1))
            );

            // Accept changes
            pool.apply_changes(time_source.as_ref(), changeset);

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
            pool.apply_changes(time_source.as_ref(), changeset);

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
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &committee);
            Arc::get_mut(&mut payload_builder)
                .unwrap()
                .expect_validate_payload()
                .withf(move |_, _, payloads, _| {
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
            let parent = block_chain.last().unwrap();
            let mut test_block: Block = pool.make_next_block_from_parent(parent.as_ref()).into();
            let rank = Rank(1);
            let node_id = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                test_block.height(),
                &committee,
                rank,
            );

            test_block.context.registry_version = RegistryVersion::from(11);
            test_block.context.certified_height = Height::from(1);
            test_block.rank = rank;
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

            let validator = Validator::new(
                replica_config.clone(),
                membership,
                registry_client.clone(),
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            // ensure that the validator initially does not validate anything, as it is not
            // time for rank 1 yet
            assert!(validator
                .on_state_change(&PoolReader::new(&pool))
                .is_empty(),);

            // After sufficiently advancing the time, ensure that the validator validates
            // the block
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
            time_source
                .set_time(time_source.get_relative_time() + delay)
                .unwrap();
            let valid_results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_valid(&valid_results, &block_proposal);
        });
    }

    #[test]
    // Construct a proposal block with a non-notarized parent and make sure we're
    // not validating this block until the parent gets notarized.
    fn test_block_validation_without_notarized_parent() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let certified_height = Height::from(1);
            let committee = (0..4).map(node_test_id).collect::<Vec<_>>();
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &committee);
            Arc::get_mut(&mut payload_builder)
                .unwrap()
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
                    Arc::new(ic_test_utilities::state::get_initial_state(0, 0)),
                )));

            add_subnet_record(
                &data_provider,
                11,
                replica_config.subnet_id,
                SubnetRecordBuilder::from(&[]).build(),
            );

            registry_client.update_to_latest_version();

            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(3));

            let validator = Validator::new(
                replica_config,
                membership.clone(),
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            let valid_results = validator.on_state_change(&PoolReader::new(&pool));
            assert_block_valid(&valid_results, &test_block);
            pool.apply_changes(time_source.as_ref(), valid_results);

            let mut next_block = pool.make_next_block_from_parent(test_block.as_ref());
            next_block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                next_block.height(),
                &committee,
                Rank(0),
            );
            next_block.content.as_mut().context.registry_version = RegistryVersion::from(11);
            next_block.content.as_mut().context.certified_height = Height::from(1);
            next_block.content.as_mut().rank = Rank(0);
            next_block.update_content();
            pool.insert_unvalidated(next_block.clone());
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
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &subnet_members);
            Arc::get_mut(&mut payload_builder)
                .unwrap()
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

            let validator = Validator::new(
                replica_config,
                membership.clone(),
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            pool.apply_changes(time_source.as_ref(), results);

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
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &subnet_members);

            Arc::get_mut(&mut payload_builder)
                .unwrap()
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

            let validator = Validator::new(
                replica_config,
                membership.clone(),
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            let results = validator.on_state_change(&PoolReader::new(&pool));
            match results.first() {
                Some(ChangeAction::MoveToValidated(ConsensusMessage::BlockProposal(proposal))) => {
                    assert_eq!(proposal, &test_block);
                }
                _ => panic!(),
            }
        })
    }

    #[test]
    fn test_block_context_time() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &subnet_members);

            Arc::get_mut(&mut payload_builder)
                .unwrap()
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

            let validator = Validator::new(
                replica_config,
                membership.clone(),
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );
            // Construct a block with a time greater than the current consensus time, which
            // should not be validated yet.
            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            let block_time = 10000;
            test_block.content.as_mut().context.time =
                Time::from_nanos_since_unix_epoch(block_time);
            test_block.update_content();
            pool.insert_unvalidated(test_block.clone());
            let results = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(results, ChangeSet::new());

            // when we advance the time, it should be validated
            time_source
                .set_time(Time::from_nanos_since_unix_epoch(block_time))
                .unwrap();
            let results = validator.on_state_change(&PoolReader::new(&pool));
            match results.first() {
                Some(ChangeAction::MoveToValidated(ConsensusMessage::BlockProposal(proposal))) => {
                    assert_eq!(proposal, &test_block);
                }
                _ => panic!(),
            }

            // after we finalize a block with time `block_time`, the validator should reject
            // a child block with a smaller time
            pool.apply_changes(time_source.as_ref(), results);
            pool.notarize(&test_block);
            pool.finalize(&test_block);
            pool.insert_validated(pool.make_next_beacon());

            let mut test_block = make_next_block(&pool, membership.as_ref(), &subnet_members);
            test_block.content.as_mut().context.time =
                Time::from_nanos_since_unix_epoch(block_time - 1);
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
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());
            let block = pool.make_next_block();
            pool.insert_validated(block.clone());

            let share = NotarizationShare::fake(block.as_ref(), block.signature.signer);
            let mut notarization = Notarization::fake(share.content);
            notarization.signature.signers = vec![];

            pool.insert_unvalidated(notarization.clone());

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

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
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

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

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            // Only one notarization is emitted in the ChangeSet.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert!(matches!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::Notarization(_))
            ));
            pool.apply_changes(time_source.as_ref(), changeset);

            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert!(matches!(
                changeset[0],
                ChangeAction::RemoveFromUnvalidated(ConsensusMessage::Notarization(_))
            ));
            pool.apply_changes(time_source.as_ref(), changeset);

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
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

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

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            // Only one finalization is emitted in the ChangeSet.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert!(matches!(
                changeset[0],
                ChangeAction::MoveToValidated(ConsensusMessage::Finalization(_))
            ));
            assert_eq!(changeset.len(), 1);
            pool.apply_changes(time_source.as_ref(), changeset);

            // Next run does not consider the extra Finalization.
            let changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 0);
        })
    }

    #[test]
    fn test_validate_catch_up_package() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            // Setup validator dependencies.
            let (
                payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &(0..4).map(node_test_id).collect::<Vec<_>>());

            pool.advance_round_normal_operation_n(9);
            pool.prepare_round().dont_add_catch_up_package().advance();

            let block = pool.latest_notarized_blocks().next().unwrap();
            pool.finalize_block(&block);
            let finalization = pool.validated().finalization().get_highest().unwrap();
            let catch_up_package = pool.make_catch_up_package(finalization.height());
            pool.insert_unvalidated(catch_up_package.clone());

            state_manager
                .get_mut()
                .expect_get_state_hash_at()
                .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));

            let validator = Validator::new(
                replica_config,
                membership,
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            let mut changeset = validator.on_state_change(&PoolReader::new(&pool));
            assert_eq!(changeset.len(), 1);
            assert_eq!(
                changeset.pop(),
                Some(ChangeAction::MoveToValidated(
                    ConsensusMessage::CatchUpPackage(catch_up_package)
                ))
            );
        })
    }

    #[test]
    fn test_block_validated_through_notarization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_members = (0..4).map(node_test_id).collect::<Vec<_>>();
            let (
                mut payload_builder,
                membership,
                state_manager,
                message_routing,
                crypto,
                _data_provider,
                registry_client,
                mut pool,
                dkg_pool,
                time_source,
                replica_config,
            ) = setup_dependencies(pool_config, &subnet_members);
            pool.advance_round_normal_operation();

            Arc::get_mut(&mut payload_builder)
                .unwrap()
                .expect_validate_payload()
                .returning(|_, _, _, _| {
                    Err(ValidationError::Transient(
                        PayloadTransientError::XNetPayloadValidationError(
                            XNetTransientValidationError::StateNotCommittedYet(Height::from(0)),
                        ),
                    ))
                });
            state_manager
                .get_mut()
                .expect_latest_certified_height()
                .return_const(Height::from(0));

            let validator = Validator::new(
                replica_config,
                membership.clone(),
                registry_client,
                crypto,
                payload_builder,
                state_manager,
                message_routing,
                dkg_pool,
                no_op_logger(),
                ValidatorMetrics::new(MetricsRegistry::new()),
                Arc::clone(&time_source) as Arc<_>,
            );

            // First ensure that we require the parent block
            pool.insert_validated(pool.make_next_beacon());
            let parent_block = pool.make_next_block();
            let mut block = pool.make_next_block_from_parent(parent_block.as_ref());
            block.signature.signer = get_block_maker_by_rank(
                membership.borrow(),
                &PoolReader::new(&pool),
                block.height(),
                &subnet_members,
                Rank(0),
            );
            block.content.as_mut().rank = Rank(0);

            block.update_content();
            let content =
                NotarizationContent::new(block.height(), ic_crypto::crypto_hash(block.as_ref()));
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
            pool.apply_changes(time_source.as_ref(), changeset);
        })
    }
}
