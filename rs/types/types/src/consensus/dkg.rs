//! Defines types used for distributed key generation.

use super::*;
use crate::{
    ReplicaVersion,
    artifact::PbArtifact,
    consensus::backwards_compatibility::BackwardsCompatibleOption,
    crypto::threshold_sig::ni_dkg::{
        NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTranscript,
        config::NiDkgConfig,
        errors::{
            create_transcript_error::DkgCreateTranscriptError,
            verify_dealing_error::DkgVerifyDealingError,
        },
    },
    messages::CallbackId,
    registry::RegistryClientError,
    state_manager::StateManagerError,
};
use ic_protobuf::types::v1 as pb;
use serde_with::serde_as;
use std::collections::BTreeMap;

/// Contains a Node's contribution to a DKG dealing.
pub type Message = BasicSigned<DealingContent>;

impl IdentifiableArtifact for Message {
    const NAME: &'static str = "dkg";
    type Id = DkgMessageId;
    fn id(&self) -> Self::Id {
        self.into()
    }
}

impl PbArtifact for Message {
    type PbId = ic_protobuf::types::v1::DkgMessageId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = ic_protobuf::types::v1::DkgMessage;
    type PbMessageError = ProxyDecodeError;
}

/// Identifier of a DKG message.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
pub struct DkgMessageId {
    pub hash: CryptoHashOf<Message>,
    pub height: Height,
}

impl From<&Message> for DkgMessageId {
    fn from(msg: &Message) -> Self {
        Self {
            hash: crypto_hash(msg),
            height: msg.content.dkg_id.start_block_height,
        }
    }
}

impl From<DkgMessageId> for pb::DkgMessageId {
    fn from(id: DkgMessageId) -> Self {
        Self {
            hash: id.hash.clone().get().0,
            height: id.height.get(),
        }
    }
}

impl TryFrom<pb::DkgMessageId> for DkgMessageId {
    type Error = ProxyDecodeError;

    fn try_from(id: pb::DkgMessageId) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: CryptoHash(id.hash.clone()).into(),
            height: Height::from(id.height),
        })
    }
}

/// Holds the content of a DKG dealing
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DealingContent {
    pub version: ReplicaVersion,
    /// the cryptographic data of the dealing
    pub dealing: NiDkgDealing,
    /// The id of the DKG instance this dealing belongs to
    pub dkg_id: NiDkgId,
}

impl DealingContent {
    /// Create a new DealingContent
    pub fn new(dealing: NiDkgDealing, dkg_id: NiDkgId) -> Self {
        DealingContent {
            version: ReplicaVersion::default(),
            dealing,
            dkg_id,
        }
    }
}

impl SignedBytesWithoutDomainSeparator for DealingContent {
    fn write_signed_bytes_without_domain_separator(&self, bytes: &mut Vec<u8>) {
        serde_cbor::to_writer(bytes, &self).unwrap();
    }
}

impl From<Message> for pb::DkgMessage {
    fn from(message: Message) -> Self {
        Self {
            replica_version: message.content.version.to_string(),
            dkg_id: Some(pb::NiDkgId::from(message.content.dkg_id)),
            dealing: bincode::serialize(&message.content.dealing).unwrap(),
            signature: message.signature.signature.get().0,
            signer: Some(crate::node_id_into_protobuf(message.signature.signer)),
        }
    }
}

impl From<&Message> for pb::DkgMessage {
    fn from(message: &Message) -> Self {
        Self {
            replica_version: message.content.version.to_string(),
            dkg_id: Some(pb::NiDkgId::from(message.content.dkg_id.clone())),
            dealing: bincode::serialize(&message.content.dealing).unwrap(),
            signature: message.signature.signature.clone().get().0,
            signer: Some(crate::node_id_into_protobuf(message.signature.signer)),
        }
    }
}

impl TryFrom<pb::DkgMessage> for Message {
    type Error = ProxyDecodeError;

    fn try_from(message: pb::DkgMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            content: DealingContent {
                version: ReplicaVersion::try_from(message.replica_version)?,
                dealing: bincode::deserialize(&message.dealing)?,
                dkg_id: try_from_option_field(message.dkg_id, "DkgId not found")?,
            },
            signature: BasicSignature {
                signature: BasicSigOf::from(BasicSig(message.signature)),
                signer: node_id_try_from_option(message.signer)?,
            },
        })
    }
}

impl HasVersion for DealingContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

/// A NiDKG transcript result computed for a remote subnet, together with the
/// originating DKG id and the callback id of the request it answers.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct RemoteTranscriptResult {
    /// The id of the DKG instance this transcript belongs to.
    pub dkg_id: NiDkgId,
    /// The callback id of the request this transcript answers.
    pub callback_id: CallbackId,
    /// The transcript itself, or an error message describing why it could not
    /// be created.
    pub transcript_result: Result<NiDkgTranscript, String>,
}

impl RemoteTranscriptResult {
    /// Create a new [`RemoteTranscriptResult`].
    pub fn new(
        dkg_id: NiDkgId,
        callback_id: CallbackId,
        transcript_result: Result<NiDkgTranscript, String>,
    ) -> Self {
        Self {
            dkg_id,
            callback_id,
            transcript_result,
        }
    }
}

/// Status of remote DKG attempts for a given target subnet.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum RemoteDkgAttempts {
    /// The DKG for the target subnet has been completed.
    Completed,
    /// The DKG for the target subnet is on attempt `n`. The contained value
    /// is always strictly greater than zero; do not construct this variant
    /// directly, use [`From<u32>`] instead.
    Attempt(u32),
}

impl From<u32> for RemoteDkgAttempts {
    /// Construct a value from a raw attempt count: `0` becomes
    /// [`RemoteDkgAttempts::Completed`], `n > 0` becomes
    /// [`RemoteDkgAttempts::Attempt`]`(n)`.
    fn from(count: u32) -> Self {
        if count == 0 {
            Self::Completed
        } else {
            Self::Attempt(count)
        }
    }
}

impl std::hash::Hash for RemoteDkgAttempts {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Forward to `u32::hash` of the underlying count so that the hash
        // matches the prior representation that stored a raw `u32`.
        match self {
            RemoteDkgAttempts::Completed => 0_u32.hash(state),
            RemoteDkgAttempts::Attempt(n) => n.hash(state),
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct SplittingArgs {
    pub destination_subnet_id: SubnetId,
    pub source_subnet_id: SubnetId,
}

#[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(test, derive(ExhaustiveSet))]
/// Represents the status of subnet splitting at the given summary height.
pub enum SubnetSplittingStatus {
    /// The subnet hasn't been requested to be split.
    #[default]
    NotScheduled,
    /// The subnet is requested to be split at the height of the summary block.
    /// Contains all the information necessary to determine the new subnet of the replica
    Scheduled(SplittingArgs),
    /// The subnet was split at the previous summary block.
    PostSplit { new_subnet_id: SubnetId },
}

/// The DKG summary will be present as the DKG payload at every block,
/// corresponding to the start of a new DKG interval.
#[serde_as]
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DkgSummary {
    /// The registry version used to create this summary.
    pub registry_version: RegistryVersion,
    /// The crypto configs of the currently computed DKGs, indexed by DKG Ids.
    #[serde_as(as = "Vec<(_, _)>")]
    pub configs: BTreeMap<NiDkgId, NiDkgConfig>,
    /// Current transcripts indexed by their tags. The values are guaranteed
    /// to be present, if a DKG is being computed for a given tag.
    #[serde_as(as = "Vec<(_, _)>")]
    current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    /// Transcripts for the next DKG interval. The values are not guaranteed to
    /// be present for any given tag (e.g., when the DKG computation
    /// failed); in this case we fall back the current transcript
    /// corresponding to this tag.
    #[serde_as(as = "Vec<(_, _)>")]
    next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    /// Transcripts that are computed for remote subnets.
    pub transcripts_for_remote_subnets: Vec<RemoteTranscriptResult>,
    /// The length of the current interval in rounds (following the start
    /// block).
    pub interval_length: Height,
    /// The length of the next interval in rounds (following the start block).
    pub next_interval_length: Height,
    /// The height of the block containing that summary.
    pub height: Height,
    /// The number of intervals a DKG for the given remote target was attempted.
    pub remote_dkg_attempts: BTreeMap<NiDkgTargetId, RemoteDkgAttempts>,
    /// Status of the subnet splitting.
    pub subnet_splitting_status: BackwardsCompatibleOption<SubnetSplittingStatus, false>,
}

impl DkgSummary {
    /// Create a new Summary
    pub fn new(
        configs: Vec<NiDkgConfig>,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        registry_version: RegistryVersion,
        interval_length: Height,
        next_interval_length: Height,
        height: Height,
        remote_dkg_attempts: BTreeMap<NiDkgTargetId, RemoteDkgAttempts>,
        subnet_splitting_status: SubnetSplittingStatus,
    ) -> Self {
        Self {
            configs: configs
                .into_iter()
                .map(|config| (config.dkg_id().clone(), config))
                .collect(),
            current_transcripts,
            next_transcripts,
            transcripts_for_remote_subnets: vec![],
            registry_version,
            interval_length,
            next_interval_length,
            height,
            remote_dkg_attempts,
            // subnet_splitting_status: BackwardsCompatibleOption::default(),
            subnet_splitting_status: BackwardsCompatibleOption::new_for_test_only(Some(
                subnet_splitting_status,
            )),
        }
    }

    /// Adds provided transcripts as current transcripts to the summary. Should
    /// be used for testing only.
    pub fn with_current_transcripts(
        mut self,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
    ) -> Self {
        self.current_transcripts = current_transcripts;
        self
    }

    /// Returns a reference to the current transcript for the given tag. Note
    /// that currently we expect that a valid summary contains the current
    /// transcript for any DKG tag.
    pub fn current_transcript(&self, tag: &NiDkgTag) -> Option<&NiDkgTranscript> {
        self.current_transcripts.get(tag)
    }

    /// Returns a reference to the current transcripts.
    pub fn current_transcripts(&self) -> &BTreeMap<NiDkgTag, NiDkgTranscript> {
        &self.current_transcripts
    }

    /// Returns a reference to the next transcript for the given tag if
    /// available.
    pub fn next_transcript(&self, tag: &NiDkgTag) -> Option<&NiDkgTranscript> {
        self.next_transcripts.get(tag)
    }

    /// Returns a reference to the next transcripts.
    pub fn next_transcripts(&self) -> &BTreeMap<NiDkgTag, NiDkgTranscript> {
        &self.next_transcripts
    }

    /// Return the set of transcripts (current and next) for all tags.
    /// This function avoids expensive copying when transcripts are large.
    pub fn into_transcripts(self) -> Vec<NiDkgTranscript> {
        self.current_transcripts
            .into_iter()
            .chain(self.next_transcripts)
            .map(|(_, t)| t)
            .collect()
    }

    /// Returns `true` if the provided height is included in the DKG interval
    /// corresponding to the current summary. Note that the summary block is
    /// considered to be part of the interval. For example, if the start height
    /// is 10 and the interval length is 5, we consider all heights from 10
    /// to 15 as being included in the interval.
    pub fn current_interval_includes(&self, height: Height) -> bool {
        let start = self.height;
        let end = start + self.interval_length;
        start <= height && height <= end
    }

    /// Returns `true` if the provided height is included in the next DKG
    /// interval. For example, if the current interval starts at height 10, the
    /// length of the current interval is 5, and the length of the following
    /// interval is 3, we consider all heights from 16 to 19 as being
    /// included in the next interval.
    pub fn next_interval_includes(&self, height: Height) -> bool {
        let start = self.get_next_start_height();
        let end = start + self.next_interval_length;
        start <= height && height <= end
    }

    /// Returns the start height of the next interval. This would be the height,
    /// where the next summary block would appear.
    pub fn get_next_start_height(&self) -> Height {
        self.height + self.interval_length + Height::from(1)
    }

    /// Returns the oldest registry version that is still relevant to DKG.
    pub(crate) fn get_oldest_registry_version_in_use(&self) -> RegistryVersion {
        self.current_transcripts()
            .values()
            .map(|transcript| transcript.registry_version)
            .min()
            .expect("No current transcripts available")
    }

    pub fn subnet_splitting_status(&self) -> SubnetSplittingStatus {
        self.subnet_splitting_status
            .as_ref()
            .copied()
            .unwrap_or_default()
    }
}

fn build_transcripts_vec(
    transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
) -> Vec<pb::NiDkgTranscript> {
    transcripts
        .values()
        .map(pb::NiDkgTranscript::from)
        .collect()
}

fn build_callback_ided_transcripts_vec(
    transcripts: &[RemoteTranscriptResult],
) -> Vec<pb::CallbackIdedNiDkgTranscript> {
    transcripts
        .iter()
        .map(|transcript| pb::CallbackIdedNiDkgTranscript {
            dkg_id: Some(pb::NiDkgId::from(transcript.dkg_id.clone())),
            transcript_result: match &transcript.transcript_result {
                Ok(transcript) => Some(pb::NiDkgTranscriptResult {
                    val: Some(pb::ni_dkg_transcript_result::Val::Transcript(
                        pb::NiDkgTranscript::from(transcript),
                    )),
                }),
                Err(error_string) => Some(pb::NiDkgTranscriptResult {
                    val: Some(pb::ni_dkg_transcript_result::Val::ErrorString(
                        error_string.as_bytes().to_vec(),
                    )),
                }),
            },
            callback_id: transcript.callback_id.get(),
        })
        .collect()
}

fn build_remote_dkg_attempts_vec(
    map: &BTreeMap<NiDkgTargetId, RemoteDkgAttempts>,
) -> Vec<pb::RemoteDkgAttemptCount> {
    map.iter()
        .map(|(target_id, attempts)| {
            let attempt_no = match attempts {
                RemoteDkgAttempts::Completed => 0,
                RemoteDkgAttempts::Attempt(n) => *n,
            };
            pb::RemoteDkgAttemptCount {
                target_id: target_id.to_vec(),
                attempt_no,
            }
        })
        .collect()
}

impl From<&DkgSummary> for pb::Summary {
    fn from(
        DkgSummary {
            registry_version,
            configs,
            current_transcripts,
            next_transcripts,
            transcripts_for_remote_subnets,
            interval_length,
            next_interval_length,
            height,
            remote_dkg_attempts,
            subnet_splitting_status,
        }: &DkgSummary,
    ) -> Self {
        Self {
            registry_version: registry_version.get(),
            configs: configs.values().map(pb::NiDkgConfig::from).collect(),
            current_transcripts: build_transcripts_vec(current_transcripts),
            next_transcripts: build_transcripts_vec(next_transcripts),
            interval_length: interval_length.get(),
            next_interval_length: next_interval_length.get(),
            height: height.get(),
            transcripts_for_remote_subnets: build_callback_ided_transcripts_vec(
                transcripts_for_remote_subnets,
            ),
            remote_dkg_attempts: build_remote_dkg_attempts_vec(remote_dkg_attempts),
            subnet_splitting_status: subnet_splitting_status
                .as_ref()
                .map(pb::summary::SubnetSplittingStatus::from),
        }
    }
}

fn build_tagged_transcripts_map(
    transcripts: &[pb::NiDkgTranscript],
) -> Result<BTreeMap<NiDkgTag, NiDkgTranscript>, ProxyDecodeError> {
    transcripts
        .iter()
        .map(|transcript_pb| {
            let transcript = NiDkgTranscript::try_from(transcript_pb)?;
            Ok((transcript.dkg_id.dkg_tag.clone(), transcript))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

fn build_transcripts_vec_from_pb(
    transcripts: Vec<pb::CallbackIdedNiDkgTranscript>,
) -> Result<Vec<RemoteTranscriptResult>, String> {
    let mut transcripts_for_remote_subnets = Vec::new();
    for transcript in transcripts.into_iter() {
        let id = transcript.dkg_id.ok_or_else(|| {
            "Missing DkgPayload::Summary::IdedNiDkgTranscript::NiDkgId".to_string()
        })?;
        let dkg_id = NiDkgId::try_from(id)
            .map_err(|e| format!("Failed to convert NiDkgId of transcript: {e:?}"))?;
        let callback_id = CallbackId::from(transcript.callback_id);
        let transcript_result = transcript
            .transcript_result
            .ok_or("Missing DkgPayload::Summary::IdedNiDkgTranscript::NiDkgTranscriptResult")?;
        let transcript_result = build_transcript_result(&transcript_result)
            .map_err(|e| format!("Failed to convert NiDkgTranscriptResult: {e:?}"))?;
        transcripts_for_remote_subnets.push(RemoteTranscriptResult {
            dkg_id,
            callback_id,
            transcript_result,
        });
    }
    Ok(transcripts_for_remote_subnets)
}

fn build_remote_dkg_attempts_map(
    vec: &[pb::RemoteDkgAttemptCount],
) -> BTreeMap<NiDkgTargetId, RemoteDkgAttempts> {
    vec.iter()
        .map(|item| {
            let mut id = [0_u8; NiDkgTargetId::SIZE];
            // Safely convert the received slice to a fixed-size slice.
            let mut v = Vec::<u8>::new();
            v.extend_from_slice(&item.target_id);
            v.resize(NiDkgTargetId::SIZE, 0_u8);
            id.copy_from_slice(&v);
            // Return the key-value pair.
            (
                NiDkgTargetId::new(id),
                RemoteDkgAttempts::from(item.attempt_no),
            )
        })
        .collect()
}

fn build_transcript_result(
    transcript_result: &pb::NiDkgTranscriptResult,
) -> Result<Result<NiDkgTranscript, String>, String> {
    match transcript_result
        .val
        .as_ref()
        .ok_or("Val missing in DkgPayload::Summary::IdedNiDkgTranscript::NiDkgTranscriptResult")?
    {
        pb::ni_dkg_transcript_result::Val::Transcript(transcript) => Ok(Ok(
            NiDkgTranscript::try_from(transcript).map_err(|e| e.to_string())?,
        )),
        pb::ni_dkg_transcript_result::Val::ErrorString(error_string) => {
            Ok(Err(std::str::from_utf8(error_string)
                .map_err(|e| format!("Failed to convert ErrorString: {e:?}"))?
                .to_string()))
        }
    }
}

impl From<SplittingArgs> for pb::SplittingArgs {
    fn from(args: SplittingArgs) -> Self {
        Self {
            destination_subnet_id: Some(subnet_id_into_protobuf(args.destination_subnet_id)),
            source_subnet_id: Some(subnet_id_into_protobuf(args.source_subnet_id)),
        }
    }
}

impl TryFrom<pb::SplittingArgs> for SplittingArgs {
    type Error = ProxyDecodeError;

    fn try_from(args: pb::SplittingArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            destination_subnet_id: subnet_id_try_from_option(
                args.destination_subnet_id,
                "SplittingArgs::destination_subnet_id",
            )?,
            source_subnet_id: subnet_id_try_from_option(
                args.source_subnet_id,
                "SplittingArgs::source_subnet_id",
            )?,
        })
    }
}

impl From<&SubnetSplittingStatus> for pb::summary::SubnetSplittingStatus {
    fn from(status: &SubnetSplittingStatus) -> Self {
        match status {
            SubnetSplittingStatus::NotScheduled => {
                pb::summary::SubnetSplittingStatus::NotScheduled(())
            }
            SubnetSplittingStatus::Scheduled(splitting_args) => {
                pb::summary::SubnetSplittingStatus::Scheduled(pb::SplittingArgs::from(
                    *splitting_args,
                ))
            }
            SubnetSplittingStatus::PostSplit { new_subnet_id } => {
                pb::summary::SubnetSplittingStatus::PostSplit(subnet_id_into_protobuf(
                    *new_subnet_id,
                ))
            }
        }
    }
}

impl TryFrom<pb::summary::SubnetSplittingStatus> for SubnetSplittingStatus {
    type Error = ProxyDecodeError;

    fn try_from(status: pb::summary::SubnetSplittingStatus) -> Result<Self, Self::Error> {
        match status {
            pb::summary::SubnetSplittingStatus::NotScheduled(()) => {
                Ok(SubnetSplittingStatus::NotScheduled)
            }
            pb::summary::SubnetSplittingStatus::Scheduled(splitting_args) => {
                Ok(SubnetSplittingStatus::Scheduled(splitting_args.try_into()?))
            }
            pb::summary::SubnetSplittingStatus::PostSplit(subnet_id) => {
                Ok(SubnetSplittingStatus::PostSplit {
                    new_subnet_id: subnet_id_try_from_protobuf(subnet_id)?,
                })
            }
        }
    }
}

impl TryFrom<pb::Summary> for DkgSummary {
    type Error = ProxyDecodeError;

    fn try_from(summary: pb::Summary) -> Result<Self, Self::Error> {
        Ok(Self {
            registry_version: RegistryVersion::from(summary.registry_version),
            configs: summary
                .configs
                .into_iter()
                .map(|config| NiDkgConfig::try_from(config).map(|c| (c.dkg_id.clone(), c)))
                .collect::<Result<BTreeMap<_, _>, _>>()?,
            current_transcripts: build_tagged_transcripts_map(&summary.current_transcripts)?,
            next_transcripts: build_tagged_transcripts_map(&summary.next_transcripts)?,
            interval_length: Height::from(summary.interval_length),
            next_interval_length: Height::from(summary.next_interval_length),
            height: Height::from(summary.height),
            transcripts_for_remote_subnets: build_transcripts_vec_from_pb(
                summary.transcripts_for_remote_subnets,
            )
            .map_err(ProxyDecodeError::Other)?,
            remote_dkg_attempts: build_remote_dkg_attempts_map(&summary.remote_dkg_attempts),
            subnet_splitting_status: BackwardsCompatibleOption::try_from_proto(
                summary.subnet_splitting_status,
            )?,
        })
    }
}

/// The DKG payload is either the DKG Summary, if this payload belongs to a
/// start block of a new DKG interval, or a tuple containing the start height
/// and the set of valid dealings corresponding to the current interval.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum DkgPayload {
    /// DKG Summary payload
    Summary(DkgSummary),
    /// DKG Dealings payload
    Data(DkgDataPayload),
}

/// DealingMessages is a vector of DKG messages
pub type DealingMessages = Vec<Message>;

/// Dealings contains dealing messages and the height at which this DKG interval
/// started
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct DkgDataPayload {
    /// The height of the DKG interval that this object belongs to
    pub start_height: Height,
    /// The dealing messages
    pub messages: DealingMessages,
    /// Transcripts that are computed for remote subnets.
    pub transcripts_for_remote_subnets: Vec<RemoteTranscriptResult>,
}

impl TryFrom<pb::DkgDataPayload> for DkgDataPayload {
    type Error = ProxyDecodeError;

    fn try_from(data_payload: pb::DkgDataPayload) -> Result<Self, Self::Error> {
        Ok(Self {
            start_height: Height::from(data_payload.summary_height),
            messages: data_payload
                .dealings
                .into_iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?,
            transcripts_for_remote_subnets: build_transcripts_vec_from_pb(
                data_payload.transcripts_for_remote_subnets,
            )
            .map_err(ProxyDecodeError::Other)?,
        })
    }
}

impl DkgDataPayload {
    /// Return an empty [`DkgDataPayload`] using the given start_height.
    pub fn new_empty(start_height: Height) -> Self {
        Self::new(start_height, vec![])
    }

    /// Return a new [`DkgDataPayload`].
    pub fn new(start_height: Height, messages: DealingMessages) -> Self {
        Self {
            start_height,
            messages,
            transcripts_for_remote_subnets: vec![],
        }
    }

    /// Return a new [`DkgDataPayload`] with the given remote DKG transcripts.
    pub fn new_with_remote_dkg_transcripts(
        start_height: Height,
        messages: DealingMessages,
        remote_dkg_transcripts: Vec<RemoteTranscriptResult>,
    ) -> Self {
        Self {
            start_height,
            messages,
            transcripts_for_remote_subnets: remote_dkg_transcripts,
        }
    }

    /// Returns true if the payload is empty
    pub fn is_empty(&self) -> bool {
        let DkgDataPayload {
            start_height: _,
            messages,
            transcripts_for_remote_subnets,
        } = self;
        messages.is_empty() && transcripts_for_remote_subnets.is_empty()
    }
}

impl NiDkgTag {
    /// Returns the threshold (minimal number of nodes) required to accomplish a
    /// certain crypto-operation.
    pub fn threshold_for_subnet_of_size(&self, subnet_size: usize) -> Threshold {
        let committee_size = get_committee_size(subnet_size);
        let f = crate::consensus::get_faults_tolerated(committee_size);
        match self {
            NiDkgTag::LowThreshold => f + 1,
            NiDkgTag::HighThreshold | NiDkgTag::HighThresholdForKey(_) => committee_size - f,
        }
    }
}

impl From<&DkgSummary> for pb::DkgPayload {
    fn from(summary: &DkgSummary) -> Self {
        Self {
            val: Some(pb::dkg_payload::Val::Summary(pb::Summary::from(summary))),
        }
    }
}

impl From<&DkgDataPayload> for pb::DkgPayload {
    fn from(data_payload: &DkgDataPayload) -> Self {
        Self {
            val: Some(pb::dkg_payload::Val::DataPayload(pb::DkgDataPayload {
                dealings: data_payload
                    .messages
                    .iter()
                    .map(pb::DkgMessage::from)
                    .collect(),
                summary_height: data_payload.start_height.get(),
                transcripts_for_remote_subnets: build_callback_ided_transcripts_vec(
                    data_payload.transcripts_for_remote_subnets.as_slice(),
                ),
            })),
        }
    }
}

impl TryFrom<pb::DkgPayload> for DkgPayload {
    type Error = ProxyDecodeError;

    fn try_from(summary: pb::DkgPayload) -> Result<Self, Self::Error> {
        match summary
            .val
            .ok_or(ProxyDecodeError::MissingField("DkgPayload::val"))?
        {
            pb::dkg_payload::Val::Summary(summary) => {
                Ok(DkgPayload::Summary(DkgSummary::try_from(summary)?))
            }
            pb::dkg_payload::Val::DataPayload(data_payload) => {
                Ok(DkgPayload::Data(DkgDataPayload::try_from(data_payload)?))
            }
        }
    }
}

/// Errors which could occur when creating a Dkg payload.
#[derive(PartialEq, Debug)]
pub enum DkgPayloadCreationError {
    CryptoError(CryptoError),
    StateManagerError(StateManagerError),
    DkgCreateTranscriptError(DkgCreateTranscriptError),
    FailedToGetDkgIntervalSettingFromRegistry(RegistryClientError),
    FailedToGetSubnetMemberListFromRegistry(RegistryClientError),
    FailedToGetVetKdKeyList(RegistryClientError),
    SubnetSplittingStatusError(String),
}

/// Reasons for why a dkg payload might be invalid.
#[allow(clippy::large_enum_variant)]
#[derive(PartialEq, Debug)]
pub enum InvalidDkgPayloadReason {
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    MismatchedDkgSummary(DkgSummary, DkgSummary),
    MissingDkgConfigForDealing,
    DkgStartHeightDoesNotMatchParentBlock,
    DkgSummaryAtNonStartHeight(Height),
    DkgDealingAtStartHeight(Height),
    InvalidDealer(NodeId),
    DealerAlreadyDealt(NodeId),
    /// There are multiple dealings from the same dealer in the payload.
    DuplicateDealers,
    /// The number of dealings in the payload exceeds the maximum allowed number of dealings.
    TooManyDealings {
        limit: usize,
        actual: usize,
    },
    /// The remote NiDKG transcripts that were included with this payload are invalid
    InvalidRemoteNiDkgTranscripts,
}

/// Possible failures which could occur while validating a dkg payload. They don't imply that the
/// payload is invalid.
#[allow(dead_code)]
#[derive(PartialEq, Debug)]
pub enum DkgPayloadValidationFailure {
    PayloadCreationFailed(DkgPayloadCreationError),
    /// Crypto related errors.
    CryptoError(CryptoError),
    DkgVerifyDealingError(DkgVerifyDealingError),
    FailedToGetMaxDealingsPerBlock(RegistryClientError),
    FailedToGetRegistryVersion,
}

impl From<DkgVerifyDealingError> for InvalidDkgPayloadReason {
    fn from(err: DkgVerifyDealingError) -> Self {
        InvalidDkgPayloadReason::DkgVerifyDealingError(err)
    }
}

impl From<DkgVerifyDealingError> for DkgPayloadValidationFailure {
    fn from(err: DkgVerifyDealingError) -> Self {
        DkgPayloadValidationFailure::DkgVerifyDealingError(err)
    }
}

impl From<CryptoError> for InvalidDkgPayloadReason {
    fn from(err: CryptoError) -> Self {
        InvalidDkgPayloadReason::CryptoError(err)
    }
}

impl From<CryptoError> for DkgPayloadValidationFailure {
    fn from(err: CryptoError) -> Self {
        DkgPayloadValidationFailure::CryptoError(err)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::crypto::threshold_sig::ni_dkg::NiDkgMasterPublicKeyId;
    use ic_management_canister_types_private::{VetKdCurve, VetKdKeyId};
    use strum::EnumCount;
    use strum::IntoEnumIterator;

    #[test]
    fn should_correctly_calculate_threshold_for_ni_dkg_tag_low_threshold() {
        let low_threshold_tag = NiDkgTag::LowThreshold;
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(0), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(1), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(2), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(3), 1);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(4), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(5), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(6), 2);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(28), 10);
        assert_eq!(low_threshold_tag.threshold_for_subnet_of_size(64), 22);
    }

    #[test]
    fn should_correctly_calculate_threshold_for_ni_dkg_tag_high_threshold() {
        let high_threshold_tag = NiDkgTag::HighThreshold;
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(0), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(1), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(2), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(3), 1);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(4), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(5), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(6), 3);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(28), 19);
        assert_eq!(high_threshold_tag.threshold_for_subnet_of_size(64), 43);
    }

    #[test]
    #[allow(clippy::single_element_loop)]
    fn should_correctly_calculate_threshold_for_ni_dkg_tag_high_threshold_for_key() {
        for ni_dkg_master_public_key_id in [NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "some key".to_string(),
        })] {
            let tag = NiDkgTag::HighThresholdForKey(ni_dkg_master_public_key_id);

            assert_eq!(tag.threshold_for_subnet_of_size(0), 1);
            assert_eq!(tag.threshold_for_subnet_of_size(1), 1);
            assert_eq!(tag.threshold_for_subnet_of_size(2), 1);
            assert_eq!(tag.threshold_for_subnet_of_size(3), 1);
            assert_eq!(tag.threshold_for_subnet_of_size(4), 3);
            assert_eq!(tag.threshold_for_subnet_of_size(5), 3);
            assert_eq!(tag.threshold_for_subnet_of_size(6), 3);
            assert_eq!(tag.threshold_for_subnet_of_size(28), 19);
            assert_eq!(tag.threshold_for_subnet_of_size(64), 43);
        }
        assert_eq!(NiDkgMasterPublicKeyId::COUNT, 1);
        assert_eq!(VetKdCurve::iter().count(), 1);
    }

    #[test]
    fn should_correctly_calculate_faults_tolerated_for_committee_of_size() {
        use crate::consensus::get_faults_tolerated;
        assert_eq!(get_faults_tolerated(0), 0);
        assert_eq!(get_faults_tolerated(1), 0);
        assert_eq!(get_faults_tolerated(2), 0);
        assert_eq!(get_faults_tolerated(3), 0);
        assert_eq!(get_faults_tolerated(4), 1);
        assert_eq!(get_faults_tolerated(5), 1);
        assert_eq!(get_faults_tolerated(6), 1);
        assert_eq!(get_faults_tolerated(7), 2);
        assert_eq!(get_faults_tolerated(28), 9);
        assert_eq!(get_faults_tolerated(64), 21);
    }
}
