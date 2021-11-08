//! Defines types used for distributed key generation.

use super::*;
use crate::{
    crypto::threshold_sig::ni_dkg::{
        config::NiDkgConfig, NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTranscript,
    },
    ReplicaVersion,
};
use ic_protobuf::types::v1 as pb;
use serde_with::serde_as;
use std::collections::BTreeMap;

/// Contains a Node's contribution to a DKG dealing.
pub type Message = BasicSigned<DealingContent>;

/// Holds the content of a DKG dealing
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DealingContent {
    version: ReplicaVersion,
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
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

impl From<&Message> for pb::DkgMessage {
    fn from(message: &Message) -> Self {
        Self {
            replica_version: message.content.version.to_string(),
            dkg_id: Some(pb::NiDkgId::from(message.content.dkg_id)),
            dealing: bincode::serialize(&message.content.dealing).unwrap(),
            signature: message.signature.signature.clone().get().0,
            signer: Some(crate::node_id_into_protobuf(message.signature.signer)),
        }
    }
}

impl TryFrom<pb::DkgMessage> for Message {
    type Error = String;
    fn try_from(message: pb::DkgMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            content: DealingContent::new(
                bincode::deserialize(&message.dealing)
                    .map_err(|err| format!("Couldn't deserialize the dealing: {:?}", err))?,
                NiDkgId::try_from(message.dkg_id.expect("No Dkg id found"))
                    .map_err(|err| format!("Couldn't deserialize the Dkg id: {:?}", err))?,
            ),
            signature: BasicSignature {
                signature: BasicSigOf::from(BasicSig(message.signature)),
                signer: node_id_try_from_protobuf(message.signer.expect("No signer found"))
                    .map_err(|err| format!("Couldn't parse the node id: {:?}", err))?,
            },
        })
    }
}

impl HasVersion for DealingContent {
    fn version(&self) -> &ReplicaVersion {
        &self.version
    }
}

/// The DKG summary will be present as the DKG payload at every block,
/// corresponding to the start of a new DKG interval.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Summary {
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
    /// Transcripts that are computed for new subnets being created.
    #[serde_as(as = "Vec<(_, _)>")]
    transcripts_for_new_subnets: BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    /// The length of the current interval in rounds (following the start
    /// block).
    pub interval_length: Height,
    /// The length of the next interval in rounds (following the start block).
    pub next_interval_length: Height,
    /// The height of the block conatining that summary.
    pub height: Height,
    /// The number of intervals a DKG for the given remote target was attempted.
    pub initial_dkg_attempts: BTreeMap<NiDkgTargetId, u32>,
}

impl Summary {
    /// Create a new Summary
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        configs: Vec<NiDkgConfig>,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        transcripts_for_new_subnets: BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
        registry_version: RegistryVersion,
        interval_length: Height,
        next_interval_length: Height,
        height: Height,
        initial_dkg_attempts: BTreeMap<NiDkgTargetId, u32>,
    ) -> Self {
        Self {
            configs: configs
                .into_iter()
                .map(|config| (config.dkg_id(), config))
                .collect(),
            current_transcripts,
            next_transcripts,
            transcripts_for_new_subnets,
            registry_version,
            interval_length,
            next_interval_length,
            height,
            initial_dkg_attempts,
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
    pub fn current_transcript(&self, tag: &NiDkgTag) -> &NiDkgTranscript {
        self.current_transcripts
            .get(tag)
            .unwrap_or_else(|| panic!("No current transcript available for tag {:?}", tag))
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
            .chain(self.next_transcripts.into_iter())
            .map(|(_, t)| t)
            .collect()
    }

    /// Return the set of next transcripts for all tags. If for some tag
    /// the next transcript is not available, the current transcript is used.
    /// This function avoids expensive copying when transcripts are large.
    pub fn into_next_transcripts(self) -> BTreeMap<NiDkgTag, NiDkgTranscript> {
        let mut next_transcripts = self.next_transcripts;
        self.current_transcripts
            .into_iter()
            .map(|(tag, current)| (tag, next_transcripts.remove(&tag).unwrap_or(current)))
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

    /// Returns the transcripts for new subnets
    pub fn transcripts_for_new_subnets(
        &self,
    ) -> &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>> {
        &self.transcripts_for_new_subnets
    }

    /// Returns the oldest registry version that is still relevant to DKG.
    ///
    /// P2P should keep up connections to all nodes registered in any registry
    /// between the one returned from this function and the current
    /// `RegistryVersion`.
    pub fn get_subnet_membership_version(&self) -> RegistryVersion {
        self.current_transcripts()
            .iter()
            .map(|(_id, transcript)| transcript.registry_version)
            .min()
            .expect("No current transcripts available")
    }
}

fn build_tagged_transcripts_vec(
    transcripts: &BTreeMap<NiDkgTag, NiDkgTranscript>,
) -> Vec<pb::TaggedNiDkgTranscript> {
    transcripts
        .iter()
        .map(|(tag, transcript)| pb::TaggedNiDkgTranscript {
            tag: pb::NiDkgTag::from(tag) as i32,
            transcript: Some(pb::NiDkgTranscript::from(transcript)),
        })
        .collect()
}

fn build_ided_transcripts_vec(
    transcripts: &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
) -> Vec<pb::IdedNiDkgTranscript> {
    transcripts
        .iter()
        .map(|(id, transcript_result)| pb::IdedNiDkgTranscript {
            dkg_id: Some(pb::NiDkgId::from(*id)),
            transcript_result: match transcript_result {
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
        })
        .collect()
}

fn build_initial_dkg_attempts_vec(
    map: &BTreeMap<NiDkgTargetId, u32>,
) -> Vec<pb::InitialDkgAttemptCount> {
    map.iter()
        .map(|(target_id, attempt_no)| pb::InitialDkgAttemptCount {
            target_id: target_id.to_vec(),
            attempt_no: *attempt_no,
        })
        .collect()
}

impl From<&Summary> for pb::Summary {
    fn from(summary: &Summary) -> Self {
        Self {
            registry_version: summary.registry_version.get(),
            configs: summary
                .configs
                .values()
                .map(pb::NiDkgConfig::from)
                .collect(),
            current_transcripts: build_tagged_transcripts_vec(&summary.current_transcripts),
            next_transcripts: build_tagged_transcripts_vec(&summary.next_transcripts),
            interval_length: summary.interval_length.get(),
            next_interval_length: summary.next_interval_length.get(),
            height: summary.height.get(),
            transcripts_for_new_subnets: build_ided_transcripts_vec(
                &summary.transcripts_for_new_subnets,
            ),
            initial_dkg_attempts: build_initial_dkg_attempts_vec(&summary.initial_dkg_attempts),
        }
    }
}

fn build_tagged_transcripts_map(
    transcripts: &[pb::TaggedNiDkgTranscript],
) -> Result<BTreeMap<NiDkgTag, NiDkgTranscript>, String> {
    transcripts
        .iter()
        .map(|tagged_transcript| {
            tagged_transcript
                .transcript
                .as_ref()
                .ok_or_else(|| "Transcript missing".to_string())
                .and_then(|t| {
                    Ok((
                        NiDkgTag::try_from(tagged_transcript.tag).map_err(|e| {
                            format!("Failed to convert NiDkgTag of transcript: {:?}", e)
                        })?,
                        NiDkgTranscript::try_from(t)?,
                    ))
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

fn build_ided_transcripts_map(
    transcripts: Vec<pb::IdedNiDkgTranscript>,
) -> Result<BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>, String> {
    let mut transcripts_for_new_subnets =
        BTreeMap::<NiDkgId, Result<NiDkgTranscript, String>>::new();
    for transcript in transcripts.into_iter() {
        let id = transcript.dkg_id.ok_or_else(|| {
            "Missing DkgPayload::Summary::IdedNiDkgTranscript::NiDkgId".to_string()
        })?;
        let id = NiDkgId::try_from(id)
            .map_err(|e| format!("Failed to convert NiDkgId of transcript: {:?}", e))?;
        let transcript_result = transcript
            .transcript_result
            .ok_or("Missing DkgPayload::Summary::IdedNiDkgTranscript::NiDkgTranscriptResult")?;
        let transcript_result = build_transcript_result(&transcript_result)
            .map_err(|e| format!("Failed to convert NiDkgTranscriptResult: {:?}", e))?;
        transcripts_for_new_subnets.insert(id, transcript_result);
    }
    Ok(transcripts_for_new_subnets)
}

fn build_initial_dkg_attempts_map(
    vec: &[pb::InitialDkgAttemptCount],
) -> BTreeMap<NiDkgTargetId, u32> {
    vec.iter()
        .map(|item| {
            let mut id = [0u8; NiDkgTargetId::SIZE];
            // Safely convert the received slice to a fixed-size slice.
            let mut v = Vec::<u8>::new();
            v.extend_from_slice(&item.target_id);
            v.resize(NiDkgTargetId::SIZE, 0u8);
            id.copy_from_slice(&v);
            // Return the key-value pair.
            (NiDkgTargetId::new(id), item.attempt_no)
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
        pb::ni_dkg_transcript_result::Val::Transcript(transcript) => {
            Ok(Ok(NiDkgTranscript::try_from(transcript)?))
        }
        pb::ni_dkg_transcript_result::Val::ErrorString(error_string) => {
            Ok(Err(std::str::from_utf8(error_string)
                .map_err(|e| format!("Failed to convert ErrorString: {:?}", e))?
                .to_string()))
        }
    }
}

impl TryFrom<pb::Summary> for Summary {
    type Error = String;
    fn try_from(summary: pb::Summary) -> Result<Self, Self::Error> {
        Ok(Self {
            registry_version: RegistryVersion::from(summary.registry_version),
            configs: summary
                .configs
                .into_iter()
                .map(|config| NiDkgConfig::try_from(config).map(|c| (c.dkg_id, c)))
                .collect::<Result<BTreeMap<_, _>, _>>()?,
            current_transcripts: build_tagged_transcripts_map(&summary.current_transcripts)?,
            next_transcripts: build_tagged_transcripts_map(&summary.next_transcripts)?,
            interval_length: Height::from(summary.interval_length),
            next_interval_length: Height::from(summary.next_interval_length),
            height: Height::from(summary.height),
            transcripts_for_new_subnets: build_ided_transcripts_map(
                summary.transcripts_for_new_subnets,
            )?,
            initial_dkg_attempts: build_initial_dkg_attempts_map(&summary.initial_dkg_attempts),
        })
    }
}

/// The DKG payload is either the DKG Summary, if this payload belongs to a
/// start block of a new DKG interval, or a tuple containing the start height
/// and the set of valid dealings corresponding to the current interval.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Payload {
    /// DKG Summary payload
    Summary(Summary),
    /// DKG Dealings payload
    Dealings(Dealings),
}

/// DealingMessages is a vector of DKG messages
pub type DealingMessages = Vec<Message>;

/// Dealings contains dealing messages and the height at which this DKG interval
/// started
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dealings {
    /// The height of the DKG interval that this object belongs to
    pub start_height: Height,
    /// The dealing messages
    pub messages: DealingMessages,
}

impl TryFrom<pb::Dealings> for Dealings {
    type Error = String;
    fn try_from(dealings: pb::Dealings) -> Result<Self, Self::Error> {
        Ok(Self {
            start_height: Height::from(dealings.summary_height),
            messages: dealings
                .dealings
                .into_iter()
                .map(|protobuf_dealing| {
                    Message::try_from(protobuf_dealing).expect("Couldn't parse the dealing")
                })
                .collect(),
        })
    }
}

impl Dealings {
    /// Return an empty DealingsPayload using the given start_height.
    pub fn new_empty(start_height: Height) -> Self {
        Self::new(start_height, vec![])
    }

    /// Return an new DealingsPayload.
    pub fn new(start_height: Height, messages: DealingMessages) -> Self {
        Self {
            start_height,
            messages,
        }
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
            NiDkgTag::HighThreshold => committee_size - f,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

impl From<&Summary> for pb::DkgPayload {
    fn from(summary: &Summary) -> Self {
        Self {
            val: Some(pb::dkg_payload::Val::Summary(pb::Summary::from(summary))),
        }
    }
}

impl From<&Dealings> for pb::DkgPayload {
    fn from(dealings: &Dealings) -> Self {
        Self {
            val: Some(pb::dkg_payload::Val::Dealings(pb::Dealings {
                dealings: dealings.messages.iter().map(pb::DkgMessage::from).collect(),
                summary_height: dealings.start_height.get(),
            })),
        }
    }
}

impl TryFrom<pb::DkgPayload> for Payload {
    type Error = String;
    fn try_from(summary: pb::DkgPayload) -> Result<Self, Self::Error> {
        match summary.val.ok_or("Val missing in DkgPayload")? {
            pb::dkg_payload::Val::Summary(summary) => {
                Ok(Payload::Summary(Summary::try_from(summary)?))
            }
            pb::dkg_payload::Val::Dealings(dealings) => {
                Ok(Payload::Dealings(Dealings::try_from(dealings)?))
            }
        }
    }
}
