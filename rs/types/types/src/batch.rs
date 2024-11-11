//! Contains Batch, Payload, and specific Payload types that are passed between
//! Consensus and Message Routing.

mod canister_http;
mod execution_environment;
mod ingress;
mod self_validating;
mod xnet;

pub use self::{
    canister_http::{CanisterHttpPayload, MAX_CANISTER_HTTP_PAYLOAD_SIZE},
    execution_environment::{
        CanisterQueryStats, LocalQueryStats, QueryStats, QueryStatsPayload, RawQueryStats,
        TotalQueryStats,
    },
    ingress::{IngressPayload, IngressPayloadError},
    self_validating::{SelfValidatingPayload, MAX_BITCOIN_PAYLOAD_IN_BYTES},
    xnet::XNetPayload,
};
use crate::{
    consensus::idkg::PreSigId,
    crypto::canister_threshold_sig::MasterPublicKey,
    messages::{CallbackId, Payload, SignedIngress},
    xnet::CertifiedStreamSlice,
    Height, Randomness, RegistryVersion, SubnetId, Time,
};
use ic_base_types::NodeId;
use ic_btc_replica_types::BitcoinAdapterResponse;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types::MasterPublicKeyId;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    hash::Hash,
};

/// The `Batch` provided to Message Routing for deterministic processing.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Batch {
    /// The sequence number attached to the batch.
    pub batch_number: Height,
    /// The batch summary is always set by the consensus, see `deliver_batches()`.
    /// The tests and the `PocketIC` might set it to `None`, i.e. "unknown".
    pub batch_summary: Option<BatchSummary>,
    /// Whether the state obtained by executing this batch needs to be fully
    /// hashed to be eligible for StateSync.
    pub requires_full_state_hash: bool,
    /// The payload messages to be processed.
    pub messages: BatchMessages,
    /// A source of randomness for processing the Batch.
    pub randomness: Randomness,
    /// The Master public keys of the subnet.
    pub idkg_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    /// The pre-signature Ids available to be matched with signature requests.
    pub idkg_pre_signature_ids: BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>>,
    /// The version of the registry to be referenced when processing the batch.
    pub registry_version: RegistryVersion,
    /// A clock time to be used for processing messages.
    pub time: Time,
    /// Responses to subnet calls that require consensus' involvement.
    pub consensus_responses: Vec<ConsensusResponse>,
    /// Information about block makers
    pub blockmaker_metrics: BlockmakerMetrics,
}

/// The context built by Consensus for deterministic processing. Captures all
/// fields that have semantic meaning within the Chain Consensus protocol.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ValidationContext {
    /// The registry version to be associated with the payload.
    pub registry_version: RegistryVersion,
    /// The certified state height necessary for the validation of a payload.
    pub certified_height: Height,
    /// The clock time being used for the payload.
    pub time: Time,
}

impl ValidationContext {
    /// The derived PartialOrd trait implementation uses a lexicographic
    /// ordering over its fields, which is not what we want in the case of
    /// ValidationContext. We need every single field to be equal or greater
    /// than those of 'other' to return true. Otherwise, we return false.
    pub fn greater_or_equal(&self, other: &ValidationContext) -> bool {
        self.registry_version >= other.registry_version
            && self.certified_height >= other.certified_height
            && self.time >= other.time
    }

    /// Same as [`Self::greater_or_equal`], except that we require time to be strictly
    /// greater.
    pub fn greater(&self, other: &ValidationContext) -> bool {
        self.registry_version >= other.registry_version
            && self.certified_height >= other.certified_height
            && self.time > other.time
    }
}

/// The payload of a batch.
///
/// Contains ingress messages, XNet messages and self-validating messages.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct BatchPayload {
    pub ingress: IngressPayload,
    pub xnet: XNetPayload,
    pub self_validating: SelfValidatingPayload,
    pub canister_http: Vec<u8>,
    pub query_stats: Vec<u8>,
}

/// Batch properties collected form the last DKG summary block.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BatchSummary {
    /// The next checkpoint height.
    ///
    /// In a case of a subnet recovery, the DSM will observe an instant
    /// jump for the `batch_number` and `next_checkpoint_height` values.
    /// The `next_checkpoint_height`, if set, should be always greater
    /// than the `batch_number`.
    pub next_checkpoint_height: Height,
    /// The current checkpoint interval length.
    ///
    /// The DKG interval length is normally 499 rounds (199 for system subnets).
    pub current_interval_length: Height,
}

/// Return ingress messages, xnet messages, and responses from the bitcoin adapter.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct BatchMessages {
    pub signed_ingress_msgs: Vec<SignedIngress>,
    pub certified_stream_slices: BTreeMap<SubnetId, CertifiedStreamSlice>,
    pub bitcoin_adapter_responses: Vec<BitcoinAdapterResponse>,
    pub query_stats: Option<QueryStatsPayload>,
}

/// Error type that can occur during an `BatchPayload::into_messages` call
#[derive(Debug)]
pub enum IntoMessagesError {
    IngressPayloadError(IngressPayloadError),
    QueryStatsPayloadError(ProxyDecodeError),
}

impl BatchPayload {
    /// Extract and return the set of ingress and xnet messages in a
    /// BatchPayload.
    /// Return error if deserialization of ingress payload fails.
    #[allow(clippy::result_large_err)]
    pub fn into_messages(self) -> Result<BatchMessages, IntoMessagesError> {
        Ok(BatchMessages {
            signed_ingress_msgs: self
                .ingress
                .try_into()
                .map_err(IntoMessagesError::IngressPayloadError)?,
            certified_stream_slices: self.xnet.stream_slices,
            bitcoin_adapter_responses: self.self_validating.0,
            query_stats: QueryStatsPayload::deserialize(&self.query_stats)
                .map_err(IntoMessagesError::QueryStatsPayloadError)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ingress.is_empty()
            && self.xnet.stream_slices.is_empty()
            && self.self_validating.is_empty()
            && self.canister_http.is_empty()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockmakerMetrics {
    pub blockmaker: NodeId,
    pub failed_blockmakers: Vec<NodeId>,
}

impl BlockmakerMetrics {
    pub fn new_for_test() -> Self {
        Self {
            blockmaker: NodeId::new(ic_base_types::PrincipalId::new_node_test_id(0)),
            failed_blockmakers: vec![],
        }
    }
}

/// Response to a subnet call that requires Consensus' involvement.
///
/// Only holds the payload and callback ID, Execution populates other fields
/// (originator, respondent, refund) from the incoming request.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct ConsensusResponse {
    pub callback: CallbackId,
    pub payload: Payload,
}

impl ConsensusResponse {
    pub fn new(callback: CallbackId, payload: Payload) -> Self {
        Self { callback, payload }
    }
}

impl From<&ConsensusResponse> for pb::ConsensusResponse {
    fn from(rep: &ConsensusResponse) -> Self {
        let p = match &rep.payload {
            Payload::Data(d) => pb::consensus_response::Payload::Data(d.clone()),
            Payload::Reject(r) => pb::consensus_response::Payload::Reject(r.into()),
        };
        Self {
            callback: rep.callback.get(),
            payload: Some(p),
        }
    }
}

impl TryFrom<pb::ConsensusResponse> for ConsensusResponse {
    type Error = ProxyDecodeError;

    fn try_from(rep: pb::ConsensusResponse) -> Result<Self, Self::Error> {
        let payload = match rep
            .payload
            .ok_or(ProxyDecodeError::MissingField("ConsensusResponse::payload"))?
        {
            pb::consensus_response::Payload::Data(d) => Payload::Data(d),
            pb::consensus_response::Payload::Reject(r) => Payload::Reject(r.try_into()?),
        };

        Ok(Self {
            callback: rep.callback.into(),
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CountBytes;

    /// This is a quick test to check the invariant, that the [`Default`] implementation
    /// of a payload section actually produces the empty payload,
    #[test]
    fn default_batch_payload_is_empty() {
        assert_eq!(IngressPayload::default().count_bytes(), 0);
        assert_eq!(SelfValidatingPayload::default().count_bytes(), 0);
    }

    #[test]
    fn test_validation_context_ordering() {
        let context1 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        let context2 = ValidationContext {
            registry_version: RegistryVersion::new(2),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context2));
        assert!(context2.greater_or_equal(&context1));

        let context3 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(2),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context3));
        assert!(context3.greater_or_equal(&context1));

        let context4 = ValidationContext {
            registry_version: RegistryVersion::new(1),
            certified_height: Height::new(1),
            time: Time::from_nanos_since_unix_epoch(2),
        };
        assert!(!context1.greater_or_equal(&context4));
        assert!(context4.greater_or_equal(&context1));

        let context5 = ValidationContext {
            registry_version: RegistryVersion::new(0),
            certified_height: Height::new(2),
            time: Time::from_nanos_since_unix_epoch(1),
        };
        assert!(!context1.greater_or_equal(&context5));
        assert!(!context5.greater_or_equal(&context1));
    }
}
