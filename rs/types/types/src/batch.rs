//! Contains Batch, Payload, and specific Payload types that are passed between
//! Consensus and Message Routing.

mod canister_http;
mod ingress;
mod self_validating;
mod xnet;

pub use self::canister_http::{CanisterHttpPayload, MAX_CANISTER_HTTP_PAYLOAD_SIZE};
pub use self::ingress::{IngressPayload, IngressPayloadError};
pub use self::self_validating::{SelfValidatingPayload, MAX_BITCOIN_PAYLOAD_IN_BYTES};
pub use self::xnet::XNetPayload;

use super::{
    messages::{Response, SignedIngress},
    xnet::CertifiedStreamSlice,
    Height, Randomness, RegistryVersion, SubnetId, Time,
};
use crate::crypto::canister_threshold_sig::MasterEcdsaPublicKey;
use ic_btc_types_internal::BitcoinAdapterResponse;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_ic00_types::EcdsaKeyId;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryInto};

/// The `Batch` provided to Message Routing for deterministic processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// The sequence number attached to the batch.
    pub batch_number: Height,
    /// Whether the state obtained by executing this batch needs to be fully
    /// hashed to be eligible for StateSync.
    pub requires_full_state_hash: bool,
    /// The payload messages to be processed.
    pub messages: BatchMessages,
    /// A source of randomness for processing the Batch.
    pub randomness: Randomness,
    /// The ECDSA public key of the subnet.
    pub ecdsa_subnet_public_keys: BTreeMap<EcdsaKeyId, MasterEcdsaPublicKey>,
    /// The version of the registry to be referenced when processing the batch.
    pub registry_version: RegistryVersion,
    /// A clock time to be used for processing messages.
    pub time: Time,
    /// Responses to subnet calls that require consensus' involvement.
    pub consensus_responses: Vec<Response>,
}

/// The context built by Consensus for deterministic processing. Captures all
/// fields that have semantic meaning within the Chain Consensus protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}

/// The payload of a batch.
///
/// Contains ingress messages, XNet messages and self-validating messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct BatchPayload {
    pub ingress: IngressPayload,
    pub xnet: XNetPayload,
    pub self_validating: SelfValidatingPayload,
    pub canister_http: Vec<u8>,
}

/// Return ingress messages, xnet messages, and responses from the bitcoin adapter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchMessages {
    pub signed_ingress_msgs: Vec<SignedIngress>,
    pub certified_stream_slices: BTreeMap<SubnetId, CertifiedStreamSlice>,
    pub bitcoin_adapter_responses: Vec<BitcoinAdapterResponse>,
}

impl BatchPayload {
    /// Extract and return the set of ingress and xnet messages in a
    /// BatchPayload.
    /// Return error if deserialization of ingress payload fails.
    #[allow(clippy::result_large_err)]
    pub fn into_messages(self) -> Result<BatchMessages, IngressPayloadError> {
        Ok(BatchMessages {
            signed_ingress_msgs: self.ingress.try_into()?,
            certified_stream_slices: self.xnet.stream_slices,
            bitcoin_adapter_responses: self.self_validating.0,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ingress.is_empty()
            && self.xnet.stream_slices.is_empty()
            && self.self_validating.is_empty()
            && self.canister_http.is_empty()
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
        assert_eq!(CanisterHttpPayload::default().count_bytes(), 0);
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
