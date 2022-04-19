//! This module contains various definitions related to Ingress messages

use super::{MessageId, RawHttpRequestVal, EXPECTED_MESSAGE_ID_LENGTH};
use crate::{
    messages::message_id::hash_of_map,
    messages::{
        Authentication, HasCanisterId, HttpCallContent, HttpCanisterUpdate, HttpRequest,
        HttpRequestContent, HttpRequestEnvelope, HttpRequestError, SignedRequestBytes,
    },
    CanisterId, CountBytes, PrincipalId, SubnetId, Time, UserId,
};
use ic_protobuf::{
    log::ingress_message_log_entry::v1::IngressMessageLogEntry,
    proxy::{try_from_option_field, ProxyDecodeError},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use maplit::btreemap;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom, TryInto},
    mem::size_of,
};

/// The contents of a signed ingress message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SignedIngressContent {
    sender: UserId,
    canister_id: CanisterId,
    method_name: String,
    arg: Vec<u8>,
    ingress_expiry: u64,
    nonce: Option<Vec<u8>>,
}

impl SignedIngressContent {
    pub fn sender(&self) -> UserId {
        self.sender
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn method_name(&self) -> &str {
        self.method_name.as_str()
    }

    pub fn arg(&self) -> &[u8] {
        &self.arg
    }

    pub fn nonce(&self) -> Option<&Vec<u8>> {
        self.nonce.as_ref()
    }

    pub fn ingress_expiry(&self) -> Time {
        Time::from_nanos_since_unix_epoch(self.ingress_expiry)
    }
}

impl HasCanisterId for SignedIngressContent {
    fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl HttpRequestContent for SignedIngressContent {
    // TODO(EXC-236): Avoid the duplication between this method and the one in
    // `HttpCanisterUpdate`.
    fn id(&self) -> MessageId {
        use RawHttpRequestVal::*;
        let mut map = btreemap! {
            "request_type".to_string() => String("call".to_string()),
            "canister_id".to_string() => Bytes(self.canister_id.get().to_vec()),
            "method_name".to_string() => String(self.method_name.clone()),
            "arg".to_string() => Bytes(self.arg.clone()),
            "ingress_expiry".to_string() => U64(self.ingress_expiry),
            "sender".to_string() => Bytes(self.sender.get().to_vec()),
        };
        if let Some(nonce) = &self.nonce {
            map.insert("nonce".to_string(), Bytes(nonce.clone()));
        }
        MessageId::from(hash_of_map(&map))
    }

    fn sender(&self) -> UserId {
        self.sender
    }

    fn ingress_expiry(&self) -> u64 {
        self.ingress_expiry
    }

    fn nonce(&self) -> Option<Vec<u8>> {
        self.nonce.clone()
    }
}

impl TryFrom<HttpCanisterUpdate> for SignedIngressContent {
    type Error = HttpRequestError;

    fn try_from(update: HttpCanisterUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            sender: UserId::from(PrincipalId::try_from(update.sender.0).map_err(|err| {
                HttpRequestError::InvalidPrincipalId(format!(
                    "Converting sender to PrincipalId failed with {}",
                    err
                ))
            })?),
            canister_id: CanisterId::try_from(update.canister_id.0).map_err(|err| {
                HttpRequestError::InvalidPrincipalId(format!(
                    "Converting canister_id to PrincipalId failed with {:?}",
                    err
                ))
            })?,
            method_name: update.method_name,
            arg: update.arg.0,
            ingress_expiry: update.ingress_expiry,
            nonce: update.nonce.map(|n| n.0),
        })
    }
}

/// Describes the signed ingress message that was received from the end user.
/// To construct a `SignedIngress`, either use `TryFrom<SignedRequestBytes>`
/// or directly deserialize from bytes. This guarantees that the correct
/// byte sequence is remembered as part of `SignedIngress`, which will always
/// serialize to the same sequence.
#[derive(Clone, Debug)]
pub struct SignedIngress {
    signed: HttpRequest<SignedIngressContent>,
    binary: SignedRequestBytes,
}

impl PartialEq for SignedIngress {
    fn eq(&self, other: &Self) -> bool {
        self.binary.eq(&other.binary)
    }
}

impl Eq for SignedIngress {}

impl std::hash::Hash for SignedIngress {
    fn hash<Hasher: std::hash::Hasher>(&self, state: &mut Hasher) {
        self.binary.hash(state);
    }
}

impl From<SignedIngress> for SignedRequestBytes {
    fn from(ingress: SignedIngress) -> Self {
        ingress.binary
    }
}

impl AsRef<HttpRequest<SignedIngressContent>> for SignedIngress {
    fn as_ref(&self) -> &HttpRequest<SignedIngressContent> {
        &self.signed
    }
}

impl From<SignedIngress> for SignedIngressContent {
    fn from(ingress: SignedIngress) -> SignedIngressContent {
        ingress.signed.take_content()
    }
}

impl Serialize for SignedIngress {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.binary.as_ref())
    }
}

impl<'de> Deserialize<'de> for SignedIngress {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "Expectiong a sequence of bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
        }

        let bytes = deserializer.deserialize_bytes(BytesVisitor)?;
        SignedIngress::try_from(SignedRequestBytes::from(bytes)).map_err(serde::de::Error::custom)
    }
}

impl From<&SignedIngress> for IngressMessageLogEntry {
    fn from(ingress: &SignedIngress) -> Self {
        Self {
            canister_id: Some(ingress.canister_id().to_string()),
            compute_allocation: None,
            desired_id: None,
            expiry_time: Some(ingress.signed.ingress_expiry()),
            memory_allocation: None,
            message_id: Some(format!("{}", ingress.signed.id())),
            method_name: Some(ingress.method_name()),
            mode: None,
            reason: None,
            request_type: Some(String::from("call")),
            sender: Some(ingress.signed.sender().to_string()),
            size: None,
            batch_time: None,
            batch_time_plus_ttl: None,
        }
    }
}

impl SignedIngress {
    pub fn binary(&self) -> &SignedRequestBytes {
        &self.binary
    }

    pub fn content(&self) -> &SignedIngressContent {
        self.signed.content()
    }

    pub fn authentication(&self) -> &Authentication {
        self.signed.authentication()
    }

    pub fn canister_id(&self) -> CanisterId {
        self.content().canister_id
    }

    pub fn method_name(&self) -> String {
        self.content().method_name.clone()
    }

    pub fn method_arg(&self) -> &[u8] {
        &self.content().arg
    }

    pub fn log_entry(&self) -> IngressMessageLogEntry {
        self.into()
    }

    pub fn expiry_time(&self) -> Time {
        Time::from_nanos_since_unix_epoch(self.content().ingress_expiry)
    }

    pub fn id(&self) -> MessageId {
        self.signed.id()
    }

    pub fn sender(&self) -> UserId {
        self.signed.sender()
    }

    pub fn nonce(&self) -> Option<Vec<u8>> {
        self.signed.nonce()
    }
}

impl TryFrom<SignedRequestBytes> for SignedIngress {
    type Error = HttpRequestError;

    fn try_from(binary: SignedRequestBytes) -> Result<Self, Self::Error> {
        let request: HttpRequestEnvelope<HttpCallContent> = (&binary).try_into()?;
        let signed = request.try_into()?;
        Ok(SignedIngress { signed, binary })
    }
}

/// The conversion from 'HttpRequestEnvelope<HttpCallContent>' to
/// 'SignedIngress' goes through serialization first, because the
/// actual encoded bytes has to be part of 'SignedIngress'.
impl TryFrom<HttpRequestEnvelope<HttpCallContent>> for SignedIngress {
    type Error = HttpRequestError;

    fn try_from(request: HttpRequestEnvelope<HttpCallContent>) -> Result<Self, Self::Error> {
        let bytes = SignedRequestBytes::try_from(request)?;
        SignedIngress::try_from(bytes)
    }
}

impl CountBytes for SignedIngress {
    fn count_bytes(&self) -> usize {
        // Since we not only add the message, but also the pointer to the message,
        // we need to account for that when building the length
        self.binary().len() + EXPECTED_MESSAGE_ID_LENGTH
    }
}

/// A message sent from an end user to a canister.
///
/// Used internally by the InternetComputer. See related [`SignedIngress`] for
/// the message as it was received from the `HttpHandler`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Eq, Hash)]
pub struct Ingress {
    pub source: UserId,
    pub receiver: CanisterId,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub method_payload: Vec<u8>,
    pub message_id: MessageId,
    pub expiry_time: Time,
}

impl From<SignedIngress> for Ingress {
    fn from(signed_ingress: SignedIngress) -> Self {
        Self {
            source: signed_ingress.sender(),
            receiver: signed_ingress.canister_id(),
            method_name: signed_ingress.method_name(),
            method_payload: signed_ingress.method_arg().to_vec(),
            message_id: signed_ingress.id(),
            expiry_time: signed_ingress.expiry_time(),
        }
    }
}

impl From<SignedIngressContent> for Ingress {
    fn from(ingress: SignedIngressContent) -> Self {
        let message_id = ingress.id();
        Self {
            source: ingress.sender,
            receiver: ingress.canister_id,
            method_name: ingress.method_name,
            method_payload: ingress.arg,
            message_id,
            expiry_time: Time::from_nanos_since_unix_epoch(ingress.ingress_expiry),
        }
    }
}

impl From<&Ingress> for pb_ingress::Ingress {
    fn from(item: &Ingress) -> Self {
        Self {
            source: Some(crate::user_id_into_protobuf(item.source)),
            receiver: Some(pb_types::CanisterId::from(item.receiver)),
            method_name: item.method_name.clone(),
            method_payload: item.method_payload.clone(),
            message_id: item.message_id.as_bytes().to_vec(),
            expiry_time_nanos: item.expiry_time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_ingress::Ingress> for Ingress {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::Ingress) -> Result<Self, Self::Error> {
        Ok(Self {
            source: crate::user_id_try_from_protobuf(try_from_option_field(
                item.source,
                "Ingress::source",
            )?)?,
            receiver: try_from_option_field(item.receiver, "Ingress::receiver")?,
            method_name: item.method_name,
            method_payload: item.method_payload,
            message_id: item.message_id.as_slice().try_into()?,
            expiry_time: Time::from_nanos_since_unix_epoch(item.expiry_time_nanos),
        })
    }
}

impl CountBytes for Ingress {
    fn count_bytes(&self) -> usize {
        size_of::<Ingress>() + self.method_name.len() + self.method_payload.len()
    }
}

// Tests whether the given ingress message is addressed to the subnet (rather
// than to a canister).
pub fn is_subnet_message(msg: &SignedIngressContent, own_subnet_id: SubnetId) -> bool {
    let canister_id = msg.canister_id();
    canister_id == CanisterId::ic_00() || canister_id.get_ref() == own_subnet_id.get_ref()
}
