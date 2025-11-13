//! This module contains various definitions related to Ingress messages

use super::{EXPECTED_MESSAGE_ID_LENGTH, MessageId};
use crate::{
    CanisterId, CountBytes, PrincipalId, Time, UserId,
    artifact::{IdentifiableArtifact, IngressMessageId, PbArtifact},
    messages::{
        Authentication, HasCanisterId, HttpCallContent, HttpCanisterUpdate, HttpRequest,
        HttpRequestContent, HttpRequestEnvelope, HttpRequestError, SignedRequestBytes,
        http::{CallOrQuery, representation_independent_hash_call_or_query},
    },
};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInfoRequest, CanisterMetadataRequest, ClearChunkStoreArgs,
    DeleteCanisterSnapshotArgs, IC_00, InstallChunkedCodeArgs, InstallCodeArgsV2,
    ListCanisterSnapshotArgs, LoadCanisterSnapshotArgs, Method, Payload,
    ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs, RenameCanisterArgs,
    StoredChunksArgs, TakeCanisterSnapshotArgs, UpdateSettingsArgs, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
};
use ic_protobuf::{
    log::ingress_message_log_entry::v1::IngressMessageLogEntry,
    proxy::{ProxyDecodeError, try_from_option_field},
    state::ingress::v1 as pb_ingress,
    types::v1 as pb_types,
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use prost::bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, TryFrom, TryInto},
    mem::size_of,
    str::FromStr,
};

/// The contents of a signed ingress message.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
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

    /// Checks whether the given ingress message is addressed to the subnet (rather than to a canister).
    pub fn is_addressed_to_subnet(&self) -> bool {
        self.canister_id() == IC_00
    }

    pub fn ingress_expiry(&self) -> Time {
        Time::from_nanos_since_unix_epoch(self.ingress_expiry)
    }

    #[cfg(test)]
    pub fn new(
        sender: UserId,
        canister_id: CanisterId,
        method_name: String,
        arg: Vec<u8>,
        ingress_expiry: u64,
        nonce: Option<Vec<u8>>,
    ) -> Self {
        Self {
            sender,
            canister_id,
            method_name,
            arg,
            ingress_expiry,
            nonce,
        }
    }
}

impl HasCanisterId for SignedIngressContent {
    fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

impl HttpRequestContent for SignedIngressContent {
    fn id(&self) -> MessageId {
        MessageId::from(representation_independent_hash_call_or_query(
            CallOrQuery::Call,
            self.canister_id.get().into_vec(),
            &self.method_name,
            self.arg.clone(),
            self.ingress_expiry,
            self.sender.get().into_vec(),
            self.nonce.as_deref(),
        ))
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
                    "Converting sender to PrincipalId failed with {err}"
                ))
            })?),
            canister_id: CanisterId::try_from(update.canister_id.0).map_err(|err| {
                HttpRequestError::InvalidPrincipalId(format!(
                    "Converting canister_id to PrincipalId failed with {err:?}"
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

impl IdentifiableArtifact for SignedIngress {
    const NAME: &'static str = "ingress";
    type Id = IngressMessageId;
    fn id(&self) -> Self::Id {
        self.into()
    }
}

impl PbArtifact for SignedIngress {
    type PbId = ic_protobuf::types::v1::IngressMessageId;
    type PbIdError = ProxyDecodeError;
    type PbMessage = Bytes;
    type PbMessageError = ProxyDecodeError;
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

impl From<SignedIngress> for Bytes {
    fn from(value: SignedIngress) -> Self {
        Self::copy_from_slice(value.binary().as_ref())
    }
}

impl TryFrom<Bytes> for SignedIngress {
    type Error = ProxyDecodeError;
    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        SignedRequestBytes::from(value.to_vec())
            .try_into()
            .map_err(|e| ProxyDecodeError::CborDecodeError(Box::new(e)))
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

        impl serde::de::Visitor<'_> for BytesVisitor {
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

    pub fn take_content(self) -> SignedIngressContent {
        self.signed.take_content()
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

/// The conversion from `HttpRequestEnvelope<HttpCallContent>` to
/// `SignedIngress` goes through serialization first, because the
/// actual encoded bytes has to be part of `SignedIngress`.
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, ValidateEq)]
pub struct Ingress {
    pub source: UserId,
    pub receiver: CanisterId,
    pub effective_canister_id: Option<CanisterId>,
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    #[validate_eq(Ignore)]
    pub method_payload: Vec<u8>,
    pub message_id: MessageId,
    pub expiry_time: Time,
}

impl Ingress {
    /// Checks whether the given ingress message is addressed to the subnet (rather than to a canister).
    pub fn is_addressed_to_subnet(&self) -> bool {
        self.receiver == IC_00
    }
}

impl From<(SignedIngress, Option<CanisterId>)> for Ingress {
    fn from(item: (SignedIngress, Option<CanisterId>)) -> Self {
        let (signed_ingress, effective_canister_id) = item;
        Self {
            source: signed_ingress.sender(),
            receiver: signed_ingress.canister_id(),
            effective_canister_id,
            method_name: signed_ingress.method_name(),
            method_payload: signed_ingress.method_arg().to_vec(),
            message_id: signed_ingress.id(),
            expiry_time: signed_ingress.expiry_time(),
        }
    }
}

impl From<(SignedIngressContent, Option<CanisterId>)> for Ingress {
    fn from(item: (SignedIngressContent, Option<CanisterId>)) -> Self {
        let (ingress, effective_canister_id) = item;
        let message_id = ingress.id();
        Self {
            source: ingress.sender,
            receiver: ingress.canister_id,
            effective_canister_id,
            method_name: ingress.method_name,
            method_payload: ingress.arg,
            message_id,
            expiry_time: Time::from_nanos_since_unix_epoch(ingress.ingress_expiry),
        }
    }
}

impl From<&Ingress> for pb_ingress::Ingress {
    fn from(item: &Ingress) -> Self {
        let effective_canister_id = item.effective_canister_id.map(pb_types::CanisterId::from);
        Self {
            source: Some(crate::user_id_into_protobuf(item.source)),
            receiver: Some(pb_types::CanisterId::from(item.receiver)),
            method_name: item.method_name.clone(),
            method_payload: item.method_payload.clone(),
            message_id: item.message_id.as_bytes().to_vec(),
            expiry_time_nanos: item.expiry_time.as_nanos_since_unix_epoch(),
            effective_canister_id,
        }
    }
}

impl TryFrom<pb_ingress::Ingress> for Ingress {
    type Error = ProxyDecodeError;
    fn try_from(item: pb_ingress::Ingress) -> Result<Self, Self::Error> {
        let effective_canister_id =
            try_from_option_field(item.effective_canister_id, "Ingress::effective_canister_id")
                .ok();
        Ok(Self {
            source: crate::user_id_try_from_protobuf(try_from_option_field(
                item.source,
                "Ingress::source",
            )?)?,
            receiver: try_from_option_field(item.receiver, "Ingress::receiver")?,
            effective_canister_id,
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

/// Errors returned when parsing an ingress payload.
#[derive(Eq, PartialEq, Debug)]
pub enum ParseIngressError {
    /// The requested subnet method is not available.
    UnknownSubnetMethod,
    /// Failed to parse method payload.
    InvalidSubnetPayload(String),
    /// The subnet method can not be called via ingress messages.
    SubnetMethodNotAllowed,
}

impl ParseIngressError {
    pub fn into_user_error(self, method_name: &str) -> UserError {
        match self {
            ParseIngressError::UnknownSubnetMethod => UserError::new(
                ErrorCode::CanisterMethodNotFound,
                format!("ic00 interface does not expose method {method_name}"),
            ),
            ParseIngressError::SubnetMethodNotAllowed => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!("ic00 method {method_name} can not be called via ingress messages"),
            ),
            ParseIngressError::InvalidSubnetPayload(err) => UserError::new(
                ErrorCode::InvalidManagementPayload,
                format!("Failed to parse payload for ic00 method {method_name}: {err}"),
            ),
        }
    }
}

/// Helper function to extract the effective canister id from the payload of an ingress message.
pub fn extract_effective_canister_id(
    ingress: &SignedIngressContent,
) -> Result<Option<CanisterId>, ParseIngressError> {
    if !ingress.is_addressed_to_subnet() {
        return Ok(None);
    }
    match Method::from_str(ingress.method_name()) {
        Ok(Method::ProvisionalCreateCanisterWithCycles) | Ok(Method::ProvisionalTopUpCanister) => {
            Ok(None)
        }
        Ok(Method::StartCanister)
        | Ok(Method::CanisterStatus)
        | Ok(Method::DeleteCanister)
        | Ok(Method::UninstallCode)
        | Ok(Method::StopCanister) => match CanisterIdRecord::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::CanisterInfo) => match CanisterInfoRequest::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::CanisterMetadata) => match CanisterMetadataRequest::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::UpdateSettings) => match UpdateSettingsArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::InstallCode) => match InstallCodeArgsV2::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::InstallChunkedCode) => match InstallChunkedCodeArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.target_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::UploadChunk) => match UploadChunkArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::ClearChunkStore) => match ClearChunkStoreArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::StoredChunks) => match StoredChunksArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::TakeCanisterSnapshot) => match TakeCanisterSnapshotArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::LoadCanisterSnapshot) => match LoadCanisterSnapshotArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },
        Ok(Method::ListCanisterSnapshots) => {
            match ListCanisterSnapshotArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::DeleteCanisterSnapshot) => {
            match DeleteCanisterSnapshotArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::ReadCanisterSnapshotMetadata) => {
            match ReadCanisterSnapshotMetadataArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::ReadCanisterSnapshotData) => {
            match ReadCanisterSnapshotDataArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::UploadCanisterSnapshotMetadata) => {
            match UploadCanisterSnapshotMetadataArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::UploadCanisterSnapshotData) => {
            match UploadCanisterSnapshotDataArgs::decode(ingress.arg()) {
                Ok(record) => Ok(Some(record.get_canister_id())),
                Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
            }
        }
        Ok(Method::RenameCanister) => match RenameCanisterArgs::decode(ingress.arg()) {
            Ok(record) => Ok(Some(record.get_canister_id())),
            Err(err) => Err(ParseIngressError::InvalidSubnetPayload(err.to_string())),
        },

        Ok(Method::CreateCanister)
        | Ok(Method::SetupInitialDKG)
        | Ok(Method::DepositCycles)
        | Ok(Method::HttpRequest)
        | Ok(Method::RawRand)
        | Ok(Method::ECDSAPublicKey)
        | Ok(Method::SignWithECDSA)
        | Ok(Method::ReshareChainKey)
        | Ok(Method::SchnorrPublicKey)
        | Ok(Method::SignWithSchnorr)
        | Ok(Method::VetKdPublicKey)
        | Ok(Method::VetKdDeriveKey)
        | Ok(Method::BitcoinGetBalance)
        | Ok(Method::BitcoinGetUtxos)
        | Ok(Method::BitcoinGetBlockHeaders)
        | Ok(Method::BitcoinSendTransaction)
        | Ok(Method::BitcoinSendTransactionInternal)
        | Ok(Method::BitcoinGetSuccessors)
        | Ok(Method::BitcoinGetCurrentFeePercentiles)
        | Ok(Method::NodeMetricsHistory)
        | Ok(Method::SubnetInfo)
        | Ok(Method::FetchCanisterLogs) => {
            // Subnet method not allowed for ingress.
            Err(ParseIngressError::SubnetMethodNotAllowed)
        }
        Err(_) => Err(ParseIngressError::UnknownSubnetMethod),
    }
}

#[cfg(test)]
mod test {
    use crate::UserId;
    use crate::messages::ingress_messages::{
        ParseIngressError, SignedIngressContent, extract_effective_canister_id,
    };
    use ic_base_types::PrincipalId;
    use ic_management_canister_types_private::IC_00;
    use std::convert::From;

    #[test]
    fn ingress_subnet_message_with_invalid_payload() {
        let msg: SignedIngressContent = SignedIngressContent {
            sender: UserId::from(PrincipalId::new_user_test_id(0)),
            canister_id: IC_00,
            method_name: "start_canister".to_string(),
            arg: vec![],
            ingress_expiry: 0,
            nonce: None,
        };
        let result = extract_effective_canister_id(&msg);
        assert!(
            matches!(result, Err(ParseIngressError::InvalidSubnetPayload(_))),
            "Expected InvalidSubnetPayload error, got: {result:?}"
        );
    }

    #[test]
    fn ingress_subnet_message_with_unknown_method() {
        let msg: SignedIngressContent = SignedIngressContent {
            sender: UserId::from(PrincipalId::new_user_test_id(0)),
            canister_id: IC_00,
            method_name: "unknown_method".to_string(),
            arg: vec![],
            ingress_expiry: 0,
            nonce: None,
        };
        assert_eq!(
            extract_effective_canister_id(&msg),
            Err(ParseIngressError::UnknownSubnetMethod)
        );
    }
}
