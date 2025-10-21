use crate::vault::remote_csp_vault::TarpcCspVaultRequest;
use crate::vault::remote_csp_vault::TarpcCspVaultResponse;
use bincode::config::Options;
use bytes::{Bytes, BytesMut};
use core::marker::PhantomData;
use educe::Educe;
use ic_crypto_internal_logmon::metrics::{CryptoMetrics, MessageType, MetricsDomain, ServiceType};
use ic_logger::{ReplicaLogger, debug};
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tarpc::{ClientMessage, Response};
use tokio_serde::{Deserializer, Serializer};

/// An instantiation of the `bincode` codec use in a transport.
///
/// The implementation is mostly copied from `tokio-serde` of version 0.8 (see
/// https://github.com/carllerche/tokio-serde/blob/v0.8.0/src/lib.rs#L336).
/// The difference is that our implementation serializes objects using
/// `bincode::serialize_into()` and the original implementation uses
/// `bincode::serialize()`. The difference between the aforementioned functions
/// is that `bincode::serialize()` calls `Object::serialize()` twice, once to
/// determine the size of the object to be serialized and the second time to
/// copy the bytes. This is very efficient to do for types that already hold
/// values. However, for types like [`EccPoint`] that first invoke costly
/// conversions on the inner value that yield something that will actually be
/// serialized, calling `Object::serialize()` twice is expensive.
#[derive(Educe)]
#[educe(Debug)]
pub struct Bincode<Item, SinkItem, O = bincode::DefaultOptions> {
    #[educe(Debug(ignore))]
    pub options: O,
    #[educe(Debug(ignore))]
    ghost: PhantomData<(Item, SinkItem)>,
}

impl<Item, SinkItem> Default for Bincode<Item, SinkItem> {
    fn default() -> Self {
        Bincode {
            options: Default::default(),
            ghost: PhantomData,
        }
    }
}

impl<Item, SinkItem, O> From<O> for Bincode<Item, SinkItem, O>
where
    O: Options,
{
    fn from(options: O) -> Self {
        Self {
            options,
            ghost: PhantomData,
        }
    }
}

impl<Item, SinkItem, O> Deserializer<Item> for Bincode<Item, SinkItem, O>
where
    for<'a> Item: Deserialize<'a>,
    O: Options + Clone,
{
    type Error = io::Error;

    fn deserialize(self: Pin<&mut Self>, src: &BytesMut) -> Result<Item, Self::Error> {
        self.options
            .clone()
            .deserialize(src)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl<Item, SinkItem, O> Serializer<SinkItem> for Bincode<Item, SinkItem, O>
where
    SinkItem: Serialize,
    O: Options + Clone,
{
    type Error = io::Error;

    fn serialize(self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
        let mut buf = Vec::with_capacity(1024);
        self.options
            .clone()
            .serialize_into(&mut buf, item)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(buf.into())
    }
}

/// Wrap a codec (something that implements the traits [`Serializer`] and [`Deserializer`])
/// to observe the result of serialization and deserialization.
pub struct ObservableCodec<Codec, Observer> {
    inner_codec: Codec,
    observer: Observer,
}

impl<Codec, Observer> ObservableCodec<Codec, Observer> {
    pub fn new(codec: Codec, observer: Observer) -> Self {
        ObservableCodec {
            inner_codec: codec,
            observer,
        }
    }
}

impl<Codec, Observer, S> Serializer<S> for ObservableCodec<Codec, Observer>
where
    Codec: Serializer<S> + Unpin,
    Observer: SerializationObserver<S> + Unpin,
{
    type Error = Codec::Error;

    fn serialize(mut self: Pin<&mut Self>, item: &S) -> Result<Bytes, Self::Error> {
        let start = Instant::now();
        let result = Pin::new(&mut self.inner_codec).serialize(item);
        if let Ok(serialized_bytes) = &result {
            self.observer
                .observe_serialization_result(item, serialized_bytes, Some(start));
        }
        result
    }
}

impl<Codec, Observer, D> Deserializer<D> for ObservableCodec<Codec, Observer>
where
    Codec: Deserializer<D> + Unpin,
    Observer: DeserializationObserver<D> + Unpin,
{
    type Error = Codec::Error;

    fn deserialize(mut self: Pin<&mut Self>, src: &BytesMut) -> Result<D, Self::Error> {
        let start = Instant::now();
        let result = Pin::new(&mut self.inner_codec).deserialize(src);
        if let Ok(deserialized) = &result {
            self.observer
                .observe_deserialization_result(src, deserialized, Some(start));
        }

        result
    }
}

trait SerializationObserver<S> {
    fn observe_serialization_result(&self, src: &S, result: &Bytes, start_time: Option<Instant>);
}

trait DeserializationObserver<D> {
    fn observe_deserialization_result(
        &self,
        src: &BytesMut,
        result: &D,
        start_time: Option<Instant>,
    );
}

pub struct CspVaultObserver {
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl CspVaultObserver {
    pub fn new(logger: ReplicaLogger, metrics: Arc<CryptoMetrics>) -> Self {
        Self { logger, metrics }
    }
}

impl SerializationObserver<ClientMessage<TarpcCspVaultRequest>> for CspVaultObserver {
    fn observe_serialization_result(
        &self,
        src: &ClientMessage<TarpcCspVaultRequest>,
        result: &Bytes,
        start_time: Option<Instant>,
    ) {
        if let ClientMessage::Request(request) = src {
            let vault_method = CspVaultMethod::from(&request.message);
            let (domain, method_name) = vault_method.detail();
            let number_of_bytes = result.len();
            debug!(
                self.logger,
                "CSP vault client sent {} bytes (request to '{}')", number_of_bytes, method_name
            );
            self.metrics.observe_vault_message_serialization(
                ServiceType::Client,
                MessageType::Request,
                domain,
                method_name,
                number_of_bytes,
                start_time,
            );
        }
    }
}

impl DeserializationObserver<Response<TarpcCspVaultResponse>> for CspVaultObserver {
    fn observe_deserialization_result(
        &self,
        src: &BytesMut,
        result: &Response<TarpcCspVaultResponse>,
        start_time: Option<Instant>,
    ) {
        if let Response {
            message: Ok(response),
            ..
        } = result
        {
            let vault_method = CspVaultMethod::from(response);
            let (domain, method_name) = vault_method.detail();
            let number_of_bytes = src.len();
            debug!(
                self.logger,
                "CSP vault client received {} bytes (response of '{}')",
                number_of_bytes,
                method_name,
            );
            self.metrics.observe_vault_message_serialization(
                ServiceType::Client,
                MessageType::Response,
                domain,
                method_name,
                number_of_bytes,
                start_time,
            );
        }
    }
}

impl SerializationObserver<Response<TarpcCspVaultResponse>> for CspVaultObserver {
    fn observe_serialization_result(
        &self,
        src: &Response<TarpcCspVaultResponse>,
        result: &Bytes,
        start_time: Option<Instant>,
    ) {
        if let Response {
            message: Ok(response),
            ..
        } = src
        {
            let vault_method = CspVaultMethod::from(response);
            let (domain, method_name) = vault_method.detail();
            let number_of_bytes = result.len();
            debug!(
                self.logger,
                "CSP vault server sent {} bytes (request to '{}')", number_of_bytes, method_name
            );
            self.metrics.observe_vault_message_serialization(
                ServiceType::Server,
                MessageType::Response,
                domain,
                method_name,
                number_of_bytes,
                start_time,
            );
        }
    }
}

impl DeserializationObserver<ClientMessage<TarpcCspVaultRequest>> for CspVaultObserver {
    fn observe_deserialization_result(
        &self,
        src: &BytesMut,
        result: &ClientMessage<TarpcCspVaultRequest>,
        start_time: Option<Instant>,
    ) {
        if let ClientMessage::Request(request) = result {
            let vault_method = CspVaultMethod::from(&request.message);
            let (domain, method_name) = vault_method.detail();
            let number_of_bytes = src.len();
            debug!(
                self.logger,
                "CSP vault server received {} bytes (response of '{}')",
                number_of_bytes,
                method_name,
            );
            self.metrics.observe_vault_message_serialization(
                ServiceType::Server,
                MessageType::Request,
                domain,
                method_name,
                number_of_bytes,
                start_time,
            );
        }
    }
}

enum CspVaultMethod {
    Sign,
    GenNodeSigningKeyPair,
    MultiSign,
    GenCommitteeSigningKeyPair,
    ThresholdSign,
    GenDealingEncryptionKeyPair,
    UpdateForwardSecureEpoch,
    CreateDealing,
    LoadThresholdSigningKey,
    RetainThresholdKeysIfPresent,
    SksContains,
    PksAndSksContains,
    ValidatePksAndSks,
    CurrentNodePublicKeys,
    CurrentNodePublicKeysWithTimestamps,
    IdkgKeyCount,
    GenTlsKeyPair,
    TlsSign,
    IdkgCreateDealing,
    IdkgVerifyDealingPrivate,
    IdkgLoadTranscript,
    IdkgLoadTranscriptWithOpenings,
    IdkgRetainActiveKeys,
    IdkgGenDealingEncryptionKeyPair,
    IdkgOpenDealing,
    CreateEcdsaSigShare,
    CreateSchnorrSigShare,
    CreateEncryptedVetKdKeyShare,
    NewPublicSeed,
}

impl CspVaultMethod {
    fn detail(&self) -> (MetricsDomain, &str) {
        match self {
            CspVaultMethod::Sign => (MetricsDomain::BasicSignature, "sign"),
            CspVaultMethod::GenNodeSigningKeyPair => {
                (MetricsDomain::BasicSignature, "gen_node_signing_key_pair")
            }
            CspVaultMethod::MultiSign => (MetricsDomain::MultiSignature, "multi_sign"),
            CspVaultMethod::GenCommitteeSigningKeyPair => (
                MetricsDomain::MultiSignature,
                "gen_committee_signing_key_pair",
            ),
            CspVaultMethod::ThresholdSign => (MetricsDomain::ThresholdSignature, "threshold_sign"),
            CspVaultMethod::GenDealingEncryptionKeyPair => (
                MetricsDomain::NiDkgAlgorithm,
                "gen_dealing_encryption_key_pair",
            ),
            CspVaultMethod::UpdateForwardSecureEpoch => {
                (MetricsDomain::NiDkgAlgorithm, "update_forward_secure_epoch")
            }
            CspVaultMethod::CreateDealing => (MetricsDomain::NiDkgAlgorithm, "create_dealing"),
            CspVaultMethod::LoadThresholdSigningKey => {
                (MetricsDomain::NiDkgAlgorithm, "load_threshold_signing_key")
            }
            CspVaultMethod::RetainThresholdKeysIfPresent => (
                MetricsDomain::NiDkgAlgorithm,
                "retain_threshold_keys_if_present",
            ),
            CspVaultMethod::SksContains => (MetricsDomain::KeyManagement, "sks_contains"),
            CspVaultMethod::PksAndSksContains => {
                (MetricsDomain::KeyManagement, "pks_and_sks_contains")
            }
            CspVaultMethod::ValidatePksAndSks => {
                (MetricsDomain::KeyManagement, "validate_pks_and_sks")
            }
            CspVaultMethod::CurrentNodePublicKeys => {
                (MetricsDomain::KeyManagement, "current_node_public_keys")
            }
            CspVaultMethod::CurrentNodePublicKeysWithTimestamps => (
                MetricsDomain::KeyManagement,
                "current_node_public_keys_with_timestamps",
            ),
            CspVaultMethod::IdkgKeyCount => (MetricsDomain::KeyManagement, "idkg_key_count"),
            CspVaultMethod::GenTlsKeyPair => (MetricsDomain::TlsHandshake, "gen_tls_key_pair"),
            CspVaultMethod::TlsSign => (MetricsDomain::TlsHandshake, "tls_sign"),
            CspVaultMethod::IdkgCreateDealing => {
                (MetricsDomain::IdkgProtocol, "idkg_create_dealing")
            }
            CspVaultMethod::IdkgVerifyDealingPrivate => {
                (MetricsDomain::IdkgProtocol, "idkg_verify_dealing_private")
            }
            CspVaultMethod::IdkgLoadTranscript => {
                (MetricsDomain::IdkgProtocol, "idkg_load_transcript")
            }
            CspVaultMethod::IdkgLoadTranscriptWithOpenings => (
                MetricsDomain::IdkgProtocol,
                "idkg_load_transcript_with_openings",
            ),
            CspVaultMethod::IdkgRetainActiveKeys => {
                (MetricsDomain::IdkgProtocol, "idkg_retain_active_keys")
            }
            CspVaultMethod::IdkgGenDealingEncryptionKeyPair => (
                MetricsDomain::IdkgProtocol,
                "idkg_gen_dealing_encryption_key_pair",
            ),
            CspVaultMethod::IdkgOpenDealing => (MetricsDomain::IdkgProtocol, "idkg_open_dealing"),
            CspVaultMethod::CreateEcdsaSigShare => {
                (MetricsDomain::ThresholdEcdsa, "create_ecdsa_sig_share")
            }
            CspVaultMethod::CreateSchnorrSigShare => {
                (MetricsDomain::ThresholdSchnorr, "create_schnorr_sig_share")
            }
            CspVaultMethod::CreateEncryptedVetKdKeyShare => {
                (MetricsDomain::VetKd, "create_encrypted_vetkd_key_share")
            }
            CspVaultMethod::NewPublicSeed => (MetricsDomain::PublicSeed, "new_public_seed"),
        }
    }
}

impl From<&TarpcCspVaultRequest> for CspVaultMethod {
    fn from(request: &TarpcCspVaultRequest) -> Self {
        type Req = TarpcCspVaultRequest;
        type Method = CspVaultMethod;
        match request {
            Req::Sign { .. } => Method::Sign,
            Req::GenNodeSigningKeyPair { .. } => Method::GenNodeSigningKeyPair,
            Req::MultiSign { .. } => Method::MultiSign,
            Req::GenCommitteeSigningKeyPair { .. } => Method::GenCommitteeSigningKeyPair,
            Req::ThresholdSign { .. } => Method::ThresholdSign,
            Req::GenDealingEncryptionKeyPair { .. } => Method::GenDealingEncryptionKeyPair,
            Req::UpdateForwardSecureEpoch { .. } => Method::UpdateForwardSecureEpoch,
            Req::CreateDealing { .. } => Method::CreateDealing,
            Req::LoadThresholdSigningKey { .. } => Method::LoadThresholdSigningKey,
            Req::RetainThresholdKeysIfPresent { .. } => Method::RetainThresholdKeysIfPresent,
            Req::SksContains { .. } => Method::SksContains,
            Req::PksAndSksContains { .. } => Method::PksAndSksContains,
            Req::ValidatePksAndSks { .. } => Method::ValidatePksAndSks,
            Req::CurrentNodePublicKeys { .. } => Method::CurrentNodePublicKeys,
            Req::CurrentNodePublicKeysWithTimestamps { .. } => {
                Method::CurrentNodePublicKeysWithTimestamps
            }
            Req::IdkgKeyCount { .. } => Method::IdkgKeyCount,
            Req::GenTlsKeyPair { .. } => Method::GenTlsKeyPair,
            Req::TlsSign { .. } => Method::TlsSign,
            Req::IdkgCreateDealing { .. } => Method::IdkgCreateDealing,
            Req::IdkgVerifyDealingPrivate { .. } => Method::IdkgVerifyDealingPrivate,
            Req::IdkgLoadTranscript { .. } => Method::IdkgLoadTranscript,
            Req::IdkgLoadTranscriptWithOpenings { .. } => Method::IdkgLoadTranscriptWithOpenings,
            Req::IdkgRetainActiveKeys { .. } => Method::IdkgRetainActiveKeys,
            Req::IdkgGenDealingEncryptionKeyPair { .. } => Method::IdkgGenDealingEncryptionKeyPair,
            Req::IdkgOpenDealing { .. } => Method::IdkgOpenDealing,
            Req::CreateEcdsaSigShare { .. } => Method::CreateEcdsaSigShare,
            Req::CreateSchnorrSigShare { .. } => Method::CreateSchnorrSigShare,
            Req::CreateEncryptedVetkdKeyShare { .. } => Method::CreateEncryptedVetKdKeyShare,
            Req::NewPublicSeed { .. } => Method::NewPublicSeed,
        }
    }
}

impl From<&TarpcCspVaultResponse> for CspVaultMethod {
    fn from(response: &TarpcCspVaultResponse) -> Self {
        type Resp = TarpcCspVaultResponse;
        type Method = CspVaultMethod;
        match response {
            Resp::Sign { .. } => Method::Sign,
            Resp::GenNodeSigningKeyPair { .. } => Method::GenNodeSigningKeyPair,
            Resp::MultiSign { .. } => Method::MultiSign,
            Resp::GenCommitteeSigningKeyPair { .. } => Method::GenCommitteeSigningKeyPair,
            Resp::ThresholdSign { .. } => Method::ThresholdSign,
            Resp::GenDealingEncryptionKeyPair { .. } => Method::GenDealingEncryptionKeyPair,
            Resp::UpdateForwardSecureEpoch { .. } => Method::UpdateForwardSecureEpoch,
            Resp::CreateDealing { .. } => Method::CreateDealing,
            Resp::LoadThresholdSigningKey { .. } => Method::LoadThresholdSigningKey,
            Resp::RetainThresholdKeysIfPresent { .. } => Method::RetainThresholdKeysIfPresent,
            Resp::SksContains { .. } => Method::SksContains,
            Resp::PksAndSksContains { .. } => Method::PksAndSksContains,
            Resp::ValidatePksAndSks { .. } => Method::ValidatePksAndSks,
            Resp::CurrentNodePublicKeys { .. } => Method::CurrentNodePublicKeys,
            Resp::CurrentNodePublicKeysWithTimestamps { .. } => {
                Method::CurrentNodePublicKeysWithTimestamps
            }
            Resp::IdkgKeyCount { .. } => Method::IdkgKeyCount,
            Resp::GenTlsKeyPair { .. } => Method::GenTlsKeyPair,
            Resp::TlsSign { .. } => Method::TlsSign,
            Resp::IdkgCreateDealing { .. } => Method::IdkgCreateDealing,
            Resp::IdkgVerifyDealingPrivate { .. } => Method::IdkgVerifyDealingPrivate,
            Resp::IdkgLoadTranscript { .. } => Method::IdkgLoadTranscript,
            Resp::IdkgLoadTranscriptWithOpenings { .. } => Method::IdkgLoadTranscriptWithOpenings,
            Resp::IdkgRetainActiveKeys { .. } => Method::IdkgRetainActiveKeys,
            Resp::IdkgGenDealingEncryptionKeyPair { .. } => Method::IdkgGenDealingEncryptionKeyPair,
            Resp::IdkgOpenDealing { .. } => Method::IdkgOpenDealing,
            Resp::CreateEcdsaSigShare { .. } => Method::CreateEcdsaSigShare,
            Resp::CreateSchnorrSigShare { .. } => Method::CreateSchnorrSigShare,
            Resp::CreateEncryptedVetkdKeyShare { .. } => Method::CreateEncryptedVetKdKeyShare,
            Resp::NewPublicSeed { .. } => Method::NewPublicSeed,
        }
    }
}
