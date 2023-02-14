use crate::vault::remote_csp_vault::TarpcCspVaultRequest;
use crate::vault::remote_csp_vault::TarpcCspVaultResponse;
use ic_crypto_internal_logmon::metrics::{CryptoMetrics, MessageType, MetricsDomain, ServiceType};
use ic_logger::{debug, ReplicaLogger};
use prost::bytes::{Bytes, BytesMut};
use std::pin::Pin;
use std::sync::Arc;
use tarpc::{ClientMessage, Response};
use tokio_serde::{Deserializer, Serializer};

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
        let result = Pin::new(&mut self.inner_codec).serialize(item);
        if let Ok(serialized_bytes) = &result {
            self.observer
                .observe_serialization_result(item, serialized_bytes);
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
        let result = Pin::new(&mut self.inner_codec).deserialize(src);
        if let Ok(deserialized) = &result {
            self.observer
                .observe_deserialization_result(src, deserialized);
        }
        result
    }
}

trait SerializationObserver<S> {
    fn observe_serialization_result(&self, src: &S, result: &Bytes);
}

trait DeserializationObserver<D> {
    fn observe_deserialization_result(&self, src: &BytesMut, result: &D);
}

pub struct CspVaultClientObserver {
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl CspVaultClientObserver {
    pub fn new(logger: ReplicaLogger, metrics: Arc<CryptoMetrics>) -> Self {
        Self { logger, metrics }
    }
}

impl SerializationObserver<ClientMessage<TarpcCspVaultRequest>> for CspVaultClientObserver {
    fn observe_serialization_result(
        &self,
        src: &ClientMessage<TarpcCspVaultRequest>,
        result: &Bytes,
    ) {
        if let ClientMessage::Request(request) = src {
            let vault_method = CspVaultMethod::from(&request.message);
            let (domain, method_name) = vault_method.detail();
            let number_of_bytes = result.len();
            debug!(
                self.logger,
                "CSP vault client sent {} bytes (request to '{}')", number_of_bytes, method_name
            );
            self.metrics.observe_vault_message_size(
                ServiceType::Client,
                MessageType::Request,
                domain,
                method_name,
                number_of_bytes,
            );
        }
    }
}

impl DeserializationObserver<Response<TarpcCspVaultResponse>> for CspVaultClientObserver {
    fn observe_deserialization_result(
        &self,
        src: &BytesMut,
        result: &Response<TarpcCspVaultResponse>,
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
            self.metrics.observe_vault_message_size(
                ServiceType::Client,
                MessageType::Response,
                domain,
                method_name,
                number_of_bytes,
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
    ThresholdKeygenForTest,
    GenDealingEncryptionKeyPair,
    UpdateForwardSecureEpoch,
    CreateDealing,
    LoadThresholdSigningKey,
    RetainThresholdKeysIfPresent,
    SksContains,
    PksAndSksContains,
    PksAndSksComplete,
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
    EcdsaSignShare,
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
            CspVaultMethod::ThresholdKeygenForTest => (
                MetricsDomain::ThresholdSignature,
                "threshold_keygen_for_test",
            ),
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
            CspVaultMethod::PksAndSksComplete => {
                (MetricsDomain::KeyManagement, "pks_and_sks_complete")
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
            CspVaultMethod::EcdsaSignShare => (MetricsDomain::ThresholdEcdsa, "ecdsa_sign_share"),
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
            Req::ThresholdKeygenForTest { .. } => Method::ThresholdKeygenForTest,
            Req::GenDealingEncryptionKeyPair { .. } => Method::GenDealingEncryptionKeyPair,
            Req::UpdateForwardSecureEpoch { .. } => Method::UpdateForwardSecureEpoch,
            Req::CreateDealing { .. } => Method::CreateDealing,
            Req::LoadThresholdSigningKey { .. } => Method::LoadThresholdSigningKey,
            Req::RetainThresholdKeysIfPresent { .. } => Method::RetainThresholdKeysIfPresent,
            Req::SksContains { .. } => Method::SksContains,
            Req::PksAndSksContains { .. } => Method::PksAndSksContains,
            Req::PksAndSksComplete { .. } => Method::PksAndSksComplete,
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
            Req::EcdsaSignShare { .. } => Method::EcdsaSignShare,
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
            Resp::ThresholdKeygenForTest { .. } => Method::ThresholdKeygenForTest,
            Resp::GenDealingEncryptionKeyPair { .. } => Method::GenDealingEncryptionKeyPair,
            Resp::UpdateForwardSecureEpoch { .. } => Method::UpdateForwardSecureEpoch,
            Resp::CreateDealing { .. } => Method::CreateDealing,
            Resp::LoadThresholdSigningKey { .. } => Method::LoadThresholdSigningKey,
            Resp::RetainThresholdKeysIfPresent { .. } => Method::RetainThresholdKeysIfPresent,
            Resp::SksContains { .. } => Method::SksContains,
            Resp::PksAndSksContains { .. } => Method::PksAndSksContains,
            Resp::PksAndSksComplete { .. } => Method::PksAndSksComplete,
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
            Resp::EcdsaSignShare { .. } => Method::EcdsaSignShare,
            Resp::NewPublicSeed { .. } => Method::NewPublicSeed,
        }
    }
}
