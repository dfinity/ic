use crate::vault::remote_csp_vault::TarpcCspVaultRequest;
use crate::vault::remote_csp_vault::TarpcCspVaultResponse;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::{debug, ReplicaLogger};
use prost::bytes::{Bytes, BytesMut};
use std::pin::Pin;
use std::sync::Arc;
use tarpc::{ClientMessage, Response};
use tokio_serde::{Deserializer, Serializer};

/// Wrap a codec (something that implements the traits [`Serializer`] and [`Deserializer`])
/// to add logging and metrics capabilities to observe the amount of bytes
/// being serialized or deserialized.
pub struct SizeLoggingCodec<Codec> {
    inner_codec: Codec,
    logger: ReplicaLogger,
    _metrics: Arc<CryptoMetrics>,
}

impl<Codec> SizeLoggingCodec<Codec> {
    pub fn new(codec: Codec, logger: ReplicaLogger) -> Self {
        SizeLoggingCodec {
            inner_codec: codec,
            logger,
            _metrics: Arc::new(CryptoMetrics::none()),
        }
    }

    // TODO CRP-1835 add metrics
    fn observe_serialization_result(&self, request: &TarpcCspVaultRequest, result: &Bytes) {
        debug!(
            self.logger,
            "Request to method '{}' serialized {} bytes",
            method_name_from_request(request),
            result.len()
        );
    }

    // TODO CRP-1835 add metrics
    fn observe_deserialization_result(&self, src: &BytesMut, result: &TarpcCspVaultResponse) {
        debug!(
            self.logger,
            "Response of method '{}' deserialized {} bytes",
            method_name_from_response(result),
            src.len()
        );
    }
}

impl<Codec> Serializer<ClientMessage<TarpcCspVaultRequest>> for SizeLoggingCodec<Codec>
where
    Codec: Serializer<ClientMessage<TarpcCspVaultRequest>> + Unpin,
{
    type Error = Codec::Error;

    fn serialize(
        mut self: Pin<&mut Self>,
        item: &ClientMessage<TarpcCspVaultRequest>,
    ) -> Result<Bytes, Self::Error> {
        let result = Pin::new(&mut self.inner_codec).serialize(item);
        if let (Ok(bytes), ClientMessage::Request(request)) = (&result, item) {
            self.observe_serialization_result(&request.message, bytes);
        }
        result
    }
}

impl<Codec> Deserializer<Response<TarpcCspVaultResponse>> for SizeLoggingCodec<Codec>
where
    Codec: Deserializer<Response<TarpcCspVaultResponse>> + Unpin,
{
    type Error = Codec::Error;

    fn deserialize(
        mut self: Pin<&mut Self>,
        src: &BytesMut,
    ) -> Result<Response<TarpcCspVaultResponse>, Self::Error> {
        let result = Pin::new(&mut self.inner_codec).deserialize(src);
        if let Ok(Response {
            message: Ok(vault_response),
            ..
        }) = &result
        {
            self.observe_deserialization_result(src, vault_response);
        }
        result
    }
}

fn method_name_from_request(request: &TarpcCspVaultRequest) -> String {
    type Req = TarpcCspVaultRequest;
    match request {
        Req::Sign { .. } => "sign",
        Req::GenNodeSigningKeyPair { .. } => "gen_node_signing_key_pair",
        Req::MultiSign { .. } => "multi_sign",
        Req::GenCommitteeSigningKeyPair { .. } => "gen_committee_signing_key_pair",
        Req::ThresholdSign { .. } => "threshold_sign",
        Req::ThresholdKeygenForTest { .. } => "threshold_keygen_for_test",
        Req::GenDealingEncryptionKeyPair { .. } => "gen_dealing_encryption_key_pair",
        Req::UpdateForwardSecureEpoch { .. } => "update_forward_secure_epoch",
        Req::CreateDealing { .. } => "create_dealing",
        Req::LoadThresholdSigningKey { .. } => "load_threshold_signing_key",
        Req::RetainThresholdKeysIfPresent { .. } => "retain_threshold_keys_if_present",
        Req::SksContains { .. } => "sks_contains",
        Req::PksContains { .. } => "pks_contains",
        Req::CurrentNodePublicKeys { .. } => "current_node_public_keys",
        Req::GenTlsKeyPair { .. } => "gen_tls_key_pair",
        Req::TlsSign { .. } => "tls_sign",
        Req::IdkgCreateDealing { .. } => "idkg_create_dealing",
        Req::IdkgVerifyDealingPrivate { .. } => "idkg_verify_dealing_private",
        Req::IdkgLoadTranscript { .. } => "idkg_load_transcript",
        Req::IdkgLoadTranscriptWithOpenings { .. } => "idkg_load_transcript_with_openings",
        Req::IdkgRetainActiveKeys { .. } => "idkg_retain_active_keys",
        Req::IdkgGenDealingEncryptionKeyPair { .. } => "idkg_gen_dealing_encryption_key_pair",
        Req::IdkgOpenDealing { .. } => "idkg_open_dealing",
        Req::EcdsaSignShare { .. } => "ecdsa_sign_share",
        Req::NewPublicSeed { .. } => "new_public_seed",
    }
    .to_string()
}

fn method_name_from_response(response: &TarpcCspVaultResponse) -> String {
    type Resp = TarpcCspVaultResponse;
    match response {
        Resp::Sign { .. } => "sign",
        Resp::GenNodeSigningKeyPair { .. } => "gen_node_signing_key_pair",
        Resp::MultiSign { .. } => "multi_sign",
        Resp::GenCommitteeSigningKeyPair { .. } => "gen_committee_signing_key_pair",
        Resp::ThresholdSign { .. } => "threshold_sign",
        Resp::ThresholdKeygenForTest { .. } => "threshold_keygen_for_test",
        Resp::GenDealingEncryptionKeyPair { .. } => "gen_dealing_encryption_key_pair",
        Resp::UpdateForwardSecureEpoch { .. } => "update_forward_secure_epoch",
        Resp::CreateDealing { .. } => "create_dealing",
        Resp::LoadThresholdSigningKey { .. } => "load_threshold_signing_key",
        Resp::RetainThresholdKeysIfPresent { .. } => "retain_threshold_keys_if_present",
        Resp::SksContains { .. } => "sks_contains",
        Resp::PksContains { .. } => "pks_contains",
        Resp::CurrentNodePublicKeys { .. } => "current_node_public_keys",
        Resp::GenTlsKeyPair { .. } => "gen_tls_key_pair",
        Resp::TlsSign { .. } => "tls_sign",
        Resp::IdkgCreateDealing { .. } => "idkg_create_dealing",
        Resp::IdkgVerifyDealingPrivate { .. } => "idkg_verify_dealing_private",
        Resp::IdkgLoadTranscript { .. } => "idkg_load_transcript",
        Resp::IdkgLoadTranscriptWithOpenings { .. } => "idkg_load_transcript_with_openings",
        Resp::IdkgRetainActiveKeys { .. } => "idkg_retain_active_keys",
        Resp::IdkgGenDealingEncryptionKeyPair { .. } => "idkg_gen_dealing_encryption_key_pair",
        Resp::IdkgOpenDealing { .. } => "idkg_open_dealing",
        Resp::EcdsaSignShare { .. } => "ecdsa_sign_share",
        Resp::NewPublicSeed { .. } => "new_public_seed",
    }
    .to_string()
}
