//! This module contains functions for constructing CUPs from registry and for
//! verifying CUPs.

use ic_consensus_dkg::payload_builder::get_dkg_summary_from_cup_contents;
use ic_consensus_idkg::{
    make_bootstrap_summary, make_bootstrap_summary_with_initial_dealings,
    utils::{get_idkg_chain_key_config_if_enabled, inspect_idkg_chain_key_initializations},
};
use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_protobuf::{
    proxy::ProxyDecodeError, registry::subnet::v1::CatchUpPackageContents, types::v1 as pb,
};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    Height, RegistryVersion, SubnetId, Time,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpContentProtobufBytes, CatchUpPackage,
        HashedBlock, HashedRandomBeacon, Payload, RandomBeaconContent, Rank, SummaryPayload, idkg,
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoError, CryptoHash, Signable, Signed,
        crypto_hash,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag},
    },
    signature::ThresholdSignature,
};
use phantom_newtype::Id;
use std::fmt;

/// The reasons why a [`CatchUpPackage`] can fail verification.
#[derive(Debug)]
pub enum CatchUpPackageVerificationError {
    /// The DKG summary of the CUP has no current high-threshold transcript, so
    /// the expected signer cannot be determined.
    HighThresholdTranscriptNotFound,
    /// The signer of the CUP is not the DKG id of the current high-threshold
    /// transcript in the DKG summary of the CUP.
    InappropriateDkgId {
        transcript_dkg_id: NiDkgId,
        signer_dkg_id: NiDkgId,
    },
    /// The signature could not be verified with the subnet's public key.
    SignatureVerificationFailed(CryptoError),
}

impl fmt::Display for CatchUpPackageVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighThresholdTranscriptNotFound => {
                write!(f, "the DKG summary has no high-threshold transcript")
            }
            Self::InappropriateDkgId {
                transcript_dkg_id,
                signer_dkg_id,
            } => write!(
                f,
                "the signer {signer_dkg_id} is not the high-threshold DKG id {transcript_dkg_id} of the DKG summary"
            ),
            Self::SignatureVerificationFailed(err) => {
                write!(f, "signature verification failed: {err}")
            }
        }
    }
}

impl std::error::Error for CatchUpPackageVerificationError {}

/// The reasons why a CUP protobuf can fail verification, see [`verify_catch_up_package_proto`].
#[derive(Debug)]
pub enum CatchUpPackageProtoVerificationError {
    /// The protobuf could not be deserialized into a [`CatchUpPackage`].
    DeserializationFailed(ProxyDecodeError),
    /// The deserialized CUP failed verification.
    VerificationFailed(CatchUpPackageVerificationError),
}

impl fmt::Display for CatchUpPackageProtoVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeserializationFailed(err) => write!(f, "failed to deserialize the CUP: {err}"),
            Self::VerificationFailed(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for CatchUpPackageProtoVerificationError {}

/// Verifies that the given CUP was signed by the given subnet. This function checks that
///
/// 1. the `signer` of the CUP is the DKG id of the high-threshold transcript in the CUP's DKG
///    summary.
/// 2. the combined threshold signature over the CUP content verifies with the public key of
///    `subnet_id` at the registry version recorded in the CUP's DKG summary.
#[allow(clippy::result_large_err)]
pub fn verify_catch_up_package<C>(
    crypto: &C,
    subnet_id: SubnetId,
    cup: &CatchUpPackage,
) -> Result<(), CatchUpPackageVerificationError>
where
    C: ThresholdSigVerifierByPublicKey<CatchUpContent> + ?Sized,
{
    verify_catch_up_package_impl(
        crypto,
        subnet_id,
        cup,
        &cup.content,
        &cup.signature.signature,
    )
}

/// Deserializes the given CUP protobuf and verifies it like [`verify_catch_up_package`], except
/// that the signature is verified over the original `content` bytes of the protobuf instead of the
/// re-encoded content of the deserialized CUP. Returns the deserialized CUP on success.
///
/// The encoding of the CUP content may change across replica versions, in which case deserializing
/// and re-encoding it does not reproduce the bytes that were signed. Prefer this function whenever
/// the protobuf may have been produced by a different replica version.
#[allow(clippy::result_large_err)]
pub fn verify_catch_up_package_proto<C>(
    crypto: &C,
    subnet_id: SubnetId,
    proto: &pb::CatchUpPackage,
) -> Result<CatchUpPackage, CatchUpPackageProtoVerificationError>
where
    C: ThresholdSigVerifierByPublicKey<CatchUpContentProtobufBytes> + ?Sized,
{
    let cup = CatchUpPackage::try_from(proto)
        .map_err(CatchUpPackageProtoVerificationError::DeserializationFailed)?;
    verify_catch_up_package_impl(
        crypto,
        subnet_id,
        &cup,
        &CatchUpContentProtobufBytes::from(proto),
        &CombinedThresholdSigOf::new(CombinedThresholdSig(proto.signature.clone())),
    )
    .map_err(CatchUpPackageProtoVerificationError::VerificationFailed)?;
    Ok(cup)
}

#[allow(clippy::result_large_err)]
fn verify_catch_up_package_impl<M, C>(
    crypto: &C,
    subnet_id: SubnetId,
    cup: &CatchUpPackage,
    message: &M,
    signature: &CombinedThresholdSigOf<M>,
) -> Result<(), CatchUpPackageVerificationError>
where
    M: Signable,
    C: ThresholdSigVerifierByPublicKey<M> + ?Sized,
{
    let expected_signer = &cup
        .content
        .block
        .as_ref()
        .payload
        .as_ref()
        .as_summary()
        .dkg
        .current_transcript(&NiDkgTag::HighThreshold)
        .ok_or(CatchUpPackageVerificationError::HighThresholdTranscriptNotFound)?
        .dkg_id;
    if &cup.signature.signer != expected_signer {
        return Err(CatchUpPackageVerificationError::InappropriateDkgId {
            transcript_dkg_id: expected_signer.clone(),
            signer_dkg_id: cup.signature.signer.clone(),
        });
    }

    crypto
        .verify_combined_threshold_sig_by_public_key(
            signature,
            message,
            subnet_id,
            cup.content.registry_version(),
        )
        .map_err(CatchUpPackageVerificationError::SignatureVerificationFailed)
}

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet from the provided CUP contents
pub fn make_registry_cup_from_cup_contents(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    cup_contents: CatchUpPackageContents,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let replica_version = match registry.get_replica_version(subnet_id, registry_version) {
        Ok(Some(replica_version)) => replica_version,
        err => {
            warn!(
                logger,
                "Failed to retrieve subnet replica version at registry version {:?}: {:?}",
                registry_version,
                err
            );
            return None;
        }
    };
    let dkg_summary = match get_dkg_summary_from_cup_contents(
        cup_contents.clone(),
        subnet_id,
        registry,
        registry_version,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            warn!(
                logger,
                "Failed constructing NiDKG summary block from CUP contents: {}.", err
            );

            return None;
        }
    };
    let cup_height = Height::new(cup_contents.height);

    let idkg_summary = match bootstrap_idkg_summary(
        cup_contents.clone(),
        subnet_id,
        registry_version,
        registry,
        logger,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            warn!(
                logger,
                "Failed constructing IDKG summary block from CUP contents: {}.", err
            );

            return None;
        }
    };

    let Some(low_threshold_transcript) = dkg_summary.current_transcript(&NiDkgTag::LowThreshold)
    else {
        warn!(
            logger,
            "No current low threshold transcript in registry CUP contents"
        );
        return None;
    };
    let low_dkg_id = low_threshold_transcript.dkg_id.clone();

    let Some(high_threshold_transcript) = dkg_summary.current_transcript(&NiDkgTag::HighThreshold)
    else {
        warn!(
            logger,
            "No current high threshold transcript in registry CUP contents"
        );
        return None;
    };
    let high_dkg_id = high_threshold_transcript.dkg_id.clone();

    // In a NNS subnet recovery case the block validation context needs to reference a registry
    // version of the NNS to be recovered. Otherwise the validation context points to a registry
    // version without the NNS subnet record.
    let block_registry_version = cup_contents
        .registry_store_uri
        .as_ref()
        .map(|v| RegistryVersion::from(v.registry_version))
        .unwrap_or(registry_version);
    let block = Block {
        version: replica_version.clone(),
        parent: Id::from(CryptoHash(Vec::new())),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: dkg_summary,
                idkg: idkg_summary,
            }),
        ),
        height: cup_height,
        rank: Rank(0),
        context: ValidationContext {
            certified_height: cup_height,
            registry_version: block_registry_version,
            time: Time::from_nanos_since_unix_epoch(cup_contents.time),
        },
    };
    let random_beacon = Signed {
        content: RandomBeaconContent {
            version: replica_version,
            height: cup_height,
            parent: Id::from(CryptoHash(Vec::new())),
        },
        signature: ThresholdSignature {
            signer: low_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    };

    Some(CatchUpPackage {
        content: CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            Id::from(CryptoHash(cup_contents.state_hash)),
            /* oldest_registry_version_in_use_by_replicated_state */ None,
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    })
}

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet
pub fn make_registry_cup(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let versioned_record = match registry.get_cup_contents(subnet_id, registry_version) {
        Ok(versioned_record) => versioned_record,
        Err(e) => {
            warn!(
                logger,
                "Failed to retrieve versioned record from the registry {:?}", e,
            );
            return None;
        }
    };

    let Some(cup_contents) = versioned_record.value else {
        warn!(
            logger,
            "Missing registry CUP contents at version {}", versioned_record.version
        );
        return None;
    };

    make_registry_cup_from_cup_contents(
        registry,
        subnet_id,
        cup_contents,
        versioned_record.version,
        logger,
    )
}

fn bootstrap_idkg_summary_from_cup_contents(
    cup_contents: CatchUpPackageContents,
    subnet_id: SubnetId,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    let initial_dealings = inspect_idkg_chain_key_initializations(
        cup_contents.ecdsa_initializations,
        cup_contents.chain_key_initializations,
    )?;
    if initial_dealings.is_empty() {
        return Ok(None);
    };

    make_bootstrap_summary_with_initial_dealings(
        subnet_id,
        Height::new(cup_contents.height),
        initial_dealings,
        logger,
    )
    .map_err(|err| format!("Failed to create IDKG summary block: {err:?}"))
}

fn bootstrap_idkg_summary(
    cup_contents: CatchUpPackageContents,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    let height = Height::new(cup_contents.height);
    if let Some(summary) =
        bootstrap_idkg_summary_from_cup_contents(cup_contents, subnet_id, logger)?
    {
        return Ok(Some(summary));
    }

    match get_idkg_chain_key_config_if_enabled(subnet_id, registry_version, registry_client)
        .map_err(|err| format!("Failed getting the chain key config: {err:?}"))?
    {
        Some(chain_key_config) => Ok(make_bootstrap_summary(
            subnet_id,
            chain_key_config
                .key_configs
                .iter()
                .map(|key_config| key_config.key_id.clone())
                .filter_map(|key_id| key_id.try_into().ok())
                .collect(),
            height,
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use ic_crypto_test_utils_ni_dkg::dummy_initial_dkg_transcript;
    use ic_interfaces_registry::{RegistryClient, RegistryVersionedRecord};
    use ic_logger::no_op_logger;
    use ic_protobuf::registry::subnet::v1::{
        CatchUpPackageContents, RecoveryArgs, RegistryStoreUri, SubnetRecord,
        catch_up_package_contents::CupType,
    };
    use ic_types::{
        Height, NodeId, PrincipalId, RegistryVersion, ReplicaVersion, Time,
        consensus::{ConsensusMessageHashable, HasVersion},
        crypto::{AlgorithmId, CryptoHash, CryptoResult, threshold_sig::ni_dkg::NiDkgTag},
        registry::RegistryClientError,
    };
    use ic_types_test_utils::ids::subnet_test_id;
    use std::cell::RefCell;

    const LATEST_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(12345);

    /// Builds a registry client serving the CUP contents and the subnet record which
    /// [`make_registry_cup`] needs, with the given `registry_store_uri` in the CUP contents.
    fn setup_registry(registry_store_uri: Option<RegistryStoreUri>) -> impl RegistryClient {
        MockRegistryClient::new(LATEST_REGISTRY_VERSION, move |key, _| {
            use prost::Message;
            if key.starts_with("catch_up_package_contents_") {
                // Build a dummy cup
                let committee = vec![NodeId::from(PrincipalId::new_node_test_id(0))];
                let cup =
                    CatchUpPackageContents {
                        initial_ni_dkg_transcript_low_threshold: Some(
                            dummy_initial_dkg_transcript(committee.clone(), NiDkgTag::LowThreshold),
                        ),
                        initial_ni_dkg_transcript_high_threshold: Some(
                            dummy_initial_dkg_transcript(committee, NiDkgTag::HighThreshold),
                        ),
                        height: 54321,
                        time: 1,
                        state_hash: vec![1, 2, 3, 4, 5],
                        registry_store_uri: registry_store_uri.clone(),
                        ecdsa_initializations: vec![],
                        chain_key_initializations: vec![],
                        cup_type: Some(CupType::Recovery(RecoveryArgs {
                            height: 54321,
                            time: 1,
                            state_hash: vec![1, 2, 3, 4, 5],
                        })),
                    };

                // Encode the cup to protobuf
                let mut value = Vec::with_capacity(cup.encoded_len());
                cup.encode(&mut value).unwrap();
                Some(value)
            } else if key.starts_with("subnet_record_") {
                // Build a dummy subnet record. The only value used from this are the
                // `membership` and `dkg_interval_length` fields.
                let subnet_record = SubnetRecord {
                    membership: vec![PrincipalId::new_subnet_test_id(1).to_vec()],
                    dkg_interval_length: 99,
                    replica_version_id: "TestID".to_string(),
                    ..SubnetRecord::default()
                };

                // Encode the `SubnetRecord` to protobuf
                let mut value = Vec::with_capacity(subnet_record.encoded_len());
                subnet_record.encode(&mut value).unwrap();
                Some(value)
            } else {
                None
            }
        })
    }

    /// A [`ThresholdSigVerifierByPublicKey`] returning a fixed result and recording the signed
    /// bytes, subnet id and registry version it was asked to verify.
    struct RecordingCrypto {
        result: CryptoResult<()>,
        calls: RefCell<Vec<(Vec<u8>, SubnetId, RegistryVersion)>>,
    }

    impl RecordingCrypto {
        fn accepting() -> Self {
            Self {
                result: Ok(()),
                calls: RefCell::new(vec![]),
            }
        }

        fn rejecting() -> Self {
            Self {
                result: Err(CryptoError::MalformedSignature {
                    algorithm: AlgorithmId::ThresBls12_381,
                    sig_bytes: vec![],
                    internal_error: "invalid signature".to_string(),
                }),
                calls: RefCell::new(vec![]),
            }
        }
    }

    impl<T: Signable> ThresholdSigVerifierByPublicKey<T> for RecordingCrypto {
        fn verify_combined_threshold_sig_by_public_key(
            &self,
            _signature: &CombinedThresholdSigOf<T>,
            message: &T,
            subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()> {
            self.calls
                .borrow_mut()
                .push((message.as_signed_bytes(), subnet_id, registry_version));
            self.result.clone()
        }
    }

    /// Builds a (registry) CUP with a correct signer whose block's validation context refers to a
    /// different registry version than its DKG summary.
    fn cup_for_verification() -> CatchUpPackage {
        let registry_client = setup_registry(/*registry_store_uri=*/ None);
        let mut cup = make_registry_cup(
            &registry_client,
            subnet_test_id(0),
            LATEST_REGISTRY_VERSION,
            &no_op_logger(),
        )
        .unwrap();
        let mut block = cup.content.block.as_ref().clone();
        block.context.registry_version = LATEST_REGISTRY_VERSION + RegistryVersion::from(10);
        cup.content.block = HashedBlock::new(crypto_hash, block);
        assert!(cup.check_integrity());
        assert_eq!(cup.content.registry_version(), LATEST_REGISTRY_VERSION);
        cup
    }

    #[test]
    fn test_verify_catch_up_package_verifies_at_the_dkg_summary_registry_version() {
        let cup = cup_for_verification();
        let crypto = RecordingCrypto::accepting();

        verify_catch_up_package(&crypto, subnet_test_id(7), &cup).unwrap();

        assert_eq!(
            crypto.calls.into_inner(),
            vec![(
                cup.content.as_signed_bytes(),
                subnet_test_id(7),
                LATEST_REGISTRY_VERSION
            )]
        );
    }

    #[test]
    fn test_verify_catch_up_package_rejects_inappropriate_signer() {
        let mut cup = cup_for_verification();
        let expected = cup.signature.signer.clone();
        cup.signature.signer.dealer_subnet = subnet_test_id(42);
        let crypto = RecordingCrypto::accepting();

        let err = verify_catch_up_package(&crypto, subnet_test_id(0), &cup).unwrap_err();

        assert!(
            matches!(
                &err,
                CatchUpPackageVerificationError::InappropriateDkgId { transcript_dkg_id, signer_dkg_id }
                    if *transcript_dkg_id == expected && *signer_dkg_id == cup.signature.signer
            ),
            "unexpected error: {err}"
        );
        assert!(
            crypto.calls.borrow().is_empty(),
            "the signature must not be verified if the signer is wrong"
        );
    }

    #[test]
    fn test_verify_catch_up_package_rejects_invalid_signature() {
        let cup = cup_for_verification();
        let crypto = RecordingCrypto::rejecting();

        let err = verify_catch_up_package(&crypto, subnet_test_id(0), &cup).unwrap_err();

        assert!(
            matches!(
                err,
                CatchUpPackageVerificationError::SignatureVerificationFailed(_)
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_catch_up_package_proto_returns_the_deserialized_cup() {
        let expected_cup = cup_for_verification();
        let proto = pb::CatchUpPackage::from(expected_cup.clone());
        let crypto = RecordingCrypto::accepting();

        let cup = verify_catch_up_package_proto(&crypto, subnet_test_id(7), &proto).unwrap();

        assert_eq!(cup, expected_cup);
        assert_eq!(
            crypto.calls.into_inner(),
            vec![(
                CatchUpContentProtobufBytes::from(&proto).as_signed_bytes(),
                subnet_test_id(7),
                LATEST_REGISTRY_VERSION
            )]
        );
    }

    #[test]
    fn test_verify_catch_up_package_proto_verifies_the_original_content_bytes() {
        let mut proto = pb::CatchUpPackage::from(cup_for_verification());
        // Append an unknown field to the content, which is skipped when decoding, so that the
        // original bytes differ from the re-encoded content of the deserialized CUP.
        proto.content.extend_from_slice(&[0xC0, 0x3E, 0x01]);
        let crypto = RecordingCrypto::accepting();

        let cup = verify_catch_up_package_proto(&crypto, subnet_test_id(7), &proto).unwrap();

        assert_ne!(cup.content.as_signed_bytes(), proto.content);
        assert_eq!(
            crypto.calls.into_inner(),
            vec![(
                CatchUpContentProtobufBytes::from(&proto).as_signed_bytes(),
                subnet_test_id(7),
                LATEST_REGISTRY_VERSION
            )]
        );
    }

    #[test]
    fn test_verify_catch_up_package_proto_rejects_undeserializable_cup() {
        let mut proto = pb::CatchUpPackage::from(cup_for_verification());
        proto.content = vec![1, 2, 3, 4];
        let crypto = RecordingCrypto::accepting();

        let err = verify_catch_up_package_proto(&crypto, subnet_test_id(0), &proto).unwrap_err();

        assert!(
            matches!(
                err,
                CatchUpPackageProtoVerificationError::DeserializationFailed(_)
            ),
            "unexpected error: {err}"
        );
        assert!(
            crypto.calls.borrow().is_empty(),
            "the signature must not be verified if the CUP cannot be deserialized"
        );
    }

    #[test]
    fn test_verify_catch_up_package_proto_rejects_inappropriate_signer() {
        let mut cup = cup_for_verification();
        cup.signature.signer.dkg_tag = NiDkgTag::LowThreshold;
        let proto = pb::CatchUpPackage::from(cup);
        let crypto = RecordingCrypto::accepting();

        let err = verify_catch_up_package_proto(&crypto, subnet_test_id(0), &proto).unwrap_err();

        assert!(
            matches!(
                err,
                CatchUpPackageProtoVerificationError::VerificationFailed(
                    CatchUpPackageVerificationError::InappropriateDkgId { .. }
                )
            ),
            "unexpected error: {err}"
        );
        assert!(crypto.calls.borrow().is_empty());
    }

    #[test]
    fn test_make_registry_cup() {
        let registry_client = setup_registry(/*registry_store_uri=*/ None);
        let result = make_registry_cup(
            &registry_client,
            subnet_test_id(0),
            registry_client.get_latest_version(),
            &no_op_logger(),
        )
        .unwrap();

        assert_eq!(
            result.content.state_hash.get_ref(),
            &CryptoHash(vec![1, 2, 3, 4, 5])
        );
        assert_eq!(
            result.content.block.get_value().context.registry_version,
            LATEST_REGISTRY_VERSION
        );
        assert_eq!(
            result.content.block.get_value().context.certified_height,
            Height::from(54321)
        );
        assert_eq!(
            result.content.version(),
            &ReplicaVersion::from_str("TestID").unwrap()
        );
        assert_eq!(result.signature.signer.dealer_subnet, subnet_test_id(0));
    }

    /// A registry CUP must reference the same registry version in the DKG summary of its block and
    /// in that block's validation context.
    #[test]
    fn test_registry_cup_registry_versions_agree() {
        for registry_store_uri in [
            None,
            Some(RegistryStoreUri {
                uri: "https://localhost/registry.tar.gz".to_string(),
                hash: "".to_string(),
                registry_version: 999,
            }),
        ] {
            let expected_registry_version = registry_store_uri
                .as_ref()
                .map(|uri| RegistryVersion::from(uri.registry_version))
                .unwrap_or(LATEST_REGISTRY_VERSION);

            let registry_client = setup_registry(registry_store_uri.clone());
            let cup = make_registry_cup(
                &registry_client,
                subnet_test_id(0),
                registry_client.get_latest_version(),
                &no_op_logger(),
            )
            .expect("Failed to create the registry CUP");

            assert_eq!(
                cup.content.registry_version(),
                cup.content.block.get_value().context.registry_version,
                "Registry versions of the DKG summary and the block context disagree \
                 for registry_store_uri {registry_store_uri:?}"
            );
            assert_eq!(cup.content.registry_version(), expected_registry_version);
        }
    }

    /// `RegistryClient` implementation that allows to provide a custom function
    /// to provide a `get_versioned_value`.
    struct MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        latest_registry_version: RegistryVersion,
        get_versioned_value_fun: F,
    }

    impl<F> MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        fn new(latest_registry_version: RegistryVersion, get_versioned_value_fun: F) -> Self {
            Self {
                latest_registry_version,
                get_versioned_value_fun,
            }
        }
    }

    impl<F> RegistryClient for MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>> + Send + Sync,
    {
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
            let value = (self.get_versioned_value_fun)(key, version);
            Ok(RegistryVersionedRecord {
                key: key.to_string(),
                version,
                value,
            })
        }

        // Not needed for this test
        fn get_key_family(
            &self,
            _: &str,
            _: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            Ok(vec![])
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.latest_registry_version
        }

        // Not needed for this test
        fn get_version_timestamp(&self, _: RegistryVersion) -> Option<Time> {
            None
        }
    }
}
