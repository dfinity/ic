use core::{convert::From, iter::Iterator};
use ic_interfaces::batch_payload::PastPayload;
use ic_management_canister_types_private::{
    EcdsaKeyId, MasterPublicKeyId, Payload, SchnorrKeyId, SignWithECDSAReply, SignWithSchnorrReply,
    VetKdDeriveKeyResult, VetKdKeyId,
};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SignWithThresholdContext, ThresholdArguments,
};
use ic_test_utilities_consensus::idkg::fake_signature_request_args;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::RegistryVersion;
use ic_types::consensus::idkg::{EcdsaSigShare, IDkgMessage, PreSigId, RequestId, SchnorrSigShare};
use ic_types::crypto::canister_threshold_sig::{ThresholdEcdsaSigShare, ThresholdSchnorrSigShare};
use ic_types::{
    Height, NumBytes,
    batch::{ChainKeyAgreement, ChainKeyErrorCode, ChainKeyPayload, chain_key_payload_to_bytes},
    consensus::idkg::VetKdKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShareContent,
    crypto::{CryptoHash, CryptoHashOf},
    messages::CallbackId,
    time::UNIX_EPOCH,
};
use ic_types_test_utils::ids::node_test_id;
use std::str::FromStr;
use std::{collections::BTreeMap, sync::Arc};
use strum::EnumCount;

/// Create a map of agreements with all possible types
pub(super) fn make_chain_key_agreements(
    id1: u64,
    id2: u64,
    id3: u64,
) -> BTreeMap<CallbackId, ChainKeyAgreement> {
    assert_eq!(ChainKeyAgreement::COUNT, 2);
    assert_eq!(ChainKeyErrorCode::COUNT, 2);
    BTreeMap::from([
        (
            CallbackId::from(id1),
            ChainKeyAgreement::Success(vec![1, 2, 3, 4]),
        ),
        (
            CallbackId::from(id2),
            ChainKeyAgreement::Reject(ChainKeyErrorCode::TimedOut),
        ),
        (
            CallbackId::from(id3),
            ChainKeyAgreement::Reject(ChainKeyErrorCode::InvalidKey),
        ),
    ])
}

/// Create a map of agreements with the same, given type
pub(super) fn make_chain_key_agreements_with_payload(
    ids: &[u64],
    agreement: ChainKeyAgreement,
) -> BTreeMap<CallbackId, ChainKeyAgreement> {
    let mut map = BTreeMap::new();
    for id in ids {
        map.insert(CallbackId::new(*id), agreement.clone());
    }
    map
}

/// Convert the given agreements payload to bytes, using a maximum size of 1KiB.
pub(super) fn as_bytes(agreements: BTreeMap<CallbackId, ChainKeyAgreement>) -> Vec<u8> {
    chain_key_payload_to_bytes(ChainKeyPayload { agreements }, NumBytes::new(1024))
}

/// Turn the given payload bytes into a generic [`PastPayload`]
pub(super) fn as_past_payload(payload: &[u8]) -> PastPayload<'_> {
    PastPayload {
        height: Height::from(0),
        time: UNIX_EPOCH,
        block_hash: CryptoHashOf::from(CryptoHash(vec![])),
        payload,
    }
}

/// Create a [`ChainKeyConfig`] with one ECDSA, two VetKD key IDs, and one Schnorr key ID,
/// and 1 second request timeout
pub(super) fn make_chain_key_config() -> ChainKeyConfig {
    let key_config = KeyConfig {
        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId::from_str("Secp256k1:some_key_1").unwrap()),
        pre_signatures_to_create_in_advance: Some(1),
        max_queue_size: 3,
    };
    let key_config_1 = KeyConfig {
        key_id: MasterPublicKeyId::VetKd(VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap()),
        pre_signatures_to_create_in_advance: None,
        max_queue_size: 3,
    };
    let key_config_2 = KeyConfig {
        key_id: MasterPublicKeyId::VetKd(
            VetKdKeyId::from_str("bls12_381_g2:some_other_key").unwrap(),
        ),
        pre_signatures_to_create_in_advance: None,
        max_queue_size: 3,
    };
    let key_config_3 = KeyConfig {
        key_id: MasterPublicKeyId::Schnorr(SchnorrKeyId::from_str("Ed25519:some_key_3").unwrap()),
        pre_signatures_to_create_in_advance: Some(1),
        max_queue_size: 3,
    };

    ChainKeyConfig {
        key_configs: vec![
            key_config.clone(),
            key_config_1.clone(),
            key_config_2.clone(),
            key_config_3.clone(),
        ],
        // 1 second timeout
        signature_request_timeout_ns: Some(1_000_000_000),
        ..ChainKeyConfig::default()
    }
}

pub(super) fn fake_completed_signature_request_context(
    key_id: MasterPublicKeyId,
) -> SignWithThresholdContext {
    fake_signature_request_context(key_id, Some(PreSigId(0)), Some([0; 32]))
}

pub(super) fn fake_signature_request_context(
    key_id: MasterPublicKeyId,
    pre_sig_id: Option<PreSigId>,
    nonce: Option<[u8; 32]>,
) -> SignWithThresholdContext {
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(
            key_id,
            Height::from(100),
            pre_sig_id,
            RegistryVersion::from(10),
        ),
        derivation_path: Arc::new(vec![vec![]]),
        batch_time: UNIX_EPOCH,
        deprecated_pseudo_random_id: None,
        nonce,
    }
}

/// Create a fake request context for each key ID in the given config.
/// Callback IDs are assigned sequentially starting at 0.
pub(super) fn make_contexts(
    config: &ChainKeyConfig,
) -> BTreeMap<CallbackId, SignWithThresholdContext> {
    let mut map = BTreeMap::new();
    for (i, key_id) in config.key_ids().into_iter().enumerate() {
        map.insert(
            CallbackId::new(i as u64),
            fake_completed_signature_request_context(key_id),
        );
    }
    map
}

/// Create four artifact shares for each request context
pub(super) fn make_shares(
    contexts: &BTreeMap<CallbackId, SignWithThresholdContext>,
) -> Vec<IDkgMessage> {
    let committee = (0..4).map(|id| node_test_id(id as u64)).collect::<Vec<_>>();
    let mut messages = vec![];
    for (&callback_id, context) in contexts {
        for &signer_id in &committee {
            let request_id = RequestId {
                callback_id,
                height: Height::from(0),
            };
            let message = match context.args {
                ThresholdArguments::Ecdsa(_) => IDkgMessage::EcdsaSigShare(EcdsaSigShare {
                    signer_id,
                    request_id,
                    share: ThresholdEcdsaSigShare {
                        sig_share_raw: vec![],
                    },
                }),
                ThresholdArguments::Schnorr(_) => IDkgMessage::SchnorrSigShare(SchnorrSigShare {
                    signer_id,
                    request_id,
                    share: ThresholdSchnorrSigShare {
                        sig_share_raw: vec![],
                    },
                }),
                ThresholdArguments::VetKd(_) => IDkgMessage::VetKdKeyShare(VetKdKeyShare {
                    signer_id,
                    request_id,
                    share: VetKdEncryptedKeyShare {
                        encrypted_key_share: VetKdEncryptedKeyShareContent(vec![]),
                        node_signature: vec![],
                    },
                }),
            };
            messages.push(message);
        }
    }
    messages
}

/// Create a properly-encoded but dummy agreement for the given request context.
pub(super) fn fake_agreement_for_context(context: &SignWithThresholdContext) -> ChainKeyAgreement {
    let data = match &context.args {
        ThresholdArguments::Ecdsa(_) => SignWithECDSAReply {
            signature: vec![0xDE; 64],
        }
        .encode(),
        ThresholdArguments::Schnorr(_) => SignWithSchnorrReply {
            signature: vec![0xDE; 64],
        }
        .encode(),
        ThresholdArguments::VetKd(_) => VetKdDeriveKeyResult {
            encrypted_key: vec![0xDE; 64],
        }
        .encode(),
    };
    ChainKeyAgreement::Success(data)
}
