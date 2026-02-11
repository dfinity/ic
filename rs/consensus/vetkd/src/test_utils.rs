use core::{convert::From, iter::Iterator};
use ic_interfaces::batch_payload::PastPayload;
use ic_management_canister_types_private::{EcdsaKeyId, MasterPublicKeyId, VetKdKeyId};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    EcdsaArguments, SchnorrArguments, SignWithThresholdContext, ThresholdArguments, VetKdArguments,
};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::consensus::idkg::{EcdsaSigShare, IDkgMessage, RequestId, SchnorrSigShare};
use ic_types::crypto::canister_threshold_sig::{ThresholdEcdsaSigShare, ThresholdSchnorrSigShare};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet,
};
use ic_types::{
    Height, NumBytes,
    batch::{VetKdAgreement, VetKdErrorCode, VetKdPayload, vetkd_payload_to_bytes},
    consensus::idkg::VetKdKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShare,
    crypto::vetkd::VetKdEncryptedKeyShareContent,
    crypto::{CryptoHash, CryptoHashOf},
    messages::CallbackId,
    time::UNIX_EPOCH,
};
use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
use std::str::FromStr;
use std::{collections::BTreeMap, sync::Arc};
use strum::EnumCount;

/// Create a map of agreements with all possible types
pub(super) fn make_vetkd_agreements(
    id1: u64,
    id2: u64,
    id3: u64,
) -> BTreeMap<CallbackId, VetKdAgreement> {
    assert_eq!(VetKdAgreement::COUNT, 2);
    assert_eq!(VetKdErrorCode::COUNT, 2);
    BTreeMap::from([
        (
            CallbackId::from(id1),
            VetKdAgreement::Success(vec![1, 2, 3, 4]),
        ),
        (
            CallbackId::from(id2),
            VetKdAgreement::Reject(VetKdErrorCode::TimedOut),
        ),
        (
            CallbackId::from(id3),
            VetKdAgreement::Reject(VetKdErrorCode::InvalidKey),
        ),
    ])
}

/// Create a map of agreements with the same, given type
pub(super) fn make_vetkd_agreements_with_payload(
    ids: &[u64],
    agreement: VetKdAgreement,
) -> BTreeMap<CallbackId, VetKdAgreement> {
    let mut map = BTreeMap::new();
    for id in ids {
        map.insert(CallbackId::new(*id), agreement.clone());
    }
    map
}

/// Convert the given agreements payload to bytes, using a maximum size of 1KiB.
pub(super) fn as_bytes(vetkd_agreements: BTreeMap<CallbackId, VetKdAgreement>) -> Vec<u8> {
    vetkd_payload_to_bytes(VetKdPayload { vetkd_agreements }, NumBytes::new(1024))
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

/// Create a [`ChainKeyConfig`] with one ECDSA and two VetKD key IDs,
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

    ChainKeyConfig {
        key_configs: vec![
            key_config.clone(),
            key_config_1.clone(),
            key_config_2.clone(),
        ],
        // 1 second timeout
        signature_request_timeout_ns: Some(1_000_000_000),
        ..ChainKeyConfig::default()
    }
}

pub(super) fn fake_dkg_id(key_id: VetKdKeyId) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id)),
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

pub(super) fn fake_signature_request_args(key_id: MasterPublicKeyId) -> ThresholdArguments {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
            key_id,
            message_hash: [0; 32],
            pre_signature: None,
        }),
        MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
            key_id,
            message: Arc::new(vec![1; 48]),
            taproot_tree_root: None,
            pre_signature: None,
        }),
        MasterPublicKeyId::VetKd(key_id) => ThresholdArguments::VetKd(VetKdArguments {
            key_id: key_id.clone(),
            input: Arc::new(vec![1; 32]),
            transport_public_key: vec![1; 32],
            ni_dkg_id: fake_dkg_id(key_id),
            height: Height::from(100),
        }),
    }
}

pub(super) fn fake_signature_request_context(
    key_id: MasterPublicKeyId,
) -> SignWithThresholdContext {
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id),
        derivation_path: Arc::new(vec![vec![]]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [0; 32],
        matched_pre_signature: None,
        nonce: None,
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
            fake_signature_request_context(key_id),
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
