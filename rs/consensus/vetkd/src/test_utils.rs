use ic_interfaces::{
    batch_payload::{PastPayload},
};
use ic_management_canister_types::{MasterPublicKeyId};
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
};
use ic_types::{
    batch::{
        vetkd_payload_to_bytes,
        VetKdAgreement, VetKdErrorCode, VetKdPayload,
    },
    consensus::idkg::VetKdKeyShare,
    crypto::{
        vetkd::{VetKdEncryptedKeyShare},
    },
    messages::{CallbackId},
    Height, NumBytes,
};
use std::{
    collections::{BTreeMap},
    sync::{Arc},
};
    use core::{convert::From, iter::Iterator};
    use ic_interfaces::p2p::consensus::MutablePool;
    use ic_management_canister_types::{EcdsaKeyId, VetKdKeyId};
    use ic_registry_subnet_features::KeyConfig;
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        EcdsaArguments, SchnorrArguments, VetKdArguments,
    };
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::consensus::idkg::{EcdsaSigShare, IDkgMessage, RequestId, SchnorrSigShare};
    use ic_types::crypto::canister_threshold_sig::{
        ThresholdEcdsaSigShare, ThresholdSchnorrSigShare,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet,
    };
    use ic_types::crypto::vetkd::VetKdEncryptedKeyShareContent;
    use ic_types::{
        crypto::{CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
    };
    use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
    use std::str::FromStr;
    use strum::EnumCount;


pub(super) fn make_vetkd_agreements(ids: [u64; 3]) -> BTreeMap<CallbackId, VetKdAgreement> {
    assert_eq!(VetKdAgreement::COUNT, 2);
    assert_eq!(VetKdErrorCode::COUNT, 2);
    BTreeMap::from([
        (
            CallbackId::from(ids[0]),
            VetKdAgreement::Success(vec![1, 2, 3, 4]),
        ),
        (
            CallbackId::from(ids[1]),
            VetKdAgreement::Reject(VetKdErrorCode::TimedOut),
        ),
        (
            CallbackId::from(ids[2]),
            VetKdAgreement::Reject(VetKdErrorCode::InvalidKey),
        ),
    ])
}

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

pub(super) fn as_bytes(vetkd_agreements: BTreeMap<CallbackId, VetKdAgreement>) -> Vec<u8> {
    vetkd_payload_to_bytes(VetKdPayload { vetkd_agreements }, NumBytes::new(1024))
}

pub(super) fn as_past_payload(payload: &[u8]) -> PastPayload {
    PastPayload {
        height: Height::from(0),
        time: UNIX_EPOCH,
        block_hash: CryptoHashOf::from(CryptoHash(vec![])),
        payload,
    }
}

pub(super) fn make_chain_key_config() -> ChainKeyConfig {
    let key_config = KeyConfig {
        key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId::from_str("Secp256k1:some_key_1").unwrap()),
        pre_signatures_to_create_in_advance: 1,
        max_queue_size: 3,
    };
    let key_config_1 = KeyConfig {
        key_id: MasterPublicKeyId::VetKd(
            VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap(),
        ),
        pre_signatures_to_create_in_advance: 1,
        max_queue_size: 3,
    };
    let key_config_2 = KeyConfig {
        key_id: MasterPublicKeyId::VetKd(
            VetKdKeyId::from_str("bls12_381_g2:some_other_key").unwrap(),
        ),
        pre_signatures_to_create_in_advance: 1,
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
        }),
        MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
            key_id,
            message: Arc::new(vec![1; 48]),
            taproot_tree_root: None,
        }),
        MasterPublicKeyId::VetKd(key_id) => ThresholdArguments::VetKd(VetKdArguments {
            key_id: key_id.clone(),
            derivation_id: vec![1; 32],
            encryption_public_key: vec![1; 32],
            ni_dkg_id: fake_dkg_id(key_id),
            height: Height::from(0),
        }),
    }
}

pub(super) fn fake_signature_request_context(key_id: MasterPublicKeyId) -> SignWithThresholdContext {
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id),
        derivation_path: vec![],
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [0; 32],
        matched_pre_signature: None,
        nonce: None,
    }
}

pub(super) fn make_contexts(config: &ChainKeyConfig) -> BTreeMap<CallbackId, SignWithThresholdContext> {
    let mut map = BTreeMap::new();
    for (i, key_id) in config.key_ids().into_iter().enumerate() {
        map.insert(
            CallbackId::new(i as u64),
            fake_signature_request_context(key_id),
        );
    }
    map
}

pub(super) fn make_shares(contexts: &BTreeMap<CallbackId, SignWithThresholdContext>) -> Vec<IDkgMessage> {
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
                ThresholdArguments::Schnorr(_) => {
                    IDkgMessage::SchnorrSigShare(SchnorrSigShare {
                        signer_id,
                        request_id,
                        share: ThresholdSchnorrSigShare {
                            sig_share_raw: vec![],
                        },
                    })
                }
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