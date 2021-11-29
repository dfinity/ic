use ic_crypto_tree_hash::{Digest, LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::verify_combined;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{threshold_sig::ThresholdSigPublicKey, CombinedThresholdSigOf, CryptoHash},
    CanisterId, CryptoHashOfPartialState, Time,
};
use ledger_canister::{EncodedBlock, HashOf};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

pub(crate) fn verify_block_hash(
    cert: &ledger_canister::Certification,
    hash: HashOf<EncodedBlock>,
    root_key: &Option<ThresholdSigPublicKey>,
    canister_id: &CanisterId,
) -> Result<(), String> {
    match root_key {
        Some(root_key) => {
            let (from_cert, _) = check_certificate(
                canister_id,
                root_key,
                cert.as_ref()
                    .ok_or("verify tip failed: no data certificate present")?,
            )
            .map_err(|e| format!("Certification error: {:?}", e))?;
            if from_cert.as_bytes() != hash.into_bytes() {
                Err("verify block hash failed".to_string())
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

#[derive(Debug)]
pub enum CertificationError {
    /// Failed to deserialize some part of the response.
    DeserError(String),
    /// The signature verification failed.
    InvalidSignature(String),
    /// The value at path "/canister/<cid>/certified_data" doesn't match the
    /// hash computed from the mixed hash tree with registry deltas.
    CertifiedDataMismatch { certified: Digest, computed: Digest },
    /// Parsing and signature verification was successful, but the list of
    /// deltas doesn't satisfy postconditions of the method.
    InvalidDeltas(String),
    /// The hash tree in the response was not well-formed.
    MalformedHashTree(String),
}

fn verify_combined_threshold_sig(
    msg: &CryptoHashOfPartialState,
    sig: &CombinedThresholdSigOf<CertificationContent>,
    root_key: &ThresholdSigPublicKey,
) -> Result<(), CertificationError> {
    verify_combined(&CertificationContent::new(msg.clone()), sig, root_key)
        .map_err(|e| CertificationError::InvalidSignature(e.to_string()))
}

fn check_certificate(
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    encoded_certificate: &[u8],
) -> Result<(Digest, Time), CertificationError> {
    #[derive(Deserialize)]
    struct Certificate {
        tree: MixedHashTree,
        signature: CombinedThresholdSigOf<CertificationContent>,
    }

    #[derive(Deserialize)]
    struct CanisterView {
        certified_data: Digest,
    }

    #[derive(Deserialize)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = serde_cbor::from_slice(encoded_certificate).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certificate from canister {}: {}",
            canister_id, err
        ))
    })?;

    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));

    verify_combined_threshold_sig(&digest, &certificate.signature, nns_pk).map_err(|err| {
        CertificationError::InvalidSignature(format!(
            "failed to verify threshold signature: root_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, nns_pk, err
        ))
    })?;

    let replica_labeled_tree =
        LabeledTree::<Vec<u8>>::try_from(certificate.tree).map_err(|err| {
            CertificationError::MalformedHashTree(format!(
                "failed to convert hash tree to labeled tree: {:?}",
                err
            ))
        })?;

    let replica_state = ReplicaState::deserialize(LabeledTreeDeserializer::new(
        &replica_labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack replica state from a labeled tree: {}",
            err
        ))
    })?;

    let time = Time::from_nanos_since_unix_epoch(replica_state.time.0);

    replica_state
        .canister
        .get(canister_id)
        .map(|canister| (canister.certified_data.clone(), time))
        .ok_or_else(|| {
            CertificationError::MalformedHashTree(format!(
                "cannot find certified_data for canister {} in the tree",
                canister_id
            ))
        })
}
