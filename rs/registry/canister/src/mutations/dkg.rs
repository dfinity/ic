use candid::{CandidType, Decode, Deserialize};

use ic_base_types::PrincipalId;
use ic_ic00_types::EcdsaKeyId;
use ic_protobuf::{
    registry::crypto::v1::PublicKey,
    registry::subnet::v1::{InitialIDkgDealings, InitialNiDkgTranscriptRecord},
};

/// The next two types are exactly the same types as the ones defined in
/// rs/types/src/ic00.rs
/// The reason for keeping a copy is because we can't depend on ic-types crate,
/// as it is not wasm32-safe.
#[derive(CandidType, Deserialize, Debug)]
pub(crate) struct SetupInitialDKGArgs {
    // We use PrincipalId here because it is needed by the setup_initial_dkg API
    pub node_ids: Vec<PrincipalId>,
    pub registry_version: u64,
}

#[derive(Debug)]
pub(crate) struct SetupInitialDKGResponse {
    pub low_threshold_transcript_record: InitialNiDkgTranscriptRecord,
    pub high_threshold_transcript_record: InitialNiDkgTranscriptRecord,
    pub fresh_subnet_id: PrincipalId,
    pub subnet_threshold_public_key: PublicKey,
}

impl SetupInitialDKGResponse {
    pub fn decode(blob: &[u8]) -> Result<Self, String> {
        let serde_encoded_transcript_records =
            Decode!(blob, Vec<u8>).expect("failed to decode response");
        match serde_cbor::from_slice::<(
            InitialNiDkgTranscriptRecord,
            InitialNiDkgTranscriptRecord,
            PrincipalId,
            PublicKey,
        )>(&serde_encoded_transcript_records)
        {
            Err(err) => Err(format!("Payload deserialization error: '{}'", err)),
            Ok((
                low_threshold_transcript_record,
                high_threshold_transcript_record,
                fresh_subnet_id,
                subnet_threshold_public_key,
            )) => Ok(Self {
                low_threshold_transcript_record,
                high_threshold_transcript_record,
                fresh_subnet_id,
                subnet_threshold_public_key,
            }),
        }
    }
}
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct ComputeInitialEcdsaDealingsArgs {
    pub key_id: EcdsaKeyId,
    pub nodes: Vec<PrincipalId>,
    pub registry_version: u64,
}

#[derive(Debug)]
pub struct ComputeInitialEcdsaDealingsResponse {
    pub initial_dealings: InitialIDkgDealings,
}

impl ComputeInitialEcdsaDealingsResponse {
    pub fn decode(blob: &[u8]) -> Result<Self, String> {
        let serde_encoded_transcript_records =
            Decode!(blob, Vec<u8>).expect("failed to decode response");
        match serde_cbor::from_slice::<(InitialIDkgDealings,)>(&serde_encoded_transcript_records) {
            Err(err) => Err(format!("Payload deserialization error: '{}'", err)),
            Ok((initial_dealings,)) => Ok(Self { initial_dealings }),
        }
    }
}
