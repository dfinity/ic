use axum::{
    body::Bytes,
    extract::State,
    http::{Request, StatusCode},
    Extension,
};
use bytes::BytesMut;
use ic_base_types::NodeId;
use ic_interfaces::p2p::state_sync::StateSyncArtifactId;
use ic_logger::ReplicaLogger;
use ic_protobuf::p2p::v1 as pb;
use prost::Message;
use std::sync::Arc;

use crate::utils::{Advert, XorDistance};

pub const STATE_SYNC_ADVERT_PATH: &str = "/state-sync/advert";

pub(crate) async fn state_sync_advert_handler(
    State(state): State<Arc<StateSyncAdvertHandler>>,
    Extension(peer): Extension<NodeId>,
    payload: Bytes,
) -> Result<(), StatusCode> {
    let advert: Advert = pb::Advert::decode(payload)
        .map(|advert| Advert::try_from(advert).map_err(|_| StatusCode::BAD_REQUEST))
        .map_err(|_| StatusCode::BAD_REQUEST)??;

    state
        .advert_sender
        .send((advert, peer))
        .await
        .expect("State sync manager stopped.");

    Ok(())
}

pub(crate) struct StateSyncAdvertHandler {
    _log: ReplicaLogger,
    advert_sender: tokio::sync::mpsc::Sender<(Advert, NodeId)>,
}

impl StateSyncAdvertHandler {
    pub fn new(
        log: ReplicaLogger,
        advert_sender: tokio::sync::mpsc::Sender<(Advert, NodeId)>,
    ) -> Self {
        Self {
            _log: log,
            advert_sender,
        }
    }
}

pub(crate) fn build_advert_handler_request(
    artifact_id: StateSyncArtifactId,
    partial_state: Option<XorDistance>,
) -> Request<Bytes> {
    let advert = Advert {
        id: artifact_id,
        partial_state,
    };

    let advert = pb::Advert::from(advert);
    let mut raw = BytesMut::with_capacity(advert.encoded_len());
    advert.encode(&mut raw).expect("Allocated enough memory");

    Request::builder()
        .uri(STATE_SYNC_ADVERT_PATH)
        .body(raw.freeze())
        .expect("Building from typed values")
}
