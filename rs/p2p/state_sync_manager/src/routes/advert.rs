use std::sync::Arc;

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

pub const STATE_SYNC_ADVERT_PATH: &str = "/state-sync/advert";

pub(crate) async fn state_sync_advert_handler(
    State(state): State<Arc<StateSyncAdvertHandler>>,
    Extension(peer): Extension<NodeId>,
    payload: Bytes,
) -> Result<(), StatusCode> {
    let id: StateSyncArtifactId = pb::StateSyncId::decode(payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .into();

    state
        .advert_sender
        .send((id, peer))
        .await
        .expect("State sync manager stopped.");

    Ok(())
}

pub(crate) struct StateSyncAdvertHandler {
    _log: ReplicaLogger,
    advert_sender: tokio::sync::mpsc::Sender<(StateSyncArtifactId, NodeId)>,
}

impl StateSyncAdvertHandler {
    pub fn new(
        log: ReplicaLogger,
        advert_sender: tokio::sync::mpsc::Sender<(StateSyncArtifactId, NodeId)>,
    ) -> Self {
        Self {
            _log: log,
            advert_sender,
        }
    }
}

pub(crate) fn build_advert_handler_request(artifact_id: StateSyncArtifactId) -> Request<Bytes> {
    let pb: pb::StateSyncId = artifact_id.into();

    let mut raw = BytesMut::with_capacity(pb.encoded_len());
    pb.encode(&mut raw).expect("Allocated enough memory");

    Request::builder()
        .uri(STATE_SYNC_ADVERT_PATH)
        .body(raw.freeze())
        .expect("Building from typed values")
}
