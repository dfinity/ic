use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use ic_tracing::{utils::SharedBuffer, ReloadHandles};
use std::io::BufReader;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing_flame::FlameLayer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::Layer;

use crate::common::CONTENT_TYPE_SVG;

const DEFAULT_TRACING_FLAMEGRAPH_DURATION: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct TracingFlamegraphService(ReloadHandles);

impl TracingFlamegraphService {
    pub(crate) fn route() -> &'static str {
        "/_/tracing/flamegraph"
    }

    pub(crate) fn build_router(handles: ReloadHandles) -> Router {
        Router::new()
            .route(Self::route(), axum::routing::get(tracing_flamegraph_handle))
            .with_state(Self(handles))
    }
}

pub(crate) async fn tracing_flamegraph_handle(
    State(TracingFlamegraphService(reload_handles)): State<TracingFlamegraphService>,
) -> impl IntoResponse {
    let writer = SharedBuffer::default();
    let flame_layer =
        FlameLayer::new(writer.clone()).with_filter(Targets::new().with_default(LevelFilter::INFO));

    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let guard = flame_layer.inner().flush_on_drop();
        reload_handles.push(flame_layer.boxed());

        tokio::time::sleep(DEFAULT_TRACING_FLAMEGRAPH_DURATION).await;

        reload_handles.pop();

        drop(guard);
        let data = writer.reset();
        let _ = tx.send(data);
    });

    let data = rx.await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error: {}", err),
        )
            .into_response()
    })?;
    let reader = BufReader::new(data.as_slice());
    let mut body: Vec<u8> = vec![];
    let mut opts = inferno::flamegraph::Options::default();
    inferno::flamegraph::from_reader(&mut opts, reader, &mut body)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", err),
            )
                .into_response()
        })
        .map(|()| {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, CONTENT_TYPE_SVG)],
                body,
            )
                .into_response()
        })
}
