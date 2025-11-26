use std::{
    backtrace::Backtrace,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::http::{Response, StatusCode};
use bytes::Bytes;
use ic_artifact_downloader::FetchArtifact;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, AssembleResult, BouncerValue};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    consensus::U64Artifact,
    mocks::{MockBouncerFactory, MockPeers, MockTransport, MockValidatedPoolReader},
};
use ic_protobuf::proxy::ProtoProxy;
use ic_types::artifact::PbArtifact;
use ic_types_test_utils::ids::NODE_1;
use mockall::Sequence;
use tokio::runtime::Handle;

/// Check that an update with ID for which the bouncer value changes from MaybeWantsLater to Wants is downloaded.
#[tokio::test]
async fn priority_from_stash_to_fetch() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{info}\n@stackTrace:{stacktrace}");
        std::process::abort();
    }));

    let mut mock_pfn = MockBouncerFactory::new();
    let mut seq = Sequence::new();
    mock_pfn
        .expect_new_bouncer()
        .times(1)
        .returning(|_| Box::new(|_| BouncerValue::MaybeWantsLater))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_new_bouncer()
        .times(1)
        .returning(|_| Box::new(|_| BouncerValue::Wants))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_refresh_period()
        .returning(|| std::time::Duration::from_secs(3));

    let mut mock_transport = MockTransport::new();
    mock_transport.expect_rpc().returning(|_, _| {
        Ok(Response::builder()
            .body(Bytes::from(
                <<U64Artifact as PbArtifact>::PbMessage>::proxy_encode(U64Artifact::id_to_msg(
                    0, 1024,
                )),
            ))
            .unwrap())
    });
    let pool = MockValidatedPoolReader::default();

    let (fetch_artifact, _router) = FetchArtifact::new(
        no_op_logger(),
        Handle::current(),
        Arc::new(RwLock::new(pool)),
        Arc::new(mock_pfn),
        MetricsRegistry::default(),
    );
    let fetch_artifact: FetchArtifact<U64Artifact> = fetch_artifact(Arc::new(mock_transport));
    let mut mock_peers = MockPeers::default();
    mock_peers.expect_peers().return_const(vec![NODE_1]);
    assert_eq!(
        fetch_artifact.assemble_message(0, None, mock_peers).await,
        AssembleResult::Done {
            message: U64Artifact::id_to_msg(0, 1024),
            peer_id: NODE_1
        }
    );
}

#[tokio::test]
async fn fetch_to_stash_to_fetch() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{info}\n@stackTrace:{stacktrace}");
        std::process::abort();
    }));

    let return_artifact = Arc::new(AtomicBool::default());
    let return_artifact_clone = return_artifact.clone();
    let mut mock_pfn = MockBouncerFactory::new();
    let priorities = Arc::new(Mutex::new(vec![
        BouncerValue::Wants,
        BouncerValue::MaybeWantsLater,
        BouncerValue::MaybeWantsLater,
        BouncerValue::MaybeWantsLater,
    ]));
    mock_pfn.expect_new_bouncer().returning(move |_| {
        let priorities = priorities.clone();

        let p = {
            let mut priorities_g = priorities.lock().unwrap();
            let p = priorities_g.pop().unwrap_or(BouncerValue::Wants);
            if priorities_g.is_empty() {
                return_artifact.store(true, Ordering::SeqCst);
            }
            p
        };
        Box::new(move |_| p)
    });
    mock_pfn
        .expect_refresh_period()
        .returning(|| std::time::Duration::from_secs(3));
    let mut mock_transport = MockTransport::new();
    mock_transport.expect_rpc().returning(move |_, _| {
        if return_artifact_clone.load(Ordering::SeqCst) {
            Ok(Response::builder()
                .body(Bytes::from(
                    <<U64Artifact as PbArtifact>::PbMessage>::proxy_encode(U64Artifact::id_to_msg(
                        0, 1024,
                    )),
                ))
                .unwrap())
        } else {
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Bytes::new())
                .unwrap())
        }
    });

    let pool = MockValidatedPoolReader::default();
    let (fetch_artifact, _router) = FetchArtifact::new(
        no_op_logger(),
        Handle::current(),
        Arc::new(RwLock::new(pool)),
        Arc::new(mock_pfn),
        MetricsRegistry::default(),
    );
    let fetch_artifact: FetchArtifact<U64Artifact> = fetch_artifact(Arc::new(mock_transport));
    let mut mock_peers = MockPeers::default();
    mock_peers.expect_peers().return_const(vec![NODE_1]);
    assert_eq!(
        fetch_artifact.assemble_message(0, None, mock_peers).await,
        AssembleResult::Done {
            message: U64Artifact::id_to_msg(0, 1024),
            peer_id: NODE_1
        }
    );
}

/// Verify that downloads with AdvertId != ArtifactId are not added to the pool.
#[tokio::test]
async fn invalid_artifact_not_accepted() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{info}\n@stackTrace:{stacktrace}");
        std::process::abort();
    }));
    let mut mock_transport = MockTransport::new();
    let mut seq = Sequence::new();
    // Respond with artifact that does not correspond to the advertised ID
    mock_transport
        .expect_rpc()
        .once()
        .returning(|_, _| {
            Ok(Response::builder()
                .body(Bytes::from(
                    <<U64Artifact as PbArtifact>::PbMessage>::proxy_encode(U64Artifact::id_to_msg(
                        1, 1024,
                    )),
                ))
                .unwrap())
        })
        .in_sequence(&mut seq);
    // Respond with artifact that does correspond to the advertised ID
    mock_transport
        .expect_rpc()
        .once()
        .returning(|_, _| {
            // Respond with artifact that does correspond to the advertised ID
            Ok(Response::builder()
                .body(Bytes::from(
                    <<U64Artifact as PbArtifact>::PbMessage>::proxy_encode(U64Artifact::id_to_msg(
                        0, 1024,
                    )),
                ))
                .unwrap())
        })
        .in_sequence(&mut seq);

    let pool = MockValidatedPoolReader::default();
    let mut mock_pfn = MockBouncerFactory::new();
    mock_pfn
        .expect_new_bouncer()
        .returning(|_| Box::new(|_| BouncerValue::Wants));
    mock_pfn
        .expect_refresh_period()
        .returning(|| std::time::Duration::from_secs(3));
    let (fetch_artifact, _router) = FetchArtifact::new(
        no_op_logger(),
        Handle::current(),
        Arc::new(RwLock::new(pool)),
        Arc::new(mock_pfn),
        MetricsRegistry::default(),
    );
    let fetch_artifact: FetchArtifact<U64Artifact> = fetch_artifact(Arc::new(mock_transport));
    let mut mock_peers = MockPeers::default();
    mock_peers.expect_peers().return_const(vec![NODE_1]);
    assert_eq!(
        fetch_artifact.assemble_message(0, None, mock_peers).await,
        AssembleResult::Done {
            message: U64Artifact::id_to_msg(0, 1024),
            peer_id: NODE_1
        }
    );
}

/// Verify that advert that transitions from stash to drop is not downloaded.
#[tokio::test]
async fn priority_from_stash_to_drop() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{info}\n@stackTrace:{stacktrace}");
        std::process::abort();
    }));

    let mut mock_pfn: MockBouncerFactory<U64Artifact> = MockBouncerFactory::new();
    let mut seq = Sequence::new();
    mock_pfn
        .expect_new_bouncer()
        .times(1)
        .returning(|_| Box::new(|_| BouncerValue::MaybeWantsLater))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_new_bouncer()
        .times(1)
        .returning(|_| Box::new(|_| BouncerValue::Unwanted))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_refresh_period()
        .returning(|| std::time::Duration::from_secs(3));

    let mut mock_transport = MockTransport::new();
    mock_transport.expect_rpc().returning(|_, _| {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Bytes::new())
            .unwrap())
    });
    let pool = MockValidatedPoolReader::default();
    let (fetch_artifact, _router) = FetchArtifact::new(
        no_op_logger(),
        Handle::current(),
        Arc::new(RwLock::new(pool)),
        Arc::new(mock_pfn),
        MetricsRegistry::default(),
    );
    let fetch_artifact: FetchArtifact<U64Artifact> = fetch_artifact(Arc::new(mock_transport));
    let mut mock_peers = MockPeers::default();
    mock_peers.expect_peers().return_const(vec![NODE_1]);
    assert_eq!(
        fetch_artifact.assemble_message(0, None, mock_peers).await,
        AssembleResult::Unwanted
    );
}
