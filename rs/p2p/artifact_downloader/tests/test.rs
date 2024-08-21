use std::{
    backtrace::Backtrace,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
};

use axum::http::{Response, StatusCode};
use bytes::Bytes;
use ic_artifact_downloader::FetchArtifact;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, Priority};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::{
    consensus::U64Artifact,
    mocks::{MockPeers, MockPriorityFnFactory, MockTransport, MockValidatedPoolReader},
};
use ic_protobuf::proxy::ProtoProxy;
use ic_types::artifact::PbArtifact;
use ic_types_test_utils::ids::NODE_1;
use mockall::Sequence;
use tokio::runtime::Handle;

/// Check that an advert for which the priority changes from stash to fetch is downloaded.
#[tokio::test]
async fn priority_from_stash_to_fetch() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));

    let mut mock_pfn = MockPriorityFnFactory::new();
    let mut seq = Sequence::new();
    mock_pfn
        .expect_get_priority_function()
        .times(1)
        .returning(|_| Box::new(|_| Priority::Stash))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_get_priority_function()
        .times(1)
        .returning(|_| Box::new(|_| Priority::FetchNow))
        .in_sequence(&mut seq);

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
    let artifact = fetch_artifact
        .assemble_message(0, None, mock_peers)
        .await
        .unwrap();
    assert_eq!(artifact, (U64Artifact::id_to_msg(0, 1024), NODE_1));
}

#[tokio::test]
async fn fetch_to_stash_to_fetch() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));

    let return_artifact = Arc::new(AtomicBool::default());
    let return_artifact_clone = return_artifact.clone();
    let mut mock_pfn = MockPriorityFnFactory::new();
    let priorities = Arc::new(Mutex::new(vec![
        Priority::FetchNow,
        Priority::Stash,
        Priority::Stash,
        Priority::Stash,
    ]));
    mock_pfn.expect_get_priority_function().returning(move |_| {
        let priorities = priorities.clone();

        let p = {
            let mut priorities_g = priorities.lock().unwrap();
            let p = priorities_g.pop().unwrap_or(Priority::FetchNow);
            if priorities_g.is_empty() {
                return_artifact.store(true, Ordering::SeqCst);
            }
            p
        };
        Box::new(move |_| p)
    });
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
    let artifact = fetch_artifact
        .assemble_message(0, None, mock_peers)
        .await
        .unwrap();
    assert_eq!(artifact, (U64Artifact::id_to_msg(0, 1024), NODE_1));
}

/// Verify that downloads with AdvertId != ArtifactId are not added to the pool.
#[tokio::test]
async fn invalid_artifact_not_accepted() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
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
    let mut mock_pfn = MockPriorityFnFactory::new();
    mock_pfn
        .expect_get_priority_function()
        .returning(|_| Box::new(|_| Priority::FetchNow));
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
    let artifact = fetch_artifact
        .assemble_message(0, None, mock_peers)
        .await
        .unwrap();
    assert_eq!(artifact, (U64Artifact::id_to_msg(0, 1024), NODE_1));
}

/// Verify that advert that transitions from stash to drop is not downloaded.
#[tokio::test]
async fn priority_from_stash_to_drop() {
    // Abort process if a thread panics. This catches detached tokio tasks that panic.
    // https://github.com/tokio-rs/tokio/issues/4516
    std::panic::set_hook(Box::new(|info| {
        let stacktrace = Backtrace::force_capture();
        println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
        std::process::abort();
    }));

    let mut mock_pfn: MockPriorityFnFactory<U64Artifact> = MockPriorityFnFactory::new();
    let mut seq = Sequence::new();
    mock_pfn
        .expect_get_priority_function()
        .times(1)
        .returning(|_| Box::new(|_| Priority::Stash))
        .in_sequence(&mut seq);
    mock_pfn
        .expect_get_priority_function()
        .times(1)
        .returning(|_| Box::new(|_| Priority::Drop))
        .in_sequence(&mut seq);

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
    fetch_artifact
        .assemble_message(0, None, mock_peers)
        .await
        .unwrap_err();
}
