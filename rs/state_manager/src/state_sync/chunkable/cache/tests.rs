use super::*;
use ic_metrics::MetricsRegistry;
use ic_test_utilities::with_test_replica_logger;
use tempfile::TempDir;

const NUM_THREADS: u32 = 3;

/// Helper struct to hold all objects that live beyond a single
/// `IncompleteState`
struct TestEnvironment {
    log: ReplicaLogger,
    metrics: StateManagerMetrics,
    state_layout: StateLayout,
    cache: Arc<parking_lot::RwLock<StateSyncCache>>,
    _root_dir: TempDir,
}

impl TestEnvironment {
    fn new(log: ReplicaLogger) -> Self {
        let root_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
        let cache = Arc::new(parking_lot::RwLock::new(StateSyncCache::new(log.clone())));
        let metrics = StateManagerMetrics::new(&MetricsRegistry::new());
        let state_layout = StateLayout::new(log.clone(), root_dir.path().to_owned());

        Self {
            log,
            metrics,
            state_layout,
            cache,
            _root_dir: root_dir,
        }
    }
}

/// Creates a fake DownloadState::Loading.
/// We only use download states for comparison in tests, so it doesn't matter
/// if the contents make sense.
fn fake_loading(seed: u32) -> (DownloadState, Manifest, HashSet<usize>) {
    let manifest = Manifest {
        version: seed,
        file_table: vec![],
        chunk_table: vec![],
    };
    let fetch_chunks: HashSet<usize> = maplit::hashset! { (seed + 1) as usize };
    let state = DownloadState::Loading {
        manifest: manifest.clone(),
        fetch_chunks: fetch_chunks.clone(),
    };
    (state, manifest, fetch_chunks)
}

/// Creates a fake DownloadState::Completed for an empty state.
fn fake_complete() -> DownloadState {
    let manifest = Manifest {
        version: 0,
        file_table: vec![],
        chunk_table: vec![],
    };
    let artifact = Artifact::StateSync(StateSyncMessage {
        height: Height::new(0),
        root_hash: CryptoHashOfState::from(CryptoHash(vec![0; 32])),
        checkpoint_root: PathBuf::new(),
        manifest,
        get_state_sync_chunk: None,
    });
    DownloadState::Complete(Box::new(artifact))
}

/// Creates an `IncompleteState` at `height` with download state `state`.
fn incomplete_state_for_tests(
    env: &TestEnvironment,
    height: Height,
    state: DownloadState,
) -> IncompleteState {
    let hash = CryptoHashOfState::from(CryptoHash(vec![0; 32]));
    let state_sync_refs = StateSyncRefs {
        active: Arc::new(parking_lot::RwLock::new(Default::default())),
        cache: Arc::clone(&env.cache),
    };
    let mut result = IncompleteState::new(
        env.log.clone(),
        height,
        hash,
        env.state_layout.clone(),
        None,
        env.metrics.clone(),
        SubnetType::Application,
        Arc::new(Mutex::new(scoped_threadpool::Pool::new(NUM_THREADS))),
        state_sync_refs,
    );

    // The constructor doesn't create the directory, it gets created when we receive
    // a manifest (in production), or later in this function (in tests)
    assert!(!result.root.exists());

    result.state = state;
    // if Loading, populate the scratchpad with a file named after the seed
    // contained in manifest
    if let DownloadState::Loading {
        ref manifest,
        fetch_chunks: _,
    } = &result.state
    {
        std::fs::create_dir(&result.root).unwrap();
        let mut _file = std::fs::File::create(result.root.join(manifest.version.to_string()));
    }
    result
}

// Blank state syncs should never alter the cache
#[test]
fn blank_sync() {
    with_test_replica_logger(|log| {
        let env = TestEnvironment::new(log);
        let sync = incomplete_state_for_tests(&env, Height::new(5), DownloadState::Blank);
        let scratchpad = sync.root.clone();

        // In production, a Blank sync should not have the scratchpad created, as we
        // would never have received a manifest.
        // In this test we only ever called `IncompleteState::new` and no other
        // production code, so it should be the same.
        assert!(!scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());
        assert!(env.cache.read().get().is_none());
    })
}

// Loading syncs should be cached, unless they are older than what's in the
// cache Any data deleted from cache should be cleaned up properly on
// disk.
#[test]
fn loading_sync() {
    with_test_replica_logger(|log| {
        let env = TestEnvironment::new(log);
        let (state, manifest, fetch_chunks) = fake_loading(1);

        let sync = incomplete_state_for_tests(&env, Height::new(5), state);
        let scratchpad = sync.root.clone();

        // In production, there should be a scratchpad. It was created when receiving
        // the manifest, and then populated with every chunk received.
        // In this test we simulate this by calling `IncompleteState::new` and then
        // creating a directory with a dummy file.
        assert!(scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());

        // The cache is populated correctly
        {
            let lock = env.cache.read();
            assert!(lock.get().is_some());
            let entry = lock.get().unwrap();
            assert_eq!(entry.height, Height::new(5));
            assert_eq!(entry.manifest, manifest);
            assert_eq!(
                entry.missing_chunks,
                fetch_chunks.iter().map(|i| i - 1).collect()
            );
            assert!(entry.path.exists());
            assert!(entry.path.join("1").exists());
        }

        // Second sync at lower height, should be ignored by cache
        let (state, _, _) = fake_loading(2);
        let sync = incomplete_state_for_tests(&env, Height::new(4), state);
        let scratchpad = sync.root.clone();

        assert!(scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());

        // The cache is still populated with the first entry
        {
            let lock = env.cache.read();
            assert!(lock.get().is_some());
            let entry = lock.get().unwrap();
            assert_eq!(entry.height, Height::new(5));
            assert_eq!(entry.manifest, manifest);
            assert_eq!(
                entry.missing_chunks,
                fetch_chunks.iter().map(|i| i - 1).collect()
            );
            assert!(entry.path.exists());
            assert!(entry.path.join("1").exists());
        }

        // Third sync at the same height as the cache, should replace cache
        let (state, manifest, fetch_chunks) = fake_loading(3);
        let sync = incomplete_state_for_tests(&env, Height::new(5), state);
        let scratchpad = sync.root.clone();

        assert!(scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());

        // The cache is now populated with the new sync
        {
            let lock = env.cache.read();
            assert!(lock.get().is_some());
            let entry = lock.get().unwrap();
            assert_eq!(entry.height, Height::new(5));
            assert_eq!(entry.manifest, manifest);
            assert_eq!(
                entry.missing_chunks,
                fetch_chunks.iter().map(|i| i - 1).collect()
            );
            assert!(entry.path.exists());
            assert!(entry.path.join("3").exists());
            assert!(!entry.path.join("1").exists());
        }

        // Fourth sync at higher height than cache, should replace
        let old_cache_path = env.cache.read().get().unwrap().path.clone();
        let (state, manifest, fetch_chunks) = fake_loading(4);

        let sync = incomplete_state_for_tests(&env, Height::new(6), state);
        let scratchpad = sync.root.clone();
        assert!(scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());
        assert!(!old_cache_path.exists());

        // The cache is populated with the latest sync
        {
            let lock = env.cache.read();
            assert!(lock.get().is_some());
            let entry = lock.get().unwrap();
            assert_eq!(entry.height, Height::new(6));
            assert_eq!(entry.manifest, manifest);
            assert_eq!(
                entry.missing_chunks,
                fetch_chunks.iter().map(|i| i - 1).collect()
            );
            assert!(entry.path.exists());
            assert!(entry.path.join("4").exists());
        }
    })
}

// Completed syncs can clear the cache if they are not older, but don't replace
// the cache with anything new
#[test]
fn completed_sync() {
    with_test_replica_logger(|log| {
        let env = TestEnvironment::new(log);

        let complete = fake_complete();
        let sync = incomplete_state_for_tests(&env, Height::new(5), complete.clone());
        let scratchpad = sync.root.clone();

        // In production, there shouldn't be a scratchpad, as we rename it when
        // converting an `IncompleteState` into a proper checkpoint.
        // In this test we simulate this by only ever calling `IncompleteState::new`,
        // and never creating a directory.
        assert!(!scratchpad.exists());

        drop(sync);

        assert!(!scratchpad.exists());

        // Should have been ignored
        assert!(env.cache.read().get().is_none());

        // Populate cache

        let (state, _, _) = fake_loading(1);
        let sync = incomplete_state_for_tests(&env, Height::new(5), state);
        drop(sync);

        assert!(env.cache.read().get().is_some());

        // Cannot delete cache with lower height completed sync
        let sync = incomplete_state_for_tests(&env, Height::new(4), complete.clone());
        drop(sync);
        assert!(env.cache.read().get().is_some());

        // Can delete cache with completed sync at same height
        let sync = incomplete_state_for_tests(&env, Height::new(5), complete.clone());
        drop(sync);
        assert!(env.cache.read().get().is_none());

        // Populate cache again
        let (state, _, _) = fake_loading(1);
        let sync = incomplete_state_for_tests(&env, Height::new(5), state);
        drop(sync);

        // Can delete cache with completed sync at higher height
        let sync = incomplete_state_for_tests(&env, Height::new(6), complete);
        drop(sync);
        assert!(env.cache.read().get().is_none());
    })
}

// If the cache is written, but the target folder already exists, then we have
// to make sure the existing folder is not being referenced as a valid cache.
// Current behavior is to not write to the cache in these cases.
#[test]
fn existing_folder() {
    with_test_replica_logger(|log| {
        let env = TestEnvironment::new(log);
        let (state, _, _) = fake_loading(1);

        let height = Height::new(5);
        let sync = incomplete_state_for_tests(&env, height, state);

        let cache_dir = env.state_layout.state_sync_cache(height).unwrap();

        // create a non-empty folder where the cache should be
        std::fs::create_dir(&cache_dir).unwrap();
        let file_path = cache_dir.join("empty_file");
        let mut _file = std::fs::File::create(&file_path).unwrap();

        drop(sync);

        assert!(!file_path.exists());
        assert!(env.cache.read().get().is_none());
    })
}
