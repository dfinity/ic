//! Implementation of the registry client. Calls to the API always return
//! immediately. The provided data provider is polled periodically in the
//! background when start_polling() is called.
use crossbeam_channel::{RecvTimeoutError, Sender, TrySendError};
pub use ic_interfaces_registry::{
    POLLING_PERIOD, RegistryClient, RegistryClientVersionedResult, RegistryDataProvider,
    RegistryRecord, ZERO_REGISTRY_VERSION, empty_zero_registry_record,
};
use ic_metrics::MetricsRegistry;
pub use ic_types::{
    RegistryVersion, Time,
    crypto::threshold_sig::ThresholdSigPublicKey,
    registry::{RegistryClientError, RegistryDataProviderError},
    time::current_time,
};
use ic_utils_thread::JoinOnDrop;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::{collections::BTreeMap, thread::JoinHandle};

use crate::metrics::Metrics;

#[derive(Clone)]
pub struct RegistryClientImpl {
    cache: Arc<RwLock<CacheState>>,
    data_provider: Arc<dyn RegistryDataProvider>,
    metrics: Arc<Metrics>,
    poll_thread: Arc<RwLock<Option<PollThread>>>,
}

/// RegistryClientImpl polls the data provider and caches the received results.
impl RegistryClientImpl {
    /// Creates a new instance of the RegistryClient.
    pub fn new(
        data_provider: Arc<dyn RegistryDataProvider>,
        metrics_registry: Option<&MetricsRegistry>,
    ) -> Self {
        let metrics = match metrics_registry {
            Some(metrics_registry) => Arc::new(Metrics::new(metrics_registry)),
            None => Arc::new(Metrics::new(&MetricsRegistry::new())),
        };

        Self {
            cache: Arc::new(RwLock::new(CacheState::new())),
            data_provider,
            metrics,
            poll_thread: Arc::new(RwLock::new(None)),
        }
    }

    /// Calls `poll_once()` synchronously, if it succeeds a background task is
    /// spawned that continuously polls for updates.
    /// The background task is stopped when the object is dropped.
    pub fn fetch_and_start_polling(&self) -> Result<(), RegistryClientError> {
        let mut cancel_sig_lock = self.poll_thread.write().unwrap();
        if cancel_sig_lock.is_some() {
            return Err(RegistryClientError::PollLockFailed {
                error: "'fetch_and_start_polling' already called".to_string(),
            });
        }
        self.poll_once()?;

        let (cancel_sig_sender, cancel_sig_receiver) = crossbeam_channel::bounded::<()>(1);
        let self_ = self.clone();
        let join_handle = std::thread::Builder::new()
            .name("RegistryClient_Thread".to_string())
            .spawn(move || {
                while Err(RecvTimeoutError::Timeout)
                    == cancel_sig_receiver.recv_timeout(POLLING_PERIOD)
                {
                    if let Ok(()) = self_.poll_once() {}
                }
            })
            .expect("Could not spawn background thread.");
        *cancel_sig_lock = Some(PollThread::new(cancel_sig_sender, join_handle));

        Ok(())
    }

    /// Fetches the newest updates from the registry data provider.
    ///
    /// Returns an error if a poll is already in progress or querying the data
    /// provider failed. Returns `Ok` if querying the data provider succeeded,
    /// regardless of whether a newer registry version was available or not.
    pub fn poll_once(&self) -> Result<(), RegistryClientError> {
        let (records, version) = {
            let latest_version = self.cache.read().unwrap().latest_version;
            let records = match self
                .data_provider
                .get_updates_since(latest_version)
            {
                Ok(records) if !records.is_empty() => records,
                Ok(_) /*if version == cache_state.latest_version*/ => return Ok(()),
                Err(e) => return Err(RegistryClientError::from(e)),
            };
            let new_version = records
                .iter()
                .max_by_key(|r| r.version)
                .map(|r| r.version)
                .unwrap_or(latest_version);

            (records, new_version)
        };

        // Ensure exclusive access to the cache.
        let mut cache_state = self.cache.write().unwrap();

        // Check version again under write lock, to prevent race conditions.
        if version > cache_state.latest_version {
            self.metrics.registry_version.set(version.get() as i64);
            cache_state.update(records, version);
        }
        Ok(())
    }

    /// Calls poll_once() at most `retries` many times or until
    /// `get_latest_version()` reports the same version at least twice.
    ///
    /// This method can be used in situations where the registry client is
    /// backed by a data provider that fetches changelogs from the registry
    /// canister directly and the client needs to be updated to the current
    /// version without starting a background thread.
    ///
    /// # Errors
    ///
    /// Errors of poll_once() are propagated.
    ///
    /// If the same latest version cannot be observed after `retries` retries, a
    /// `RegistryClientError::PollingLatestVersionFailed` is returned.
    pub fn try_polling_latest_version(&self, retries: usize) -> Result<(), RegistryClientError> {
        let mut last_version = self.get_latest_version();
        for _ in 0..retries {
            match self.poll_once() {
                Ok(()) => {}
                Err(RegistryClientError::DataProviderQueryFailed {
                    source: RegistryDataProviderError::Transfer { source },
                    ..
                }) if source.contains("Request timed out") => {
                    eprintln!("Request timed out, retrying.");
                    continue;
                }
                Err(e) => return Err(e),
            }
            let new_version = self.get_latest_version();
            if new_version == last_version {
                return Ok(());
            }
            last_version = new_version;
        }
        Err(RegistryClientError::PollingLatestVersionFailed { retries })
    }

    fn check_version(
        &self,
        version: RegistryVersion,
    ) -> Result<RwLockReadGuard<'_, CacheState>, RegistryClientError> {
        let cache_state = self.cache.read().unwrap();
        if version > cache_state.latest_version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }
        Ok(cache_state)
    }
}

struct PollThread {
    cancel_sig_sender: Sender<()>,
    _join_handle: JoinOnDrop<()>,
}

impl PollThread {
    fn new(cancel_sig_sender: Sender<()>, join_handle: JoinHandle<()>) -> Self {
        Self {
            cancel_sig_sender,
            _join_handle: JoinOnDrop::new(join_handle),
        }
    }
}

impl Drop for PollThread {
    // The drop handler of PollThread gets called before the drop handler of its
    // fields. Hence, the thread is joined after the signal is sent.
    fn drop(&mut self) {
        match self.cancel_sig_sender.try_send(()) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            e => e.expect("Could not send cancellation signal."),
        };
    }
}

#[derive(Clone)]
struct CacheState {
    records: Vec<RegistryRecord>,
    timestamps: BTreeMap<RegistryVersion, Time>,
    latest_version: RegistryVersion,
}

impl CacheState {
    fn new() -> Self {
        Self {
            records: vec![],
            latest_version: ZERO_REGISTRY_VERSION,
            timestamps: Default::default(),
        }
    }

    fn update(&mut self, records: Vec<RegistryRecord>, new_version: RegistryVersion) {
        assert!(new_version > self.latest_version);
        self.timestamps.insert(new_version, current_time());
        for record in records {
            assert!(record.version > self.latest_version);
            self.timestamps.insert(record.version, current_time());
            let search_key = (&record.key, &record.version);
            match self
                .records
                .binary_search_by_key(&search_key, |r| (&r.key, &r.version))
            {
                Ok(_) => (),
                Err(i) => {
                    self.records.insert(i, record);
                }
            };
        }
        self.latest_version = new_version;
    }
}

impl RegistryClient for RegistryClientImpl {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_versioned_value"])
            .start_timer();

        if version == ZERO_REGISTRY_VERSION {
            return Ok(empty_zero_registry_record(key));
        }
        let cache_state = self.check_version(version)?;

        let search_key = &(key, &version);
        let record = match cache_state
            .records
            .binary_search_by_key(search_key, |r| (&r.key, &r.version))
        {
            // We have an exact match
            Ok(idx) => cache_state.records[idx].clone(),
            // A record with the same key and record version < version
            Err(idx) if idx > 0 && cache_state.records[idx - 1].key == key => {
                cache_state.records[idx - 1].clone()
            }
            // No entry found, key does not exist
            _ => empty_zero_registry_record(key),
        };

        Ok(record)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_key_family"])
            .start_timer();

        if version == ZERO_REGISTRY_VERSION {
            return Ok(vec![]);
        }
        let cache_state = self.check_version(version)?;

        let first_registry_version = RegistryVersion::from(1);
        // The pair (k, version) is unique and no entry exists with version 0. Thus, the
        // first entry of interest is at the insertion point of (prefix, 1).
        let search_key = &(key_prefix, &first_registry_version);

        let first_match_index = match cache_state
            .records
            .binary_search_by_key(search_key, |r| (&r.key, &r.version))
        {
            // An exact match just means the key family will have size 1.
            Ok(idx) => idx,
            // The entry at idx cannot be lexicographically less than key_prefix, otherwise the
            // correctness assumption about bin search would not hold.
            Err(idx) => {
                // If the key at this position does not start with `key_prefix`, the set of keys
                // starting with `key_prefix` is empty.
                if !cache_state.records[idx].key.starts_with(key_prefix) {
                    return Ok(vec![]);
                }
                idx
            }
        };

        // 1. Skip all entries up to the first_match_index
        // 2. Filter out all versions newer than the one we are interested in
        // 3. Only consider the subsequence that starts with the given prefix
        let records = cache_state
            .records
            .iter()
            .skip(first_match_index) // (1)
            .filter(|r| r.version <= version) // (2)
            .take_while(|r| r.key.starts_with(key_prefix)); // (3)

        // For each key, keep only the record values for the latest record versions. We rely upon
        // the fact that for a fixed key, the records are sorted by version.
        let mut effective_records = BTreeMap::new();
        for record in records {
            effective_records.insert(record.key.clone(), &record.value);
        }
        // Finally, remove empty records, i.e., those for which `value` is `None`.
        let result = effective_records
            .into_iter()
            .filter_map(|(key, value)| value.is_some().then_some(key))
            .collect();
        Ok(result)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_latest_version"])
            .start_timer();
        let cache_state = self.cache.read().unwrap();
        cache_state.latest_version
    }

    fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time> {
        let _timer = self
            .metrics
            .api_call_duration
            .with_label_values(&["get_version_timestamp"])
            .start_timer();
        self.cache
            .read()
            .unwrap()
            .timestamps
            .get(&registry_version)
            .cloned()
    }
}

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "client_tests.rs"]
mod tests;
