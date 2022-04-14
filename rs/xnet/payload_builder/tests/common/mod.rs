// Not all tests use all fixtures, prevent spurious warnings.
#![allow(dead_code)]

use ic_config::state_manager::Config;
use ic_interfaces::{certification::Verifier, certified_stream_store::CertifiedStreamStore};
use ic_interfaces_state_manager::*;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{testing::ReplicatedStateTesting, Stream};
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::fake::{Fake, FakeVerifier},
    metrics::{
        fetch_gauge, fetch_histogram_stats, fetch_int_counter_vec, HistogramStats, MetricVec,
    },
    state::arb_stream,
    types::ids::{SUBNET_1, SUBNET_42},
};
use ic_types::{
    consensus::certification::{Certification, CertificationContent},
    crypto::Signed,
    signature::ThresholdSignature,
    xnet::{CertifiedStreamSlice, StreamIndex},
    Height, SubnetId,
};
use ic_xnet_payload_builder::certified_slice_pool::{
    UnpackedStreamSlice, METRIC_POOL_SIZE_BYTES, METRIC_TAKE_COUNT, METRIC_TAKE_GCED_MESSAGES,
    METRIC_TAKE_MESSAGES, METRIC_TAKE_SIZE_BYTES,
};
use proptest::prelude::*;
use std::{convert::TryFrom, sync::Arc};
use tempfile::{Builder, TempDir};

pub const OWN_SUBNET: SubnetId = SUBNET_42;
pub const REMOTE_SUBNET: SubnetId = SUBNET_1;

/// Test fixture around a `StateManager`, to help with generating valid
/// `CertifiedStreamSlices` (minus signature, but including a root hash).
pub struct StateManagerFixture {
    pub state_manager: StateManagerImpl,
    pub certified_height: Height,
    pub metrics: MetricsRegistry,
    pub temp_dir: TempDir,
    pub log: ReplicaLogger,
}

impl StateManagerFixture {
    /// Creates a new `Fixture` around an empty state.
    pub fn new(log: ReplicaLogger) -> Self {
        Self::with_subnet_type(SubnetType::Application, log)
    }

    /// Creates a new `Fixture` around an empty state.
    pub fn with_subnet_type(subnet_type: SubnetType, log: ReplicaLogger) -> Self {
        let temp_dir = Builder::new().prefix("test").tempdir().unwrap();
        let config = Config::new(temp_dir.path().into());
        let metrics = MetricsRegistry::new();
        let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

        let state_manager = StateManagerImpl::new(
            verifier,
            OWN_SUBNET,
            subnet_type,
            log.clone(),
            &metrics,
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        Self {
            state_manager,
            certified_height: 0.into(),
            metrics,
            temp_dir,
            log,
        }
    }

    /// Adds a stream to the wrapped state, creates a new checkpoint and
    /// certifies it.
    pub fn with_stream(mut self, destination_subnet: SubnetId, stream: Stream) -> Self {
        let (mut height, mut state) = self.state_manager.take_tip();

        state.modify_streams(|streams| {
            streams.insert(destination_subnet, stream);
        });

        height.inc_assign();
        self.state_manager
            .commit_and_certify(state, height, CertificationScope::Metadata);
        certify_height(&self.state_manager, height);
        self.certified_height = height;

        self
    }

    /// Convenience wrapper around
    /// `self.state_manager.encode_certified_stream_slice()`.
    pub fn get_slice(
        &self,
        subnet_id: SubnetId,
        from: StreamIndex,
        msg_count: usize,
    ) -> CertifiedStreamSlice {
        self.state_manager
            .encode_certified_stream_slice(subnet_id, Some(from), Some(from), Some(msg_count), None)
            .expect("failed to encode certified stream")
    }

    /// Convenience wrapper around
    /// `self.state_manager.encode_certified_stream_slice()`.
    pub fn get_partial_slice(
        &self,
        subnet_id: SubnetId,
        witness_from: StreamIndex,
        msg_from: StreamIndex,
        msg_count: usize,
    ) -> CertifiedStreamSlice {
        self.state_manager
            .encode_certified_stream_slice(
                subnet_id,
                Some(witness_from),
                Some(msg_from),
                Some(msg_count),
                None,
            )
            .expect("failed to encode certified stream")
    }

    /// Returns the value of the `METRIC_POOL_SIZE_BYTES` gauge.
    pub fn fetch_pool_size_bytes(&self) -> usize {
        fetch_gauge(&self.metrics, METRIC_POOL_SIZE_BYTES).unwrap() as usize
    }

    /// Returns the value of the `METRIC_TAKE_COUNT` counters.
    pub fn fetch_pool_take_count(&self) -> MetricVec<u64> {
        fetch_int_counter_vec(&self.metrics, METRIC_TAKE_COUNT)
    }

    /// Returns the `METRIC_TAKE_MESSAGES` histogram's stats.
    pub fn fetch_pool_take_messages(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_TAKE_MESSAGES).unwrap()
    }

    /// Returns the `METRIC_TAKE_GCED_MESSAGES` histogram's stats.
    pub fn fetch_pool_take_gced_messages(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_TAKE_GCED_MESSAGES).unwrap()
    }

    /// Returns the `METRIC_TAKE_SIZE_BYTES` histogram's stats.
    pub fn fetch_pool_take_size_bytes(&self) -> HistogramStats {
        fetch_histogram_stats(&self.metrics, METRIC_TAKE_SIZE_BYTES).unwrap()
    }
}

prop_compose! {
    /// Generates a strategy consisting of an arbitrary stream and valid slice begin and message
    /// count values for extracting a slice from the stream.
    pub fn arb_stream_slice(min_size: usize, max_size: usize)(
        stream in arb_stream(min_size, max_size),
        from_percent in -20..120i64,
        percent_above_min_size in 0..120i64,
    ) ->  (Stream, StreamIndex, usize) {
        let from_percent = from_percent.max(0).min(100) as usize;
        let percent_above_min_size = percent_above_min_size.max(0).min(100) as usize;
        let msg_count = min_size +
            (stream.messages().len() - min_size) * percent_above_min_size / 100;
        let from = stream.messages_begin() +
            (((stream.messages().len() - msg_count) * from_percent / 100) as u64).into();

        (stream, from, msg_count)
    }
}

/// Creates a certification for the given height, including a valid hash but
/// with a fake signature.
fn certify_height(state_manager: &impl StateManager, h: Height) -> Certification {
    let hash = state_manager
        .list_state_hashes_to_certify()
        .into_iter()
        .find_map(|(height, hash)| if height == h { Some(hash) } else { None })
        .expect("no hash to certify");

    let certification = Certification {
        height: h,
        signed: Signed {
            content: CertificationContent::new(hash),
            signature: ThresholdSignature::fake(),
        },
    };

    state_manager.deliver_state_certification(certification.clone());
    certification
}

/// `CertifiedStreamSlice` equality assert that prints unpacked slice contents
/// on failure.
pub fn assert_slices_eq(expected: CertifiedStreamSlice, actual: CertifiedStreamSlice) {
    if expected != actual {
        panic!(
            "assertion failed: `(expected == actual)`\n  expected: `{}`\n  actual: `{}`",
            slice_to_string(expected),
            slice_to_string(actual)
        );
    }
}

/// `Option<CertifiedStreamSlice>` equality assert that prints unpacked slice
/// contents on failure.
pub fn assert_opt_slices_eq(
    expected: Option<CertifiedStreamSlice>,
    actual: Option<CertifiedStreamSlice>,
) {
    if expected != actual {
        panic!(
            "assertion failed: `(expected == actual)`\n  expected: `{}`\n  actual: `{}`",
            opt_slice_to_string(expected),
            opt_slice_to_string(actual),
        );
    }
}

/// `(Option<CertifiedStreamSlice>, Option<CertifiedStreamSlice>)` equality
/// assert that prints unpacked slice contents on failure.
pub fn assert_opt_slice_pairs_eq(
    expected: (Option<CertifiedStreamSlice>, Option<CertifiedStreamSlice>),
    actual: (Option<CertifiedStreamSlice>, Option<CertifiedStreamSlice>),
) {
    if expected != actual {
        panic!(
            "assertion failed: `(expected == actual)`\n  expected: `({}, {})`\n  actual: `({}, {})`",
            opt_slice_to_string(expected.0),
            opt_slice_to_string(expected.1),
            opt_slice_to_string(actual.0),
            opt_slice_to_string(actual.1),
        );
    }
}

fn opt_slice_to_string(slice: Option<CertifiedStreamSlice>) -> String {
    slice.map(slice_to_string).unwrap_or_else(|| "None".into())
}

fn slice_to_string(slice: CertifiedStreamSlice) -> String {
    UnpackedStreamSlice::try_from(slice.clone())
        .map(|unpacked| format!("{:?}", unpacked))
        .unwrap_or(format!("{:?}", slice))
}
