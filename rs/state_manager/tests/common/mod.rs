use assert_matches::assert_matches;
use ic_base_types::{NumSeconds, PrincipalId};
use ic_config::state_manager::Config;
use ic_interfaces::validation::ValidationResult;
use ic_interfaces::{
    certification::{CertificationPermanentError, Verifier, VerifierError},
    certified_stream_store::DecodeStreamError,
};
use ic_interfaces::{certified_stream_store::CertifiedStreamStore, state_manager::*};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, ReplicatedState, SchedulerState, Stream, SystemState};
use ic_state_layout::{CheckpointLayout, RwPolicy};
use ic_state_manager::{stream_encoding, StateManagerImpl};
use ic_test_utilities::{
    consensus::fake::{Fake, FakeVerifier},
    state::initial_execution_state,
    types::ids::{subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{
    artifact::{Artifact, StateSyncMessage},
    chunkable::{
        ArtifactErrorCode::{ChunkVerificationFailed, ChunksMoreNeeded},
        Chunkable, ChunkableArtifact,
    },
    consensus::{
        certification::{Certification, CertificationContent},
        ThresholdSignature,
    },
    crypto::Signed,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    CanisterId, CryptoHashOfState, Cycles, Height, RegistryVersion, SubnetId,
};
use ic_wasm_types::BinaryEncodedWasm;
use std::sync::Arc;
use tempfile::Builder;

fn new_canister_state(
    canister_id: CanisterId,
    controller: PrincipalId,
    initial_cycles: Cycles,
    freeze_threshold: NumSeconds,
) -> CanisterState {
    let scheduler_state = SchedulerState::default();
    let system_state =
        SystemState::new_running(canister_id, controller, initial_cycles, freeze_threshold);
    CanisterState::new(system_state, None, scheduler_state)
}

pub fn empty_wasm() -> BinaryEncodedWasm {
    BinaryEncodedWasm::new(vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
        0x02, 0x01, 0x00,
    ])
}

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

pub const fn height(h: u64) -> Height {
    Height::new(h)
}

pub fn heights_to_certify(state_manager: &impl StateManager) -> Vec<Height> {
    state_manager
        .list_state_hashes_to_certify()
        .iter()
        .map(|p| p.0)
        .collect()
}

pub fn certify_height(state_manager: &impl StateManager, h: Height) -> Certification {
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

#[derive(Default)]
struct RejectingVerifier;

impl Verifier for RejectingVerifier {
    fn validate(
        &self,
        _subnet_id: SubnetId,
        _certification: &Certification,
        _registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError> {
        Err(CertificationPermanentError::RejectedByRejectingVerifier.into())
    }
}

/// Fixture for encoding/decoding tests of certified stream slices.
///
/// Encodes the given `stream` into a `CertifiedStreamSlice` with the given
/// `size_limit`, applies `f` to the encoded slice and tries to decode the
/// slice returned by `f`.
///
/// If `destination_subnet` is `Some(subnet)` it will address the stream at
/// `subnet` and at `SubnetId::new(42)` otherwise. The flag
/// `should_pass_verification` allows to control whether the verification of the
/// certification contained in the encoded `CertifiedStreamSlice` should succeed
/// or not.
///
/// # Panics
/// Whenever encoding and/or decoding would under normal circumstances return an
/// error.
pub fn encode_decode_stream_test<
    F: FnOnce(StateManagerImpl, CertifiedStreamSlice) -> (StateManagerImpl, CertifiedStreamSlice),
>(
    stream: Stream,
    size_limit: Option<usize>,
    destination_subnet: Option<SubnetId>,
    should_pass_verification: bool,
    f: F,
) {
    state_manager_test_with_verifier_result(should_pass_verification, |state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        let destination_subnet = destination_subnet.unwrap_or_else(|| subnet_test_id(42));

        let mut streams = state.take_streams();
        streams.insert(destination_subnet, stream.clone());
        state.put_streams(streams);

        state_manager.commit_and_certify(state, Height::new(1), CertificationScope::Metadata);

        certify_height(&state_manager, Height::new(1));

        let slice = state_manager
            .encode_certified_stream_slice(destination_subnet, None, None, size_limit, None)
            .expect("failed to encode certified stream");

        let (state_manager, slice) = f(state_manager, slice);

        let decoded_slice = state_manager.decode_certified_stream_slice(
            subnet_test_id(42),
            RegistryVersion::new(1),
            &slice,
        );

        let decoded_slice =
            decoded_slice.unwrap_or_else(|e| panic!("Failed to decode slice with error {:?}", e));

        assert_eq!(
            stream.slice(stream.header().begin, size_limit),
            decoded_slice
        );
    });
}

/// Fixture for encoding tests of partial certified stream slices.
///
/// Encodes a slice from the given `stream` with the given limits into a
/// `CertifiedStreamSlice`, and checks that:
///
///  1. the payload is the same as that of a `CertifiedStreamSlice` with both
/// witness and payload beginning at `msg_begin` and the same limits; and
///  2. the witness is the same as that of a `CertifiedStreamSlice` with both
/// witness and payload beginning at `witness_begin` and matching message limit.
///
/// # Panics
/// Whenever encoding and/or decoding would under normal circumstances return an
/// error.
pub fn encode_partial_slice_test(
    stream: Stream,
    witness_begin: StreamIndex,
    msg_begin: StreamIndex,
    msg_limit: usize,
    byte_limit: usize,
) {
    state_manager_test(|state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        let destination_subnet = subnet_test_id(42);

        let mut streams = state.take_streams();
        streams.insert(destination_subnet, stream.clone());
        state.put_streams(streams);

        state_manager.commit_and_certify(state, Height::new(1), CertificationScope::Metadata);

        certify_height(&state_manager, Height::new(1));

        let slice = state_manager
            .encode_certified_stream_slice(
                destination_subnet,
                Some(witness_begin),
                Some(msg_begin),
                Some(msg_limit),
                Some(byte_limit),
            )
            .expect("failed to encode certified stream");

        // Slice with the same payload and matching witness.
        let same_payload_slice = state_manager
            .encode_certified_stream_slice(
                destination_subnet,
                Some(msg_begin),
                Some(msg_begin),
                Some(msg_limit),
                Some(byte_limit),
            )
            .expect("failed to encode certified stream");
        assert_eq!(same_payload_slice.payload, slice.payload);

        let decoded_slice = state_manager
            .decode_certified_stream_slice(
                subnet_test_id(42),
                RegistryVersion::new(1),
                &same_payload_slice,
            )
            .unwrap_or_else(|e| panic!("Failed to decode slice with error {:?}", e));
        let msg_count = decoded_slice.messages().map(|m| m.len()).unwrap_or(0);

        // Slice with the same witness and matching payload.
        let same_witness_slice = state_manager
            .encode_certified_stream_slice(
                destination_subnet,
                Some(witness_begin),
                Some(witness_begin),
                Some(msg_count + (msg_begin - witness_begin).get() as usize),
                None,
            )
            .expect("failed to encode certified stream");
        assert_eq!(same_witness_slice.merkle_proof, slice.merkle_proof);

        // Sanity check: if an actual partial slice, decoding should fail.
        if witness_begin != msg_begin {
            assert_matches!(
                state_manager.decode_certified_stream_slice(
                    subnet_test_id(42),
                    RegistryVersion::new(1),
                    &slice,
                ),
                Err(DecodeStreamError::SerializationError(_))
            );
        }
    });
}

/// Fixture for modifying the payload of a `CertifiedStreamSlice.
///
/// Decodes the given `slice` and applies `f` to the decoded slice to obtain a
/// new stream. The obtained stream is then committed, certified, and encoded
/// into a `CertifiedStreamSlice` using `state_manager`. The function returns
/// the `state_manager` with the new state committed and a
/// `CertifiedStreamSlice` having `payload` set to the newly encoded payload,
/// while retaining the remaining fields from `slice`.
///
///
/// # Panics
/// Whenever encoding and/or decoding would under normal circumstances return an
/// error.
pub fn modify_encoded_stream_helper<F: FnOnce(StreamSlice) -> Stream>(
    state_manager: StateManagerImpl,
    slice: CertifiedStreamSlice,
    f: F,
) -> (StateManagerImpl, CertifiedStreamSlice) {
    let (_subnet, decoded_slice) =
        stream_encoding::decode_stream_slice(&slice.payload[..]).unwrap();

    let modified_stream = f(decoded_slice);

    let (_height, mut state) = state_manager.take_tip();

    let mut streams = state.take_streams();
    streams.clear();
    streams.insert(subnet_test_id(42), modified_stream);
    state.put_streams(streams);

    state_manager.commit_and_certify(state, Height::new(2), CertificationScope::Metadata);

    certify_height(&state_manager, Height::new(2));

    let new_slice = state_manager
        .encode_certified_stream_slice(subnet_test_id(42), None, None, None, None)
        .expect("failed to encode certified stream");

    (
        state_manager,
        CertifiedStreamSlice {
            payload: new_slice.payload,
            merkle_proof: slice.merkle_proof,
            certification: slice.certification,
        },
    )
}

pub fn wait_for_checkpoint(state_manager: &impl StateManager, h: Height) -> CryptoHashOfState {
    use std::time::{Duration, Instant};

    let timeout = Duration::from_secs(10);
    let started = Instant::now();
    while started.elapsed() < timeout {
        if let Some(hash) = state_manager
            .get_state_hash_at(h)
            .expect("state must be committed before calling wait_for_checkpoint")
        {
            return hash;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    panic!("Checkpoint @{} didn't complete in {:?}", h, timeout)
}

pub fn insert_dummy_canister(state: &mut ReplicatedState, canister_id: CanisterId) {
    let can_layout = CheckpointLayout::<RwPolicy>::new(state.path().into(), Height::from(0))
        .and_then(|layout| layout.canister(&canister_id))
        .expect("failed to obtain canister layout");

    let wasm = empty_wasm();
    let mut canister_state = new_canister_state(
        canister_id,
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let mut execution_state = initial_execution_state(Some(can_layout.raw_path()));
    execution_state.wasm_binary = wasm;
    canister_state.execution_state = Some(execution_state);
    state.put_canister_state(canister_state);
}

pub fn pipe_state_sync(src: StateSyncMessage, mut dst: Box<dyn Chunkable>) -> StateSyncMessage {
    while !dst.is_complete() {
        let ids: Vec<_> = dst.chunks_to_download().collect();

        assert!(
            !ids.is_empty(),
            "Can't have incomplete artifact that needs no chunks"
        );
        for id in ids {
            let chunk = Box::new(src.clone())
                .get_chunk(id)
                .unwrap_or_else(|| panic!("Requested unknown chunk {}", id));

            match dst.add_chunk(chunk) {
                Ok(Artifact::StateSync(msg)) => {
                    assert!(
                        dst.is_complete(),
                        "add_chunk returned OK but the artifact is not complete"
                    );
                    return msg;
                }
                Ok(artifact) => {
                    panic!("Unexpected artifact type: {:?}", artifact);
                }
                Err(ChunksMoreNeeded) => (),
                Err(ChunkVerificationFailed) => panic!("Encountered invalid chunk {}", id),
            }
        }
    }
    unreachable!()
}

pub fn state_manager_test_with_verifier_result<F: FnOnce(StateManagerImpl)>(
    should_pass_verification: bool,
    f: F,
) {
    let tmp = Builder::new().prefix("test").tempdir().unwrap();
    let config = Config::new(tmp.path().into());
    let metrics_registry = MetricsRegistry::new();
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = if should_pass_verification {
        Arc::new(FakeVerifier::new())
    } else {
        Arc::new(RejectingVerifier::default())
    };

    with_test_replica_logger(|log| {
        f(StateManagerImpl::new(
            verifier,
            own_subnet,
            SubnetType::Application,
            log,
            &metrics_registry,
            &config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));
    })
}

pub fn state_manager_test<F: FnOnce(StateManagerImpl)>(f: F) {
    state_manager_test_with_verifier_result(true, f)
}

pub fn state_manager_restart_test<Fixture, Test, R>(fixture: Fixture, test: Test)
where
    Fixture: FnOnce(StateManagerImpl) -> R,
    Test: FnOnce(StateManagerImpl, R),
{
    let tmp = Builder::new().prefix("test").tempdir().unwrap();
    let config = Config::new(tmp.path().into());
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());
    with_test_replica_logger(|log| {
        let metrics_registry = MetricsRegistry::new();

        let result = fixture(StateManagerImpl::new(
            Arc::clone(&verifier),
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &metrics_registry,
            &config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));
        let metrics_registry = MetricsRegistry::new();
        test(
            StateManagerImpl::new(
                verifier,
                own_subnet,
                SubnetType::Application,
                log,
                &metrics_registry,
                &config,
                ic_types::malicious_flags::MaliciousFlags::default(),
            ),
            result,
        );
    });
}
