use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_config::{
    flag_status::FlagStatus,
    state_manager::{lsmt_config_default, Config, LsmtConfig},
};
use ic_interfaces::{
    certification::{InvalidCertificationReason, Verifier, VerifierError},
    p2p::state_sync::{Chunk, ChunkId, Chunkable},
    validation::ValidationResult,
};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, DecodeStreamError};
use ic_interfaces_state_manager::*;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::execution_state::WasmBinary;
use ic_replicated_state::{testing::ReplicatedStateTesting, ReplicatedState, Stream};
use ic_state_manager::{
    state_sync::types::{StateSyncMessage, MANIFEST_CHUNK_ID_OFFSET},
    state_sync::StateSync,
    stream_encoding, StateManagerImpl,
};
use ic_test_utilities_consensus::fake::{Fake, FakeVerifier};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::{initial_execution_state, new_canister_state};
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::ids::{subnet_test_id, user_test_id};
use ic_types::{
    consensus::certification::{Certification, CertificationContent},
    crypto::Signed,
    signature::ThresholdSignature,
    xnet::{CertifiedStreamSlice, StreamIndex, StreamSlice},
    CanisterId, CryptoHashOfState, Cycles, Height, RegistryVersion, SubnetId,
};
use ic_wasm_types::CanisterModule;
use std::{collections::HashSet, sync::Arc};

pub const EMPTY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x02,
    0x01, 0x00,
];

pub fn empty_wasm() -> CanisterModule {
    CanisterModule::new(EMPTY_WASM.to_vec())
}

pub fn empty_wasm_size() -> usize {
    EMPTY_WASM.len()
}

const ALTERNATE_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
    0x02, 0x01, 0x00,
];

pub fn alternate_wasm() -> CanisterModule {
    CanisterModule::new(ALTERNATE_WASM.to_vec())
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
        Err(InvalidCertificationReason::RejectedByRejectingVerifier.into())
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
    state_manager_test_with_verifier_result(should_pass_verification, |_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        let destination_subnet = destination_subnet.unwrap_or_else(|| subnet_test_id(42));

        state.modify_streams(|streams| {
            streams.insert(destination_subnet, stream.clone());
        });

        state_manager.commit_and_certify(state, Height::new(1), CertificationScope::Metadata, None);

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
            stream.slice(stream.header().begin(), size_limit),
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
///     witness and payload beginning at `msg_begin` and the same limits; and
///  2. the witness is the same as that of a `CertifiedStreamSlice` with both
///     witness and payload beginning at `witness_begin` and matching message limit.
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
    state_manager_test(|_metrics, state_manager| {
        let (_height, mut state) = state_manager.take_tip();

        let destination_subnet = subnet_test_id(42);

        state.modify_streams(|streams| {
            streams.insert(destination_subnet, stream.clone());
        });

        state_manager.commit_and_certify(state, Height::new(1), CertificationScope::Metadata, None);

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

    state.modify_streams(|streams| {
        streams.clear();
        streams.insert(subnet_test_id(42), modified_stream);
    });

    state_manager.commit_and_certify(state, Height::new(2), CertificationScope::Metadata, None);

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

    let timeout = Duration::from_secs(20);
    let started = Instant::now();
    while started.elapsed() < timeout {
        match state_manager.get_state_hash_at(h) {
            Ok(hash) => return hash,
            Err(StateHashError::Permanent(err)) => {
                panic!("Unable to get checkpoint @{}: {:?}", h, err);
            }
            Err(StateHashError::Transient(err)) => match err {
                TransientStateHashError::StateNotCommittedYet(_) => {
                    panic!(
                        "state must be committed before calling wait_for_checkpoint: {:?}",
                        err
                    );
                }
                TransientStateHashError::HashNotComputedYet(_) => {
                    std::thread::sleep(Duration::from_millis(500));
                }
            },
        }
    }

    panic!("Checkpoint @{} didn't complete in {:?}", h, timeout)
}

pub fn insert_dummy_canister(state: &mut ReplicatedState, canister_id: CanisterId) {
    let wasm = empty_wasm();
    let mut canister_state = new_canister_state(
        canister_id,
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let mut execution_state = initial_execution_state();
    execution_state.wasm_binary = WasmBinary::new(wasm);
    canister_state.execution_state = Some(execution_state);
    state.put_canister_state(canister_state);
}

pub fn insert_canister_with_many_controllers(
    state: &mut ReplicatedState,
    canister_id: CanisterId,
    num_controllers: u64,
) {
    let wasm = empty_wasm();
    let mut canister_state = new_canister_state(
        canister_id,
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );

    let mut controllers = std::mem::take(&mut canister_state.system_state.controllers);
    for i in 25..(24 + num_controllers) {
        controllers.insert(user_test_id(i).get());
    }
    canister_state.system_state.controllers = controllers;

    let mut execution_state = initial_execution_state();
    execution_state.wasm_binary = WasmBinary::new(wasm);
    canister_state.execution_state = Some(execution_state);
    state.put_canister_state(canister_state);
}

pub fn replace_wasm(state: &mut ReplicatedState, canister_id: CanisterId) {
    let wasm = alternate_wasm();

    state
        .canister_state_mut(&canister_id)
        .unwrap()
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary = WasmBinary::new(wasm);
}

#[derive(Eq, PartialEq, Debug)]
pub enum StateSyncErrorCode {
    MetaManifestVerificationFailed,
    ManifestVerificationFailed,
    OtherChunkVerificationFailed,
}

pub fn pipe_state_sync(src: StateSyncMessage, mut dst: Box<dyn Chunkable<StateSyncMessage>>) {
    let is_finished = pipe_partial_state_sync(&src, &mut *dst, &Default::default(), false)
        .expect("State sync chunk verification failed.");
    assert!(is_finished, "State sync not completed");
}

fn alter_chunk_data(chunk: &mut Chunk) {
    let mut chunk_data = chunk.as_bytes().to_vec();
    match chunk_data.last_mut() {
        Some(last) => {
            // Alter the last element of chunk_data.
            *last = last.wrapping_add(1);
        }
        None => {
            // chunk_data is originally empty. Reset it to some non-empty value.
            chunk_data = vec![9; 100];
        }
    }
    *chunk = chunk_data.into();
}

/// Pipe the meta-manifest (chunk 0) from src to dest.
/// Alter the chunk data if `use_bad_chunk` is set to true.
pub fn pipe_meta_manifest(
    src: &StateSyncMessage,
    dst: &mut dyn Chunkable<StateSyncMessage>,
    use_bad_chunk: bool,
) -> Result<bool, StateSyncErrorCode> {
    let ids: Vec<_> = dst.chunks_to_download().collect();

    // Only the meta-manifest should be requested
    assert_eq!(ids, vec! {ChunkId::new(0)});

    let id = ids[0];

    let mut chunk = src
        .clone()
        .get_chunk(id)
        .unwrap_or_else(|| panic!("Requested unknown chunk {}", id));

    if use_bad_chunk {
        alter_chunk_data(&mut chunk);
    }

    match dst.add_chunk(id, chunk) {
        Ok(()) => Ok(dst.chunks_to_download().next().is_none()),
        Err(_) => Err(StateSyncErrorCode::MetaManifestVerificationFailed),
    }
}

/// Pipe the manifest chunks from src to dest and
/// return the StateSyncMessage if the state sync completes.
/// Alter the data of the chunk in the middle position if `use_bad_chunk` is set to true.
pub fn pipe_manifest(
    src: &StateSyncMessage,
    dst: &mut dyn Chunkable<StateSyncMessage>,
    use_bad_chunk: bool,
) -> Result<bool, StateSyncErrorCode> {
    let ids: Vec<_> = dst.chunks_to_download().collect();

    // Only the manifest chunks should be requested
    let manifest_chunks: HashSet<_> = (MANIFEST_CHUNK_ID_OFFSET
        ..MANIFEST_CHUNK_ID_OFFSET + src.meta_manifest.sub_manifest_hashes.len() as u32)
        .map(ChunkId::new)
        .collect();
    assert!(ids.iter().all(|id| manifest_chunks.contains(id)));

    for (index, id) in ids.iter().enumerate() {
        let mut chunk = src
            .clone()
            .get_chunk(*id)
            .unwrap_or_else(|| panic!("Requested unknown chunk {}", id));

        if use_bad_chunk && index == ids.len() / 2 {
            alter_chunk_data(&mut chunk);
        }

        match dst.add_chunk(*id, chunk) {
            Ok(()) => {
                if dst.chunks_to_download().next().is_none() {
                    return Ok(true);
                }
            }
            Err(_) => {
                return Err(StateSyncErrorCode::ManifestVerificationFailed);
            }
        }
    }
    Ok(false)
}

/// Pipe chunks from src to dst, but omit any chunks in omit
/// Alter the data of the chunk in the middle position if `use_bad_chunk` is set to true.
pub fn pipe_partial_state_sync(
    src: &StateSyncMessage,
    dst: &mut dyn Chunkable<StateSyncMessage>,
    omit: &HashSet<ChunkId>,
    use_bad_chunk: bool,
) -> Result<bool, StateSyncErrorCode> {
    loop {
        let ids: Vec<_> = dst.chunks_to_download().collect();

        if ids.is_empty() {
            break;
        }

        let mut omitted_chunks = false;
        for (index, id) in ids.iter().enumerate() {
            if omit.contains(id) {
                omitted_chunks = true;
                continue;
            }
            let mut chunk = src
                .clone()
                .get_chunk(*id)
                .unwrap_or_else(|| panic!("Requested unknown chunk {}", id));

            if use_bad_chunk && index == ids.len() / 2 {
                alter_chunk_data(&mut chunk);
            }

            match dst.add_chunk(*id, chunk) {
                Ok(()) => {
                    if dst.chunks_to_download().next().is_none() {
                        return Ok(true);
                    }
                }
                Err(_) => return Err(StateSyncErrorCode::OtherChunkVerificationFailed),
            }
        }
        if omitted_chunks {
            return Ok(false);
        }
    }
    unreachable!()
}

pub fn state_manager_test_with_verifier_result<F: FnOnce(&MetricsRegistry, StateManagerImpl)>(
    should_pass_verification: bool,
    f: F,
) {
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    let metrics_registry = MetricsRegistry::new();
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = if should_pass_verification {
        Arc::new(FakeVerifier::new())
    } else {
        Arc::new(RejectingVerifier)
    };

    with_test_replica_logger(|log| {
        f(
            &metrics_registry,
            StateManagerImpl::new(
                verifier,
                own_subnet,
                SubnetType::Application,
                log,
                &metrics_registry,
                &config,
                None,
                ic_types::malicious_flags::MaliciousFlags::default(),
            ),
        );
    })
}

fn state_manager_test_with_state_sync_and_verifier_result<
    F: FnOnce(&MetricsRegistry, Arc<StateManagerImpl>, StateSync),
>(
    should_pass_verification: bool,
    f: F,
) {
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    let metrics_registry = MetricsRegistry::new();
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = if should_pass_verification {
        Arc::new(FakeVerifier::new())
    } else {
        Arc::new(RejectingVerifier)
    };

    with_test_replica_logger(|log| {
        let sm = Arc::new(StateManagerImpl::new(
            verifier,
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &metrics_registry,
            &config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));
        f(&metrics_registry, sm.clone(), StateSync::new(sm, log));
    })
}

pub fn state_manager_restart_test_with_state_sync<Test>(test: Test)
where
    Test: FnOnce(
        &MetricsRegistry,
        Arc<StateManagerImpl>,
        StateSync,
        Box<dyn Fn(StateManagerImpl, Option<Height>) -> (MetricsRegistry, Arc<StateManagerImpl>)>,
    ),
{
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

    with_test_replica_logger(|log| {
        let log_sm = log.clone();
        let make_state_manager = move |starting_height| {
            let metrics_registry = MetricsRegistry::new();

            let state_manager = Arc::new(StateManagerImpl::new(
                Arc::clone(&verifier),
                own_subnet,
                SubnetType::Application,
                log_sm.clone(),
                &metrics_registry,
                &config,
                starting_height,
                ic_types::malicious_flags::MaliciousFlags::default(),
            ));

            (metrics_registry, state_manager)
        };

        let (metrics_registry, state_manager) = make_state_manager(None);
        let state_sync = StateSync::new(state_manager.clone(), log.clone());

        let restart_fn = Box::new(move |state_manager, starting_height| {
            drop(state_manager);
            make_state_manager(starting_height)
        });
        test(&metrics_registry, state_manager, state_sync, restart_fn);
    });
}

pub fn state_manager_test<F: FnOnce(&MetricsRegistry, StateManagerImpl)>(f: F) {
    state_manager_test_with_verifier_result(true, f)
}

pub fn state_manager_test_with_state_sync<
    F: FnOnce(&MetricsRegistry, Arc<StateManagerImpl>, StateSync),
>(
    f: F,
) {
    state_manager_test_with_state_sync_and_verifier_result(true, f)
}

pub fn state_manager_restart_test_deleting_metadata<Test>(test: Test)
where
    Test: FnOnce(
        &MetricsRegistry,
        StateManagerImpl,
        Box<dyn Fn(StateManagerImpl, Option<Height>) -> (MetricsRegistry, StateManagerImpl)>,
    ),
{
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

    with_test_replica_logger(|log| {
        let make_state_manager = move |starting_height| {
            let metrics_registry = MetricsRegistry::new();

            let state_manager = StateManagerImpl::new(
                Arc::clone(&verifier),
                own_subnet,
                SubnetType::Application,
                log.clone(),
                &metrics_registry,
                &config,
                starting_height,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );

            (metrics_registry, state_manager)
        };

        let (metrics_registry, state_manager) = make_state_manager(None);

        let restart_fn = Box::new(move |state_manager, starting_height| {
            drop(state_manager);
            std::fs::remove_file(tmp.path().join("states_metadata.pbuf")).unwrap();
            make_state_manager(starting_height)
        });

        test(&metrics_registry, state_manager, restart_fn);
    });
}

pub fn lsmt_with_sharding() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        shard_num_pages: 1,
    }
}

pub fn lsmt_without_sharding() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        shard_num_pages: u64::MAX,
    }
}

pub fn lsmt_disabled() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Disabled,
        shard_num_pages: u64::MAX,
    }
}

pub fn state_manager_restart_test_with_lsmt<Test>(lsmt_config: LsmtConfig, test: Test)
where
    Test: FnOnce(
        &MetricsRegistry,
        StateManagerImpl,
        Box<
            dyn Fn(
                StateManagerImpl,
                Option<Height>,
                LsmtConfig,
            ) -> (MetricsRegistry, StateManagerImpl),
        >,
    ),
{
    let tmp = tmpdir("sm");
    let config = Config::new(tmp.path().into());
    let own_subnet = subnet_test_id(42);
    let verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

    with_test_replica_logger(|log| {
        let make_state_manager = move |starting_height, lsmt_config| {
            let metrics_registry = MetricsRegistry::new();

            let mut config = config.clone();
            config.lsmt_config = lsmt_config;

            let state_manager = StateManagerImpl::new(
                Arc::clone(&verifier),
                own_subnet,
                SubnetType::Application,
                log.clone(),
                &metrics_registry,
                &config,
                starting_height,
                ic_types::malicious_flags::MaliciousFlags::default(),
            );

            (metrics_registry, state_manager)
        };

        let (metrics_registry, state_manager) = make_state_manager(None, lsmt_config);

        let restart_fn = Box::new(move |state_manager, starting_height, lsmt_config| {
            drop(state_manager);
            make_state_manager(starting_height, lsmt_config)
        });

        test(&metrics_registry, state_manager, restart_fn);
    });
}

pub fn state_manager_restart_test_with_metrics<Test>(test: Test)
where
    Test: FnOnce(
        &MetricsRegistry,
        StateManagerImpl,
        Box<dyn Fn(StateManagerImpl, Option<Height>) -> (MetricsRegistry, StateManagerImpl)>,
    ),
{
    state_manager_restart_test_with_lsmt(
        lsmt_config_default(),
        |metrics, state_manager, restart_fn| {
            let restart_fn_simplified = Box::new(move |state_manager, starting_height| {
                restart_fn(state_manager, starting_height, lsmt_config_default())
            });
            test(metrics, state_manager, restart_fn_simplified);
        },
    );
}

pub fn state_manager_restart_test<Test>(test: Test)
where
    Test:
        FnOnce(StateManagerImpl, Box<dyn Fn(StateManagerImpl, Option<Height>) -> StateManagerImpl>),
{
    state_manager_restart_test_with_metrics(|_metrics, state_manager, restart_fn| {
        let restart_fn_without_metrics = Box::new(move |state_manager, starting_height| {
            restart_fn(state_manager, starting_height).1
        });
        test(state_manager, restart_fn_without_metrics);
    });
}
