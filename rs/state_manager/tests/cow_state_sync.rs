use ic_config::state_manager::Config;
use ic_cow_state::*;
use ic_interfaces::artifact_manager::ArtifactClient;
use ic_interfaces::certification::Verifier;
use ic_interfaces::state_manager::*;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{page_map, NumWasmPages64, PageMap};
use ic_state_layout::{CanisterLayout, CheckpointLayout, RwPolicy};
use ic_state_manager::StateManagerImpl;
use ic_sys::PAGE_SIZE;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    types::ids::{canister_test_id, node_test_id, subnet_test_id},
    with_test_replica_logger,
};
use ic_types::{artifact::StateSyncArtifactId, CanisterId, ExecutionRound, Height};
use ic_utils::ic_features::*;
use std::{path::Path, sync::Arc};
use tempfile::Builder;

use ic_cow_state::MappedState;

pub mod common;
use common::*;

// we define 10MB partitions so all the modifications are
// sufficiently spaced out
fn get_page_nr(partition_nr: u64, offset_pages: u64) -> u64 {
    // with default chunk size as 1 MB we define partition size as 3MB
    let partition_size = 256 * 3;
    partition_nr * partition_size + offset_pages
}

fn get_page_off(pg_nr: u64) -> usize {
    pg_nr as usize * PAGE_SIZE
}

#[test]
fn cow_state_can_distinguish_cow_files_in_state_sync() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    state_manager_test(|src_state_manager| {
        // Dummy canister has empty canister heap. Subnet queues are empty
        // too. Without domain hash separator, `state_file` and
        // `subnet_queues.buf` would have the same hash.
        let (_height, mut state) = src_state_manager.take_tip();
        insert_dummy_canister(&mut state, canister_test_id(100));
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);

        let (_height, state) = src_state_manager.take_tip();
        let new_height = height(2);
        src_state_manager.commit_and_certify(state, new_height, CertificationScope::Full);

        let hash = wait_for_checkpoint(&src_state_manager, new_height);
        let id = StateSyncArtifactId {
            height: new_height,
            hash,
        };

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        state_manager_test(|dst_state_manager| {
            let (_height, mut state) = dst_state_manager.take_tip();
            insert_dummy_canister(&mut state, canister_test_id(100));
            dst_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
            wait_for_checkpoint(&dst_state_manager, height(1));

            let chunkable = dst_state_manager.create_chunkable_state(&id);
            let dst_msg = pipe_state_sync(msg, chunkable);
            let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
            assert!(
                result.is_ok(),
                "Failed to process state sync artifact: {:?}",
                result
            );

            let recovered_state = dst_state_manager
                .get_state_at(new_height)
                .expect("Destination state manager didn't receive the state")
                .take()
                .as_ref()
                .clone();

            let src_state = src_state_manager.get_latest_state().take();
            assert_eq!(src_state.as_ref(), &recovered_state);
        })
    })
}

#[test]
fn cow_state_can_do_simple_state_sync_transfer() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    let src_tmp = Builder::new().prefix("test").tempdir().unwrap();
    let src_config = Config::new(src_tmp.path().into());

    let dst_tmp = Builder::new().prefix("test").tempdir().unwrap();
    let dst_config = Config::new(dst_tmp.path().into());

    let src_metrics_registry = MetricsRegistry::new();
    let dst_metrics_registry = MetricsRegistry::new();

    let src_verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());
    let dst_verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

    with_test_replica_logger(|log| {
        let canister_id: CanisterId = canister_test_id(100);
        let own_subnet = subnet_test_id(42);

        let src_state_manager = StateManagerImpl::new(
            src_verifier,
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &src_metrics_registry,
            &src_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let dst_state_manager = StateManagerImpl::new(
            dst_verifier,
            own_subnet,
            SubnetType::Application,
            log,
            &dst_metrics_registry,
            &dst_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let p0_o200 = get_page_nr(0, 200);
        let p0_o205 = get_page_nr(0, 205);
        let p1_o100 = get_page_nr(1, 100);
        let p2_o100 = get_page_nr(2, 100);
        let p3_o100 = get_page_nr(3, 100);

        let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
        let random_bytes1: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

        // ====================================================================
        // Test 1: state_sync can sync cow state to an empty state manager
        // ====================================================================
        let (_height, mut state) = src_state_manager.take_tip();

        insert_dummy_canister(&mut state, canister_id);

        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.clone().unwrap();

        let mapped_state = es.cow_mem_mgr.get_map();

        mapped_state.update_heap_page(p0_o200, &random_bytes);
        mapped_state.update_heap_page(p1_o100, &random_bytes);
        mapped_state.soft_commit(&[p0_o200, p1_o100]);

        es.last_executed_round = ExecutionRound::from(1);
        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Verify destination received the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(height(1))
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);
        let (_height, tip_state) = dst_state_manager.take_tip();
        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(vec![height(1)], heights_to_certify(&dst_state_manager));

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.clone().unwrap();
        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        // --------------------------- Make sure that the snapshot was also created
        // correctly -------------------
        let es = canister_state.execution_state.clone().unwrap();
        let mapped_state = es.cow_mem_mgr.get_map_for_snapshot(1).unwrap();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        recovered_state.put_canister_state(canister_state);
        // put the tip back
        dst_state_manager.commit_and_certify(tip_state, height(2), CertificationScope::Full);
        // End Test 1

        let (_height, tip_state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip_state, height(2), CertificationScope::Full);

        // ====================================================================
        // Test 2: Without modifying source, perform another state sync. dst state
        // manager should recreate state by doing local file copy
        // ====================================================================
        let (_height, state) = src_state_manager.take_tip();

        let new_height = height(3);

        src_state_manager.commit_and_certify(state, new_height, CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, new_height);
        let id = StateSyncArtifactId {
            height: new_height,
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Verify dst recreated the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(new_height)
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);

        let (_height, tip_state) = dst_state_manager.take_tip();

        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(
            vec![height(1), height(2), height(3)],
            heights_to_certify(&dst_state_manager)
        );

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.clone().unwrap();
        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        // --------------------------- Make sure that the snapshot was also created
        // correctly -------------------
        let es = canister_state.execution_state.clone().unwrap();
        let mapped_state = es.cow_mem_mgr.get_map_for_snapshot(1).unwrap();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        recovered_state.put_canister_state(canister_state);
        dst_state_manager.commit_and_certify(tip_state, height(4), CertificationScope::Full);
        // End Test2
        let (_height, tip_state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip_state, height(4), CertificationScope::Full);

        // ====================================================================
        // Test 3 Modify only the first chunk, create one more chunk that looks like
        // an existing one and verify all three chunks are synced
        // correctly
        // ====================================================================
        let (_height, mut state) = src_state_manager.take_tip();

        let new_height = height(5);

        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.clone().unwrap();

        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.update_heap_page(p0_o200, &random_bytes1);
        mapped_state.update_heap_page(p0_o205, &random_bytes2);

        // create 2 more chunks that are identical to one created at height 1 and
        // hence should also be part of the state_synced state at height 4 at dst
        // This should trigger local copy
        mapped_state.update_heap_page(p2_o100, &random_bytes);
        mapped_state.update_heap_page(p3_o100, &random_bytes);

        mapped_state.soft_commit(&[p0_o200, p0_o205, p2_o100, p3_o100]);

        es.last_executed_round = ExecutionRound::from(5);
        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);

        // Insert second canister and make it look partly like first canister
        // This will force state sync to do local copy across canisters
        let canister_2_id: CanisterId = canister_test_id(200);

        insert_dummy_canister(&mut state, canister_2_id);
        let mut canister_2_state = state.take_canister_state(&canister_2_id).unwrap();
        let mut es = canister_2_state.execution_state.clone().unwrap();

        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.update_heap_page(p2_o100, &random_bytes);
        mapped_state.update_heap_page(p3_o100, &random_bytes);

        mapped_state.soft_commit(&[p2_o100, p3_o100]);

        es.last_executed_round = ExecutionRound::from(5);
        canister_2_state.execution_state = Some(es);

        state.put_canister_state(canister_2_state);

        src_state_manager.commit_and_certify(state, new_height, CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, new_height);
        let id = StateSyncArtifactId {
            height: new_height,
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // ================ verify dst recreated state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(new_height)
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);

        let (_height, tip_state) = dst_state_manager.take_tip();

        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(
            vec![height(1), height(2), height(3), height(4), height(5)],
            heights_to_certify(&dst_state_manager)
        );

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();
        let es1 = canister_state.execution_state.unwrap();
        let mapped_state = es1.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o205)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes2);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p2_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p3_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let canister_state = recovered_state.take_canister_state(&canister_2_id).unwrap();
        let es2 = canister_state.execution_state.unwrap();
        let mapped_state = es2.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o205)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes2);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p2_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p3_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        // ----------------------------------- validate the snapshot also got state
        // synced correctly ----------------
        let mapped_state = es1.cow_mem_mgr.get_map_for_snapshot(5).unwrap();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o205)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes2);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p2_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p3_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let mapped_state = es2.cow_mem_mgr.get_map_for_snapshot(5).unwrap();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o205)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes2);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_ne!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p2_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p3_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);
        // End Test 3
    })
}

#[test]
fn cow_state_can_do_simple_state_sync_transfer_with_stable_memory() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    let src_tmp = Builder::new().prefix("test").tempdir().unwrap();
    let src_config = Config::new(src_tmp.path().into());

    let dst_tmp = Builder::new().prefix("test").tempdir().unwrap();
    let dst_config = Config::new(dst_tmp.path().into());

    let src_metrics_registry = MetricsRegistry::new();
    let dst_metrics_registry = MetricsRegistry::new();

    let src_verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());
    let dst_verifier: Arc<dyn Verifier> = Arc::new(FakeVerifier::new());

    with_test_replica_logger(|log| {
        let canister_id: CanisterId = canister_test_id(100);
        let own_subnet = subnet_test_id(42);

        let src_state_manager = StateManagerImpl::new(
            src_verifier,
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &src_metrics_registry,
            &src_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let dst_state_manager = StateManagerImpl::new(
            dst_verifier,
            own_subnet,
            SubnetType::Application,
            log,
            &dst_metrics_registry,
            &dst_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let p0_o0 = get_page_nr(0, 0);
        let p0_o10 = get_page_nr(0, 10);
        let p0_o14 = get_page_nr(0, 14);
        let p1_o4 = get_page_nr(1, 4);

        let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
        let random_bytes1: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

        // ====================================================================
        // Test 1: state_sync can sync cow stable memory to an empty state manager
        // ====================================================================
        let (_height, mut state) = src_state_manager.take_tip();

        insert_dummy_canister(&mut state, canister_id);

        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.take().unwrap();
        let mut system_state = &mut canister_state.system_state;

        let mut buf = page_map::Buffer::new(PageMap::default());
        // let layout = canister_layout(state.path(), &canister_id);
        // system_state.stable_memory = StableMemory::open(layout.raw_path());
        system_state.stable_memory_size = NumWasmPages64::new(10);

        buf.write(&random_bytes[..], get_page_off(p0_o0));

        buf.write(&random_bytes1[..], get_page_off(p0_o10));

        buf.write(&random_bytes2[..], get_page_off(p0_o14));
        system_state.stable_memory = buf.into_page_map();

        // sm.commit();

        es.last_executed_round = ExecutionRound::from(1);
        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);
        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, height(1));
        let id = StateSyncArtifactId {
            height: height(1),
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Verify destination received the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(height(1))
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);
        let (_height, tip_state) = dst_state_manager.take_tip();
        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(vec![height(1)], heights_to_certify(&dst_state_manager));

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();
        let buf = page_map::Buffer::new(canister_state.system_state.stable_memory.clone());

        assert_eq!(
            canister_state.system_state.stable_memory_size,
            NumWasmPages64::new(10)
        );

        let mut read_bytes = vec![0; PAGE_SIZE];

        buf.read(&mut read_bytes[..], get_page_off(p0_o0));
        assert_eq!(read_bytes, random_bytes);

        buf.read(&mut read_bytes[..], get_page_off(p0_o10));
        assert_eq!(read_bytes, random_bytes1);

        buf.read(&mut read_bytes[..], get_page_off(p0_o14));
        assert_eq!(read_bytes, random_bytes2);

        // Make sure that the snapshot was also created correctly

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o0), // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o10),
            // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o14),
            // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes2);

        recovered_state.put_canister_state(canister_state);
        // put the tip back
        dst_state_manager.commit_and_certify(tip_state, height(2), CertificationScope::Full);
        // End Test 1

        let (_height, tip_state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip_state, height(2), CertificationScope::Full);
        // ====================================================================
        // Test 2: Without modifying source, perform another state sync. dst state
        // manager should recreate state by doing local file copy
        // ====================================================================
        let (_height, state) = src_state_manager.take_tip();

        let new_height = height(3);

        src_state_manager.commit_and_certify(state, new_height, CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, new_height);
        let id = StateSyncArtifactId {
            height: new_height,
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Verify dst recreated the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(new_height)
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);

        let (_height, tip_state) = dst_state_manager.take_tip();

        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(
            vec![height(1), height(2), height(3)],
            heights_to_certify(&dst_state_manager)
        );

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();
        let buf = page_map::Buffer::new(canister_state.system_state.stable_memory.clone());

        assert_eq!(
            canister_state.system_state.stable_memory_size,
            NumWasmPages64::new(10)
        );

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o0),
            // None,
        );
        assert_eq!(read_bytes, random_bytes);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o10),
            // None,
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o14),
            // None,
        );
        assert_eq!(read_bytes, random_bytes2);

        // Make sure that the snapshot was also created correctly

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o0),
            // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o10),
            // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o14),
            // Some(ExecutionRound::from(1)),
        );
        assert_eq!(read_bytes, random_bytes2);

        recovered_state.put_canister_state(canister_state);
        dst_state_manager.commit_and_certify(tip_state, height(4), CertificationScope::Full);
        // End Test2

        let (_height, tip_state) = src_state_manager.take_tip();
        src_state_manager.commit_and_certify(tip_state, height(4), CertificationScope::Full);

        // ====================================================================
        // Test 3 Grow stable memory modify only the first chunk,
        // create one more chunk that looks like
        // an existing one and verify all three chunks are synced
        // correctly along with the new size
        // ====================================================================
        let (_height, mut state) = src_state_manager.take_tip();

        let new_height = height(5);

        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.take().unwrap();

        canister_state.system_state.stable_memory_size += NumWasmPages64::new(50);
        let mut buf = page_map::Buffer::new(canister_state.system_state.stable_memory);
        buf.write(
            &random_bytes1,
            get_page_off(p0_o0),
            // None,
        );

        buf.write(
            &random_bytes2,
            get_page_off(p1_o4),
            // None,
        );
        canister_state.system_state.stable_memory = buf.into_page_map();

        // sm.commit();

        es.last_executed_round = ExecutionRound::from(5);
        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);

        src_state_manager.commit_and_certify(state, new_height, CertificationScope::Full);
        let hash = wait_for_checkpoint(&src_state_manager, new_height);
        let id = StateSyncArtifactId {
            height: new_height,
            hash,
        };

        let state = src_state_manager.get_latest_state().take();

        let msg = src_state_manager
            .get_validated_by_identifier(&id)
            .expect("failed to get state sync messages");

        // Verify dst recreated the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id);

        let dst_msg = pipe_state_sync(msg, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state = dst_state_manager
            .get_state_at(new_height)
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        assert_eq!(state.as_ref(), &recovered_state);

        let (_height, tip_state) = dst_state_manager.take_tip();

        assert_eq!(state.as_ref(), &tip_state);
        assert_eq!(
            vec![height(1), height(2), height(3), height(4), height(5)],
            heights_to_certify(&dst_state_manager)
        );

        let canister_state = recovered_state.take_canister_state(&canister_id).unwrap();

        assert_eq!(
            canister_state.system_state.stable_memory_size,
            NumWasmPages64::new(60)
        );
        let buf = page_map::Buffer::new(canister_state.system_state.stable_memory);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o0),
            // None,
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o10),
            // None,
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o14),
            // None,
        );
        assert_eq!(read_bytes, random_bytes2);

        buf.read(
            &mut read_bytes,
            get_page_off(p1_o4),
            // None,
        );
        assert_eq!(read_bytes, random_bytes2);

        // Make sure that the snapshot was also created correctly

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o0),
            // Some(ExecutionRound::from(5)),
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o10),
            // Some(ExecutionRound::from(5)),
        );
        assert_eq!(read_bytes, random_bytes1);

        buf.read(
            &mut read_bytes,
            get_page_off(p0_o14),
            // Some(ExecutionRound::from(5)),
        );
        assert_eq!(read_bytes, random_bytes2);

        buf.read(
            &mut read_bytes,
            get_page_off(p1_o4),
            // Some(ExecutionRound::from(5)),
        );
        assert_eq!(read_bytes, random_bytes2);

        // End Test 3
    })
}

#[allow(dead_code)]
fn canister_layout(state_path: &Path, canister_id: &CanisterId) -> CanisterLayout<RwPolicy> {
    CheckpointLayout::<RwPolicy>::new(state_path.into(), Height::from(0))
        .and_then(|layout| layout.canister(canister_id))
        .expect("failed to obtain canister layout")
}
