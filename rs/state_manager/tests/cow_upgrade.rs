use ic_config::state_manager::Config;
use ic_cow_state::*;
use ic_interfaces::artifact_manager::ArtifactClient;
use ic_interfaces::certification::Verifier;
use ic_interfaces::state_manager::*;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::PageIndex;
use ic_state_manager::StateManagerImpl;
use ic_sys::PAGE_SIZE;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    types::ids::{canister_test_id, node_test_id, subnet_test_id},
    with_test_replica_logger,
};
use ic_types::{artifact::StateSyncArtifactId, CanisterId};
use ic_utils::ic_features::*;
use std::sync::Arc;
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
fn cow_state_can_handle_upgrade() {
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
            src_verifier.clone(),
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &src_metrics_registry,
            &src_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let p0_o10 = get_page_nr(0, 10);
        let p0_o20 = get_page_nr(0, 20);
        let p0_o257 = get_page_nr(0, 257);

        let random_bytes = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes1 = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes2 = [rand::random::<u8>(); PAGE_SIZE];

        let pd = &[
            (PageIndex::new(p0_o10), &random_bytes),
            (PageIndex::new(p0_o20), &random_bytes1),
            (PageIndex::new(p0_o257), &random_bytes2),
        ];

        let (_height, mut state) = src_state_manager.take_tip();

        insert_dummy_canister(&mut state, canister_id);

        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.clone().unwrap();

        es.page_map.update(pd);

        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);

        src_state_manager.commit_and_certify(state, height(1), CertificationScope::Full);
        let hash_1 = wait_for_checkpoint(&src_state_manager, height(1));
        let id_1 = StateSyncArtifactId {
            height: height(1),
            hash: hash_1,
        };

        // Now we have created the canister and it should be a non cow canister.
        // turn on cow and check if it upgrades
        cow_state_feature::enable(cow_state_feature::cow_state);

        drop(src_state_manager);

        let src_metrics_registry = MetricsRegistry::new();
        let src_state_manager = StateManagerImpl::new(
            src_verifier.clone(),
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &src_metrics_registry,
            &src_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let (_height, mut state) = src_state_manager.take_tip();
        let canister_state = state.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.clone().unwrap();
        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o10)), PAGE_SIZE).to_vec()
        };

        assert_eq!(read_bytes, random_bytes);
        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o20)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o257)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes2);

        // Modify the canister further as cow canister
        let p0_o200 = get_page_nr(0, 200);
        let p0_o205 = get_page_nr(0, 205);
        let p1_o100 = get_page_nr(1, 100);
        let p2_o100 = get_page_nr(2, 100);
        let p3_o100 = get_page_nr(3, 100);

        let random_bytes3 = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes4 = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes5 = [rand::random::<u8>(); PAGE_SIZE];

        mapped_state.update_heap_page(p0_o200, &random_bytes3);
        mapped_state.update_heap_page(p0_o205, &random_bytes4);
        mapped_state.update_heap_page(p1_o100, &random_bytes5);
        mapped_state.update_heap_page(p2_o100, &random_bytes1);
        mapped_state.update_heap_page(p3_o100, &random_bytes2);

        mapped_state.soft_commit(&[p0_o200, p0_o205, p1_o100, p2_o100, p3_o100]);

        state.put_canister_state(canister_state);

        src_state_manager.commit_and_certify(state, height(2), CertificationScope::Full);
        let hash_2 = wait_for_checkpoint(&src_state_manager, height(2));
        let id_2 = StateSyncArtifactId {
            height: height(2),
            hash: hash_2,
        };

        // Disable cow forcing a downgrade and then validate
        cow_state_feature::disable(cow_state_feature::cow_state);

        drop(src_state_manager);

        let src_metrics_registry = MetricsRegistry::new();
        let src_state_manager = StateManagerImpl::new(
            src_verifier,
            own_subnet,
            SubnetType::Application,
            log.clone(),
            &src_metrics_registry,
            &src_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let (_height, mut state) = src_state_manager.take_tip();
        let mut canister_state = state.take_canister_state(&canister_id).unwrap();
        let mut es = canister_state.execution_state.clone().unwrap();
        assert!(!es.cow_mem_mgr.is_valid());

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o10));
        assert_eq!(read_bytes, &random_bytes);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o20));
        assert_eq!(read_bytes, &random_bytes1);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o257));
        assert_eq!(read_bytes, &random_bytes2);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o200));
        assert_eq!(read_bytes, &random_bytes3);
        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o205));
        assert_eq!(read_bytes, &random_bytes4);
        let read_bytes = es.page_map.get_page(PageIndex::new(p1_o100));
        assert_eq!(read_bytes, &random_bytes5);
        let read_bytes = es.page_map.get_page(PageIndex::new(p2_o100));
        assert_eq!(read_bytes, &random_bytes1);
        let read_bytes = es.page_map.get_page(PageIndex::new(p3_o100));
        assert_eq!(read_bytes, &random_bytes2);

        // add/overwrite few more pages
        let p0_o50 = get_page_nr(0, 50);
        let p0_o60 = get_page_nr(0, 60);
        let p3_o257 = get_page_nr(3, 257);

        let random_bytes6 = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes7 = [rand::random::<u8>(); PAGE_SIZE];
        let random_bytes8 = [rand::random::<u8>(); PAGE_SIZE];

        let pd = &[
            (PageIndex::new(p0_o50), &random_bytes6),
            (PageIndex::new(p0_o60), &random_bytes7),
            (PageIndex::new(p0_o257), &random_bytes8),
            (PageIndex::new(p3_o257), &random_bytes8),
        ];

        es.page_map.update(pd);

        canister_state.execution_state = Some(es);

        state.put_canister_state(canister_state);

        src_state_manager.commit_and_certify(state, height(3), CertificationScope::Full);
        let hash_3 = wait_for_checkpoint(&src_state_manager, height(3));
        let id_3 = StateSyncArtifactId {
            height: height(3),
            hash: hash_3,
        };

        // At this point we have 3 checkpoints 1->non cow, 2->cow 3->non cow.
        // Now lets do state sync of each and make sure they recover correctly

        let dst_state_manager = StateManagerImpl::new(
            dst_verifier,
            own_subnet,
            SubnetType::Application,
            log,
            &dst_metrics_registry,
            &dst_config,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );

        let msg_1 = src_state_manager
            .get_validated_by_identifier(&id_1)
            .expect("failed to get state sync messages");

        // Verify destination received the state correctly
        let chunkable = dst_state_manager.create_chunkable_state(&id_1);

        let dst_msg = pipe_state_sync(msg_1, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state_1 = dst_state_manager
            .get_state_at(height(1))
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        // This should be non_cow
        let canister_state = recovered_state_1.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.unwrap();
        assert!(!es.cow_mem_mgr.is_valid());

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o10));
        assert_eq!(read_bytes, &random_bytes);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o20));
        assert_eq!(read_bytes, &random_bytes1);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o257));
        assert_eq!(read_bytes, &random_bytes2);

        // ============== now state_sync 2 make sure it comes back as cow correctly
        let msg_2 = src_state_manager
            .get_validated_by_identifier(&id_2)
            .expect("failed to get state sync messages");

        let chunkable = dst_state_manager.create_chunkable_state(&id_2);

        let dst_msg = pipe_state_sync(msg_2, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state_2 = dst_state_manager
            .get_state_at(height(2))
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        let canister_state = recovered_state_2.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.unwrap();
        assert!(es.cow_mem_mgr.is_valid());
        let mapped_state = es.cow_mem_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = mapped_state.get_heap_base();

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o10)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o20)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o257)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes2);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o200)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes3);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p0_o205)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes4);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p1_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes5);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p2_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes1);

        let read_bytes = unsafe {
            std::slice::from_raw_parts(base.add(get_page_off(p3_o100)), PAGE_SIZE).to_vec()
        };
        assert_eq!(read_bytes, random_bytes2);

        // lets state sync the third one :
        let msg_3 = src_state_manager
            .get_validated_by_identifier(&id_3)
            .expect("failed to get state sync messages");

        let chunkable = dst_state_manager.create_chunkable_state(&id_3);

        let dst_msg = pipe_state_sync(msg_3, chunkable);
        let result = dst_state_manager.check_artifact_acceptance(dst_msg, &node_test_id(0));
        assert!(
            result.is_ok(),
            "Failed to process state sync artifact: {:?}",
            result
        );

        let mut recovered_state_3 = dst_state_manager
            .get_state_at(height(3))
            .expect("Destination state manager didn't receive the state")
            .take()
            .as_ref()
            .clone();

        let canister_state = recovered_state_3.take_canister_state(&canister_id).unwrap();
        let es = canister_state.execution_state.unwrap();
        assert!(!es.cow_mem_mgr.is_valid());

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o10));
        assert_eq!(read_bytes, &random_bytes);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o20));
        assert_eq!(read_bytes, &random_bytes1);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o50));
        assert_eq!(read_bytes, &random_bytes6);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o60));
        assert_eq!(read_bytes, &random_bytes7);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o257));
        assert_eq!(read_bytes, &random_bytes8);

        let read_bytes = es.page_map.get_page(PageIndex::new(p3_o257));
        assert_eq!(read_bytes, &random_bytes8);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o200));
        assert_eq!(read_bytes, &random_bytes3);

        let read_bytes = es.page_map.get_page(PageIndex::new(p0_o205));
        assert_eq!(read_bytes, &random_bytes4);

        let read_bytes = es.page_map.get_page(PageIndex::new(p1_o100));
        assert_eq!(read_bytes, &random_bytes5);

        let read_bytes = es.page_map.get_page(PageIndex::new(p2_o100));
        assert_eq!(read_bytes, &random_bytes1);

        let read_bytes = es.page_map.get_page(PageIndex::new(p3_o100));
        assert_eq!(read_bytes, &random_bytes2);
    })
}
