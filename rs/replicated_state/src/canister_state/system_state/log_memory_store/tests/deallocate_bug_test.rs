use ic_config::flag_status::FlagStatus;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_types::CanisterLog;

#[test]
fn test_next_idx_preserved_after_deallocate() {
    let mut store = LogMemoryStore::new(FlagStatus::Enabled);
    store.resize_for_testing(4096);
    
    let mut delta = CanisterLog::default_delta();
    delta.add_record(vec![1, 2, 3]);
    delta.add_record(vec![4, 5, 6]);
    store.append_delta_log(&mut delta);
    
    let next_idx = store.next_idx();
    assert_eq!(next_idx, 2);
    
    // Setting limit to 0 invokes deallocate()
    store.resize_for_testing(0);
    
    // The next_idx should be preserved even if deallocated
    assert_eq!(store.next_idx(), 2);
}
