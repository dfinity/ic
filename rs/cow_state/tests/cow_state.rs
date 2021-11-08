use ic_cow_state::*;
use ic_utils::ic_features::cow_state_feature;
use std::ptr;

use ic_sys::PAGE_SIZE;
use libc::{c_void, mprotect, PROT_READ, PROT_WRITE};
use tempfile::tempdir;

fn reset_mem_protection(base: *mut u8, len: usize, new_permissions: libc::c_int) {
    unsafe {
        let result = mprotect(base as *mut c_void, len, new_permissions);

        assert_eq!(
            result,
            0,
            "mprotect failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[test]
fn cow_state_heap_basic() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    // Lets create bunch of random bytes
    let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());

    // Test1: create a mapping, modify the memory, soft commit it and
    // then verify that modifications persists
    let mapped_state = cow_mem_mgr.get_map();
    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    unsafe { std::ptr::copy_nonoverlapping(random_bytes.as_ptr(), base, PAGE_SIZE) };
    mapped_state.soft_commit(&[0]);

    cow_mem_mgr.checkpoint();

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly
    assert_eq!(read_bytes, random_bytes);

    // Test2: Overwrite the modifications but do not soft commit
    // the modifications. Make sure nothing gets persisted
    unsafe {
        ptr::write_bytes(base, 0xff, PAGE_SIZE);
    }

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base, PAGE_SIZE).to_vec() };

    // Assert nothing peristed
    assert_eq!(read_bytes, random_bytes);

    // Test3 Update the heap directly and make sure it survives
    let random_bytes2: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
    mapped_state.update_heap_page(1, &random_bytes2);
    mapped_state.soft_commit(&[1]);

    cow_mem_mgr.checkpoint();

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let base = unsafe { mapped_state.get_heap_base().add(PAGE_SIZE) };
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base as *const u8, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly
    assert_eq!(read_bytes, random_bytes2);

    drop(mapped_state);

    // Test 3.5 update heap unaligned and make sure it works
    let offset_to_write_at = 10 * PAGE_SIZE + 3593;
    let random_bytes35: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let mapped_state = cow_mem_mgr.get_map();
    let pages_to_commit = mapped_state.copy_to_heap(offset_to_write_at as u64, &random_bytes35);

    mapped_state.soft_commit(&pages_to_commit.as_slice());

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    mapped_state.make_heap_accessible();
    let base = unsafe { mapped_state.get_heap_base().add(offset_to_write_at) };
    // reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base as *const u8, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly
    assert_eq!(read_bytes, random_bytes35);

    drop(mapped_state);

    // Test4 end the round and make sure all the prior modifications are part of the
    // round
    cow_mem_mgr.create_snapshot(42);

    // Get a readonly mapping and make sure we can read from it correctly
    let cow_mem_mgr = CowMemoryManagerImpl::open_readonly(test_dir.path().into());
    let mapped_state = cow_mem_mgr.get_map_for_snapshot(42).unwrap();

    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly in the first page
    assert_eq!(read_bytes, random_bytes);

    let base = unsafe { mapped_state.get_heap_base().add(PAGE_SIZE) };
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base as *const u8, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly
    assert_eq!(read_bytes, random_bytes2);
}

#[test]
fn cow_state_globals_basic() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    // Lets create bunch of random bytes
    let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());

    // Test1: create a mapping, modify the memory, soft commit it and
    // then verify that modifications persists
    let mapped_state = cow_mem_mgr.get_map();
    mapped_state.update_globals(&random_bytes);

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let globals = mapped_state.get_globals();

    // Assert everything persisted correctly
    assert_eq!(globals, random_bytes.as_slice());

    cow_mem_mgr.create_snapshot(42);

    let cow_mem_mgr_ro = CowMemoryManagerImpl::open_readonly(test_dir.path().into());
    let mapped_state = cow_mem_mgr_ro.get_map_for_snapshot(42).unwrap();
    let globals = mapped_state.get_globals();

    // Assert everything persisted correctly
    assert_eq!(globals, random_bytes.as_slice());
}

#[test]
fn cow_state_clear_basic() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    // Lets create bunch of random bytes
    let random_bytes2: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());
    let mapped_state = cow_mem_mgr.get_map();

    mapped_state.update_heap_page(1, &random_bytes2);
    mapped_state.soft_commit(&[1]);

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let base = unsafe { mapped_state.get_heap_base().add(PAGE_SIZE) };
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base as *const u8, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly
    assert_eq!(read_bytes, random_bytes2);

    // clear the mappings
    mapped_state.clear();

    drop(mapped_state);

    let mapped_state = cow_mem_mgr.get_map();
    let base = unsafe { mapped_state.get_heap_base().add(PAGE_SIZE) };
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base as *const u8, PAGE_SIZE).to_vec() };

    // Assert nothing persisted correctly
    assert_ne!(read_bytes, random_bytes2);
}

fn make_path_readonly_recursive(path: &std::path::Path) -> std::io::Result<()> {
    let metadata = path.metadata()?;

    if metadata.is_dir() {
        let entries = path.read_dir()?;

        for entry_result in entries {
            let entry = entry_result?;
            make_path_readonly_recursive(&entry.path())?;
        }
    } else {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[test]
fn cow_state_heap_ro_basic() {
    cow_state_feature::enable(cow_state_feature::cow_state);

    // Lets create bunch of random bytes
    let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());

    // Test1: create a mapping, modify the memory, soft commit it and
    // then verify that modifications persists
    let mapped_state = cow_mem_mgr.get_map();
    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    unsafe { std::ptr::copy_nonoverlapping(random_bytes.as_ptr(), base, PAGE_SIZE) };
    mapped_state.soft_commit(&[0]);
    cow_mem_mgr.create_snapshot(42);

    cow_mem_mgr.checkpoint();

    // Intentionally drop the mappings to force unmaps
    drop(mapped_state);

    // make everything readonly
    make_path_readonly_recursive(test_dir.path()).unwrap();

    // Get a readonly mapping and make sure we can read from it correctly
    let cow_mem_mgr = CowMemoryManagerImpl::open_readonly(test_dir.path().into());
    let mapped_state = cow_mem_mgr.get_map_for_snapshot(42).unwrap();

    let base = mapped_state.get_heap_base();
    reset_mem_protection(base, PAGE_SIZE, PROT_READ | PROT_WRITE);

    let read_bytes = unsafe { std::slice::from_raw_parts(base, PAGE_SIZE).to_vec() };

    // Assert everything persisted correctly in the first page
    assert_eq!(read_bytes, random_bytes);

    // Make sure modifying the memory does not panic
    unsafe { std::ptr::copy_nonoverlapping(random_bytes.as_ptr(), base, PAGE_SIZE) };
}

#[test]
fn cow_state_multi_thread() {
    use std::thread;
    use tempfile::tempdir;

    cow_state_feature::enable(cow_state_feature::cow_state);
    let nr_iterations = 100;

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr =
        std::sync::Arc::new(CowMemoryManagerImpl::open_readwrite(test_dir.path().into()));

    for i in 0..30 {
        let writer_mgr = cow_mem_mgr.clone();
        let reader_mgr = cow_mem_mgr.clone();
        let reader_mgr1 = cow_mem_mgr.clone();
        let reader_mgr2 = cow_mem_mgr.clone();
        let reader_mgr3 = cow_mem_mgr.clone();
        let writer = thread::spawn(move || {
            for _ in 1..nr_iterations {
                let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();
                let mapped_state = writer_mgr.get_map();
                let pages = mapped_state.copy_to_heap(0, &random_bytes);
                mapped_state.soft_commit(&pages);
                if i % 7 == 0 {
                    writer_mgr.checkpoint();
                }
            }
        });

        let reader = thread::spawn(move || {
            for _ in 1..nr_iterations {
                let mapped_state = reader_mgr.get_map();
                mapped_state.copy_from_heap(0, 4096);
            }
        });
        let reader1 = thread::spawn(move || {
            for _ in 1..nr_iterations {
                let mapped_state = reader_mgr1.get_map();
                mapped_state.copy_from_heap(0, 4096);
            }
        });
        let reader2 = thread::spawn(move || {
            for _ in 1..nr_iterations {
                let mapped_state = reader_mgr2.get_map();
                mapped_state.copy_from_heap(0, 4096);
            }
        });
        let reader3 = thread::spawn(move || {
            for _ in 1..nr_iterations {
                let mapped_state = reader_mgr3.get_map();
                mapped_state.copy_from_heap(0, 4096);
            }
        });

        writer.join().expect("writer failed");
        reader.join().expect("reader failed");
        reader1.join().expect("reader failed");
        reader2.join().expect("reader failed");
        reader3.join().expect("reader failed");
    }
}
